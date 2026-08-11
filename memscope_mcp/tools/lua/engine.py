"""Lua scripting engine for memory operations.

Generic Lua runtime and registrar. Domain-specific functions are registered
by extensions via register_functions(), not wired here.
"""

import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional

from lupa import LuaError, LuaRuntime, lua_type

from .code_execution import LuaExecutionGuard
from .comparisons import to_uint64

# Check for cancellation every N Lua VM instructions.
# Calls a Python callback, so KeyboardInterrupt can also be delivered here.
_CANCEL_CHECK_INTERVAL = 10000

# Default timeout for Lua script execution (seconds).
# Can be overridden per-call via the timeout parameter.
DEFAULT_TIMEOUT = 180  # 3 minutes

_CANCEL_MARKER = "[CANCELLED]"
_TIMEOUT_MARKER = "[TIMEOUT]"


class _CompositionState(Enum):
    UNBOUND = auto()
    BOOTSTRAPPING = auto()
    READY = auto()
    FAILED = auto()


class _OperationKind(Enum):
    EXECUTE = auto()
    REGISTER = auto()
    BOOTSTRAP = auto()


@dataclass(frozen=True, slots=True)
class _PreparedFunctionMapping:
    owner: str
    registrations: tuple[tuple[str, Callable[..., Any]], ...]


class _LuaHandleEscapeError(RuntimeError):
    pass


class ExecutionInterrupt:
    """Stable engine-owned interruption capability for registered functions."""

    __slots__ = ("_check", "_deadline_supplier")

    def __init__(
        self,
        check: Callable[[], None],
        deadline_supplier: Callable[[], int | None],
    ) -> None:
        self._check = check
        self._deadline_supplier = deadline_supplier

    def check(self) -> None:
        self._check()

    @property
    def deadline_ns(self) -> int | None:
        return self._deadline_supplier()


class _BootstrapTransaction:
    """Private Python-only staging area for one engine composition."""

    __slots__ = ("_engine", "_token", "_staged")

    def __init__(self, engine: "MemscopeLuaEngine", token: object) -> None:
        self._engine = engine
        self._token = token
        self._staged: dict[str, tuple[str, Callable[..., Any]]] = {}

    def prepare_functions(self, owner: str, funcs: Mapping[str, Callable[..., Any]]) -> _PreparedFunctionMapping:
        registrations = self._engine._snapshot_function_mapping(owner, funcs)
        existing = self._engine._bootstrap_existing_registry(self._token)
        for name, _func in registrations:
            existing_owner = existing.get(name)
            if existing_owner is None:
                staged = self._staged.get(name)
                existing_owner = staged[0] if staged is not None else None
            if existing_owner is not None:
                raise ValueError(
                    f"Lua function '{name}' already registered by '{existing_owner}', cannot register from '{owner}'"
                )
        return _PreparedFunctionMapping(owner=owner, registrations=registrations)

    def accept_functions(self, prepared: _PreparedFunctionMapping) -> None:
        self._engine._validate_bootstrap_capability(self._token)
        for name, func in prepared.registrations:
            self._staged[name] = (prepared.owner, func)

    def commit(
        self,
        session: object,
        attach_callbacks: Mapping[str, Callable[..., Any]],
        detach_callbacks: Mapping[str, Callable[..., Any]],
    ) -> None:
        self._engine._commit_bootstrap(
            self._token,
            session,
            self._staged,
            attach_callbacks,
            detach_callbacks,
        )


class MemscopeLuaEngine:
    """Lua scripting environment for memory research.

    Owns the private Lua runtime, script preprocessing, execution, and
    per-execution state. Extensions receive only guarded engine capabilities.
    """

    def __init__(self):
        self._lua = LuaRuntime(unpack_returned_tuples=True)
        self._output: list[str] = []
        self._last_error: Optional[str] = None
        self._debug_errors: bool = False
        self._composition_state = _CompositionState.UNBOUND
        self._composition_session: object | None = None
        self._function_registry: dict[str, str] = {}  # func_name -> owner_name

        # One non-reentrant state lock protects both composition state and the
        # logical runtime lease. It is never held while calling into Lupa or
        # extension/session code.
        self._state_condition = threading.Condition(threading.Lock())
        self._operation_token: object | None = None
        self._operation_kind: _OperationKind | None = None
        self._operation_thread_id: int | None = None
        self._bootstrap_token: object | None = None

        self._execution_guard = LuaExecutionGuard()

        # Cancellation / timeout state is independent of the runtime lease so
        # another thread can always request interruption.
        self._cancel_event = threading.Event()
        self._deadline_ns: int | None = None
        self._clock = time.monotonic_ns
        self._execution_interrupt = ExecutionInterrupt(self._check_cancel, lambda: self._deadline_ns)
        self._table_factory_capability = self._make_lua_table

        # Initialize per-execution Lua globals.
        g = self._lua.globals()
        g["_results"] = self._lua.table()
        g["args"] = self._lua.table()

        # Register cancel-check callback and install debug hook. The hook makes
        # even pure-Lua loops interruptible.
        g["__cancel_check"] = self._check_cancel
        self._lua.execute(f'debug.sethook(function() __cancel_check() end, "", {_CANCEL_CHECK_INTERVAL})')

    # ========== Composition and Function Registration ==========

    @property
    def bound_session(self) -> object | None:
        """Return the composition session only after bootstrap commits READY."""

        with self._state_condition:
            if self._composition_state is _CompositionState.READY:
                return self._composition_session
            return None

    @property
    def table_factory(self) -> Callable[..., Any]:
        """Return the guarded Lua-table construction capability."""

        return self._table_factory_capability

    def _composition_callback_is_active(self, session: object) -> bool:
        """Return whether guarded callbacks belong to the committed composition."""

        with self._state_condition:
            return self._composition_state is _CompositionState.READY and self._composition_session is session

    def _allows_session_callback_registration(self, session: object) -> bool:
        """Allow ordinary callback registration only for the committed owner."""

        return self._composition_callback_is_active(session)

    @contextmanager
    def _bootstrap_transaction(self, session: object) -> Iterator[_BootstrapTransaction]:
        """Claim a session and own one private bootstrap transaction."""

        token = object()
        try:
            self._begin_bootstrap(session, token)
            transaction = _BootstrapTransaction(self, token)
            yield transaction
        except BaseException:
            self._fail_bootstrap(token)
            raise
        finally:
            self._finish_bootstrap_operation(token)

    def _begin_bootstrap(self, session: object, token: object) -> None:
        """Acquire the bootstrap lease, then reconcile the fallible claim."""

        thread_id = threading.get_ident()
        try:
            with self._state_condition:
                if self._composition_state is _CompositionState.BOOTSTRAPPING:
                    raise RuntimeError("MemscopeLuaEngine composition bootstrap is already in progress")
                if self._composition_state is _CompositionState.READY:
                    raise RuntimeError("MemscopeLuaEngine composition is already ready; bootstrap cannot run again")
                if self._composition_state is _CompositionState.FAILED:
                    raise RuntimeError(
                        "MemscopeLuaEngine composition has failed and is permanently quarantined; "
                        "bootstrap cannot run again"
                    )
                if self._operation_token is not None:
                    raise RuntimeError("MemscopeLuaEngine runtime operation is active; bootstrap cannot start")
                self._operation_token = token
                self._operation_kind = _OperationKind.BOOTSTRAP
                self._operation_thread_id = thread_id
                self._bootstrap_token = token

            session._claim_lua_composition_engine(self)
            claimed_engine = session._lua_composition_engine_identity()
            if claimed_engine is not self:
                raise RuntimeError("DebugSession composition claim did not transfer ownership")

            with self._state_condition:
                if (
                    self._operation_token is not token
                    or self._operation_kind is not _OperationKind.BOOTSTRAP
                    or self._operation_thread_id != thread_id
                    or self._bootstrap_token is not token
                    or self._composition_state is not _CompositionState.UNBOUND
                ):
                    raise RuntimeError("Lua bootstrap state changed after session claim")
                self._composition_session = session
                self._composition_state = _CompositionState.BOOTSTRAPPING
        except BaseException:
            self._reconcile_bootstrap_begin_failure(session, token)
            raise

    def _reconcile_bootstrap_begin_failure(self, session: object, token: object) -> None:
        """Release this acquisition, retaining a claimed session only as FAILED."""

        claimed_engine: object | None = None
        identity_known = False
        try:
            claimed_engine = session._lua_composition_engine_identity()
            identity_known = True
        finally:
            with self._state_condition:
                if self._operation_token is token:
                    if identity_known and claimed_engine is not self:
                        self._composition_session = None
                        self._composition_state = _CompositionState.UNBOUND
                    else:
                        self._composition_session = session
                        self._composition_state = _CompositionState.FAILED
                    self._clear_operation_locked()

    def _validate_bootstrap_capability(self, token: object) -> None:
        with self._state_condition:
            if (
                self._composition_state is not _CompositionState.BOOTSTRAPPING
                or self._operation_token is not token
                or self._operation_kind is not _OperationKind.BOOTSTRAP
                or self._operation_thread_id != threading.get_ident()
                or self._bootstrap_token is not token
            ):
                raise RuntimeError("Invalid or inactive Lua bootstrap capability")

    def _bootstrap_existing_registry(self, token: object) -> dict[str, str]:
        self._validate_bootstrap_capability(token)
        with self._state_condition:
            return dict(self._function_registry)

    def _commit_bootstrap(
        self,
        token: object,
        session: object,
        staged: Mapping[str, tuple[str, Callable[..., Any]]],
        attach_callbacks: Mapping[str, Callable[..., Any]],
        detach_callbacks: Mapping[str, Callable[..., Any]],
    ) -> None:
        """Publish staged globals/callbacks, then atomically expose READY."""

        self._validate_bootstrap_capability(token)
        if self._composition_session is not session:
            raise RuntimeError("Lua bootstrap session identity changed before commit")

        # Physical publication may partially fail, but no supported operation is
        # available while BOOTSTRAPPING and failure permanently quarantines it.
        globals_ = self._lua.globals()
        for name, (_owner, func) in staged.items():
            globals_[name] = func

        session._publish_lua_composition_callbacks(self, attach_callbacks, detach_callbacks)

        # This is the single logical commit point. Nothing fallible runs after
        # READY is set inside this method.
        with self._state_condition:
            if (
                self._composition_state is not _CompositionState.BOOTSTRAPPING
                or self._operation_token is not token
                or self._operation_kind is not _OperationKind.BOOTSTRAP
                or self._operation_thread_id != threading.get_ident()
                or self._bootstrap_token is not token
            ):
                raise RuntimeError("Lua bootstrap state changed before commit")
            for name, (owner, _func) in staged.items():
                self._function_registry[name] = owner
            self._composition_state = _CompositionState.READY

    def _fail_bootstrap(self, token: object) -> None:
        with self._state_condition:
            if (
                self._operation_token is token
                and self._bootstrap_token is token
                and self._composition_state is _CompositionState.BOOTSTRAPPING
            ):
                self._composition_state = _CompositionState.FAILED

    def _finish_bootstrap_operation(self, token: object) -> None:
        with self._state_condition:
            if self._operation_token is token and self._bootstrap_token is token:
                if self._composition_state is _CompositionState.BOOTSTRAPPING:
                    self._composition_state = _CompositionState.FAILED
                self._clear_operation_locked()

    def _clear_operation_locked(self) -> None:
        self._operation_token = None
        self._operation_kind = None
        self._operation_thread_id = None
        self._bootstrap_token = None
        self._state_condition.notify_all()

    def _require_ready_session(self) -> object:
        """Return the committed session or reject saved-script use."""

        with self._state_condition:
            if self._composition_state is not _CompositionState.READY:
                raise RuntimeError(
                    "MemscopeLuaEngine composition is not ready; "
                    "bootstrap_extensions() must complete successfully first"
                )
            assert self._composition_session is not None
            return self._composition_session

    @staticmethod
    def _snapshot_function_mapping(
        owner: str,
        funcs: Mapping[str, Callable[..., Any]],
    ) -> tuple[tuple[str, Callable[..., Any]], ...]:
        if not isinstance(owner, str) or not owner:
            raise TypeError("Lua function owner must be a non-empty string")
        if not isinstance(funcs, Mapping):
            raise TypeError("Lua function registration must be a mapping")

        registrations = tuple(funcs.items())
        names: set[str] = set()
        for name, func in registrations:
            if not isinstance(name, str) or not name:
                raise TypeError("Lua function names must be non-empty strings")
            if name in names:
                raise ValueError(f"Lua function mapping contains duplicate name '{name}'")
            if not callable(func):
                raise TypeError(f"Lua function '{name}' must be callable")
            names.add(name)
        return registrations

    def register_functions(
        self,
        owner: str,
        funcs: Mapping[str, Callable[..., Any]],
        allow_overwrite: bool = False,
    ) -> None:
        """Register one complete mapping while the engine is strictly UNBOUND."""

        with self._state_condition:
            self._require_public_registration_open_locked()
        registrations = self._snapshot_function_mapping(owner, funcs)

        with self._registration_lease(owner, registrations, allow_overwrite) as token:
            publication_started = False
            committed = False
            try:
                globals_ = self._lua.globals()
                for name, func in registrations:
                    # A failed Lua assignment cannot prove that it left the
                    # target global unchanged, so attempted publication closes
                    # the fail-open path before entering Lupa.
                    publication_started = True
                    globals_[name] = func
                with self._state_condition:
                    if (
                        self._operation_token is not token
                        or self._operation_kind is not _OperationKind.REGISTER
                        or self._operation_thread_id != threading.get_ident()
                    ):
                        raise RuntimeError("Lua function registration lease changed before commit")
                    for name, _func in registrations:
                        self._function_registry[name] = owner
                    # This is the logical mapping commit. An interruption after
                    # this marker must not downgrade the completed registration.
                    committed = True
            except BaseException:
                if publication_started and not committed:
                    self._fail_public_registration(token)
                raise

    @contextmanager
    def _registration_lease(
        self,
        owner: str,
        registrations: tuple[tuple[str, Callable[..., Any]], ...],
        allow_overwrite: bool,
    ) -> Iterator[object]:
        """Reserve public registration and release only this exact lease."""

        token = object()
        thread_id = threading.get_ident()
        try:
            with self._state_condition:
                self._require_public_registration_open_locked()
                if not allow_overwrite:
                    for name, _func in registrations:
                        existing_owner = self._function_registry.get(name)
                        if existing_owner is not None:
                            raise ValueError(
                                f"Lua function '{name}' already registered by '{existing_owner}', "
                                f"cannot register from '{owner}'"
                            )
                self._operation_token = token
                self._operation_kind = _OperationKind.REGISTER
                self._operation_thread_id = thread_id
            yield token
        finally:
            with self._state_condition:
                if self._operation_token is token:
                    self._clear_operation_locked()

    def _fail_public_registration(self, token: object) -> None:
        with self._state_condition:
            if self._operation_token is token and self._composition_state is _CompositionState.UNBOUND:
                self._composition_state = _CompositionState.FAILED

    def _require_public_registration_open_locked(self) -> None:
        if self._composition_state is _CompositionState.READY:
            raise RuntimeError("MemscopeLuaEngine composition is ready; function registration is closed")
        if self._composition_state is _CompositionState.FAILED:
            raise RuntimeError(
                "MemscopeLuaEngine composition has failed and is permanently quarantined; "
                "function registration is unavailable"
            )
        if self._composition_state is _CompositionState.BOOTSTRAPPING:
            raise RuntimeError("MemscopeLuaEngine composition is bootstrapping; function registration is closed")
        if self._operation_token is not None:
            raise RuntimeError("MemscopeLuaEngine runtime operation is active; function registration is unavailable")

    def _make_lua_table(self, *values: Any, **fields: Any) -> Any:
        """Create a Lua table only for the thread owning bootstrap/execution."""

        thread_id = threading.get_ident()
        with self._state_condition:
            if self._composition_state is _CompositionState.FAILED:
                raise RuntimeError("MemscopeLuaEngine composition is permanently quarantined")
            if (
                self._operation_token is None
                or self._operation_thread_id != thread_id
                or self._operation_kind not in {_OperationKind.BOOTSTRAP, _OperationKind.EXECUTE}
            ):
                raise RuntimeError("Lua table construction is available only during an engine-owned operation")
        return self._lua.table(*values, **fields)

    # ========== Cancellation ==========

    def _check_cancel(self) -> None:
        """Called from Lua and registered Python functions at interruption checkpoints."""

        if self._cancel_event.is_set():
            raise Exception(_CANCEL_MARKER)
        if self._deadline_ns is not None and self._clock() >= self._deadline_ns:
            self._cancel_event.set()
            raise Exception(_TIMEOUT_MARKER)

    @property
    def execution_interrupt(self) -> ExecutionInterrupt:
        """Return the stable interruption capability owned by this runtime."""

        return self._execution_interrupt

    def cancel(self) -> None:
        """Cancel the currently running Lua script at its next checkpoint."""

        self._cancel_event.set()

    # ========== Per-Execution Helpers ==========

    def _log_error(self, func_name: str, e: Exception) -> None:
        """Log error for debugging. Stores in _last_error, optionally prints."""
        self._last_error = f"{func_name}: {type(e).__name__}: {e}"
        if self._debug_errors:
            self._output.append(f"[DEBUG] {self._last_error}")

    def _lua_print(self, *args):
        """Capture Lua print statements."""
        parts = []
        for arg in args:
            parts.append("nil" if arg is None else str(arg))
        self._output.append(" ".join(parts))

    def _to_hex(self, x) -> str:
        """Convert value to hex string. Nil-safe. Negatives become uint64 bit pattern."""
        if x is None:
            return "nil"
        try:
            return f"0x{to_uint64(x):X}"
        except (ValueError, TypeError, OverflowError):
            return "0x0"

    def _safe_format(self, fmt_str: str, *args) -> str:
        """Nil-safe string formatting."""
        safe_args = [0 if arg is None else arg for arg in args]
        try:
            return fmt_str % tuple(safe_args)
        except (TypeError, ValueError):
            return f"[format error: {fmt_str} with {args}]"

    def _add_result(self, key, value):
        """Add a result to the results table."""
        self._lua.globals()["_results"][key] = value

    def _set_result(self, value):
        """Set single result value."""
        self._lua.globals()["_results"]["value"] = value

    def _python_to_lua(self, value):
        """Convert Python value to Lua-compatible value."""
        if value is None:
            return None
        if isinstance(value, dict):
            table = self._make_lua_table()
            for key, item in value.items():
                table[key] = self._python_to_lua(item)
            return table
        if isinstance(value, (list, tuple)):
            table = self._make_lua_table()
            for index, item in enumerate(value, 1):
                table[index] = self._python_to_lua(item)
            return table
        return value

    def _lua_to_python(self, value, _seen: set[int] | None = None):
        """Recursively convert Lua tables while rejecting executable handles."""

        value_type = lua_type(value)
        if value_type in {"function", "thread", "userdata"}:
            raise _LuaHandleEscapeError(f"Lua {value_type} values cannot leave the engine")
        if value_type != "table":
            if callable(value):
                raise _LuaHandleEscapeError("Callable values cannot leave the engine")
            if isinstance(value, tuple):
                return tuple(self._lua_to_python(item, _seen) for item in value)
            if isinstance(value, list):
                return [self._lua_to_python(item, _seen) for item in value]
            if isinstance(value, dict):
                return {
                    self._lua_to_python(key, _seen): self._lua_to_python(item, _seen) for key, item in value.items()
                }
            return value

        seen = _seen if _seen is not None else set()
        identity = id(value)
        if identity in seen:
            raise _LuaHandleEscapeError("Cyclic Lua tables cannot leave the engine")
        seen.add(identity)
        try:
            return {self._lua_to_python(key, seen): self._lua_to_python(item, seen) for key, item in value.items()}
        finally:
            seen.remove(identity)

    # ========== Script Preprocessing ==========

    def _preprocess_script(self, script: str) -> tuple[str, list[str]]:
        """Auto-convert large hex literals to addr() calls."""
        conversions = []
        protected = {}
        placeholder_counter = [0]

        def make_placeholder():
            placeholder = f"__PROTECTED_{placeholder_counter[0]}__"
            placeholder_counter[0] += 1
            return placeholder

        def protect(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"\[(=*)\[.*?\]\1\]", protect, script, flags=re.DOTALL)
        temp_script = re.sub(r'"(?:[^"\\]|\\.)*"', protect, temp_script)
        temp_script = re.sub(r"'(?:[^'\\]|\\.)*'", protect, temp_script)
        temp_script = re.sub(r"(addr|parseHex)\(([^)]+)\)", protect, temp_script)

        pattern = r"\b(0x[0-9A-Fa-f]{9,})\b"

        def replace_hex(match):
            hex_val = match.group(1)
            conversions.append(hex_val)
            return f'addr("{hex_val}")'

        processed = re.sub(pattern, replace_hex, temp_script)
        previous = None
        while processed != previous:
            previous = processed
            for placeholder, original in protected.items():
                processed = processed.replace(placeholder, original)

        return processed, conversions

    # ========== Script Execution ==========

    def execute(self, script: str, args: Optional[dict] = None, timeout: float | None = None) -> dict[str, Any]:
        """Execute one script with exclusive logical ownership of the runtime."""

        with self._execution_lease():
            return self._execute(script, args=args, timeout=timeout)

    @contextmanager
    def _execution_lease(self) -> Iterator[None]:
        """Serialize execution and release only this exact reservation."""

        token = object()
        thread_id = threading.get_ident()
        try:
            with self._state_condition:
                while True:
                    if self._composition_state is _CompositionState.BOOTSTRAPPING:
                        raise RuntimeError("MemscopeLuaEngine composition is bootstrapping; execution is unavailable")
                    if self._composition_state is _CompositionState.FAILED:
                        raise RuntimeError(
                            "MemscopeLuaEngine composition has failed and is permanently quarantined; "
                            "execution is unavailable"
                        )
                    if self._operation_token is None:
                        self._operation_token = token
                        self._operation_kind = _OperationKind.EXECUTE
                        self._operation_thread_id = thread_id
                        break
                    if self._operation_thread_id == thread_id:
                        raise RuntimeError("Nested Lua engine execution is not allowed")
                    if self._operation_kind is not _OperationKind.EXECUTE:
                        raise RuntimeError("MemscopeLuaEngine runtime is unavailable during another operation")
                    self._state_condition.wait()
            yield
        finally:
            with self._state_condition:
                if self._operation_token is token:
                    self._deadline_ns = None
                    self._cancel_event.clear()
                    self._clear_operation_locked()

    def _execute(self, script: str, args: Optional[dict] = None, timeout: float | None = None) -> dict[str, Any]:
        self._output = []
        self._last_error = None
        self._cancel_event.clear()
        self._execution_guard = LuaExecutionGuard()
        effective_timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
        self._deadline_ns = self._clock() + int(effective_timeout * 1_000_000_000)

        processed_script, conversions = self._preprocess_script(script)
        conversion_warning = None
        if conversions:
            conversion_warning = (
                f"Auto-converted {len(conversions)} large hex literal(s) to addr() calls: {', '.join(conversions[:3])}"
            )
            if len(conversions) > 3:
                conversion_warning += f" and {len(conversions) - 3} more"

        globals_ = self._lua.globals()
        globals_["_results"] = self._make_lua_table()
        globals_["args"] = self._python_to_lua(args) if args else self._make_lua_table()
        self._lua.execute(f'debug.sethook(function() __cancel_check() end, "", {_CANCEL_CHECK_INTERVAL})')

        try:
            result = self._lua.execute(processed_script)
            collected_results = {
                self._lua_to_python(key): self._lua_to_python(value) for key, value in globals_["_results"].items()
            }
            if result is not None:
                collected_results["return"] = self._lua_to_python(result)

            response = {
                "success": True,
                "results": collected_results,
                "output": self._output,
            }
            if conversion_warning:
                response["_warning"] = conversion_warning
            return response

        except LuaError as e:
            error_msg = str(e)
            if _CANCEL_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "CANCELLED",
                    "detail": "Script was cancelled",
                    "output": self._output,
                }
            if _TIMEOUT_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "TIMEOUT",
                    "detail": "Script exceeded execution time limit",
                    "output": self._output,
                }

            if "malformed number" in error_msg.lower() or "invalid" in error_msg.lower():
                large_hex = re.findall(r"0x[0-9A-Fa-f]{10,}", script)
                if large_hex:
                    return {
                        "success": False,
                        "error": "LUA_PARSE_ERROR",
                        "detail": (
                            f"Large hex literals detected: {', '.join(large_hex[:3])}. "
                            f'Use addr() function instead: addr("{large_hex[0]}")'
                        ),
                        "output": self._output,
                        "hint": (
                            'For 64-bit addresses, use: local myAddr = addr("0x1F58E12ECF0") '
                            "instead of: local myAddr = 0x1F58E12ECF0"
                        ),
                    }

            return {
                "success": False,
                "error": "LUA_ERROR",
                "detail": error_msg,
                "output": self._output,
            }
        except Exception as e:
            error_msg = str(e)
            if _CANCEL_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "CANCELLED",
                    "detail": "Script was cancelled",
                    "output": self._output,
                }
            if _TIMEOUT_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "TIMEOUT",
                    "detail": "Script exceeded execution time limit",
                    "output": self._output,
                }

            if "int too big" in error_msg.lower() or "cannot convert" in error_msg.lower():
                return {
                    "success": False,
                    "error": "EXECUTION_ERROR",
                    "detail": f"Lua numeric overflow with 64-bit value: {error_msg}",
                    "output": self._output,
                    "hint": (
                        "64-bit integer comparison overflow. Solutions:\n"
                        "  1. Use safeEq(a, b), safeNe(a, b), safeLt(a, b), safeGt(a, b) instead of ==, ~=, <, >\n"
                        "  2. For pointers: readPointer() returns nil for invalid pointers"
                        " - use 'if ptr then' instead of 'if ptr ~= 0 then'\n"
                        "  3. For integers: use readIntegerSafe() or safeInt(readInteger(...))"
                        " to get nil for garbage values\n"
                        "  4. For address comparisons: use isValidPointer(addr) instead of addr > 0x10000"
                    ),
                }

            return {
                "success": False,
                "error": "EXECUTION_ERROR",
                "detail": error_msg,
                "output": self._output,
            }


# Global engine singleton -- created at import, populated by bootstrap
LUA_ENGINE = MemscopeLuaEngine()


def execute_lua(script: str, args: Optional[dict] = None, timeout: float | None = None) -> dict[str, Any]:
    """Execute a CE-style Lua script. Thin wrapper around LUA_ENGINE.execute()."""
    return LUA_ENGINE.execute(script, args, timeout=timeout)
