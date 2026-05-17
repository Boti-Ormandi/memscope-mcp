"""Lua scripting engine for memory operations.

Generic Lua runtime and registrar. Domain-specific functions are registered
by extensions via register_functions(), not wired here.
"""

import re
import time
from typing import Any, Optional

from lupa import LuaError, LuaRuntime

from ...session import SESSION  # noqa: F401  exposed for test monkeypatching
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


class MemscopeLuaEngine:
    """Lua scripting environment for memory research.

    Owns the Lua runtime, script preprocessing, execution, and per-execution
    state (output capture, results table). Extensions register their functions
    through register_functions().
    """

    def __init__(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self._output: list[str] = []
        self._last_error: Optional[str] = None
        self._debug_errors: bool = False
        self._function_registry: dict[str, str] = {}  # func_name -> owner_name
        self._execution_guard = LuaExecutionGuard()

        # Cancellation / timeout state
        self._cancelled: bool = False
        self._deadline: float | None = None

        # Initialize per-execution Lua globals
        g = self.lua.globals()
        g["_results"] = self.lua.table()
        g["args"] = self.lua.table()

        # Register cancel-check callback and install debug hook.
        # The hook fires every N VM instructions, crossing into Python where:
        #  - The cancel/timeout flag is checked
        #  - KeyboardInterrupt can be delivered (Python opcode boundary)
        # This makes even pure-Lua loops interruptible.
        g["__cancel_check"] = self._check_cancel
        self.lua.execute(f'debug.sethook(function() __cancel_check() end, "", {_CANCEL_CHECK_INTERVAL})')

    # ========== Function Registration ==========

    def register_functions(self, owner: str, funcs: dict[str, callable], allow_overwrite: bool = False) -> None:
        """Register Lua global functions from an extension or plugin.

        Args:
            owner: Extension/plugin name (for error messages and tracking).
            funcs: Dict mapping Lua global names to Python callables.
            allow_overwrite: If True, silently overwrites existing registrations.
                If False (default), raises ValueError on collision.

        Raises:
            ValueError: If a function name is already registered and allow_overwrite is False.
        """
        g = self.lua.globals()
        for name, func in funcs.items():
            existing_owner = self._function_registry.get(name)
            if existing_owner is not None and not allow_overwrite:
                raise ValueError(
                    f"Lua function '{name}' already registered by '{existing_owner}', cannot register from '{owner}'"
                )
            g[name] = func
            self._function_registry[name] = owner

    # ========== Cancellation ==========

    def _check_cancel(self) -> None:
        """Called from Lua debug hook every N instructions.

        Raises on cancellation or timeout, which propagates as a LuaError
        and aborts the running script.
        """
        if self._cancelled:
            raise Exception(_CANCEL_MARKER)
        if self._deadline is not None and time.monotonic() > self._deadline:
            self._cancelled = True
            raise Exception(_TIMEOUT_MARKER)

    def cancel(self) -> None:
        """Cancel the currently running Lua script.

        The script will abort at the next debug hook check point
        (every ~10K VM instructions).
        """
        self._cancelled = True

    # ========== Per-Execution Helpers ==========
    # These are bound to the engine's per-execution state (_output, _last_error,
    # _results). Extensions capture the engine reference and delegate here.

    def _log_error(self, func_name: str, e: Exception) -> None:
        """Log error for debugging. Stores in _last_error, optionally prints."""
        self._last_error = f"{func_name}: {type(e).__name__}: {e}"
        if self._debug_errors:
            self._output.append(f"[DEBUG] {self._last_error}")

    def _lua_print(self, *args):
        """Capture Lua print statements."""
        parts = []
        for a in args:
            if a is None:
                parts.append("nil")
            else:
                parts.append(str(a))
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
        safe_args = []
        for a in args:
            if a is None:
                safe_args.append(0)
            else:
                safe_args.append(a)
        try:
            return fmt_str % tuple(safe_args)
        except (TypeError, ValueError):
            return f"[format error: {fmt_str} with {args}]"

    def _add_result(self, key, value):
        """Add a result to the results table."""
        g = self.lua.globals()
        g["_results"][key] = value

    def _set_result(self, value):
        """Set single result value."""
        g = self.lua.globals()
        g["_results"]["value"] = value

    def _python_to_lua(self, value):
        """Convert Python value to Lua-compatible value."""
        if value is None:
            return None
        elif isinstance(value, dict):
            t = self.lua.table()
            for k, v in value.items():
                t[k] = self._python_to_lua(v)
            return t
        elif isinstance(value, (list, tuple)):
            t = self.lua.table()
            for i, v in enumerate(value, 1):
                t[i] = self._python_to_lua(v)
            return t
        else:
            return value

    def _lua_to_python(self, value):
        """Recursively convert Lua table to Python dict."""
        if not hasattr(value, "items"):
            return value
        return {k: self._lua_to_python(v) for k, v in value.items()}

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

        # Protect long strings
        def protect_long_string(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"\[(=*)\[.*?\]\1\]", protect_long_string, script, flags=re.DOTALL)

        # Protect double-quoted strings
        def protect_double_string(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r'"(?:[^"\\]|\\.)*"', protect_double_string, temp_script)

        # Protect single-quoted strings
        def protect_single_string(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"'(?:[^'\\]|\\.)*'", protect_single_string, temp_script)

        # Protect already-wrapped addr()/parseHex() calls
        def protect_wrapped(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"(addr|parseHex)\(([^)]+)\)", protect_wrapped, temp_script)

        # Replace large hex literals
        pattern = r"\b(0x[0-9A-Fa-f]{9,})\b"

        def replace_hex(match):
            hex_val = match.group(1)
            conversions.append(hex_val)
            return f'addr("{hex_val}")'

        processed = re.sub(pattern, replace_hex, temp_script)

        # Restore protected content (iterate until stable - handles nested placeholders)
        prev = None
        while processed != prev:
            prev = processed
            for placeholder, original in protected.items():
                processed = processed.replace(placeholder, original)

        return processed, conversions

    # ========== Script Execution ==========

    def execute(self, script: str, args: Optional[dict] = None, timeout: float | None = None) -> dict[str, Any]:
        """Execute Lua script and return results.

        Scripts can run without an attached process. Process introspection
        functions (getProcessList, getServices, etc.) work without attachment.
        Memory functions return nil when no process is attached.
        Use attach(name_or_pid) from Lua to attach to a process.

        Args:
            script: Lua source code to execute.
            args: Optional dict passed as the Lua 'args' global table.
            timeout: Optional timeout in seconds. Script is aborted if exceeded.
        """
        self._output = []
        self._last_error = None
        self._cancelled = False
        self._execution_guard = LuaExecutionGuard()
        effective_timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
        self._deadline = time.monotonic() + effective_timeout

        # Preprocess script
        processed_script, conversions = self._preprocess_script(script)
        conversion_warning = None
        if conversions:
            conversion_warning = (
                f"Auto-converted {len(conversions)} large hex literal(s) to addr() calls: {', '.join(conversions[:3])}"
            )
            if len(conversions) > 3:
                conversion_warning += f" and {len(conversions) - 3} more"

        # Reset results and set args
        g = self.lua.globals()
        g["_results"] = self.lua.table()
        g["args"] = self._python_to_lua(args) if args else self.lua.table()

        # Reinstall cancel hook (in case a previous script removed it)
        self.lua.execute(f'debug.sethook(function() __cancel_check() end, "", {_CANCEL_CHECK_INTERVAL})')

        try:
            result = self.lua.execute(processed_script)

            # Collect results
            results_table = g["_results"]
            collected_results = {}

            if results_table:
                for k, v in results_table.items():
                    collected_results[k] = self._lua_to_python(v)

            # Handle direct return value
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

            # Cancellation / timeout (raised by _check_cancel via debug hook)
            if _CANCEL_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "CANCELLED",
                    "error_detail": "Script was cancelled",
                    "output": self._output,
                }
            if _TIMEOUT_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "TIMEOUT",
                    "error_detail": "Script exceeded execution time limit",
                    "output": self._output,
                }

            if "malformed number" in error_msg.lower() or "invalid" in error_msg.lower():
                large_hex = re.findall(r"0x[0-9A-Fa-f]{10,}", script)
                if large_hex:
                    return {
                        "success": False,
                        "error": "LUA_PARSE_ERROR",
                        "error_detail": (
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
                "error_detail": error_msg,
                "output": self._output,
            }
        except Exception as e:
            error_msg = str(e)

            # Cancellation / timeout (lupa may re-raise the original Exception
            # instead of wrapping it as LuaError, depending on the call path)
            if _CANCEL_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "CANCELLED",
                    "error_detail": "Script was cancelled",
                    "output": self._output,
                }
            if _TIMEOUT_MARKER in error_msg:
                return {
                    "success": False,
                    "error": "TIMEOUT",
                    "error_detail": "Script exceeded execution time limit",
                    "output": self._output,
                }

            if "int too big" in error_msg.lower() or "cannot convert" in error_msg.lower():
                return {
                    "success": False,
                    "error": "EXECUTION_ERROR",
                    "error_detail": f"Lua numeric overflow with 64-bit value: {error_msg}",
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
                "error_detail": error_msg,
                "output": self._output,
            }


# Global engine singleton -- created at import, populated by bootstrap
LUA_ENGINE = MemscopeLuaEngine()


def execute_lua(script: str, args: Optional[dict] = None, timeout: float | None = None) -> dict[str, Any]:
    """Execute a CE-style Lua script. Thin wrapper around LUA_ENGINE.execute()."""
    return LUA_ENGINE.execute(script, args, timeout=timeout)
