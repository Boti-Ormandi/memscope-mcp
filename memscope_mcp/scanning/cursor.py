"""Authenticated self-contained continuation state for address scans."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

from memscope_mcp.scanning.contract import (
    AllModulesScopeInput,
    ModulesScopeInput,
    RangeScopeInput,
    ScanFiltersInput,
    ScanScopeInput,
)
from memscope_mcp.scanning.model import MAX_ALIGNMENT, MAX_PATTERN_BYTES, QueryKind, ScanQuery
from memscope_mcp.scanning.pattern import compile_canonical_pattern
from memscope_mcp.scanning.scopes import (
    MemoryType,
    PermissionRequirement,
    ScanScope,
    ScopeKind,
)

CURSOR_VERSION = 1
MAX_CURSOR_BYTES = 65_536
_MAX_ADDRESS_EXCLUSIVE = 1 << 64
_MAX_JSON_DEPTH = 8
_MAX_JSON_NODES = 512
_TOKEN_PREFIX = "m1"


class CursorError(ValueError):
    """Stable cursor failure ready for application-error formatting."""

    def __init__(self, error: str, detail: str, *, hint: str | None = None) -> None:
        super().__init__(detail)
        self.error = error
        self.detail = detail
        self.hint = hint


@dataclass(frozen=True, slots=True)
class CanonicalQueryState:
    """Compiled query fields required to reconstruct matching semantics."""

    kind: QueryKind
    pattern_bytes: bytes
    mask: bytes
    alignment: int
    fingerprint: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.kind, QueryKind):
            raise TypeError("kind must be a QueryKind")
        if not isinstance(self.pattern_bytes, bytes) or not 1 <= len(self.pattern_bytes) <= MAX_PATTERN_BYTES:
            raise ValueError(f"pattern_bytes must contain between 1 and {MAX_PATTERN_BYTES} bytes")
        if not isinstance(self.mask, bytes) or len(self.mask) != len(self.pattern_bytes):
            raise ValueError("mask length must equal pattern_bytes length")
        if any(value not in (0, 0xFF) for value in self.mask):
            raise ValueError("mask bytes must be 0 or 255")
        if any(value and not fixed for value, fixed in zip(self.pattern_bytes, self.mask, strict=True)):
            raise ValueError("wildcard pattern bytes must use the canonical zero value")
        if (
            isinstance(self.alignment, bool)
            or not isinstance(self.alignment, int)
            or not 1 <= self.alignment <= MAX_ALIGNMENT
        ):
            raise ValueError(f"alignment must be between 1 and {MAX_ALIGNMENT}")
        _require_digest("fingerprint", self.fingerprint)

    @classmethod
    def from_query(cls, query: ScanQuery) -> CanonicalQueryState:
        if not isinstance(query, ScanQuery):
            raise TypeError("query must be a ScanQuery")
        return cls(
            kind=query.kind,
            pattern_bytes=query.pattern.pattern_bytes,
            mask=query.pattern.mask,
            alignment=query.alignment,
            fingerprint=query.pattern.fingerprint,
        )

    def to_query(self) -> ScanQuery:
        pattern = compile_canonical_pattern(self.pattern_bytes, self.mask)
        if not hmac.compare_digest(pattern.fingerprint, self.fingerprint):
            raise CursorError("INVALID_CURSOR", "Cursor query fingerprint does not match its compiled pattern")
        return ScanQuery(kind=self.kind, pattern=pattern, alignment=self.alignment)


@dataclass(frozen=True, slots=True)
class CanonicalScopeState:
    """Normalized scope selectors without a cached region plan."""

    kind: ScopeKind
    module_names: tuple[str, ...]
    range_start: int | None
    range_end_exclusive: int | None
    memory_types: tuple[MemoryType, ...] | None
    executable: PermissionRequirement
    writable: PermissionRequirement
    section_names: tuple[str, ...]
    fingerprint: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ScopeKind):
            raise TypeError("kind must be a ScopeKind")
        if not isinstance(self.module_names, tuple) or any(
            not isinstance(name, str) or not name or len(name.encode("utf-8")) > 260 for name in self.module_names
        ):
            raise ValueError("module_names must be a tuple of bounded non-empty strings")
        if len(self.module_names) > 64 or len(set(self.module_names)) != len(self.module_names):
            raise ValueError("module_names must contain at most 64 unique values")
        if self.memory_types is not None:
            if not isinstance(self.memory_types, tuple) or any(
                not isinstance(memory_type, MemoryType) for memory_type in self.memory_types
            ):
                raise TypeError("memory_types must be a tuple of MemoryType values or None")
            if (
                not self.memory_types
                or len(self.memory_types) > 3
                or len(set(self.memory_types)) != len(self.memory_types)
            ):
                raise ValueError("memory_types must contain between 1 and 3 unique values")
        if not isinstance(self.executable, PermissionRequirement):
            raise TypeError("executable must be a PermissionRequirement")
        if not isinstance(self.writable, PermissionRequirement):
            raise TypeError("writable must be a PermissionRequirement")
        if not isinstance(self.section_names, tuple) or any(
            not isinstance(name, str) or not name or len(name.encode("utf-8")) > 64 for name in self.section_names
        ):
            raise ValueError("section_names must be a tuple of bounded non-empty strings")
        if len(self.section_names) > 64 or len(set(self.section_names)) != len(self.section_names):
            raise ValueError("section_names must contain at most 64 unique values")
        _require_digest("fingerprint", self.fingerprint)

        if self.kind is ScopeKind.ALL_MODULES:
            if self.module_names or self.range_start is not None or self.range_end_exclusive is not None:
                raise ValueError("all-module scope must not carry module or range selectors")
        elif self.kind is ScopeKind.MODULES:
            if not self.module_names or self.range_start is not None or self.range_end_exclusive is not None:
                raise ValueError("module scope requires names and no range selectors")
        elif self.kind is ScopeKind.RANGE:
            if self.module_names or self.range_start is None or self.range_end_exclusive is None:
                raise ValueError("range scope requires exact bounds and no module selectors")
            _require_boundary("range_start", self.range_start)
            _require_boundary("range_end_exclusive", self.range_end_exclusive)
            if self.range_end_exclusive <= self.range_start:
                raise ValueError("range_end_exclusive must be greater than range_start")

    @classmethod
    def from_scope(cls, scope: ScanScope) -> CanonicalScopeState:
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")

        module_names: tuple[str, ...] = ()
        range_start: int | None = None
        range_end_exclusive: int | None = None
        if scope.kind is ScopeKind.MODULES:
            module_names = tuple(item.module.normalized_name for item in scope.ranges if item.module is not None)
            if len(module_names) != len(scope.ranges):
                raise ValueError("module scope ranges must carry module identity")
        elif scope.kind is ScopeKind.RANGE:
            if len(scope.ranges) != 1:
                raise ValueError("range scope must contain exactly one normalized range")
            range_start = scope.ranges[0].start
            range_end_exclusive = scope.ranges[0].end_exclusive

        memory_types = (
            None
            if scope.filters.memory_types is None
            else tuple(sorted(scope.filters.memory_types, key=lambda item: item.value))
        )
        return cls(
            kind=scope.kind,
            module_names=module_names,
            range_start=range_start,
            range_end_exclusive=range_end_exclusive,
            memory_types=memory_types,
            executable=scope.filters.executable,
            writable=scope.filters.writable,
            section_names=scope.filters.section_names,
            fingerprint=scope.fingerprint,
        )

    def to_input(self) -> ScanScopeInput:
        filters = ScanFiltersInput(
            memory_types=None if self.memory_types is None else [item.value for item in self.memory_types],
            executable=self.executable.value,
            writable=self.writable.value,
            sections=None if not self.section_names else list(self.section_names),
        )
        if self.kind is ScopeKind.ALL_MODULES:
            return AllModulesScopeInput(kind="all_modules", filters=filters)
        if self.kind is ScopeKind.MODULES:
            return ModulesScopeInput(kind="modules", names=list(self.module_names), filters=filters)
        return RangeScopeInput(
            kind="range",
            start=self.range_start,
            end_exclusive=self.range_end_exclusive,
            filters=filters,
        )


@dataclass(frozen=True, slots=True)
class ContinuationState:
    """Everything needed to resume one live address sequence safely."""

    version: int
    session_generation: int
    pid: int
    module_fingerprint: bytes
    query: CanonicalQueryState
    scope: CanonicalScopeState
    resume_address: int
    matches_returned_before: int
    max_matches: int
    read_gaps_detected: bool

    def __post_init__(self) -> None:
        if self.version != CURSOR_VERSION:
            raise ValueError(f"version must be {CURSOR_VERSION}")
        _require_positive_int("session_generation", self.session_generation)
        _require_positive_int("pid", self.pid)
        _require_digest("module_fingerprint", self.module_fingerprint)
        if not isinstance(self.query, CanonicalQueryState):
            raise TypeError("query must be CanonicalQueryState")
        if not isinstance(self.scope, CanonicalScopeState):
            raise TypeError("scope must be CanonicalScopeState")
        _require_boundary("resume_address", self.resume_address)
        if (
            isinstance(self.matches_returned_before, bool)
            or not isinstance(self.matches_returned_before, int)
            or self.matches_returned_before < 0
        ):
            raise ValueError("matches_returned_before must be a non-negative integer")
        if (
            isinstance(self.max_matches, bool)
            or not isinstance(self.max_matches, int)
            or not 1 <= self.max_matches <= 100_000
        ):
            raise ValueError("max_matches must be between 1 and 100000")
        if self.matches_returned_before >= self.max_matches:
            raise ValueError("matches_returned_before must remain below max_matches")
        if not isinstance(self.read_gaps_detected, bool):
            raise TypeError("read_gaps_detected must be a bool")


class CursorCodec:
    """Encode and authenticate continuation state with one server-local key."""

    def __init__(self, *, secret: bytes | None = None, instance_id: bytes | None = None) -> None:
        self._secret = secret if secret is not None else secrets.token_bytes(32)
        self._instance_id = instance_id if instance_id is not None else secrets.token_bytes(16)
        if not isinstance(self._secret, bytes) or len(self._secret) != 32:
            raise ValueError("secret must be exactly 32 bytes")
        if not isinstance(self._instance_id, bytes) or len(self._instance_id) != 16:
            raise ValueError("instance_id must be exactly 16 bytes")

    @property
    def instance_id(self) -> bytes:
        return self._instance_id

    def encode(self, state: ContinuationState) -> str:
        if not isinstance(state, ContinuationState):
            raise TypeError("state must be ContinuationState")
        payload = json.dumps(
            _state_to_json(state),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        instance = _b64encode(self._instance_id)
        encoded_payload = _b64encode(payload)
        authenticated = f"{_TOKEN_PREFIX}.{instance}.{encoded_payload}".encode("ascii")
        signature = _b64encode(hmac.new(self._secret, authenticated, hashlib.sha256).digest())
        token = f"{authenticated.decode('ascii')}.{signature}"
        if len(token.encode("utf-8")) > MAX_CURSOR_BYTES:
            raise ValueError("encoded cursor exceeds the public cursor bound")
        return token

    def decode(self, token: str) -> ContinuationState:
        encoded = _validate_token_text(token)
        parts = encoded.split(".")
        if len(parts) != 4 or parts[0] != _TOKEN_PREFIX:
            raise _invalid_cursor()

        try:
            instance = _b64decode(parts[1], maximum=16)
        except ValueError as exc:
            raise _invalid_cursor() from exc
        if len(instance) != 16:
            raise _invalid_cursor()
        if not hmac.compare_digest(instance, self._instance_id):
            raise CursorError(
                "CURSOR_STALE",
                "Cursor belongs to a different server instance",
                hint="Restart the scan from its first page",
            )

        authenticated = ".".join(parts[:3]).encode("ascii")
        try:
            signature = _b64decode(parts[3], maximum=32)
        except ValueError as exc:
            raise _invalid_cursor() from exc
        expected = hmac.new(self._secret, authenticated, hashlib.sha256).digest()
        if len(signature) != len(expected) or not hmac.compare_digest(signature, expected):
            raise _invalid_cursor()

        try:
            payload = _b64decode(parts[2], maximum=MAX_CURSOR_BYTES)
            parsed = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
            _validate_json_shape(parsed)
            return _state_from_json(parsed)
        except CursorError:
            raise
        except (UnicodeDecodeError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise _invalid_cursor() from exc


def _state_to_json(state: ContinuationState) -> dict[str, Any]:
    query = state.query
    scope = state.scope
    return {
        "c": state.matches_returned_before,
        "g": state.session_generation,
        "h": state.read_gaps_detected,
        "m": state.max_matches,
        "mf": _b64encode(state.module_fingerprint),
        "p": state.pid,
        "q": {
            "a": query.alignment,
            "b": _b64encode(query.pattern_bytes),
            "f": _b64encode(query.fingerprint),
            "k": query.kind.value,
            "m": _b64encode(query.mask),
        },
        "r": state.resume_address,
        "s": {
            "e": scope.executable.value,
            "f": _b64encode(scope.fingerprint),
            "k": scope.kind.value,
            "m": None if scope.memory_types is None else [item.value for item in scope.memory_types],
            "n": list(scope.module_names),
            "re": scope.range_end_exclusive,
            "rs": scope.range_start,
            "s": list(scope.section_names),
            "w": scope.writable.value,
        },
        "v": state.version,
    }


def _state_from_json(value: Any) -> ContinuationState:
    root = _expect_object(value, {"c", "g", "h", "m", "mf", "p", "q", "r", "s", "v"})
    version = _expect_int(root["v"], minimum=CURSOR_VERSION, maximum=CURSOR_VERSION)
    query_obj = _expect_object(root["q"], {"a", "b", "f", "k", "m"})
    scope_obj = _expect_object(root["s"], {"e", "f", "k", "m", "n", "re", "rs", "s", "w"})

    try:
        query_kind = QueryKind(_expect_string(query_obj["k"], maximum_bytes=16))
        scope_kind = ScopeKind(_expect_string(scope_obj["k"], maximum_bytes=32))
        executable = PermissionRequirement(_expect_string(scope_obj["e"], maximum_bytes=16))
        writable = PermissionRequirement(_expect_string(scope_obj["w"], maximum_bytes=16))
    except ValueError as exc:
        raise _invalid_cursor() from exc

    pattern_bytes = _b64decode(_expect_string(query_obj["b"], maximum_bytes=4096), maximum=MAX_PATTERN_BYTES)
    mask = _b64decode(_expect_string(query_obj["m"], maximum_bytes=4096), maximum=MAX_PATTERN_BYTES)
    query_fingerprint = _b64decode(_expect_string(query_obj["f"], maximum_bytes=128), maximum=32)
    module_fingerprint = _b64decode(_expect_string(root["mf"], maximum_bytes=128), maximum=32)
    scope_fingerprint = _b64decode(_expect_string(scope_obj["f"], maximum_bytes=128), maximum=32)

    raw_memory_types = scope_obj["m"]
    memory_types: tuple[MemoryType, ...] | None
    if raw_memory_types is None:
        memory_types = None
    else:
        memory_type_values = _expect_string_list(raw_memory_types, maximum_items=3, maximum_bytes=16)
        try:
            memory_types = tuple(MemoryType(item) for item in memory_type_values)
        except ValueError as exc:
            raise _invalid_cursor() from exc

    module_names = tuple(_expect_string_list(scope_obj["n"], maximum_items=64, maximum_bytes=260))
    section_names = tuple(_expect_string_list(scope_obj["s"], maximum_items=64, maximum_bytes=64))
    range_start = _expect_optional_int(scope_obj["rs"], minimum=0, maximum=_MAX_ADDRESS_EXCLUSIVE)
    range_end = _expect_optional_int(scope_obj["re"], minimum=0, maximum=_MAX_ADDRESS_EXCLUSIVE)

    return ContinuationState(
        version=version,
        session_generation=_expect_int(root["g"], minimum=1, maximum=(1 << 63) - 1),
        pid=_expect_int(root["p"], minimum=1, maximum=(1 << 32) - 1),
        module_fingerprint=module_fingerprint,
        query=CanonicalQueryState(
            kind=query_kind,
            pattern_bytes=pattern_bytes,
            mask=mask,
            alignment=_expect_int(query_obj["a"], minimum=1, maximum=MAX_ALIGNMENT),
            fingerprint=query_fingerprint,
        ),
        scope=CanonicalScopeState(
            kind=scope_kind,
            module_names=module_names,
            range_start=range_start,
            range_end_exclusive=range_end,
            memory_types=memory_types,
            executable=executable,
            writable=writable,
            section_names=section_names,
            fingerprint=scope_fingerprint,
        ),
        resume_address=_expect_int(root["r"], minimum=0, maximum=_MAX_ADDRESS_EXCLUSIVE),
        matches_returned_before=_expect_int(root["c"], minimum=0, maximum=100_000),
        max_matches=_expect_int(root["m"], minimum=1, maximum=100_000),
        read_gaps_detected=_expect_bool(root["h"]),
    )


def _validate_token_text(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise _invalid_cursor()
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _invalid_cursor() from exc
    if len(encoded) > MAX_CURSOR_BYTES:
        raise _invalid_cursor()
    return token


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("base64url value must be a non-empty string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url value must be ASCII") from exc
    if len(encoded) > maximum * 2 + 16:
        raise ValueError("base64url value exceeds its encoded bound")
    padding = b"=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url value") from exc
    if len(decoded) > maximum:
        raise ValueError("decoded value exceeds its bound")
    if _b64encode(decoded) != value:
        raise ValueError("base64url value is not canonical")
    return decoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_shape(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("cursor JSON exceeds structural bounds")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 32:
                    raise ValueError("cursor JSON has an invalid key")
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 64:
                raise ValueError("cursor JSON list exceeds its bound")
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > 4096:
                raise ValueError("cursor JSON string exceeds its bound")
        elif item is not None and not isinstance(item, (bool, int)):
            raise ValueError("cursor JSON contains an unsupported value type")

    visit(value, 0)


def _expect_object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("cursor object fields do not match the expected schema")
    return value


def _expect_int(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError("cursor integer is outside its bound")
    return value


def _expect_optional_int(value: Any, *, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    return _expect_int(value, minimum=minimum, maximum=maximum)


def _expect_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("cursor boolean has an invalid type")
    return value


def _expect_string(value: Any, *, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError("cursor string is outside its bound")
    return value


def _expect_string_list(value: Any, *, maximum_items: int, maximum_bytes: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError("cursor list is outside its bound")
    result = [_expect_string(item, maximum_bytes=maximum_bytes) for item in value]
    if len(set(result)) != len(result):
        raise ValueError("cursor list values must be unique")
    return result


def _require_digest(name: str, value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must be a 32-byte digest")


def _require_boundary(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_ADDRESS_EXCLUSIVE:
        raise ValueError(f"{name} must be an unsigned 64-bit address boundary")


def _require_positive_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _invalid_cursor() -> CursorError:
    return CursorError("INVALID_CURSOR", "Cursor is malformed or failed integrity validation")


SERVER_CURSOR_CODEC = CursorCodec()
