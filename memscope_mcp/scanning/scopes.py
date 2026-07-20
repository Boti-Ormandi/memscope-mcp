"""Normalization of strict scan scopes against one immutable process lease."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum

from memscope_mcp.scanning.contract import (
    AllModulesScopeInput,
    ModulesScopeInput,
    RangeScopeInput,
    ScanFiltersInput,
    ScanScopeInput,
)
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease, normalize_module_name
from memscope_mcp.scanning.model import ModuleRecord

USER_MODE_END_EXCLUSIVE = 1 << 47
_MAX_ADDRESS_EXCLUSIVE = 1 << 64
_DECIMAL_RE = re.compile(r"^[0-9]+$")
_HEX_RE = re.compile(r"^0[xX][0-9A-Fa-f]+$")


class ScopeKind(Enum):
    """Normalized scope families used by the planner."""

    ALL_MODULES = "all_modules"
    MODULES = "modules"
    RANGE = "range"


class MemoryType(Enum):
    """Stable memory-type names independent of pymem enum wrappers."""

    IMAGE = "image"
    MAPPED = "mapped"
    PRIVATE = "private"


class PermissionRequirement(Enum):
    """Tri-state executable and writable filter policy."""

    ANY = "any"
    REQUIRED = "required"
    FORBIDDEN = "forbidden"


class ScopeNormalizationError(ValueError):
    """Structured scope failure ready for MCP or Lua error formatting."""

    def __init__(
        self,
        error: str,
        detail: str,
        *,
        field: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.error = error
        self.detail = detail
        self.field = field
        self.hint = hint


@dataclass(frozen=True, slots=True)
class RegionFilters:
    """Canonical planner filters."""

    memory_types: frozenset[MemoryType] | None = None
    executable: PermissionRequirement = PermissionRequirement.ANY
    writable: PermissionRequirement = PermissionRequirement.ANY
    section_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.memory_types is not None:
            if not isinstance(self.memory_types, frozenset) or any(
                not isinstance(memory_type, MemoryType) for memory_type in self.memory_types
            ):
                raise TypeError("memory_types must be a frozenset of MemoryType values or None")
            if not self.memory_types:
                raise ValueError("memory_types must not be empty")
        if not isinstance(self.executable, PermissionRequirement):
            raise TypeError("executable must be a PermissionRequirement")
        if not isinstance(self.writable, PermissionRequirement):
            raise TypeError("writable must be a PermissionRequirement")
        if not isinstance(self.section_names, tuple) or any(
            not isinstance(name, str) or not name for name in self.section_names
        ):
            raise TypeError("section_names must be a tuple of non-empty strings")


@dataclass(frozen=True, slots=True)
class ScopeRange:
    """One exact half-open interval selected before virtual-memory planning."""

    start: int
    end_exclusive: int
    module: ModuleRecord | None

    def __post_init__(self) -> None:
        _require_boundary("start", self.start)
        _require_boundary("end_exclusive", self.end_exclusive)
        if self.end_exclusive <= self.start:
            raise ValueError("scope range end must be greater than start")
        if self.module is not None and not isinstance(self.module, ModuleRecord):
            raise TypeError("module must be a ModuleRecord or None")
        if self.module is not None and (
            self.start < self.module.base or self.end_exclusive > self.module.end_exclusive
        ):
            raise ValueError("module scope range must stay inside its module")


@dataclass(frozen=True, slots=True)
class ScanScope:
    """Canonical scope bound to one attachment generation and module layout."""

    kind: ScopeKind
    ranges: tuple[ScopeRange, ...]
    filters: RegionFilters
    generation: int
    module_fingerprint: bytes
    fingerprint: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ScopeKind):
            raise TypeError("kind must be a ScopeKind")
        if not isinstance(self.ranges, tuple) or any(not isinstance(item, ScopeRange) for item in self.ranges):
            raise TypeError("ranges must be a tuple of ScopeRange values")
        if not isinstance(self.filters, RegionFilters):
            raise TypeError("filters must be RegionFilters")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation <= 0:
            raise ValueError("generation must be a positive integer")
        for name, value in (
            ("module_fingerprint", self.module_fingerprint),
            ("fingerprint", self.fingerprint),
        ):
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"{name} must be a 32-byte digest")

        previous_end: int | None = None
        for scope_range in self.ranges:
            if previous_end is not None and scope_range.start < previous_end:
                raise ValueError("scope ranges must be sorted and non-overlapping")
            previous_end = scope_range.end_exclusive


def normalize_scan_scope(scope: ScanScopeInput | None, lease: ScanLease) -> ScanScope:
    """Resolve one strict boundary scope against the lease's immutable snapshot."""

    if not isinstance(lease, ScanLease):
        raise TypeError("lease must be a ScanLease")

    public_scope: ScanScopeInput
    if scope is None:
        public_scope = AllModulesScopeInput(kind="all_modules")
    else:
        public_scope = scope

    filters = _normalize_filters(public_scope.filters)
    if isinstance(public_scope, AllModulesScopeInput):
        kind = ScopeKind.ALL_MODULES
        ranges = tuple(
            ScopeRange(record.base, record.end_exclusive, record) for record in lease.modules.ordered_by_base
        )
    elif isinstance(public_scope, ModulesScopeInput):
        kind = ScopeKind.MODULES
        ranges = _resolve_named_modules(public_scope, lease.modules)
    elif isinstance(public_scope, RangeScopeInput):
        kind = ScopeKind.RANGE
        start = resolve_address_expression(public_scope.start, lease.modules, field="scope.start")
        end_exclusive = resolve_address_expression(
            public_scope.end_exclusive,
            lease.modules,
            field="scope.end_exclusive",
        )
        if start >= USER_MODE_END_EXCLUSIVE:
            raise ScopeNormalizationError(
                "INVALID_SCOPE",
                f"Range start must be below 0x{USER_MODE_END_EXCLUSIVE:X}",
                field="scope.start",
            )
        if end_exclusive > USER_MODE_END_EXCLUSIVE:
            raise ScopeNormalizationError(
                "INVALID_SCOPE",
                f"Range end must not exceed 0x{USER_MODE_END_EXCLUSIVE:X}",
                field="scope.end_exclusive",
            )
        if end_exclusive <= start:
            raise ScopeNormalizationError(
                "INVALID_SCOPE",
                "Range end must be greater than start",
                field="scope.end_exclusive",
            )
        ranges = (ScopeRange(start, end_exclusive, None),)
    else:
        raise TypeError("scope must be a strict scan scope input or None")

    fingerprint = _scope_fingerprint(kind, ranges, filters)
    return ScanScope(
        kind=kind,
        ranges=ranges,
        filters=filters,
        generation=lease.generation,
        module_fingerprint=lease.modules.fingerprint,
        fingerprint=fingerprint,
    )


def resolve_address_expression(value: int | str, modules: ModuleSnapshot, *, field: str) -> int:
    """Resolve the product address syntax without consulting mutable session state."""

    if not isinstance(modules, ModuleSnapshot):
        raise TypeError("modules must be a ModuleSnapshot")
    if isinstance(value, bool):
        raise _invalid_address(field)
    if isinstance(value, int):
        resolved = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise _invalid_address(field)
        if "+" in text:
            if text.count("+") != 1:
                raise _invalid_address(field)
            base_text, offset_text = (part.strip() for part in text.split("+", 1))
            if not base_text or not offset_text:
                raise _invalid_address(field)
            offset = _parse_unsigned_number(offset_text, field)
            if _HEX_RE.fullmatch(base_text):
                base = int(base_text, 16)
            else:
                base = _resolve_module_base(base_text, modules, field)
            resolved = base + offset
        else:
            resolved = _parse_unsigned_number(text, field)
    else:
        raise _invalid_address(field)

    if not 0 <= resolved < _MAX_ADDRESS_EXCLUSIVE:
        raise ScopeNormalizationError(
            "INVALID_SCOPE",
            "Resolved address is outside the unsigned 64-bit address space",
            field=field,
        )
    return resolved


def _resolve_named_modules(scope: ModulesScopeInput, modules: ModuleSnapshot) -> tuple[ScopeRange, ...]:
    resolved: list[ModuleRecord] = []
    seen: set[str] = set()
    for requested_name in scope.names:
        normalized = normalize_module_name(requested_name)
        if normalized in seen:
            raise ScopeNormalizationError(
                "INVALID_SCOPE",
                f"Duplicate module selector '{requested_name}'",
                field="scope.names",
            )
        seen.add(normalized)
        matches = modules.find_all(requested_name)
        if not matches:
            raise ScopeNormalizationError(
                "MODULE_NOT_FOUND",
                f"Module '{requested_name}' is not present in the attachment snapshot",
                field="scope.names",
                hint="Refresh modules if the target loaded it after attachment",
            )
        if len(matches) > 1:
            choices = _format_module_choices(matches)
            raise ScopeNormalizationError(
                "AMBIGUOUS_MODULE",
                f"Module selector '{requested_name}' matches multiple loaded modules: {choices}",
                field="scope.names",
            )
        resolved.append(matches[0])

    resolved.sort(key=lambda record: record.base)
    return tuple(ScopeRange(record.base, record.end_exclusive, record) for record in resolved)


def _resolve_module_base(module_name: str, modules: ModuleSnapshot, field: str) -> int:
    try:
        matches = modules.find_all(module_name)
    except (TypeError, ValueError) as exc:
        raise _invalid_address(field) from exc
    if not matches:
        raise ScopeNormalizationError(
            "MODULE_NOT_FOUND",
            f"Module '{module_name}' is not present in the attachment snapshot",
            field=field,
            hint="Refresh modules if the target loaded it after attachment",
        )
    if len(matches) > 1:
        choices = _format_module_choices(matches)
        raise ScopeNormalizationError(
            "AMBIGUOUS_MODULE",
            f"Module selector '{module_name}' matches multiple loaded modules: {choices}",
            field=field,
        )
    return matches[0].base


def _format_module_choices(matches: tuple[ModuleRecord, ...]) -> str:
    labels: list[str] = []
    for record in matches[:4]:
        location = record.path or record.name
        if len(location) > 96:
            location = f"...{location[-93:]}"
        labels.append(f"0x{record.base:X} ({location})")
    if len(matches) > len(labels):
        labels.append(f"... and {len(matches) - len(labels)} more")
    return ", ".join(labels)


def _normalize_filters(filters: ScanFiltersInput) -> RegionFilters:
    memory_types = (
        None
        if filters.memory_types is None
        else frozenset(MemoryType(memory_type) for memory_type in filters.memory_types)
    )
    section_names = () if filters.sections is None else tuple(name.casefold() for name in filters.sections)
    return RegionFilters(
        memory_types=memory_types,
        executable=PermissionRequirement(filters.executable),
        writable=PermissionRequirement(filters.writable),
        section_names=section_names,
    )


def _parse_unsigned_number(text: str, field: str) -> int:
    if _HEX_RE.fullmatch(text):
        return int(text, 16)
    if _DECIMAL_RE.fullmatch(text):
        return int(text, 10)
    raise _invalid_address(field)


def _invalid_address(field: str) -> ScopeNormalizationError:
    return ScopeNormalizationError(
        "INVALID_SCOPE",
        "Address must be an integer, decimal string, hex string, module+offset, or hex+offset",
        field=field,
    )


def _scope_fingerprint(
    kind: ScopeKind,
    ranges: tuple[ScopeRange, ...],
    filters: RegionFilters,
) -> bytes:
    digest = hashlib.sha256()
    digest.update(kind.value.encode("ascii"))
    for scope_range in ranges:
        digest.update(scope_range.start.to_bytes(8, "little", signed=False))
        digest.update(scope_range.end_exclusive.to_bytes(8, "little", signed=False))
        if scope_range.module is None:
            digest.update(b"\0")
        else:
            digest.update(b"\1")
            digest.update(scope_range.module.base.to_bytes(8, "little", signed=False))
            digest.update(scope_range.module.size.to_bytes(8, "little", signed=False))
            encoded = scope_range.module.normalized_name.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "little", signed=False))
            digest.update(encoded)
    if filters.memory_types is None:
        digest.update(b"*")
    else:
        for memory_type in sorted(filters.memory_types, key=lambda item: item.value):
            digest.update(memory_type.value.encode("ascii"))
            digest.update(b"\0")
    digest.update(filters.executable.value.encode("ascii"))
    digest.update(filters.writable.value.encode("ascii"))
    for name in filters.section_names:
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(2, "little", signed=False))
        digest.update(encoded)
    return digest.digest()


def _require_boundary(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_ADDRESS_EXCLUSIVE:
        raise ValueError(f"{name} must be an unsigned 64-bit address boundary")
