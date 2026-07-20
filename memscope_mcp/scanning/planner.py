"""Virtual-memory planning for normalized scan scopes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pymem.memory

from memscope_mcp.scanning.lifecycle import ScanLease, bind_scan_control
from memscope_mcp.scanning.model import ModuleRecord, ScanControl, TerminationReason
from memscope_mcp.scanning.scopes import (
    MemoryType,
    PermissionRequirement,
    ScanScope,
    ScopeKind,
    ScopeNormalizationError,
)

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

_BASE_PROTECTION_MASK = 0xFF
_READABLE_BASE_PROTECTIONS = frozenset(
    {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }
)
_EXECUTABLE_BASE_PROTECTIONS = frozenset(
    {
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }
)
_WRITABLE_BASE_PROTECTIONS = frozenset(
    {
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }
)
_MEMORY_TYPE_VALUES = {
    MemoryType.IMAGE: MEM_IMAGE,
    MemoryType.MAPPED: MEM_MAPPED,
    MemoryType.PRIVATE: MEM_PRIVATE,
}

VirtualQuery = Callable[[int, int], object]
_MAX_ADDRESS_EXCLUSIVE = 1 << 64
_VALID_MEMORY_TYPES = frozenset({MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE})


@dataclass(frozen=True, slots=True)
class ProtectionCapabilities:
    """Normalized capabilities after removing protection modifiers."""

    readable: bool
    executable: bool
    writable: bool


@dataclass(frozen=True, slots=True)
class PlannedSpan:
    """One committed readable interval that the reader may access."""

    start: int
    end_exclusive: int
    state: int
    protect: int
    memory_type: int
    module: ModuleRecord | None

    def __post_init__(self) -> None:
        if isinstance(self.start, bool) or not isinstance(self.start, int) or self.start < 0:
            raise ValueError("start must be a non-negative integer")
        if (
            isinstance(self.end_exclusive, bool)
            or not isinstance(self.end_exclusive, int)
            or self.end_exclusive <= self.start
            or self.end_exclusive > _MAX_ADDRESS_EXCLUSIVE
        ):
            raise ValueError("end_exclusive must be greater than start and inside the x64 address space")
        for name, value in (("state", self.state), ("protect", self.protect), ("memory_type", self.memory_type)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.state != MEM_COMMIT or not protection_capabilities(self.protect).readable:
            raise ValueError("planned spans must be committed and readable")
        if self.memory_type not in _VALID_MEMORY_TYPES:
            raise ValueError("memory_type must be MEM_IMAGE, MEM_MAPPED, or MEM_PRIVATE")
        if self.module is not None and not isinstance(self.module, ModuleRecord):
            raise TypeError("module must be a ModuleRecord or None")
        if self.module is not None and (
            self.start < self.module.base or self.end_exclusive > self.module.end_exclusive
        ):
            raise ValueError("module-annotated spans must stay inside their module")

    @property
    def size(self) -> int:
        return self.end_exclusive - self.start


@dataclass(frozen=True, slots=True)
class RegionPlan:
    """Complete planner output, including sticky partial-coverage state."""

    generation: int
    module_fingerprint: bytes
    scope_fingerprint: bytes
    spans: tuple[PlannedSpan, ...]
    region_count: int
    virtual_query_calls: int
    planner_gap_count: int
    read_gaps_detected: bool
    first_unplanned_address: int | None
    termination_reason: TerminationReason | None = None

    def __post_init__(self) -> None:
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation <= 0:
            raise ValueError("generation must be a positive integer")
        for name, value in (
            ("module_fingerprint", self.module_fingerprint),
            ("scope_fingerprint", self.scope_fingerprint),
        ):
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"{name} must be a 32-byte digest")
        if not isinstance(self.spans, tuple) or any(not isinstance(span, PlannedSpan) for span in self.spans):
            raise TypeError("spans must be a tuple of PlannedSpan values")
        for name, value in (
            ("region_count", self.region_count),
            ("virtual_query_calls", self.virtual_query_calls),
            ("planner_gap_count", self.planner_gap_count),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if not isinstance(self.read_gaps_detected, bool):
            raise TypeError("read_gaps_detected must be a bool")
        if self.first_unplanned_address is not None and (
            isinstance(self.first_unplanned_address, bool)
            or not isinstance(self.first_unplanned_address, int)
            or self.first_unplanned_address < 0
        ):
            raise ValueError("first_unplanned_address must be a non-negative integer or None")
        if self.termination_reason is not None and not isinstance(self.termination_reason, TerminationReason):
            raise TypeError("termination_reason must be a TerminationReason or None")
        if self.read_gaps_detected != (self.planner_gap_count > 0):
            raise ValueError("read_gaps_detected must reflect planner_gap_count")
        if (self.first_unplanned_address is None) != (self.planner_gap_count == 0):
            raise ValueError("first_unplanned_address must be present exactly when planner gaps exist")

        previous_end: int | None = None
        for span in self.spans:
            if previous_end is not None and span.start < previous_end:
                raise ValueError("planned spans must be sorted and non-overlapping")
            previous_end = span.end_exclusive


def plan_scan_regions(
    lease: ScanLease,
    scope: ScanScope,
    *,
    query_memory: VirtualQuery = pymem.memory.virtual_query,
    control: ScanControl | None = None,
) -> RegionPlan:
    """Walk every normalized interval through VirtualQueryEx before target reads."""

    if not isinstance(lease, ScanLease):
        raise TypeError("lease must be a ScanLease")
    if not isinstance(scope, ScanScope):
        raise TypeError("scope must be a ScanScope")
    if scope.generation != lease.generation or scope.module_fingerprint != lease.modules.fingerprint:
        raise ValueError("scope and lease attachment identities do not match")
    if not callable(query_memory):
        raise TypeError("query_memory must be callable")
    if scope.filters.section_names:
        raise ScopeNormalizationError(
            "INVALID_SCOPE",
            "Section filters require the section-aware planner and are not accepted by this planner",
            field="scope.filters.sections",
        )

    active_control = bind_scan_control(control, lease)
    selected_memory_types = _selected_memory_types(scope)
    spans: list[PlannedSpan] = []
    region_count = 0
    query_calls = 0
    planner_gap_count = 0
    first_unplanned_address: int | None = None
    termination_reason: TerminationReason | None = None

    for scope_range in scope.ranges:
        reason = active_control.poll()
        if reason is not None:
            termination_reason = reason
            break

        address = scope_range.start
        while address < scope_range.end_exclusive:
            reason = active_control.poll()
            if reason is not None:
                termination_reason = reason
                break

            query_calls += 1
            try:
                mbi = query_memory(lease.process_handle, address)
                region_base = _mbi_int(mbi, "BaseAddress")
                region_size = _mbi_int(mbi, "RegionSize")
                state = _mbi_int(mbi, "State")
                protect = _mbi_int(mbi, "Protect")
                memory_type = _mbi_int(mbi, "Type")
            except Exception:
                reason = active_control.poll()
                if reason is not None:
                    termination_reason = reason
                    break
                planner_gap_count += 1
                if first_unplanned_address is None:
                    first_unplanned_address = address
                break

            region_count += 1
            if region_size <= 0:
                planner_gap_count += 1
                if first_unplanned_address is None:
                    first_unplanned_address = address
                break
            region_end = region_base + region_size
            if region_base > address or region_end <= address:
                planner_gap_count += 1
                if first_unplanned_address is None:
                    first_unplanned_address = address
                break

            clipped_start = max(address, region_base, scope_range.start)
            clipped_end = min(region_end, scope_range.end_exclusive)
            if clipped_start < clipped_end and _region_matches(
                state,
                protect,
                memory_type,
                selected_memory_types,
                scope.filters.executable,
                scope.filters.writable,
            ):
                if scope.kind is ScopeKind.RANGE:
                    for piece_start, piece_end, module in _annotate_range(
                        lease,
                        clipped_start,
                        clipped_end,
                    ):
                        spans.append(
                            PlannedSpan(
                                start=piece_start,
                                end_exclusive=piece_end,
                                state=state,
                                protect=protect,
                                memory_type=memory_type,
                                module=module,
                            )
                        )
                else:
                    spans.append(
                        PlannedSpan(
                            start=clipped_start,
                            end_exclusive=clipped_end,
                            state=state,
                            protect=protect,
                            memory_type=memory_type,
                            module=scope_range.module,
                        )
                    )

            address = region_end

        if termination_reason is not None:
            break

    return RegionPlan(
        generation=lease.generation,
        module_fingerprint=lease.modules.fingerprint,
        scope_fingerprint=scope.fingerprint,
        spans=tuple(spans),
        region_count=region_count,
        virtual_query_calls=query_calls,
        planner_gap_count=planner_gap_count,
        read_gaps_detected=planner_gap_count > 0,
        first_unplanned_address=first_unplanned_address,
        termination_reason=termination_reason,
    )


def protection_capabilities(protect: int) -> ProtectionCapabilities:
    """Interpret one Win32 protection value with modifiers centralized."""

    if isinstance(protect, bool) or not isinstance(protect, int) or protect < 0:
        raise ValueError("protect must be a non-negative integer")
    if protect & PAGE_GUARD:
        return ProtectionCapabilities(False, False, False)
    base = protect & _BASE_PROTECTION_MASK
    if base == PAGE_NOACCESS:
        return ProtectionCapabilities(False, False, False)
    return ProtectionCapabilities(
        readable=base in _READABLE_BASE_PROTECTIONS,
        executable=base in _EXECUTABLE_BASE_PROTECTIONS,
        writable=base in _WRITABLE_BASE_PROTECTIONS,
    )


def is_readable_committed(state: int, protect: int) -> bool:
    """Return whether a region is committed and actually readable."""

    return state == MEM_COMMIT and protection_capabilities(protect).readable


def _selected_memory_types(scope: ScanScope) -> frozenset[int] | None:
    if scope.filters.memory_types is not None:
        return frozenset(_MEMORY_TYPE_VALUES[item] for item in scope.filters.memory_types)
    if scope.kind is ScopeKind.RANGE:
        return None
    return frozenset({MEM_IMAGE})


def _region_matches(
    state: int,
    protect: int,
    memory_type: int,
    memory_types: frozenset[int] | None,
    executable: PermissionRequirement,
    writable: PermissionRequirement,
) -> bool:
    if not is_readable_committed(state, protect):
        return False
    if memory_types is not None and memory_type not in memory_types:
        return False

    capabilities = protection_capabilities(protect)
    return _requirement_matches(executable, capabilities.executable) and _requirement_matches(
        writable,
        capabilities.writable,
    )


def _requirement_matches(requirement: PermissionRequirement, capability: bool) -> bool:
    if requirement is PermissionRequirement.ANY:
        return True
    if requirement is PermissionRequirement.REQUIRED:
        return capability
    return not capability


def _annotate_range(
    lease: ScanLease,
    start: int,
    end_exclusive: int,
) -> tuple[tuple[int, int, ModuleRecord | None], ...]:
    """Split a range span so every candidate start has stable module identity."""

    pieces: list[tuple[int, int, ModuleRecord | None]] = []
    cursor = start
    modules = lease.modules.ordered_by_base
    module_index = 0
    while module_index < len(modules) and modules[module_index].end_exclusive <= cursor:
        module_index += 1

    while cursor < end_exclusive:
        if module_index >= len(modules):
            pieces.append((cursor, end_exclusive, None))
            break

        module = modules[module_index]
        if module.base >= end_exclusive:
            pieces.append((cursor, end_exclusive, None))
            break
        if cursor < module.base:
            outside_end = min(end_exclusive, module.base)
            pieces.append((cursor, outside_end, None))
            cursor = outside_end
            continue
        if cursor < module.end_exclusive:
            module_end = min(end_exclusive, module.end_exclusive)
            pieces.append((cursor, module_end, module))
            cursor = module_end
        module_index += 1

    return tuple(pieces)


def _mbi_int(mbi: object, field: str) -> int:
    value = getattr(mbi, field)
    if hasattr(value, "value"):
        value = getattr(value, "value")
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"MEMORY_BASIC_INFORMATION.{field} must be an integer")
    return value
