"""Bounded target-memory reads, salvage, and overlap-window construction."""

from __future__ import annotations

import ctypes
from collections.abc import Callable, Iterable, Iterator
from ctypes import wintypes
from dataclasses import dataclass

import pymem.memory

from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease, bind_scan_control
from memscope_mcp.scanning.model import (
    ModuleRecord,
    ScanControl,
    ScanQuery,
    ScanStats,
    SearchWindow,
    TerminationReason,
)
from memscope_mcp.scanning.planner import PlannedSpan, RegionPlan

READ_CHUNK_SIZE = 256 * 1024
DEFAULT_PAGE_SIZE = 0x1000
STILL_ACTIVE = 259

ReadMemory = Callable[[int, int, int], bytes | bytearray | memoryview]
TargetAlive = Callable[[int], bool]

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_kernel32.GetExitCodeProcess.restype = wintypes.BOOL


@dataclass(frozen=True, slots=True)
class ReadFragment:
    """One exact successful read fragment in ascending address order."""

    start: int
    data: bytes
    module: ModuleRecord | None

    def __post_init__(self) -> None:
        if isinstance(self.start, bool) or not isinstance(self.start, int) or self.start < 0:
            raise ValueError("start must be a non-negative integer")
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("data must be non-empty bytes")
        if self.module is not None and not isinstance(self.module, ModuleRecord):
            raise TypeError("module must be a ModuleRecord or None")

    @property
    def end_exclusive(self) -> int:
        return self.start + len(self.data)


class RegionReader:
    """One-shot reader over planned spans with page-aligned failure salvage."""

    def __init__(
        self,
        lease: ScanLease,
        plan: RegionPlan,
        stats: ScanStats,
        *,
        control: ScanControl | None = None,
        read_memory: ReadMemory = pymem.memory.read_bytes,
        target_alive: TargetAlive | None = None,
        chunk_size: int = READ_CHUNK_SIZE,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        if not isinstance(lease, ScanLease):
            raise TypeError("lease must be a ScanLease")
        if not isinstance(plan, RegionPlan):
            raise TypeError("plan must be a RegionPlan")
        if not isinstance(stats, ScanStats):
            raise TypeError("stats must be ScanStats")
        if plan.generation != lease.generation or plan.module_fingerprint != lease.modules.fingerprint:
            raise ValueError("plan and lease attachment identities do not match")
        if not callable(read_memory):
            raise TypeError("read_memory must be callable")
        if target_alive is not None and not callable(target_alive):
            raise TypeError("target_alive must be callable or None")
        _require_positive_int("chunk_size", chunk_size)
        _require_positive_int("page_size", page_size)

        self.lease = lease
        self.plan = plan
        self.stats = stats
        self.control = bind_scan_control(control, lease)
        self.read_memory = read_memory
        self.target_alive = target_alive or _target_is_alive
        self.chunk_size = chunk_size
        self.page_size = page_size
        self.read_gaps_detected = plan.read_gaps_detected
        self.termination_reason = plan.termination_reason
        self.first_gap_start = plan.first_unplanned_address
        self._iterated = False

        stats.region_count = plan.region_count
        stats.span_count = len(plan.spans)
        stats.planner_query_calls = plan.virtual_query_calls
        stats.read_gap_count = plan.planner_gap_count
        stats.reader_chunk_size = chunk_size
        stats.physical_read_calls += plan.metadata_read_calls
        stats.physical_bytes_requested += plan.metadata_bytes_requested
        stats.physical_bytes_read += plan.metadata_bytes_read
        stats.unique_bytes_read += plan.metadata_bytes_read
        stats.scope_fingerprint = plan.scope_fingerprint
        stats.section_names = plan.selected_section_names

    def __iter__(self) -> Iterator[ReadFragment]:
        if self._iterated:
            raise RuntimeError("RegionReader is one-shot")
        self._iterated = True
        if self.termination_reason is not None:
            return

        for span in self.plan.spans:
            reason = self.control.poll()
            if reason is not None:
                self.termination_reason = reason
                return

            cursor = span.start
            while cursor < span.end_exclusive:
                reason = self.control.poll()
                if reason is not None:
                    self.termination_reason = reason
                    return

                chunk_end = min(cursor + self.chunk_size, span.end_exclusive)
                self.stats.logical_read_chunks += 1
                yield from self._read_with_salvage(cursor, chunk_end, span)
                if self.termination_reason is not None:
                    return
                cursor = chunk_end

    def _read_with_salvage(
        self,
        start: int,
        end_exclusive: int,
        span: PlannedSpan,
    ) -> Iterator[ReadFragment]:
        data = self._attempt_read(start, end_exclusive)
        if data is not None:
            reason = self.control.poll()
            if reason is not None:
                self.termination_reason = reason
                return
            yield ReadFragment(start=start, data=data, module=span.module)
            return

        reason = self.control.poll()
        if reason is not None:
            self.termination_reason = reason
            return

        try:
            alive = self.target_alive(self.lease.process_handle)
        except Exception:
            self.termination_reason = TerminationReason.READER_ERROR
            return
        if not alive:
            self.termination_reason = TerminationReason.TARGET_CHANGED
            return

        split = _page_aligned_split(start, end_exclusive, self.page_size)
        if split is None:
            self._record_gap(start, end_exclusive)
            return

        yield from self._read_with_salvage(start, split, span)
        if self.termination_reason is not None:
            return
        yield from self._read_with_salvage(split, end_exclusive, span)

    def _attempt_read(self, start: int, end_exclusive: int) -> bytes | None:
        size = end_exclusive - start
        self.stats.physical_read_calls += 1
        self.stats.physical_bytes_requested += size
        try:
            raw = self.read_memory(self.lease.process_handle, start, size)
        except Exception:
            return None
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError("read_memory must return bytes-like data")
        data = bytes(raw)
        self.stats.physical_bytes_read += len(data)
        if len(data) != size:
            return None
        self.stats.unique_bytes_read += size
        return data

    def _record_gap(self, start: int, end_exclusive: int) -> None:
        self.read_gaps_detected = True
        self.stats.read_gap_count += 1
        self.stats.failed_read_bytes += end_exclusive - start
        self.stats.failed_read_spans.append((start, end_exclusive))
        if self.first_gap_start is None:
            self.first_gap_start = start


class SearchWindowSource:
    """Stateful bridge from a region plan to matcher-owned candidate windows."""

    def __init__(
        self,
        query: ScanQuery,
        lease: ScanLease,
        plan: RegionPlan,
        stats: ScanStats,
        *,
        control: ScanControl | None = None,
        read_memory: ReadMemory = pymem.memory.read_bytes,
        target_alive: TargetAlive | None = None,
        chunk_size: int = READ_CHUNK_SIZE,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        if not isinstance(query, ScanQuery):
            raise TypeError("query must be a ScanQuery")
        self.query = query
        self.lease = lease
        self.reader = RegionReader(
            lease,
            plan,
            stats,
            control=control,
            read_memory=read_memory,
            target_alive=target_alive,
            chunk_size=chunk_size,
            page_size=page_size,
        )
        self._iterated = False

    @property
    def read_gaps_detected(self) -> bool:
        return self.reader.read_gaps_detected

    @property
    def termination_reason(self) -> TerminationReason | None:
        return self.reader.termination_reason

    @property
    def control(self) -> ScanControl:
        return self.reader.control

    def __iter__(self) -> Iterator[SearchWindow]:
        if self._iterated:
            raise RuntimeError("SearchWindowSource is one-shot")
        self._iterated = True
        yield from iter_search_windows(
            self.query,
            self.reader,
            self.lease.modules,
        )


def iter_search_windows(
    query: ScanQuery,
    fragments: Iterable[ReadFragment],
    modules: ModuleSnapshot,
) -> Iterator[SearchWindow]:
    """Retain one shared tail and assign every candidate start exactly once."""

    if not isinstance(query, ScanQuery):
        raise TypeError("query must be a ScanQuery")
    if not isinstance(modules, ModuleSnapshot):
        raise TypeError("modules must be a ModuleSnapshot")

    pattern_length = query.pattern.length
    tail = b""
    previous_end: int | None = None
    next_candidate_start: int | None = None

    for fragment in fragments:
        if not isinstance(fragment, ReadFragment):
            raise TypeError("fragments must contain ReadFragment values")
        if previous_end is not None and fragment.start < previous_end:
            raise ValueError("read fragments must be ascending and non-overlapping")

        contiguous = previous_end == fragment.start
        if not contiguous:
            tail = b""
            next_candidate_start = fragment.start

        combined = tail + fragment.data
        base_address = fragment.start - len(tail)
        candidate_start = fragment.start if next_candidate_start is None else next_candidate_start
        candidate_end = base_address + max(0, len(combined) - pattern_length + 1)

        if candidate_end > candidate_start:
            for eligible_start, eligible_end, module in candidate_module_segments(
                modules,
                candidate_start,
                candidate_end,
            ):
                yield SearchWindow(
                    base_address=base_address,
                    data=combined,
                    eligible_start=eligible_start,
                    eligible_end=eligible_end,
                    module=module,
                )
            next_candidate_start = candidate_end

        if pattern_length > 1:
            tail = combined[-min(pattern_length - 1, len(combined)) :]
        else:
            tail = b""
        previous_end = fragment.end_exclusive


def candidate_module_segments(
    modules: ModuleSnapshot,
    start: int,
    end_exclusive: int,
) -> tuple[tuple[int, int, ModuleRecord | None], ...]:
    pieces: list[tuple[int, int, ModuleRecord | None]] = []
    cursor = start
    ordered = modules.ordered_by_base
    module_index = 0
    while module_index < len(ordered) and ordered[module_index].end_exclusive <= cursor:
        module_index += 1

    while cursor < end_exclusive:
        if module_index >= len(ordered):
            pieces.append((cursor, end_exclusive, None))
            break

        module = ordered[module_index]
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


def _page_aligned_split(start: int, end_exclusive: int, page_size: int) -> int | None:
    first_boundary = ((start // page_size) + 1) * page_size
    if first_boundary >= end_exclusive:
        return None

    midpoint = start + (end_exclusive - start) // 2
    candidates = (
        ((midpoint + page_size - 1) // page_size) * page_size,
        (midpoint // page_size) * page_size,
        first_boundary,
    )
    for candidate in candidates:
        if start < candidate < end_exclusive:
            return candidate
    return None


def _target_is_alive(process_handle: int) -> bool:
    exit_code = wintypes.DWORD()
    if not _kernel32.GetExitCodeProcess(wintypes.HANDLE(process_handle), ctypes.byref(exit_code)):
        raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
    return exit_code.value == STILL_ACTIVE


def _require_positive_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
