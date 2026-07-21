"""One-pass execution for bounded first-hit and count scan batches."""

from __future__ import annotations

import time
from dataclasses import dataclass

from memscope_mcp.scanning.collectors import CollectorResult, ScanCollector
from memscope_mcp.scanning.lifecycle import ScanLease
from memscope_mcp.scanning.matcher import search_window
from memscope_mcp.scanning.model import (
    COLLECTOR_TERMINATIONS,
    ScanControl,
    ScanHit,
    ScanQuery,
    ScanStats,
    SearchWindow,
    TerminationReason,
)
from memscope_mcp.scanning.planner import RegionPlan
from memscope_mcp.scanning.reader import (
    DEFAULT_PAGE_SIZE,
    READ_CHUNK_SIZE,
    ReadMemory,
    RegionReader,
    TargetAlive,
    candidate_module_segments,
)


@dataclass(frozen=True, slots=True)
class BatchQuery:
    """One caller-keyed compiled query and independent result policy."""

    key: str
    query: ScanQuery
    collector: ScanCollector

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise ValueError("key must be a non-empty string")
        if not isinstance(self.query, ScanQuery):
            raise TypeError("query must be a ScanQuery")
        if not hasattr(self.collector, "offer") or not hasattr(self.collector, "finish"):
            raise TypeError("collector must implement the scan collector protocol")


@dataclass(frozen=True, slots=True)
class BatchItemResult:
    """One independently completed query result."""

    key: str
    hits: tuple[ScanHit, ...]
    observed_count: int
    termination_reason: TerminationReason
    read_gaps_detected: bool


@dataclass(slots=True)
class BatchScanResult:
    """Batch items plus traversal-wide status and shared operation counters."""

    items: tuple[BatchItemResult, ...]
    termination_reason: TerminationReason
    read_gaps_detected: bool
    stats: ScanStats


@dataclass(slots=True)
class _QueryState:
    entry: BatchQuery
    next_candidate_start: int | None = None


def execute_scan_batch_plan(
    entries: tuple[BatchQuery, ...],
    lease: ScanLease,
    plan: RegionPlan,
    *,
    control: ScanControl,
    read_memory: ReadMemory,
    target_alive: TargetAlive | None = None,
    chunk_size: int = READ_CHUNK_SIZE,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> BatchScanResult:
    """Read each planned byte once while advancing every active query."""

    if not isinstance(entries, tuple) or not 1 <= len(entries) <= 32:
        raise ValueError("entries must contain between 1 and 32 BatchQuery values")
    if any(not isinstance(entry, BatchQuery) for entry in entries):
        raise TypeError("entries must contain BatchQuery values")
    keys = [entry.key for entry in entries]
    if len(set(keys)) != len(keys):
        raise ValueError("batch query keys must be unique")
    if not isinstance(lease, ScanLease):
        raise TypeError("lease must be a ScanLease")
    if not isinstance(plan, RegionPlan):
        raise TypeError("plan must be a RegionPlan")
    if not isinstance(control, ScanControl):
        raise TypeError("control must be a ScanControl")

    started = time.perf_counter_ns()
    stats = ScanStats()
    reader = RegionReader(
        lease,
        plan,
        stats,
        control=control,
        read_memory=read_memory,
        target_alive=target_alive,
        chunk_size=chunk_size,
        page_size=page_size,
    )
    states = [_QueryState(entry) for entry in entries]
    active = set(range(len(states)))
    completed: dict[int, BatchItemResult] = {}
    shared_termination: TerminationReason | None = None
    shared_tail = b""
    previous_end: int | None = None

    for fragment in reader:
        if previous_end != fragment.start:
            shared_tail = b""
            for index in active:
                states[index].next_candidate_start = fragment.start

        combined = shared_tail + fragment.data
        base_address = fragment.start - len(shared_tail)
        for index in tuple(sorted(active)):
            state = states[index]
            reason = _advance_query(
                state,
                combined=combined,
                base_address=base_address,
                fragment_start=fragment.start,
                lease=lease,
                control=control,
                stats=stats,
            )
            if reason is None:
                continue
            if reason in COLLECTOR_TERMINATIONS:
                completed[index] = _finish_item(
                    state.entry,
                    reason,
                    read_gaps_detected=reader.read_gaps_detected,
                )
                active.remove(index)
                continue
            shared_termination = reason
            break

        if active:
            longest_active_pattern = max(states[index].entry.query.pattern.length for index in active)
            tail_size = min(longest_active_pattern - 1, len(combined))
            shared_tail = combined[-tail_size:] if tail_size > 0 else b""
        else:
            shared_tail = b""
        previous_end = fragment.end_exclusive

        if shared_termination is not None or not active:
            break

    if shared_termination is None:
        if active:
            shared_termination = reader.termination_reason or TerminationReason.SCOPE_EXHAUSTED
        else:
            reasons = {item.termination_reason for item in completed.values()}
            shared_termination = next(iter(reasons)) if len(reasons) == 1 else TerminationReason.SCOPE_EXHAUSTED

    for index in sorted(active):
        completed[index] = _finish_item(
            states[index].entry,
            shared_termination,
            read_gaps_detected=reader.read_gaps_detected,
        )

    stats.duration_ns = time.perf_counter_ns() - started
    return BatchScanResult(
        items=tuple(completed[index] for index in range(len(entries))),
        termination_reason=shared_termination,
        read_gaps_detected=reader.read_gaps_detected,
        stats=stats,
    )


def _advance_query(
    state: _QueryState,
    *,
    combined: bytes,
    base_address: int,
    fragment_start: int,
    lease: ScanLease,
    control: ScanControl,
    stats: ScanStats,
) -> TerminationReason | None:
    query = state.entry.query
    candidate_start = fragment_start if state.next_candidate_start is None else state.next_candidate_start
    candidate_end = base_address + max(0, len(combined) - query.pattern.length + 1)

    if candidate_end > candidate_start:
        for eligible_start, eligible_end, module in candidate_module_segments(
            lease.modules,
            candidate_start,
            candidate_end,
        ):
            result = search_window(
                query,
                SearchWindow(
                    base_address=base_address,
                    data=combined,
                    eligible_start=eligible_start,
                    eligible_end=eligible_end,
                    module=module,
                ),
                state.entry.collector,
                control,
                stats,
            )
            if result.termination_reason is not None:
                return result.termination_reason
        state.next_candidate_start = candidate_end
    return None


def _finish_item(
    entry: BatchQuery,
    reason: TerminationReason,
    *,
    read_gaps_detected: bool,
) -> BatchItemResult:
    result: CollectorResult = entry.collector.finish(reason)
    return BatchItemResult(
        key=entry.key,
        hits=result.hits,
        observed_count=result.observed_count,
        termination_reason=result.termination_reason,
        read_gaps_detected=read_gaps_detected,
    )
