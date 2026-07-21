"""Synchronous deterministic execution over prepared or reader-backed windows."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from memscope_mcp.scanning.collectors import ScanCollector
from memscope_mcp.scanning.lifecycle import ScanLease
from memscope_mcp.scanning.matcher import poll_control, search_window
from memscope_mcp.scanning.model import (
    ScanControl,
    ScanQuery,
    ScanResult,
    ScanStats,
    SearchWindow,
    TerminationReason,
)
from memscope_mcp.scanning.planner import RegionPlan
from memscope_mcp.scanning.reader import (
    DEFAULT_PAGE_SIZE,
    READ_CHUNK_SIZE,
    ReadMemory,
    SearchWindowSource,
    TargetAlive,
)


def execute_scan_windows(
    query: ScanQuery,
    windows: Iterable[SearchWindow],
    collector: ScanCollector,
    *,
    control: ScanControl | None = None,
    read_gaps_detected: bool = False,
) -> ScanResult:
    """Execute a compiled query over caller-prepared, address-ordered windows."""

    if not isinstance(query, ScanQuery):
        raise TypeError("query must be ScanQuery")
    if not isinstance(read_gaps_detected, bool):
        raise TypeError("read_gaps_detected must be a bool")

    active_control = control or ScanControl()
    stats = ScanStats()
    return _execute_windows(
        query,
        windows,
        collector,
        control=active_control,
        stats=stats,
        read_gap_supplier=lambda: read_gaps_detected,
        exhaustion_reason_supplier=lambda: None,
    )


def execute_scan_plan(
    query: ScanQuery,
    lease: ScanLease,
    plan: RegionPlan,
    collector: ScanCollector,
    *,
    control: ScanControl | None = None,
    read_memory: ReadMemory | None = None,
    target_alive: TargetAlive | None = None,
    chunk_size: int = READ_CHUNK_SIZE,
    page_size: int = DEFAULT_PAGE_SIZE,
    initial_read_gaps_detected: bool = False,
) -> ScanResult:
    """Stream one region plan through the bounded reader and shared matcher."""

    if not isinstance(initial_read_gaps_detected, bool):
        raise TypeError("initial_read_gaps_detected must be a bool")

    stats = ScanStats()
    source_kwargs = {
        "control": control,
        "target_alive": target_alive,
        "chunk_size": chunk_size,
        "page_size": page_size,
    }
    if read_memory is not None:
        source_kwargs["read_memory"] = read_memory
    source = SearchWindowSource(
        query,
        lease,
        plan,
        stats,
        **source_kwargs,
    )
    return _execute_windows(
        query,
        source,
        collector,
        control=source.control,
        stats=stats,
        read_gap_supplier=lambda: initial_read_gaps_detected or source.read_gaps_detected,
        exhaustion_reason_supplier=lambda: source.termination_reason,
    )


def _execute_windows(
    query: ScanQuery,
    windows: Iterable[SearchWindow],
    collector: ScanCollector,
    *,
    control: ScanControl,
    stats: ScanStats,
    read_gap_supplier: Callable[[], bool],
    exhaustion_reason_supplier: Callable[[], TerminationReason | None],
) -> ScanResult:
    started_ns = time.monotonic_ns()
    previous_eligible_end: int | None = None

    for window in windows:
        if not isinstance(window, SearchWindow):
            raise TypeError("windows must contain SearchWindow values")
        if previous_eligible_end is not None and window.eligible_start < previous_eligible_end:
            raise ValueError("search windows must own non-overlapping ascending candidate intervals")
        previous_eligible_end = window.eligible_end

        reason = poll_control(control, stats)
        if reason is not None:
            return _finish(
                collector,
                reason,
                stats,
                started_ns,
                read_gaps_detected=read_gap_supplier(),
            )

        outcome = search_window(query, window, collector, control, stats)
        if outcome.termination_reason is not None:
            return _finish(
                collector,
                outcome.termination_reason,
                stats,
                started_ns,
                read_gaps_detected=read_gap_supplier(),
                next_candidate_start=outcome.next_candidate_start,
            )

    return _finish(
        collector,
        exhaustion_reason_supplier() or TerminationReason.SCOPE_EXHAUSTED,
        stats,
        started_ns,
        read_gaps_detected=read_gap_supplier(),
    )


def _finish(
    collector: ScanCollector,
    reason: TerminationReason,
    stats: ScanStats,
    started_ns: int,
    *,
    read_gaps_detected: bool,
    next_candidate_start: int | None = None,
) -> ScanResult:
    collected = collector.finish(reason)
    stats.duration_ns = max(0, time.monotonic_ns() - started_ns)
    return ScanResult(
        hits=list(collected.hits),
        observed_count=collected.observed_count,
        termination_reason=collected.termination_reason,
        read_gaps_detected=read_gaps_detected,
        stats=stats,
        next_candidate_start=next_candidate_start,
    )
