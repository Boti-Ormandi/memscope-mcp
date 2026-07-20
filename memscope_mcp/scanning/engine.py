"""Synchronous deterministic execution over prepared search windows."""

from __future__ import annotations

import time
from collections.abc import Iterable

from memscope_mcp.scanning.collectors import ScanCollector
from memscope_mcp.scanning.matcher import poll_control, search_window
from memscope_mcp.scanning.model import (
    ScanControl,
    ScanQuery,
    ScanResult,
    ScanStats,
    SearchWindow,
    TerminationReason,
)


def execute_scan_windows(
    query: ScanQuery,
    windows: Iterable[SearchWindow],
    collector: ScanCollector,
    *,
    control: ScanControl | None = None,
    read_gaps_detected: bool = False,
) -> ScanResult:
    """Execute a compiled query over reader-prepared, address-ordered windows."""

    if not isinstance(query, ScanQuery):
        raise TypeError("query must be ScanQuery")
    if not isinstance(read_gaps_detected, bool):
        raise TypeError("read_gaps_detected must be a bool")

    active_control = control or ScanControl()
    stats = ScanStats()
    started_ns = time.monotonic_ns()
    previous_eligible_end: int | None = None

    for window in windows:
        if not isinstance(window, SearchWindow):
            raise TypeError("windows must contain SearchWindow values")
        if previous_eligible_end is not None and window.eligible_start < previous_eligible_end:
            raise ValueError("search windows must own non-overlapping ascending candidate intervals")
        previous_eligible_end = window.eligible_end

        reason = poll_control(active_control, stats)
        if reason is not None:
            return _finish(
                collector,
                reason,
                stats,
                started_ns,
                read_gaps_detected=read_gaps_detected,
            )

        outcome = search_window(query, window, collector, active_control, stats)
        if outcome.termination_reason is not None:
            return _finish(
                collector,
                outcome.termination_reason,
                stats,
                started_ns,
                read_gaps_detected=read_gaps_detected,
                next_candidate_start=outcome.next_candidate_start,
            )

    return _finish(
        collector,
        TerminationReason.SCOPE_EXHAUSTED,
        stats,
        started_ns,
        read_gaps_detected=read_gaps_detected,
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
