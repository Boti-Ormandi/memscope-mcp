"""Exact and all-wildcard matcher strategies."""

from __future__ import annotations

from memscope_mcp.scanning.collectors import ScanCollector
from memscope_mcp.scanning.model import (
    MatcherResult,
    MatcherStrategy,
    ScanControl,
    ScanHit,
    ScanQuery,
    ScanStats,
    SearchWindow,
    TerminationReason,
)


class UnsupportedMatcherError(RuntimeError):
    """Raised when a compiled pattern requires a strategy not implemented here yet."""


def search_window(
    query: ScanQuery,
    window: SearchWindow,
    collector: ScanCollector,
    control: ScanControl,
    stats: ScanStats,
) -> MatcherResult:
    """Search one owned candidate interval with the applicable implemented strategy."""

    if query.pattern.exact_bytes is not None:
        stats.record_strategy(MatcherStrategy.EXACT)
        return _search_exact(query, window, collector, control, stats)
    if query.pattern.all_wildcard:
        stats.record_strategy(MatcherStrategy.ALL_WILDCARD)
        return _search_all_wildcard(query, window, collector, control, stats)
    raise UnsupportedMatcherError("masked patterns require the hybrid matcher")


def _search_exact(
    query: ScanQuery,
    window: SearchWindow,
    collector: ScanCollector,
    control: ScanControl,
    stats: ScanStats,
) -> MatcherResult:
    exact = query.pattern.exact_bytes
    if exact is None:
        raise ValueError("exact matcher requires exact bytes")

    data = _searchable_data(window.data)
    candidate_start, candidate_end = _candidate_bounds(window, query.pattern.length)
    if candidate_start >= candidate_end:
        return MatcherResult()

    position = candidate_start - window.base_address
    search_end = candidate_end - window.base_address + query.pattern.length - 1

    while True:
        stats.find_calls += 1
        found = data.find(exact, position, search_end)
        if found < 0:
            _record_candidate_extent(stats, candidate_start, candidate_end, query.pattern.length)
            return MatcherResult()

        address = window.base_address + found
        examined_candidate_end = address + 1
        position = found + 1
        stats.candidate_count += 1
        stats.verification_count += 1

        if address % query.alignment == 0:
            decision = collector.offer(_make_hit(address, window))
            stats.committed_matches += 1
            if decision.stop:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                _poll_after_collector_stop(control, stats)
                return MatcherResult(
                    termination_reason=decision.reason,
                    next_candidate_start=examined_candidate_end,
                )

        if stats.candidate_count % control.poll_interval == 0:
            reason = _poll_control(control, stats)
            if reason is not None:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                return MatcherResult(termination_reason=reason)


def _search_all_wildcard(
    query: ScanQuery,
    window: SearchWindow,
    collector: ScanCollector,
    control: ScanControl,
    stats: ScanStats,
) -> MatcherResult:
    candidate_start, candidate_end = _candidate_bounds(window, query.pattern.length)
    if candidate_start >= candidate_end:
        return MatcherResult()

    address = _align_up(candidate_start, query.alignment)
    while address < candidate_end:
        examined_candidate_end = address + 1
        stats.candidate_count += 1
        stats.verification_count += 1
        decision = collector.offer(_make_hit(address, window))
        stats.committed_matches += 1
        if decision.stop:
            _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
            _poll_after_collector_stop(control, stats)
            return MatcherResult(
                termination_reason=decision.reason,
                next_candidate_start=examined_candidate_end,
            )

        if stats.candidate_count % control.poll_interval == 0:
            reason = _poll_control(control, stats)
            if reason is not None:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                return MatcherResult(termination_reason=reason)
        address += query.alignment

    _record_candidate_extent(stats, candidate_start, candidate_end, query.pattern.length)
    return MatcherResult()


def poll_control(control: ScanControl, stats: ScanStats) -> TerminationReason | None:
    """Poll cooperative control and account for the operation."""

    return _poll_control(control, stats)


def _poll_control(control: ScanControl, stats: ScanStats) -> TerminationReason | None:
    stats.control_polls += 1
    return control.poll()


def _poll_after_collector_stop(control: ScanControl, stats: ScanStats) -> None:
    # Outer runtime interruption still raises. Local timeout/cancel cannot replace
    # a collector boundary that has already been reached deterministically.
    _poll_control(control, stats)


def _record_candidate_extent(
    stats: ScanStats,
    candidate_start: int,
    candidate_end: int,
    pattern_length: int,
) -> None:
    if candidate_end > candidate_start:
        stats.record_examined_range(candidate_start, candidate_end + pattern_length - 1)


def _candidate_bounds(window: SearchWindow, pattern_length: int) -> tuple[int, int]:
    buffer_candidate_end = window.base_address + max(0, len(window.data) - pattern_length + 1)
    candidate_start = max(window.base_address, window.eligible_start)
    candidate_end = min(buffer_candidate_end, window.eligible_end)
    if candidate_end < candidate_start:
        return candidate_start, candidate_start
    return candidate_start, candidate_end


def _searchable_data(data: bytes | bytearray | memoryview) -> bytes | bytearray:
    if isinstance(data, memoryview):
        return data.tobytes()
    return data


def _make_hit(address: int, window: SearchWindow) -> ScanHit:
    module = window.module
    return ScanHit(
        address=address,
        module_name=None if module is None else module.name,
        module_base=None if module is None else module.base,
    )


def _align_up(value: int, alignment: int) -> int:
    remainder = value % alignment
    return value if remainder == 0 else value + alignment - remainder
