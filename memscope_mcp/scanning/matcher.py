"""Hybrid exact, wildcard, sampled-anchor, and regex matcher strategies."""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction

from memscope_mcp.scanning.collectors import (
    CollectorMode,
    CollectorStrategyHint,
    ScanCollector,
)
from memscope_mcp.scanning.model import (
    FixedSegment,
    MatcherResult,
    MatcherStrategy,
    ScanControl,
    ScanHit,
    ScanQuery,
    ScanStats,
    SearchWindow,
    TerminationReason,
)

_SAMPLE_SLICE_BYTES = 2048
_SAMPLE_SLICE_COUNT = 3
_ANCHOR_SHORTLIST_SIZE = 3
_DENSITY_SCALE = 1_000_000


@dataclass(frozen=True, slots=True)
class MaskedMatcherSelection:
    """Deterministic internal decision and bounded sample evidence for one window."""

    strategy: MatcherStrategy
    anchor: FixedSegment
    verification_order: tuple[FixedSegment, ...]
    sampled_bytes: int
    sampled_anchor_occurrences: int
    sampled_anchor_positions: int
    estimated_anchor_candidates: int
    estimated_anchor_density_ppm: int


def search_window(
    query: ScanQuery,
    window: SearchWindow,
    collector: ScanCollector,
    control: ScanControl,
    stats: ScanStats,
) -> MatcherResult:
    """Search one owned candidate interval with the selected bounded strategy."""

    if query.pattern.exact_bytes is not None:
        stats.record_strategy(MatcherStrategy.EXACT)
        return _search_exact(query, window, collector, control, stats)
    if query.pattern.all_wildcard:
        stats.record_strategy(MatcherStrategy.ALL_WILDCARD)
        return _search_all_wildcard(query, window, collector, control, stats)

    selection = select_masked_strategy(query, window, collector.strategy_hint)
    stats.record_strategy(selection.strategy)
    stats.selector_invocations += 1
    stats.selector_sampled_bytes += selection.sampled_bytes
    stats.selector_estimated_candidates += selection.estimated_anchor_candidates
    if selection.strategy is MatcherStrategy.ANCHOR:
        return _search_masked_anchor(query, window, collector, control, stats, selection)
    return _search_masked_regex(query, window, collector, control, stats)


def select_masked_strategy(
    query: ScanQuery,
    window: SearchWindow,
    collector_hint: CollectorStrategyHint,
) -> MaskedMatcherSelection:
    """Choose a masked strategy from a constant-size in-buffer sample."""

    pattern = query.pattern
    if pattern.exact_bytes is not None or pattern.all_wildcard or not pattern.segments:
        raise ValueError("masked strategy selection requires a masked pattern")
    if not isinstance(collector_hint, CollectorStrategyHint):
        raise TypeError("collector_hint must be a CollectorStrategyHint")

    data = _searchable_data(window.data)
    candidate_start, candidate_end = _candidate_bounds(window, pattern.length)
    candidate_count = candidate_end - candidate_start
    if candidate_count < 1:
        anchor = min(pattern.segments, key=lambda segment: (-len(segment.literal), segment.offset))
        return MaskedMatcherSelection(
            strategy=MatcherStrategy.ANCHOR,
            anchor=anchor,
            verification_order=_verification_order(pattern.segments, anchor, {}),
            sampled_bytes=0,
            sampled_anchor_occurrences=0,
            sampled_anchor_positions=0,
            estimated_anchor_candidates=0,
            estimated_anchor_density_ppm=0,
        )

    physical_start = candidate_start - window.base_address
    physical_end = candidate_end - window.base_address + pattern.length - 1
    samples = _sample_slices(data, physical_start, physical_end)
    sampled_bytes = sum(len(sample) for sample in samples)
    byte_counts = {
        value: sum(sample.count(bytes((value,))) for sample in samples) for value in pattern.unique_fixed_bytes
    }
    frequency_scores = {
        segment: _segment_frequency_score(segment, byte_counts, sampled_bytes) for segment in pattern.segments
    }

    longest = min(pattern.segments, key=lambda segment: (-len(segment.literal), segment.offset))
    ranked = sorted(
        pattern.segments,
        key=lambda segment: (frequency_scores[segment], -len(segment.literal), segment.offset),
    )
    shortlist = list(ranked[:_ANCHOR_SHORTLIST_SIZE])
    if longest not in shortlist:
        shortlist.append(longest)

    estimates: dict[FixedSegment, tuple[int, int, Fraction]] = {}
    for segment in shortlist:
        occurrences = sum(_count_sample_occurrences(sample, segment.literal) for sample in samples)
        positions = sum(max(0, len(sample) - len(segment.literal) + 1) for sample in samples)
        density = Fraction(occurrences + 1, positions + 1)
        estimates[segment] = (occurrences, positions, density)

    anchor = min(
        shortlist,
        key=lambda segment: (estimates[segment][2], -len(segment.literal), segment.offset),
    )
    occurrences, positions, density = estimates[anchor]
    estimated_candidates = min(candidate_count, _ceil_fraction(density.numerator, density.denominator, candidate_count))
    density_ppm = min(
        _DENSITY_SCALE,
        _ceil_fraction(density.numerator, density.denominator, _DENSITY_SCALE),
    )
    verification_order = _verification_order(pattern.segments, anchor, frequency_scores)
    strategy = _choose_masked_strategy(
        collector_hint,
        candidate_count=candidate_count,
        estimated_candidates=estimated_candidates,
        density_ppm=density_ppm,
        verification_order=verification_order,
    )
    return MaskedMatcherSelection(
        strategy=strategy,
        anchor=anchor,
        verification_order=verification_order,
        sampled_bytes=sampled_bytes,
        sampled_anchor_occurrences=occurrences,
        sampled_anchor_positions=positions,
        estimated_anchor_candidates=estimated_candidates,
        estimated_anchor_density_ppm=density_ppm,
    )


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
    work_since_poll = 0

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
        work_since_poll += 1

        if address % query.alignment == 0:
            stats.verified_matches += 1
            decision = collector.offer(_make_hit(address, window))
            stats.committed_matches += 1
            if decision.stop:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                _poll_after_collector_stop(control, stats)
                return MatcherResult(
                    termination_reason=decision.reason,
                    next_candidate_start=examined_candidate_end,
                )

        if work_since_poll >= control.poll_interval:
            work_since_poll = 0
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
    work_since_poll = 0
    while address < candidate_end:
        examined_candidate_end = address + 1
        stats.candidate_count += 1
        stats.verification_count += 1
        stats.verified_matches += 1
        work_since_poll += 1
        decision = collector.offer(_make_hit(address, window))
        stats.committed_matches += 1
        if decision.stop:
            _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
            _poll_after_collector_stop(control, stats)
            return MatcherResult(
                termination_reason=decision.reason,
                next_candidate_start=examined_candidate_end,
            )

        if work_since_poll >= control.poll_interval:
            work_since_poll = 0
            reason = _poll_control(control, stats)
            if reason is not None:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                return MatcherResult(termination_reason=reason)
        address += query.alignment

    _record_candidate_extent(stats, candidate_start, candidate_end, query.pattern.length)
    return MatcherResult()


def _search_masked_anchor(
    query: ScanQuery,
    window: SearchWindow,
    collector: ScanCollector,
    control: ScanControl,
    stats: ScanStats,
    selection: MaskedMatcherSelection,
) -> MatcherResult:
    data = _searchable_data(window.data)
    candidate_start, candidate_end = _candidate_bounds(window, query.pattern.length)
    if candidate_start >= candidate_end:
        return MatcherResult()

    anchor = selection.anchor
    position = candidate_start - window.base_address + anchor.offset
    search_end = candidate_end - window.base_address + anchor.offset + len(anchor.literal) - 1
    work_since_poll = 0

    while True:
        stats.find_calls += 1
        found = data.find(anchor.literal, position, search_end)
        if found < 0:
            _record_candidate_extent(stats, candidate_start, candidate_end, query.pattern.length)
            return MatcherResult()

        candidate_offset = found - anchor.offset
        address = window.base_address + candidate_offset
        examined_candidate_end = address + 1
        position = found + 1
        stats.candidate_count += 1
        stats.anchor_candidates += 1
        work_since_poll += 1

        if address % query.alignment == 0:
            stats.verification_count += 1
            matched = True
            for segment in selection.verification_order:
                stats.segment_verifications += 1
                if not data.startswith(segment.literal, candidate_offset + segment.offset):
                    matched = False
                    break
            if matched:
                stats.verified_matches += 1
                decision = collector.offer(_make_hit(address, window))
                stats.committed_matches += 1
                if decision.stop:
                    _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                    _poll_after_collector_stop(control, stats)
                    return MatcherResult(
                        termination_reason=decision.reason,
                        next_candidate_start=examined_candidate_end,
                    )

        if work_since_poll >= control.poll_interval:
            work_since_poll = 0
            reason = _poll_control(control, stats)
            if reason is not None:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                return MatcherResult(termination_reason=reason)


def _search_masked_regex(
    query: ScanQuery,
    window: SearchWindow,
    collector: ScanCollector,
    control: ScanControl,
    stats: ScanStats,
) -> MatcherResult:
    regex = query.pattern.regex
    if regex is None:
        raise ValueError("regex matcher requires a compiled masked regex")

    data = _searchable_data(window.data)
    candidate_start, candidate_end = _candidate_bounds(window, query.pattern.length)
    if candidate_start >= candidate_end:
        return MatcherResult()

    position = candidate_start - window.base_address
    search_end = candidate_end - window.base_address + query.pattern.length - 1
    work_since_poll = 0

    while True:
        stats.find_calls += 1
        match = regex.search(data, position, search_end)
        if match is None:
            _record_candidate_extent(stats, candidate_start, candidate_end, query.pattern.length)
            return MatcherResult()

        found = match.start()
        address = window.base_address + found
        examined_candidate_end = address + 1
        position = found + 1
        stats.candidate_count += 1
        stats.regex_candidates += 1
        stats.verification_count += 1
        work_since_poll += 1

        if address % query.alignment == 0:
            stats.verified_matches += 1
            decision = collector.offer(_make_hit(address, window))
            stats.committed_matches += 1
            if decision.stop:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                _poll_after_collector_stop(control, stats)
                return MatcherResult(
                    termination_reason=decision.reason,
                    next_candidate_start=examined_candidate_end,
                )

        if work_since_poll >= control.poll_interval:
            work_since_poll = 0
            reason = _poll_control(control, stats)
            if reason is not None:
                _record_candidate_extent(stats, candidate_start, examined_candidate_end, query.pattern.length)
                return MatcherResult(termination_reason=reason)


def poll_control(control: ScanControl, stats: ScanStats) -> TerminationReason | None:
    """Poll cooperative control and account for the operation."""

    return _poll_control(control, stats)


def _choose_masked_strategy(
    hint: CollectorStrategyHint,
    *,
    candidate_count: int,
    estimated_candidates: int,
    density_ppm: int,
    verification_order: tuple[FixedSegment, ...],
) -> MatcherStrategy:
    verification_bytes = sum(len(segment.literal) for segment in verification_order)
    verification_weight = 1 + min(15, len(verification_order) + (verification_bytes + 3) // 4)
    weighted_density = density_ppm * verification_weight

    thresholds = {
        CollectorMode.FIRST: 80_000,
        CollectorMode.PAGE: 65_000,
        CollectorMode.ADDRESSES: 65_000,
        CollectorMode.COUNT: 55_000,
    }
    threshold = thresholds[hint.mode]
    if hint.remaining_matches <= 16:
        threshold = threshold * 5 // 4
    elif hint.remaining_matches >= 1000:
        threshold = threshold * 9 // 10
    if candidate_count < 4096:
        threshold = threshold * 3 // 2

    if hint.mode is CollectorMode.FIRST:
        minimum_candidates = 64
    else:
        minimum_candidates = min(512, max(128, hint.remaining_matches * 2))

    if estimated_candidates >= minimum_candidates and weighted_density >= threshold:
        return MatcherStrategy.REGEX
    return MatcherStrategy.ANCHOR


def _verification_order(
    segments: tuple[FixedSegment, ...],
    anchor: FixedSegment,
    frequency_scores: dict[FixedSegment, float],
) -> tuple[FixedSegment, ...]:
    return tuple(
        sorted(
            (segment for segment in segments if segment != anchor),
            key=lambda segment: (frequency_scores.get(segment, 0.0), -len(segment.literal), segment.offset),
        )
    )


def _segment_frequency_score(
    segment: FixedSegment,
    byte_counts: dict[int, int],
    sampled_bytes: int,
) -> float:
    denominator = sampled_bytes + 256
    return sum(math.log((byte_counts[value] + 1) / denominator) for value in segment.literal)


def _sample_slices(
    data: bytes | bytearray,
    start: int,
    end: int,
) -> tuple[bytes, ...]:
    span = max(0, end - start)
    if span == 0:
        return ()
    total_budget = _SAMPLE_SLICE_BYTES * _SAMPLE_SLICE_COUNT
    if span <= total_budget:
        return (bytes(data[start:end]),)

    starts = (
        start,
        start + (span - _SAMPLE_SLICE_BYTES) // 2,
        end - _SAMPLE_SLICE_BYTES,
    )
    return tuple(bytes(data[sample_start : sample_start + _SAMPLE_SLICE_BYTES]) for sample_start in starts)


def _count_sample_occurrences(sample: bytes, literal: bytes) -> int:
    return sample.count(literal)


def _ceil_fraction(numerator: int, denominator: int, multiplier: int) -> int:
    return (numerator * multiplier + denominator - 1) // denominator


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
