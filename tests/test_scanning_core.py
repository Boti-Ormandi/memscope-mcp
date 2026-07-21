"""Tests for the strict compiler, bounded collectors, and initial matcher core."""

from __future__ import annotations

import gc
import random
import re
import tracemalloc
from dataclasses import FrozenInstanceError

import pytest

from memscope_mcp.scanning import pattern as pattern_module
from memscope_mcp.scanning.collectors import (
    BoundedAddressCollector,
    CountCollector,
    FirstHitCollector,
    PageCollector,
)
from memscope_mcp.scanning.engine import execute_scan_windows
from memscope_mcp.scanning.matcher import select_masked_strategy
from memscope_mcp.scanning.model import (
    CompiledPattern,
    FixedSegment,
    MatcherStrategy,
    ModuleRecord,
    ScanControl,
    ScanHit,
    SearchWindow,
    TerminationReason,
)
from memscope_mcp.scanning.oracle import find_oracle_matches, parse_oracle_pattern
from memscope_mcp.scanning.pattern import (
    PatternCompileError,
    PatternErrorReason,
    compile_aob_pattern,
    compile_canonical_pattern,
    compile_exact_bytes,
    format_canonical_pattern,
    make_aob_query,
    make_exact_query,
)


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("48 8B 05", "48 8B 05"),
        ("48 8b ?? ??", "48 8B ?? ??"),
        ("488B05????", "48 8B 05 ?? ??"),
        ("\t48   8B\r\n??  ", "48 8B ??"),
        ("??", "??"),
    ],
)
def test_production_compiler_matches_strict_oracle(text, canonical):
    compiled = compile_aob_pattern(text)
    oracle = parse_oracle_pattern(text)

    assert compiled.pattern_bytes == oracle.pattern_bytes
    assert compiled.mask == oracle.mask
    assert format_canonical_pattern(compiled) == canonical


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", PatternErrorReason.EMPTY),
        ("   ", PatternErrorReason.EMPTY),
        ("F", PatternErrorReason.ODD_COMPACT_LENGTH),
        ("ABC", PatternErrorReason.ODD_COMPACT_LENGTH),
        ("48 ? 90", PatternErrorReason.INVALID_TOKEN),
        ("48 xx 90", PatternErrorReason.INVALID_TOKEN),
        ("48 XX 90", PatternErrorReason.INVALID_TOKEN),
        ("48 ** 90", PatternErrorReason.INVALID_TOKEN),
        ("48,8B", PatternErrorReason.ODD_COMPACT_LENGTH),
        ("GG", PatternErrorReason.INVALID_TOKEN),
        ("DEAD BEEF", PatternErrorReason.INVALID_TOKEN),
        ("100", PatternErrorReason.ODD_COMPACT_LENGTH),
        ("48\u00a08B", PatternErrorReason.NON_ASCII_WHITESPACE),
    ],
)
def test_production_compiler_rejects_malformed_and_legacy_forms(text, reason):
    with pytest.raises(PatternCompileError) as captured:
        compile_aob_pattern(text)

    assert captured.value.code == "INVALID_PATTERN"
    assert captured.value.field == "pattern"
    assert captured.value.reason is reason


def test_compiler_classifies_segments_exact_and_all_wildcard_patterns():
    masked = compile_aob_pattern("?? 48 8B ?? 90 ??")
    exact = compile_exact_bytes(b"ABC")
    wildcard = compile_aob_pattern("?? ??")

    assert masked.segments == (
        FixedSegment(offset=1, literal=b"\x48\x8b"),
        FixedSegment(offset=4, literal=b"\x90"),
    )
    assert masked.fixed_byte_count == 3
    assert masked.unique_fixed_bytes == bytes(sorted({0x48, 0x8B, 0x90}))
    assert masked.exact_bytes is None
    assert masked.all_wildcard is False
    assert masked.regex is not None
    assert [match.start() for match in masked.regex.finditer(b"\x00\x48\x8b\x0a\x90\x00")] == [0]

    assert exact.exact_bytes == b"ABC"
    assert exact.all_wildcard is False
    assert exact.regex is None
    assert wildcard.exact_bytes is None
    assert wildcard.all_wildcard is True
    assert wildcard.regex is None


def test_compiler_fingerprint_is_canonical_and_shape_sensitive():
    spaced = compile_aob_pattern("48 8b ??")
    compact = compile_aob_pattern("488B??")
    different_mask = compile_aob_pattern("48 8B 00")

    assert spaced.fingerprint == compact.fingerprint
    assert spaced.fingerprint != different_mask.fingerprint
    assert len(spaced.fingerprint) == 32


def test_compile_caches_reuse_canonical_immutable_patterns():
    pattern_module._clear_pattern_compile_caches()
    try:
        spaced = compile_aob_pattern("41 42 43")
        repeated = compile_aob_pattern("41 42 43")
        compact = compile_aob_pattern("414243")
        exact = compile_exact_bytes(b"ABC")
        canonical = compile_canonical_pattern(b"ABC", b"\xff\xff\xff")

        assert repeated is spaced
        assert compact is spaced
        assert exact is spaced
        assert canonical is spaced
        assert spaced.segments == (FixedSegment(offset=0, literal=b"ABC"),)
        assert spaced.fingerprint == compile_aob_pattern("41 42 43").fingerprint
    finally:
        pattern_module._clear_pattern_compile_caches()


def test_compile_caches_are_bounded_and_evict_old_entries():
    pattern_module._clear_pattern_compile_caches()
    try:
        first = compile_aob_pattern("FF FE")
        for value in range(pattern_module._PATTERN_CACHE_SIZE + 1):
            compile_aob_pattern(value.to_bytes(2, "big").hex(" "))

        assert pattern_module._compile_aob_text_cached.cache_info().currsize == pattern_module._PATTERN_CACHE_SIZE
        assert pattern_module._compile_canonical_cached.cache_info().currsize == pattern_module._PATTERN_CACHE_SIZE
        assert compile_aob_pattern("FF FE") is not first
    finally:
        pattern_module._clear_pattern_compile_caches()


def test_compiled_models_are_frozen_and_slotted():
    with pytest.raises(TypeError, match="must be created by the pattern compiler"):
        CompiledPattern()

    pattern = compile_aob_pattern("41")
    with pytest.raises(FrozenInstanceError):
        pattern.length = 2
    assert not hasattr(pattern, "__dict__")


def test_exact_search_preserves_overlaps_and_module_identity():
    module = ModuleRecord(
        name="target.dll",
        normalized_name="target.dll",
        base=0x1000,
        size=0x100,
        path=r"C:\target.dll",
    )
    result = execute_scan_windows(
        make_exact_query(b"AA"),
        [SearchWindow(0x1000, b"AAAA", 0x1000, 0x1003, module)],
        BoundedAddressCollector(10),
    )

    assert [hit.address for hit in result.hits] == [0x1000, 0x1001, 0x1002]
    assert all(hit.module_name == "target.dll" and hit.module_base == 0x1000 for hit in result.hits)
    assert result.observed_count == 3
    assert result.termination_reason is TerminationReason.SCOPE_EXHAUSTED
    assert result.next_candidate_start is None


def test_exact_search_clips_candidate_bounds_and_uses_absolute_alignment():
    result = execute_scan_windows(
        make_exact_query(b"A", alignment=2),
        [SearchWindow(0x1001, b"AAAA", 0x1002, 0x1005)],
        BoundedAddressCollector(10),
    )

    assert [hit.address for hit in result.hits] == [0x1002, 0x1004]


def test_page_collector_stops_without_lookahead_and_preserves_resume_candidate():
    base = 0x2000
    result = execute_scan_windows(
        make_exact_query(b"A"),
        [SearchWindow(base, b"A" * 1_000_000, base, base + 1_000_000)],
        PageCollector(50, remaining_matches=5000),
    )

    assert len(result.hits) == 50
    assert result.termination_reason is TerminationReason.PAGE_LIMIT
    assert result.next_candidate_start == base + 50
    assert result.stats.candidate_count == 50
    assert result.stats.verification_count == 50
    assert result.stats.find_calls == 50
    assert result.stats.committed_matches == 50
    assert result.stats.unique_bytes_examined == 50


def test_page_continuation_has_no_duplicates_or_gaps():
    base = 0x3000
    query = make_exact_query(b"A")
    first = execute_scan_windows(
        query,
        [SearchWindow(base, b"AAAAAA", base, base + 6)],
        PageCollector(3),
    )
    second = execute_scan_windows(
        query,
        [SearchWindow(base, b"AAAAAA", first.next_candidate_start, base + 6)],
        PageCollector(3),
    )

    assert [hit.address for hit in first.hits + second.hits] == list(range(base, base + 6))
    assert second.termination_reason is TerminationReason.PAGE_LIMIT
    assert second.next_candidate_start == base + 6


def test_full_terminal_page_is_followed_by_empty_terminal_scan():
    base = 0x4000
    query = make_exact_query(b"A")
    full = execute_scan_windows(
        query,
        [SearchWindow(base, b"AAAA", base, base + 4)],
        PageCollector(4),
    )
    terminal = execute_scan_windows(
        query,
        [SearchWindow(base, b"AAAA", full.next_candidate_start, base + 4)],
        PageCollector(4),
    )

    assert full.termination_reason is TerminationReason.PAGE_LIMIT
    assert terminal.hits == []
    assert terminal.termination_reason is TerminationReason.SCOPE_EXHAUSTED
    assert terminal.next_candidate_start is None


def test_page_collector_prioritizes_consumed_cumulative_match_cap():
    base = 0x5000
    result = execute_scan_windows(
        make_exact_query(b"A"),
        [SearchWindow(base, b"AAAAA", base, base + 5)],
        PageCollector(5, remaining_matches=3),
    )

    assert len(result.hits) == 3
    assert result.termination_reason is TerminationReason.MATCH_LIMIT
    assert result.next_candidate_start == base + 3
    assert result.stats.find_calls == 3


def test_first_and_count_collectors_apply_policy_inside_current_window():
    base = 0x6000
    window = SearchWindow(base, b"AAAA", base, base + 4)

    first = execute_scan_windows(make_exact_query(b"A"), [window], FirstHitCollector())
    counted = execute_scan_windows(make_exact_query(b"A"), [window], CountCollector(3))

    assert [hit.address for hit in first.hits] == [base]
    assert first.termination_reason is TerminationReason.FIRST_HIT
    assert first.next_candidate_start == base + 1
    assert counted.hits == []
    assert counted.observed_count == 3
    assert counted.termination_reason is TerminationReason.MATCH_LIMIT
    assert counted.next_candidate_start == base + 3


def test_all_wildcard_generation_respects_length_bounds_alignment_and_cap():
    base = 0x7001
    result = execute_scan_windows(
        make_aob_query("?? ?? ??", alignment=2),
        [SearchWindow(base, b"1234567", base, base + 7)],
        BoundedAddressCollector(2),
    )

    assert [hit.address for hit in result.hits] == [0x7002, 0x7004]
    assert result.termination_reason is TerminationReason.MATCH_LIMIT
    assert result.next_candidate_start == 0x7005
    assert result.stats.candidate_count == 2


def test_all_wildcard_scope_shorter_than_pattern_has_no_candidates():
    result = execute_scan_windows(
        make_aob_query("?? ?? ??"),
        [SearchWindow(0x8000, b"12", 0x8000, 0x8002)],
        BoundedAddressCollector(10),
    )

    assert result.hits == []
    assert result.termination_reason is TerminationReason.SCOPE_EXHAUSTED
    assert result.stats.candidate_count == 0


def test_dense_all_wildcard_scan_allocation_is_independent_of_possible_match_count():
    base = 0x9000
    data = b"\0" * 1_000_000
    window = SearchWindow(base, data, base, base + len(data))

    gc.collect()
    tracemalloc.start()
    try:
        result = execute_scan_windows(
            make_aob_query("??"),
            [window],
            BoundedAddressCollector(8),
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(result.hits) == 8
    assert result.stats.candidate_count == 8
    assert result.stats.unique_bytes_examined == 8
    assert peak < 256_000


def test_immediate_deadline_and_cancellation_return_partial_termination():
    base = 0xA000
    window = SearchWindow(base, b"AAAA", base, base + 4)

    timeout = execute_scan_windows(
        make_exact_query(b"A"),
        [window],
        BoundedAddressCollector(4),
        control=ScanControl(deadline_ns=10, clock=lambda: 10),
    )
    cancelled = execute_scan_windows(
        make_exact_query(b"A"),
        [window],
        BoundedAddressCollector(4),
        control=ScanControl(cancel_checks=(lambda: True,)),
    )

    assert timeout.hits == []
    assert timeout.termination_reason is TerminationReason.TIMEOUT
    assert timeout.next_candidate_start is None
    assert cancelled.hits == []
    assert cancelled.termination_reason is TerminationReason.CANCELLED
    assert cancelled.next_candidate_start is None


def test_outer_interrupt_is_raised_instead_of_becoming_partial_result():
    class Interrupted(RuntimeError):
        pass

    def interrupt():
        raise Interrupted

    with pytest.raises(Interrupted):
        execute_scan_windows(
            make_exact_query(b"A"),
            [SearchWindow(0xB000, b"A", 0xB000, 0xB001)],
            FirstHitCollector(),
            control=ScanControl(interrupt_check=interrupt),
        )


def test_collector_rejects_non_positive_caps_and_out_of_order_hits():
    for constructor in (
        lambda: BoundedAddressCollector(0),
        lambda: PageCollector(0),
        lambda: PageCollector(1, remaining_matches=0),
        lambda: CountCollector(0),
    ):
        with pytest.raises(ValueError):
            constructor()

    collector = BoundedAddressCollector(3)
    collector.offer(ScanHit(2, None, None))
    with pytest.raises(ValueError):
        collector.offer(ScanHit(1, None, None))


def test_engine_rejects_overlapping_window_candidate_ownership():
    with pytest.raises(ValueError, match="non-overlapping"):
        execute_scan_windows(
            make_exact_query(b"A"),
            [
                SearchWindow(0xC000, b"AA", 0xC000, 0xC002),
                SearchWindow(0xC001, b"AA", 0xC001, 0xC003),
            ],
            BoundedAddressCollector(10),
        )


def test_masked_selector_prefers_rare_short_segment_over_common_long_segment():
    data = bytearray(b"A" * 20_000)
    for index in (64, 10_000, 19_000):
        data[index] = ord("Z")
    query = make_aob_query("41 41 41 41 ?? 5A")
    window = SearchWindow(0x1000, data, 0x1000, 0x1000 + len(data))

    selection = select_masked_strategy(query, window, BoundedAddressCollector(100).strategy_hint)

    assert selection.anchor == FixedSegment(offset=5, literal=b"Z")
    assert selection.strategy is MatcherStrategy.ANCHOR
    assert selection.sampled_bytes <= 6144


def test_masked_selector_uses_stable_offset_tie_break():
    query = make_aob_query("41 ?? 42")
    window = SearchWindow(0, b"\0" * 8192, 0, 8192)

    selection = select_masked_strategy(query, window, BoundedAddressCollector(100).strategy_hint)

    assert selection.anchor == FixedSegment(offset=0, literal=b"A")


def test_common_masked_anchor_selects_regex_fallback():
    query = make_aob_query("00 ?? 00")
    window = SearchWindow(0, b"\0" * 65536, 0, 65536)

    selection = select_masked_strategy(query, window, CountCollector(5000).strategy_hint)
    result = execute_scan_windows(query, [window], CountCollector(5000))

    assert selection.strategy is MatcherStrategy.REGEX
    assert result.stats.strategy_counts == {MatcherStrategy.REGEX: 1}
    assert result.stats.regex_candidates == 5000
    assert result.stats.anchor_candidates == 0


def test_common_overlapping_multibyte_anchor_selects_regex_fallback():
    query = make_aob_query("41 41 41 41 ?? 41 41 41 41")
    window = SearchWindow(0, b"A" * 65536, 0, 65536)

    selection = select_masked_strategy(query, window, CountCollector(5000).strategy_hint)

    assert selection.strategy is MatcherStrategy.REGEX
    assert selection.anchor == FixedSegment(offset=0, literal=b"AAAA")


def test_masked_selector_accounts_for_collector_policy_and_remaining_budget():
    data = bytearray((b"Z" + b"-" * 19 + b"Y" + b"-" * 19) * 2000)
    data[:3] = b"Z-Y"
    query = make_aob_query("5A ?? 59")
    window = SearchWindow(0, data, 0, len(data))

    first = select_masked_strategy(query, window, FirstHitCollector().strategy_hint)
    counted = select_masked_strategy(query, window, CountCollector(5000).strategy_hint)

    assert first.strategy is MatcherStrategy.ANCHOR
    assert counted.strategy is MatcherStrategy.REGEX


def test_masked_anchor_preserves_overlaps_alignment_and_page_resume():
    base = 0xD100
    data = (b"Zx" + b"-" * 30) * 20
    query = make_aob_query("5A ??", alignment=2)
    window = SearchWindow(base, data, base, base + len(data))

    selection = select_masked_strategy(query, window, PageCollector(10).strategy_hint)
    result = execute_scan_windows(query, [window], PageCollector(10))

    assert selection.strategy is MatcherStrategy.ANCHOR
    assert [hit.address for hit in result.hits] == [base + index * 32 for index in range(10)]
    assert result.next_candidate_start == base + 9 * 32 + 1
    assert result.stats.anchor_candidates == 10
    assert result.stats.regex_candidates == 0
    assert result.stats.candidate_count == 10


def test_regex_masked_path_preserves_newlines_metacharacters_and_overlap():
    base = 0xD800
    data = b".\n*" * 2000
    query = make_aob_query("2E ?? 2A")
    window = SearchWindow(base, data, base, base + len(data))

    result = execute_scan_windows(query, [window], BoundedAddressCollector(10))

    assert [hit.address for hit in result.hits] == [base + index * 3 for index in range(10)]
    assert result.termination_reason is TerminationReason.MATCH_LIMIT
    assert result.next_candidate_start == base + 28
    assert result.stats.strategy_counts == {MatcherStrategy.REGEX: 1}
    assert result.stats.regex_candidates == 10
    assert result.stats.candidate_count == 10
    assert result.stats.find_calls == 10


def test_dense_masked_page_allocation_is_independent_of_possible_matches():
    data = b"\0" * 1_000_000
    window = SearchWindow(0, data, 0, len(data))

    gc.collect()
    tracemalloc.start()
    try:
        result = execute_scan_windows(make_aob_query("00 ?? 00"), [window], PageCollector(100))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result.termination_reason is TerminationReason.PAGE_LIMIT
    assert result.stats.strategy_counts == {MatcherStrategy.REGEX: 1}
    assert result.stats.regex_candidates == 100
    assert peak < 512_000


def test_masked_anchor_and_regex_poll_cooperative_cancellation():
    checks = 0

    def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 2

    anchor_block = b"Zx-" + b"-" * 12 + b"Y" + b"-" * 16
    anchor_data = anchor_block * 100
    anchor = execute_scan_windows(
        make_aob_query("5A ?? 59"),
        [SearchWindow(0, anchor_data, 0, len(anchor_data))],
        BoundedAddressCollector(100),
        control=ScanControl(cancel_checks=(cancelled,), poll_interval=2),
    )

    checks = 0
    regex = execute_scan_windows(
        make_aob_query("00 ?? 00"),
        [SearchWindow(0, b"\0" * 4096, 0, 4096)],
        CountCollector(4096),
        control=ScanControl(cancel_checks=(cancelled,), poll_interval=2),
    )

    assert anchor.termination_reason is TerminationReason.CANCELLED
    assert anchor.stats.strategy_counts == {MatcherStrategy.ANCHOR: 1}
    assert anchor.stats.anchor_candidates == 2
    assert regex.termination_reason is TerminationReason.CANCELLED
    assert regex.stats.strategy_counts == {MatcherStrategy.REGEX: 1}
    assert regex.stats.regex_candidates == 2


def test_masked_regex_polls_deadline_inside_current_window():
    clock_values = iter((0, 10))
    result = execute_scan_windows(
        make_aob_query("00 ?? 00"),
        [SearchWindow(0, b"\0" * 4096, 0, 4096)],
        CountCollector(4096),
        control=ScanControl(deadline_ns=5, clock=lambda: next(clock_values), poll_interval=2),
    )

    assert result.termination_reason is TerminationReason.TIMEOUT
    assert result.next_candidate_start is None
    assert result.stats.strategy_counts == {MatcherStrategy.REGEX: 1}
    assert result.stats.regex_candidates == 2


def test_randomized_exact_engine_parity_with_oracle():
    rng = random.Random(0xE1AC7)

    for _ in range(200):
        data = bytes(rng.randrange(4) for _ in range(rng.randrange(0, 96)))
        exact = bytes(rng.randrange(4) for _ in range(rng.randrange(1, 12)))
        base = rng.randrange(0, 32)
        alignment = rng.randrange(1, 9)
        eligible_start = base + rng.randrange(0, len(data) + 1)
        eligible_end = base + rng.randrange(0, len(data) + 1)
        eligible_start, eligible_end = sorted((eligible_start, eligible_end))
        cap = rng.randrange(1, 20)

        result = execute_scan_windows(
            make_exact_query(exact, alignment=alignment),
            [SearchWindow(base, data, eligible_start, eligible_end)],
            BoundedAddressCollector(cap),
        )
        oracle = parse_oracle_pattern(" ".join(f"{value:02X}" for value in exact))
        expected = find_oracle_matches(
            data,
            oracle,
            base_address=base,
            eligible_start=eligible_start,
            eligible_end=eligible_end,
            alignment=alignment,
            max_matches=cap,
        )

        assert [hit.address for hit in result.hits] == expected


def test_randomized_all_wildcard_engine_parity_with_oracle():
    rng = random.Random(0xA11D)

    for _ in range(200):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 96)))
        length = rng.randrange(1, 12)
        base = rng.randrange(0, 32)
        alignment = rng.randrange(1, 9)
        eligible_start = base + rng.randrange(0, len(data) + 1)
        eligible_end = base + rng.randrange(0, len(data) + 1)
        eligible_start, eligible_end = sorted((eligible_start, eligible_end))
        cap = rng.randrange(1, 20)

        pattern = " ".join("??" for _ in range(length))
        result = execute_scan_windows(
            make_aob_query(pattern, alignment=alignment),
            [SearchWindow(base, data, eligible_start, eligible_end)],
            BoundedAddressCollector(cap),
        )
        expected = find_oracle_matches(
            data,
            parse_oracle_pattern(pattern),
            base_address=base,
            eligible_start=eligible_start,
            eligible_end=eligible_end,
            alignment=alignment,
            max_matches=cap,
        )

        assert [hit.address for hit in result.hits] == expected


def test_compiled_masked_regex_matches_independent_reference_for_newline_bytes():
    compiled = compile_aob_pattern("2E ?? 2A")
    assert compiled.regex is not None
    data = b".\n* .x*"
    expected = [match.start() for match in re.finditer(rb"(?=(\..\*))", data, re.DOTALL)]

    assert [match.start() for match in compiled.regex.finditer(data)] == expected


def test_compiler_enforces_text_and_compiled_byte_limits():
    assert compile_aob_pattern(" ".join("AA" for _ in range(1024))).length == 1024
    assert compile_exact_bytes(b"A" * 1024).length == 1024

    with pytest.raises(PatternCompileError) as text_error:
        compile_aob_pattern("A" * 4097)
    with pytest.raises(PatternCompileError) as byte_error:
        compile_aob_pattern(" ".join("AA" for _ in range(1025)))
    with pytest.raises(PatternCompileError) as exact_error:
        compile_exact_bytes(b"A" * 1025)

    assert text_error.value.reason is PatternErrorReason.TEXT_TOO_LONG
    assert byte_error.value.reason is PatternErrorReason.BYTE_LENGTH
    assert exact_error.value.reason is PatternErrorReason.BYTE_LENGTH


def test_x64_terminal_address_can_produce_exclusive_continuation_boundary():
    maximum_address = (1 << 64) - 1
    result = execute_scan_windows(
        make_exact_query(b"A"),
        [SearchWindow(maximum_address, b"A", maximum_address, 1 << 64)],
        FirstHitCollector(),
    )

    assert [hit.address for hit in result.hits] == [maximum_address]
    assert result.next_candidate_start == 1 << 64


def test_models_reject_out_of_range_addresses_and_windows():
    with pytest.raises(ValueError, match="unsigned 64-bit address"):
        ScanHit(1 << 64, None, None)
    with pytest.raises(ValueError, match="exceeds the x64 address space"):
        SearchWindow((1 << 64) - 1, b"AA", (1 << 64) - 1, 1 << 64)
    with pytest.raises(ValueError, match="alignment"):
        make_exact_query(b"A", alignment=True)


def test_examined_byte_ranges_do_not_double_count_window_overlap_bytes():
    base = 0xD000
    result = execute_scan_windows(
        make_exact_query(b"AA"),
        [
            SearchWindow(base, b"AA", base, base + 1),
            SearchWindow(base + 1, b"AA", base + 1, base + 2),
        ],
        BoundedAddressCollector(10),
    )

    assert [hit.address for hit in result.hits] == [base, base + 1]
    assert result.stats.unique_bytes_examined == 3


def test_local_cancellation_preserves_verified_partial_hits_without_resume_state():
    checks = 0

    def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 2

    base = 0xE000
    result = execute_scan_windows(
        make_aob_query("??"),
        [SearchWindow(base, b"AAAA", base, base + 4)],
        BoundedAddressCollector(10),
        control=ScanControl(cancel_checks=(cancelled,), poll_interval=2),
    )

    assert [hit.address for hit in result.hits] == [base, base + 1]
    assert result.termination_reason is TerminationReason.CANCELLED
    assert result.next_candidate_start is None
    assert result.stats.unique_bytes_examined == 2


def test_collector_boundary_wins_after_hit_is_already_committed():
    clock_values = iter((0, 10))
    base = 0xF000
    result = execute_scan_windows(
        make_exact_query(b"A"),
        [SearchWindow(base, b"A", base, base + 1)],
        FirstHitCollector(),
        control=ScanControl(deadline_ns=5, clock=lambda: next(clock_values)),
    )

    assert result.termination_reason is TerminationReason.FIRST_HIT
    assert result.next_candidate_start == base + 1


def test_randomized_masked_engine_parity_with_oracle():
    rng = random.Random(0xA0B5CA1)

    for _ in range(400):
        alphabet_size = rng.choice((2, 4, 16, 256))
        data = bytes(rng.randrange(alphabet_size) for _ in range(rng.randrange(0, 160)))
        length = rng.randrange(2, 16)
        wildcard_index = rng.randrange(length)
        fixed_index = rng.randrange(length)
        while fixed_index == wildcard_index:
            fixed_index = rng.randrange(length)
        tokens = []
        for index in range(length):
            if index == wildcard_index or (index != fixed_index and rng.random() < 0.35):
                tokens.append("??")
            else:
                tokens.append(f"{rng.randrange(alphabet_size):02X}")

        pattern = " ".join(tokens)
        base = rng.randrange(0, 64)
        alignment = rng.randrange(1, 9)
        eligible_start = base + rng.randrange(0, len(data) + 1)
        eligible_end = base + rng.randrange(0, len(data) + 1)
        eligible_start, eligible_end = sorted((eligible_start, eligible_end))
        cap = rng.randrange(1, 30)
        result = execute_scan_windows(
            make_aob_query(pattern, alignment=alignment),
            [SearchWindow(base, data, eligible_start, eligible_end)],
            BoundedAddressCollector(cap),
        )
        expected = find_oracle_matches(
            data,
            parse_oracle_pattern(pattern),
            base_address=base,
            eligible_start=eligible_start,
            eligible_end=eligible_end,
            alignment=alignment,
            max_matches=cap,
        )

        assert [hit.address for hit in result.hits] == expected
