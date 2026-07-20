"""Tests for the independent strict-semantics scan oracle."""

import random
import re

import pytest

from memscope_mcp.scanning.oracle import find_oracle_matches, parse_oracle_pattern


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
def test_strict_oracle_parser_accepts_only_canonical_forms(text, canonical):
    parsed = parse_oracle_pattern(text)

    assert parsed.canonical_text == canonical
    assert parsed.length == len(canonical.split())


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "F",
        "ABC",
        "48 ? 90",
        "48 xx 90",
        "48 XX 90",
        "48 ** 90",
        "48,8B",
        "GG",
        "100",
        "48\u00a08B",
    ],
)
def test_strict_oracle_parser_rejects_legacy_aliases_and_malformed_patterns(text):
    with pytest.raises(ValueError):
        parse_oracle_pattern(text)


def test_oracle_preserves_overlapping_matches_and_absolute_alignment():
    exact = parse_oracle_pattern("41 41")

    assert find_oracle_matches(b"AAAA", exact, base_address=0x1000) == [0x1000, 0x1001, 0x1002]
    assert find_oracle_matches(b"AAAA", exact, base_address=0x1001, alignment=2) == [0x1002]


def test_oracle_applies_eligible_candidate_bounds_and_result_cap():
    pattern = parse_oracle_pattern("AA ??")
    data = bytes.fromhex("AA 01 AA 02 AA 03")

    assert find_oracle_matches(
        data,
        pattern,
        base_address=0x2000,
        eligible_start=0x2001,
        eligible_end=0x2005,
    ) == [0x2002, 0x2004]
    assert find_oracle_matches(data, pattern, base_address=0x2000, max_matches=2) == [0x2000, 0x2002]


def test_oracle_all_wildcard_candidates_are_bounded_by_full_pattern_length():
    pattern = parse_oracle_pattern("?? ?? ??")

    assert find_oracle_matches(b"12345", pattern, base_address=0x3000) == [0x3000, 0x3001, 0x3002]
    assert find_oracle_matches(b"12", pattern, base_address=0x3000) == []


def test_randomized_oracle_matches_independent_overlapping_regex_reference():
    rng = random.Random(0x5CA1)

    for _ in range(250):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 96)))
        tokens = []
        regex_parts = []
        for _ in range(rng.randrange(1, 12)):
            if rng.random() < 0.35:
                tokens.append("??")
                regex_parts.append(b".")
            else:
                value = rng.randrange(256)
                tokens.append(f"{value:02X}")
                regex_parts.append(re.escape(bytes([value])))

        pattern = parse_oracle_pattern(" ".join(tokens))
        expression = re.compile(b"(?=(" + b"".join(regex_parts) + b"))", re.DOTALL)
        expected = [match.start() for match in expression.finditer(data)]

        assert find_oracle_matches(data, pattern) == expected
