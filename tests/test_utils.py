"""Unit tests for utility functions (no live process needed)."""

import pytest

from src.utils.memory_utils import format_address, format_bytes, is_valid_pointer, parse_offset
from src.utils.pattern import create_signature_pattern, match_pattern, parse_aob_pattern

# ============================================================================
# Address parsing
# ============================================================================


class TestParseOffset:
    def test_int(self):
        assert parse_offset(0x148) == 0x148

    def test_hex_string(self):
        assert parse_offset("0x148") == 0x148

    def test_decimal_string(self):
        assert parse_offset("328") == 328

    def test_uppercase_hex(self):
        assert parse_offset("0X1A0") == 0x1A0


class TestFormatAddress:
    def test_basic(self):
        assert format_address(0x7FFC8E7D0000) == "0x7FFC8E7D0000"

    def test_zero(self):
        assert format_address(0) == "0x0"

    def test_small(self):
        assert format_address(255) == "0xFF"


class TestFormatBytes:
    def test_basic(self):
        assert format_bytes(b"\x48\x8b\x05") == "48 8B 05"

    def test_empty(self):
        assert format_bytes(b"") == ""

    def test_single(self):
        assert format_bytes(b"\x00") == "00"


class TestIsValidPointer:
    def test_valid_user_mode(self):
        assert is_valid_pointer(0x7FFC8E7D0000) is True

    def test_null(self):
        assert is_valid_pointer(0) is False

    def test_too_small(self):
        assert is_valid_pointer(0xFFFF) is False

    def test_kernel_mode(self):
        assert is_valid_pointer(0xFFFF800000000000) is False

    def test_boundary_low(self):
        assert is_valid_pointer(0x10000) is True

    def test_boundary_high(self):
        assert is_valid_pointer(0x7FFFFFFFFFFF) is True


# ============================================================================
# AOB Pattern parsing
# ============================================================================


class TestParseAOBPattern:
    def test_basic_with_wildcards(self):
        p = parse_aob_pattern("48 8B 05 ?? ?? ?? ??")
        assert p.length == 7
        assert p.pattern_bytes[:3] == bytes([0x48, 0x8B, 0x05])
        assert p.mask[:3] == bytes([0xFF, 0xFF, 0xFF])
        assert p.mask[3:] == bytes([0x00, 0x00, 0x00, 0x00])

    def test_no_spaces(self):
        p = parse_aob_pattern("488B05????????")
        assert p.length == 7
        assert p.pattern_bytes[:3] == bytes([0x48, 0x8B, 0x05])

    def test_single_question_wildcard(self):
        p = parse_aob_pattern("48 ? 05")
        assert p.length == 3
        assert p.mask[1] == 0x00

    def test_all_wildcards(self):
        p = parse_aob_pattern("?? ?? ??")
        assert p.length == 3
        assert all(m == 0x00 for m in p.mask)

    def test_all_literal(self):
        p = parse_aob_pattern("48 8B 05")
        assert p.length == 3
        assert all(m == 0xFF for m in p.mask)

    def test_invalid_byte_raises(self):
        with pytest.raises(ValueError):
            parse_aob_pattern("48 ZZ 05")

    def test_preserves_original(self):
        original = "48 8B 05 ?? ?? ?? ??"
        p = parse_aob_pattern(original)
        assert p.original == original


class TestMatchPattern:
    def test_exact_match(self):
        data = bytes([0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00])
        p = parse_aob_pattern("48 8B 05")
        matches = match_pattern(data, p)
        assert matches == [0]

    def test_wildcard_match(self):
        data = bytes([0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD])
        p = parse_aob_pattern("48 8B 05 ?? ?? ?? ??")
        matches = match_pattern(data, p)
        assert matches == [0]

    def test_no_match(self):
        data = bytes([0x00, 0x00, 0x00])
        p = parse_aob_pattern("48 8B 05")
        matches = match_pattern(data, p)
        assert matches == []

    def test_multiple_matches(self):
        data = bytes([0x48, 0x00, 0x48, 0x00, 0x48])
        p = parse_aob_pattern("48")
        matches = match_pattern(data, p)
        assert matches == [0, 2, 4]

    def test_offset_start(self):
        data = bytes([0x48, 0x8B])
        p = parse_aob_pattern("48 8B")
        matches = match_pattern(data, p, start=0x1000)
        assert matches == [0x1000]

    def test_empty_pattern(self):
        p = parse_aob_pattern("")
        # Empty pattern should match nothing or have length 0
        assert p.length == 0

    def test_pattern_longer_than_data(self):
        data = bytes([0x48])
        p = parse_aob_pattern("48 8B 05")
        matches = match_pattern(data, p)
        assert matches == []


class TestCreateSignaturePattern:
    def test_basic(self):
        result = create_signature_pattern(bytes([0x48, 0x8B, 0x05]))
        assert result == "48 8B 05"

    def test_with_masks(self):
        result = create_signature_pattern(bytes([0x48, 0x8B, 0x05, 0xAA]), [3])
        assert result == "48 8B 05 ??"

    def test_empty(self):
        result = create_signature_pattern(b"")
        assert result == ""
