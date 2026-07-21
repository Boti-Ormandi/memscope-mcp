"""Unit tests for utility functions (no live process needed)."""

from memscope_mcp.utils.memory_utils import format_address, format_bytes, is_valid_pointer, parse_offset

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
