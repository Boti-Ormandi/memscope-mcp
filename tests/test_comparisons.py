"""Tests for 64-bit safe comparison functions."""

from src.tools.lua.comparisons import (
    parse_hex_address,
    safe_eq,
    safe_ge,
    safe_gt,
    safe_int,
    safe_le,
    safe_lt,
    safe_ne,
    to_lua_int64,
)


class TestToLuaInt64:
    def test_small_positive(self):
        assert to_lua_int64(42) == 42

    def test_zero(self):
        assert to_lua_int64(0) == 0

    def test_max_signed(self):
        assert to_lua_int64(0x7FFFFFFFFFFFFFFF) == 0x7FFFFFFFFFFFFFFF

    def test_above_signed_wraps_negative(self):
        # 0x8000000000000000 should wrap to -2^63
        assert to_lua_int64(0x8000000000000000) == -0x8000000000000000

    def test_max_unsigned_wraps_to_minus_one(self):
        assert to_lua_int64(0xFFFFFFFFFFFFFFFF) == -1

    def test_none_returns_none(self):
        assert to_lua_int64(None) is None

    def test_string_coercion(self):
        assert to_lua_int64("100") == 100

    def test_preserves_bit_pattern(self):
        # Round-trip: unsigned -> signed -> back to unsigned
        original = 0xDEADBEEFCAFEBABE
        signed = to_lua_int64(original)
        assert signed < 0  # should be negative
        assert signed & 0xFFFFFFFFFFFFFFFF == original


class TestParseHexAddress:
    def test_with_prefix(self):
        result = parse_hex_address("0x1F58E12ECF0")
        # Should be valid signed int64
        assert result is not None
        assert result & 0xFFFFFFFFFFFFFFFF == 0x1F58E12ECF0

    def test_without_prefix(self):
        result = parse_hex_address("1F58E12ECF0")
        assert result is not None
        assert result & 0xFFFFFFFFFFFFFFFF == 0x1F58E12ECF0

    def test_small_value(self):
        assert parse_hex_address("0xFF") == 0xFF

    def test_empty_returns_none(self):
        assert parse_hex_address("") is None

    def test_invalid_returns_none(self):
        assert parse_hex_address("not_hex") is None

    def test_none_input_returns_none(self):
        assert parse_hex_address(None) is None

    def test_whitespace_stripped(self):
        result = parse_hex_address("  0xABC  ")
        assert result == 0xABC

    def test_large_address_wraps(self):
        result = parse_hex_address("0xFFFFFFFFFFFFFFFF")
        assert result == -1  # wraps via to_lua_int64


class TestSafeEq:
    def test_equal_ints(self):
        assert safe_eq(42, 42) is True

    def test_unequal_ints(self):
        assert safe_eq(1, 2) is False

    def test_both_none(self):
        assert safe_eq(None, None) is True

    def test_one_none(self):
        assert safe_eq(None, 42) is False
        assert safe_eq(42, None) is False

    def test_large_equal(self):
        assert safe_eq(0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF) is True

    def test_string_int_coercion(self):
        assert safe_eq("42", 42) is True


class TestSafeNe:
    def test_unequal(self):
        assert safe_ne(1, 2) is True

    def test_equal(self):
        assert safe_ne(42, 42) is False

    def test_both_none(self):
        assert safe_ne(None, None) is False


class TestSafeLt:
    def test_less(self):
        assert safe_lt(1, 2) is True

    def test_equal(self):
        assert safe_lt(2, 2) is False

    def test_greater(self):
        assert safe_lt(3, 2) is False

    def test_none_left(self):
        assert safe_lt(None, 2) is False

    def test_none_right(self):
        assert safe_lt(2, None) is False


class TestSafeGt:
    def test_greater(self):
        assert safe_gt(3, 2) is True

    def test_equal(self):
        assert safe_gt(2, 2) is False

    def test_less(self):
        assert safe_gt(1, 2) is False

    def test_none(self):
        assert safe_gt(None, 2) is False


class TestSafeLe:
    def test_less(self):
        assert safe_le(1, 2) is True

    def test_equal(self):
        assert safe_le(2, 2) is True

    def test_greater(self):
        assert safe_le(3, 2) is False

    def test_both_none(self):
        assert safe_le(None, None) is True

    def test_one_none(self):
        assert safe_le(None, 2) is False


class TestSafeGe:
    def test_greater(self):
        assert safe_ge(3, 2) is True

    def test_equal(self):
        assert safe_ge(2, 2) is True

    def test_less(self):
        assert safe_ge(1, 2) is False

    def test_both_none(self):
        assert safe_ge(None, None) is True

    def test_one_none(self):
        assert safe_ge(2, None) is False


class TestSafeInt:
    def test_valid(self):
        assert safe_int(42) == 42

    def test_zero(self):
        assert safe_int(0) == 0

    def test_negative_returns_none(self):
        assert safe_int(-1) is None

    def test_over_max_returns_none(self):
        assert safe_int(0x80000000) is None

    def test_at_max(self):
        assert safe_int(0x7FFFFFFF) == 0x7FFFFFFF

    def test_custom_max(self):
        assert safe_int(100, max_val=50) is None
        assert safe_int(50, max_val=50) == 50

    def test_none_returns_none(self):
        assert safe_int(None) is None

    def test_string_coercion(self):
        assert safe_int("42") == 42

    def test_invalid_string_returns_none(self):
        assert safe_int("abc") is None
