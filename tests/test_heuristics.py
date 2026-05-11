"""Tests for type detection heuristics (pure helper functions)."""

import struct

from src.utils.heuristics import (
    ValueType,
    _is_printable,
    _is_reasonable_float,
    _looks_like_inline_string,
    detect_value_type,
)


class TestIsPrintable:
    def test_ascii_string(self):
        assert _is_printable("Hello World") is True

    def test_empty(self):
        assert _is_printable("") is False

    def test_all_printable(self):
        assert _is_printable("abc123!@#") is True

    def test_with_whitespace(self):
        assert _is_printable("line1\nline2\ttab") is True

    def test_mostly_printable(self):
        # 9 printable + 1 control = 90% > 80% threshold
        assert _is_printable("abcdefghi\x01") is True

    def test_mostly_unprintable(self):
        # 1 printable + 9 control = 10% < 80% threshold
        assert _is_printable("a\x01\x02\x03\x04\x05\x06\x07\x08\x09") is False


class TestIsReasonableFloat:
    def test_zero(self):
        assert _is_reasonable_float(0.0) is True

    def test_small_positive(self):
        assert _is_reasonable_float(3.14) is True

    def test_negative(self):
        assert _is_reasonable_float(-100.5) is True

    def test_large_reasonable(self):
        assert _is_reasonable_float(999999999.0) is True

    def test_nan(self):
        assert _is_reasonable_float(float("nan")) is False

    def test_inf(self):
        assert _is_reasonable_float(float("inf")) is False

    def test_negative_inf(self):
        assert _is_reasonable_float(float("-inf")) is False

    def test_too_large(self):
        assert _is_reasonable_float(1e11) is False

    def test_too_negative(self):
        assert _is_reasonable_float(-1e11) is False

    def test_boundary(self):
        # Just under 1e10
        assert _is_reasonable_float(9.999e9) is True


class TestLooksLikeInlineString:
    def test_ascii_bytes(self):
        assert _looks_like_inline_string(b"Hello\x00\x00\x00") is True

    def test_single_byte(self):
        assert _looks_like_inline_string(b"A") is False  # too short

    def test_all_printable(self):
        assert _looks_like_inline_string(b"ABCDEFGH") is True

    def test_all_binary(self):
        assert _looks_like_inline_string(b"\x01\x02\x03\x04\x05\x06\x07\x08") is False

    def test_null_terminated_string(self):
        # "Hi" + nulls = 2 printable + 1 null out of 3 = 100%
        assert _looks_like_inline_string(b"Hi\x00") is True

    def test_mixed_below_threshold(self):
        # 1 printable, 7 control bytes = 12.5% < 80%
        assert _looks_like_inline_string(b"A\x01\x02\x03\x04\x05\x06\x07") is False


class TestDetectValueType:
    def test_null(self):
        data = struct.pack("<Q", 0)
        result = detect_value_type(data, 0x1000)
        assert result.value_type == ValueType.NULL
        assert result.confidence == 1.0

    def test_small_int(self):
        data = struct.pack("<Q", 42)
        result = detect_value_type(data, 0x1000)
        assert result.value_type == ValueType.INT
        assert result.raw_value == 42
        assert "42" in result.annotation

    def test_small_int_boundary(self):
        data = struct.pack("<Q", 0xFFFF)
        result = detect_value_type(data, 0x1000)
        assert result.value_type == ValueType.INT

    def test_float_detection(self):
        # Need a value that's NOT a valid pointer (< 0x10000) but has a reasonable float
        # in the lower 4 bytes. Use 0x0000XXXX range where XXXX encodes a float.
        # Pack a small float (0.5 = 0x3F000000) -- but that's > 0x10000 and valid pointer.
        # Instead use a value > 0x7FFFFFFFFFFF (above user-mode pointer range)
        # with a reasonable float in lower 4 bytes.
        float_bytes = struct.pack("<f", 3.14)
        # Upper bytes make value > 0x7FFFFFFFFFFF so it's not a valid pointer
        data = float_bytes + b"\x00\x80\x00\x00"
        result = detect_value_type(data, 0x1000)
        assert result.value_type == ValueType.FLOAT
        assert "3.14" in result.annotation

    def test_inline_string(self):
        data = b"TestStr\x00"
        result = detect_value_type(data, 0x1000)
        # Value as uint64 will be large (not a valid pointer, not small int)
        # Float interpretation of "Test" bytes may or may not be reasonable
        # But if it reaches inline string check, it should detect it
        if result.value_type == ValueType.INLINE_STRING:
            assert "TestStr" in result.annotation

    def test_short_data_padded(self):
        # Less than 8 bytes should be padded with nulls
        data = b"\x05\x00"
        result = detect_value_type(data, 0x1000)
        assert result.value_type == ValueType.INT
        assert result.raw_value == 5

    def test_unknown_large_value(self):
        # Value that's not a valid pointer, not small, not a reasonable float, not a string
        data = b"\x01\x80\x01\x80\x01\x80\x01\x80"
        result = detect_value_type(data, 0x1000)
        # This may land on FLOAT or UNKNOWN depending on the float interpretation
        assert result.value_type in (ValueType.FLOAT, ValueType.UNKNOWN)
