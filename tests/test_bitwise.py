"""Tests for bitwise utility functions (Python-level, not via Lua)."""

from src.tools.lua.utilities import (
    bit_and,
    bit_extract,
    bit_lshift,
    bit_not,
    bit_or,
    bit_rshift,
    bit_xor,
)


class TestBitAnd:
    def test_basic(self):
        assert bit_and(0xFF, 0x0F) == 0x0F

    def test_zero(self):
        assert bit_and(0xFF, 0) == 0

    def test_identity(self):
        assert bit_and(0xAB, 0xFF) == 0xAB

    def test_large_values(self):
        assert bit_and(0xFFFFFFFF, 0x0000FFFF) == 0x0000FFFF


class TestBitOr:
    def test_basic(self):
        assert bit_or(0xF0, 0x0F) == 0xFF

    def test_zero(self):
        assert bit_or(0xAB, 0) == 0xAB

    def test_overlap(self):
        assert bit_or(0xFF, 0xFF) == 0xFF


class TestBitXor:
    def test_basic(self):
        assert bit_xor(0xFF, 0x0F) == 0xF0

    def test_self_cancels(self):
        assert bit_xor(0xAB, 0xAB) == 0

    def test_with_zero(self):
        assert bit_xor(0xAB, 0) == 0xAB


class TestBitNot:
    def test_zero(self):
        assert bit_not(0) == 0xFFFFFFFF

    def test_all_ones(self):
        assert bit_not(0xFFFFFFFF) == 0

    def test_byte_mask(self):
        assert bit_not(0xFF) == 0xFFFFFF00

    def test_32bit_mask(self):
        # Should always return 32-bit result
        result = bit_not(1)
        assert result <= 0xFFFFFFFF


class TestBitLshift:
    def test_basic(self):
        assert bit_lshift(1, 0) == 1

    def test_shift_by_one(self):
        assert bit_lshift(1, 1) == 2

    def test_shift_by_eight(self):
        assert bit_lshift(1, 8) == 256

    def test_shift_by_31(self):
        assert bit_lshift(1, 31) == 0x80000000

    def test_zero_shift(self):
        assert bit_lshift(0, 10) == 0


class TestBitRshift:
    def test_basic(self):
        assert bit_rshift(256, 4) == 16

    def test_shift_by_zero(self):
        assert bit_rshift(0xFF, 0) == 0xFF

    def test_unsigned_behavior(self):
        # Unsigned right shift: high bit should not sign-extend
        # 0xFFFFFFFFFFFFFFFF >> 32 should give 0xFFFFFFFF (not negative)
        result = bit_rshift(0xFFFFFFFFFFFFFFFF, 32)
        assert result == 0xFFFFFFFF
        assert result > 0

    def test_shift_to_zero(self):
        assert bit_rshift(1, 64) == 0


class TestBitExtract:
    def test_single_bit_zero(self):
        assert bit_extract(0b1010, 0) == 0

    def test_single_bit_one(self):
        assert bit_extract(0b1010, 1) == 1

    def test_single_bit_high(self):
        assert bit_extract(0b1010, 3) == 1

    def test_multi_bit_field(self):
        # Extract bits 4-7 from 0xAB = 0b10101011
        assert bit_extract(0xAB, 4, 4) == 0xA

    def test_full_byte(self):
        assert bit_extract(0xABCD, 8, 8) == 0xAB

    def test_width_one_default(self):
        assert bit_extract(0b100, 2) == 1

    def test_zero_value(self):
        assert bit_extract(0, 0, 8) == 0
