"""Tests for address parsing (non-module cases)."""

import pytest

from memscope_mcp.utils.memory_utils import parse_address


class TestParseAddressInt:
    def test_int_passthrough(self):
        assert parse_address(42) == 42

    def test_zero(self):
        assert parse_address(0) == 0

    def test_large_int(self):
        assert parse_address(0x7FFC8E7D0000) == 0x7FFC8E7D0000


class TestParseAddressHex:
    def test_hex_lowercase(self):
        assert parse_address("0x1000") == 0x1000

    def test_hex_uppercase(self):
        assert parse_address("0X1000") == 0x1000

    def test_hex_mixed_case(self):
        assert parse_address("0xDeAdBeEf") == 0xDEADBEEF

    def test_hex_large(self):
        assert parse_address("0x7FFC8E7D0000") == 0x7FFC8E7D0000

    def test_hex_leading_zeros(self):
        assert parse_address("0x00001000") == 0x1000


class TestParseAddressDecimal:
    def test_decimal(self):
        assert parse_address("4096") == 4096

    def test_decimal_zero(self):
        assert parse_address("0") == 0


class TestParseAddressWithOffset:
    def test_hex_plus_hex_offset(self):
        assert parse_address("0x1000+0x100") == 0x1100

    def test_hex_plus_decimal_offset(self):
        assert parse_address("0x1000+256") == 0x1100

    def test_whitespace(self):
        assert parse_address("  0x1000 + 0x100  ") == 0x1100

    def test_large_base_plus_offset(self):
        assert parse_address("0x180000000+0x1A208D8") == 0x180000000 + 0x1A208D8


class TestParseAddressModuleOffset:
    def test_module_not_attached_raises(self):
        # With no process attached, module lookup should fail
        with pytest.raises(ValueError, match="Module not found"):
            parse_address("missing.dll+0x1000")


class TestParseAddressErrors:
    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            parse_address("0xZZZZ")

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            parse_address("not_a_number")
