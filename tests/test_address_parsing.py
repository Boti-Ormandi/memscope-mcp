"""Tests for address parsing (non-module cases)."""

import pytest

from memscope_mcp.utils import memory_utils
from memscope_mcp.utils.memory_utils import parse_address


class _ModuleLookupSession:
    def __init__(self, module_name: str, base: int):
        self._module_name = module_name
        self._base = base

    def get_module_base(self, name: str) -> int | None:
        return self._base if name == self._module_name else None


class _UnexpectedModuleLookupSession:
    def get_module_base(self, name: str) -> int | None:
        raise AssertionError(f"global session unexpectedly consulted for {name}")


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

    def test_explicit_session_wins_for_module_expression(self, monkeypatch):
        injected = _ModuleLookupSession("custom.dll", 0x500000)
        monkeypatch.setattr(memory_utils, "SESSION", _UnexpectedModuleLookupSession())

        assert parse_address("custom.dll+0x20", session=injected) == 0x500020

    def test_no_session_uses_global_compatibility_fallback(self, monkeypatch):
        fallback = _ModuleLookupSession("legacy.dll", 0x600000)
        monkeypatch.setattr(memory_utils, "SESSION", fallback)

        assert parse_address("legacy.dll+0x20") == 0x600020


class TestParseAddressErrors:
    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            parse_address("0xZZZZ")

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            parse_address("not_a_number")
