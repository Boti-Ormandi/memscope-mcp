"""Regression tests for Lua readPointerChain semantics."""

from memscope_mcp.extensions.core.module_scan import ModuleScanExtension
from memscope_mcp.utils import memory_utils


class _FakeSession:
    def __init__(self, ptr_map, module_bases=None):
        self._ptr_map = ptr_map
        self._module_bases = {} if module_bases is None else module_bases

    def get_module_base(self, name: str) -> int | None:
        return self._module_bases.get(name)

    def read_ptr(self, address: int) -> int:
        return self._ptr_map[address]


class _UnexpectedModuleLookupSession:
    def get_module_base(self, name: str) -> int | None:
        raise AssertionError(f"global session unexpectedly consulted for {name}")


def test_get_address_uses_extension_session(monkeypatch):
    ext = ModuleScanExtension()
    ext._session = _FakeSession({}, {"game.dll": 0x100000})
    monkeypatch.setattr(memory_utils, "SESSION", _UnexpectedModuleLookupSession())

    assert ext._get_address("game.dll+0x40") == 0x100040


def test_read_pointer_chain_string_module_base_uses_extension_session(monkeypatch):
    ext = ModuleScanExtension()
    ext._session = _FakeSession({0x100010: 0x200000}, {"game.dll": 0x100000})
    monkeypatch.setattr(memory_utils, "SESSION", _UnexpectedModuleLookupSession())

    assert ext._read_pointer_chain("game.dll", 0x10) == 0x200000


def test_read_pointer_chain_adds_offset_before_deref():
    ext = ModuleScanExtension()
    ext._session = _FakeSession(
        {
            0x100010: 0x200000,
            0x200020: 0x300000,
        }
    )

    # Standard CE-style chain: [[base+0x10]+0x20]
    result = ext._read_pointer_chain(0x100000, 0x10, 0x20)

    assert result == 0x300000


def test_read_pointer_chain_accepts_hex_string_inputs():
    ext = ModuleScanExtension()
    ext._session = _FakeSession(
        {
            0x100010: 0x200000,
            0x200020: 0x300000,
        }
    )

    result = ext._read_pointer_chain("0x100000", "0x10", "0x20")

    assert result == 0x300000


def test_read_pointer_chain_returns_none_for_invalid_pointer():
    ext = ModuleScanExtension()
    ext._session = _FakeSession({0x100010: 0x10})

    result = ext._read_pointer_chain(0x100000, 0x10)

    assert result is None
