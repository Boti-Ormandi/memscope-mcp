"""Regression tests for Lua readPointerChain semantics."""

from memscope_mcp.extensions.core.module_scan import ModuleScanExtension


class _FakeSession:
    def __init__(self, ptr_map):
        self._ptr_map = ptr_map

    def read_ptr(self, address: int) -> int:
        return self._ptr_map[address]


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
