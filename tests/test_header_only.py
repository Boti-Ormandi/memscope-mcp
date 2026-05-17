"""Tests for header-only mode in the netcap plugin (Phase 3).

All tests use mocks for HOOK_MANAGER. No process attachment required.
"""

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from memscope_mcp._contrib.plugins.netcap import NetcapPlugin

# ==================== Helpers ====================


def make_table(*args, **kwargs):
    """Mock Lua table factory: 1-indexed sequential args + kwargs."""
    result = {}
    for i, val in enumerate(args, 1):
        result[i] = val
    result.update(kwargs)
    return result


@dataclass
class MockContext:
    engine: Any = None
    session: Any = None
    lua: Any = None
    table_factory: Any = None
    log_error: Any = None


def make_plugin() -> NetcapPlugin:
    """Create a NetcapPlugin and register it with a mock context."""
    plugin = NetcapPlugin()
    ctx = MockContext(table_factory=make_table, log_error=lambda *a: None)
    plugin.register(ctx)
    return plugin


def make_entry(
    hook_id=1,
    hook_name="send",
    arg0=0x1A4,
    arg1=0,
    arg2=0,
    arg3=0,
    result=0,
    data=None,
    extra_args=None,
    sequence=1,
    timestamp=12345,
):
    """Build a ring buffer entry dict as returned by HOOK_MANAGER.read_ring_buffer()."""
    captured = len(data) if data else 0
    entry = {
        "sequence": sequence,
        "hook_id": hook_id,
        "timestamp": timestamp,
        "return_addr": "0x7FFE1234",
        "arg0": arg0,
        "arg1": arg1,
        "arg2": arg2,
        "arg3": arg3,
        "result": result,
        "data_length": captured,
        "captured_length": captured,
        "data": data,
        "is_marker": False,
        "hook_name": hook_name,
    }
    if extra_args:
        entry["extra_args"] = extra_args
    return entry


# ==================== Header-Only Size Inference ====================


class TestHeaderOnlySizeInference:
    """Tests for _infer_header_only_size logic."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_send_size_from_arg(self):
        """send has length_arg=3 (Lua-indexed) -> reads arg2 (0-indexed) for size."""
        # send spec: length_arg=3 -> arg_keys[3-1] = arg_keys[2] = "arg2"
        entry = make_entry(hook_name="send", arg2=1500)
        result = self.plugin._infer_header_only_size(entry, "send")
        assert result == 1500

    def test_recv_size_from_return(self):
        """recv has length_arg=0 (return value) -> reads result for size."""
        entry = make_entry(hook_name="recv", result=800)
        result = self.plugin._infer_header_only_size(entry, "recv")
        assert result == 800

    def test_recv_negative_result(self):
        """recv with result=-1 (error) -> returns max(0, -1) = 0."""
        entry = make_entry(hook_name="recv", result=-1)
        result = self.plugin._infer_header_only_size(entry, "recv")
        assert result == 0

    def test_wsa_size_from_deref(self):
        """WSASend has length_arg=-1, special case reads arg3 (dereferenced bytes transferred)."""
        entry = make_entry(hook_name="WSASend", arg3=2048)
        result = self.plugin._infer_header_only_size(entry, "WSASend")
        assert result == 2048

    def test_unknown_hook(self):
        """Unknown hook name (not in ALL_DATA_HOOKS) returns 0."""
        entry = make_entry(hook_name="connect")
        result = self.plugin._infer_header_only_size(entry, "connect")
        assert result == 0


# ==================== Header-Only Packets ====================


class TestHeaderOnlyPackets:
    """Tests for readPackets in header-only mode."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"send": 1, "recv": 2}
        self.plugin._header_only = True
        self.plugin._max_packet_size = 4096

    def test_packets_have_no_data(self, monkeypatch):
        """Header-only packets have no data, data_hex, or data_ascii keys."""
        entry = make_entry(
            hook_id=1,
            hook_name="send",
            arg0=0x1A4,
            arg2=100,
            result=100,
            data=None,
        )
        # Ensure data_length and captured_length reflect header-only mode
        entry["data_length"] = 0
        entry["captured_length"] = 0

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        p = packets[1]

        assert "data" not in p
        assert "data_hex" not in p
        assert "data_ascii" not in p

    def test_packets_have_inferred_size(self, monkeypatch):
        """Header-only packets infer size from args. send length_arg=3 -> arg2."""
        entry = make_entry(
            hook_id=1,
            hook_name="send",
            arg0=0x1A4,
            arg2=500,
            result=500,
            data=None,
        )
        entry["data_length"] = 0
        entry["captured_length"] = 0

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        p = packets[1]

        assert p["size"] == 500
