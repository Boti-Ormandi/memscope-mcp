"""Tests for sendto/recvfrom UDP processing in the netcap plugin (Phase 3).

All tests use mocks for HOOK_MANAGER and SESSION. No process attachment required.
"""

import struct
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from contrib.plugins.netcap import AF_INET, NetcapPlugin

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


def make_sockaddr_in(port: int, ip_bytes: tuple[int, ...]) -> bytes:
    """Build a sockaddr_in structure (16 bytes)."""
    buf = bytearray(16)
    struct.pack_into("<H", buf, 0, AF_INET)
    struct.pack_into(">H", buf, 2, port)  # network byte order
    buf[4:8] = bytes(ip_bytes)
    return bytes(buf)


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


# ==================== Sendto Processing ====================


class TestSendtoProcessing:
    """Tests for sendto hook UDP processing."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"sendto": 1, "recvfrom": 2}
        self.plugin._header_only = False
        self.plugin._max_packet_size = 4096

    def test_sendto_packet(self, monkeypatch):
        """Sendto entry emits send packet and tracks UDP connection with peer address."""
        sockaddr = make_sockaddr_in(53, (8, 8, 8, 8))
        entry = make_entry(
            hook_id=1,
            hook_name="sendto",
            arg0=0x1A4,
            data=b"hello",
            result=5,
            extra_args={"arg4": 0x5000, "arg5": 16},
        )

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]

        mock_session = MagicMock()
        mock_session.read_bytes.return_value = sockaddr

        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION", mock_session)

        packets = self.plugin._read_packets(100)
        p = packets[1]

        assert p["direction"] == "send"
        assert p["socket"] == 0x1A4
        assert p["result"] == 5

        # Connection tracked as UDP
        assert 0x1A4 in self.plugin._connections
        conn = self.plugin._connections[0x1A4]
        assert conn["type"] == "udp"
        assert conn["ip"] == "8.8.8.8"
        assert conn["port"] == 53


# ==================== Recvfrom Processing ====================


class TestRecvfromProcessing:
    """Tests for recvfrom hook UDP processing."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"sendto": 1, "recvfrom": 2}
        self.plugin._header_only = False
        self.plugin._max_packet_size = 4096

    def test_recvfrom_packet(self, monkeypatch):
        """Recvfrom entry emits recv packet with peer address from sockaddr."""
        sockaddr = make_sockaddr_in(53, (8, 8, 4, 4))
        entry = make_entry(
            hook_id=2,
            hook_name="recvfrom",
            arg0=0x1A4,
            data=b"response",
            result=8,
            extra_args={"arg4": 0x6000, "arg5": 16},
        )

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]

        mock_session = MagicMock()
        mock_session.read_bytes.return_value = sockaddr

        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION", mock_session)

        packets = self.plugin._read_packets(100)
        p = packets[1]

        assert p["direction"] == "recv"
        assert p["result"] == 8

        # Connection tracked
        assert 0x1A4 in self.plugin._connections
        conn = self.plugin._connections[0x1A4]
        assert conn["type"] == "udp"


# ==================== UDP Sockaddr Failure ====================


class TestUdpSockaddrFailure:
    """Tests for UDP processing when sockaddr read fails."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"sendto": 1}
        self.plugin._header_only = False
        self.plugin._max_packet_size = 4096

    def test_sockaddr_read_fails(self, monkeypatch):
        """Packet still emitted when SESSION.read_bytes raises for sockaddr pointer."""
        entry = make_entry(
            hook_id=1,
            hook_name="sendto",
            arg0=0x1A4,
            data=b"hello",
            result=5,
            extra_args={"arg4": 0x5000, "arg5": 16},
        )

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]

        mock_session = MagicMock()
        mock_session.read_bytes.side_effect = Exception("memory read failed")

        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION", mock_session)

        packets = self.plugin._read_packets(100)

        # Packet is still emitted despite sockaddr read failure
        p = packets[1]
        assert p["direction"] == "send"
        assert p["socket"] == 0x1A4

        # No connection tracked since sockaddr read failed
        assert 0x1A4 not in self.plugin._connections
