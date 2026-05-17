"""Tests for accept/bind connection tracking in the netcap plugin (Phase 3).

All tests use mocks for HOOK_MANAGER. No process attachment required.
"""

import struct
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from memscope_mcp._contrib.plugins.netcap import AF_INET, NetcapPlugin

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


# ==================== Accept Processing ====================


class TestAcceptProcessing:
    """Tests for accept hook connection tracking."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"accept": 1}
        self.plugin._header_only = False
        self.plugin._max_packet_size = 4096

    def test_accept_tracks_connection(self, monkeypatch):
        """Accept entry tracks new socket in _connections with type='server'."""
        sockaddr = make_sockaddr_in(54321, (10, 0, 0, 5))
        entry = make_entry(hook_id=1, hook_name="accept", arg0=0x100, result=0x2B8, data=sockaddr)

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        self.plugin._read_packets(100)

        assert 0x2B8 in self.plugin._connections
        conn = self.plugin._connections[0x2B8]
        assert conn["remote_ip"] == "10.0.0.5"
        assert conn["remote_port"] == 54321
        assert conn["type"] == "server"

    def test_accept_invalid_socket(self, monkeypatch):
        """Accept with INVALID_SOCKET (0xFFFFFFFF) adds no connection, emits no packet."""
        sockaddr = make_sockaddr_in(54321, (10, 0, 0, 5))
        # result as signed int32 = -1 -> & 0xFFFFFFFF = INVALID_SOCKET
        entry = make_entry(hook_id=1, hook_name="accept", arg0=0x100, result=0xFFFFFFFF, data=sockaddr)

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)

        assert len(self.plugin._connections) == 0
        # No packet emitted (INVALID_SOCKET triggers continue)
        assert 1 not in packets

    def test_accept_packet_uses_new_socket(self, monkeypatch):
        """Accept packet uses the new socket (result) not the listening socket (arg0)."""
        sockaddr = make_sockaddr_in(54321, (10, 0, 0, 5))
        entry = make_entry(hook_id=1, hook_name="accept", arg0=0x100, result=0x2B8, data=sockaddr)

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        p = packets[1]

        # Packet socket should be the new accepted socket, not the listening socket
        assert p["socket"] == 0x2B8
        assert p["socket"] != 0x100


# ==================== Bind Processing ====================


class TestBindProcessing:
    """Tests for bind hook connection tracking."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"bind": 2}
        self.plugin._header_only = False
        self.plugin._max_packet_size = 4096

    def test_bind_tracks_local(self, monkeypatch):
        """Bind entry tracks local address on the socket."""
        sockaddr = make_sockaddr_in(8080, (0, 0, 0, 0))
        entry = make_entry(hook_id=2, hook_name="bind", arg0=0x1A4, data=sockaddr)

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        self.plugin._read_packets(100)

        assert 0x1A4 in self.plugin._connections
        conn = self.plugin._connections[0x1A4]
        assert conn["local_ip"] == "0.0.0.0"
        assert conn["local_port"] == 8080

    def test_bind_adds_to_existing(self, monkeypatch):
        """Bind adds local fields to an existing connection entry (e.g., from connect)."""
        # Pre-populate connection from a prior connect
        self.plugin._connections[0x1A4] = {
            "remote_ip": "10.0.0.1",
            "remote_port": 443,
            "family": "IPv4",
            "type": "client",
        }

        sockaddr = make_sockaddr_in(12345, (192, 168, 1, 100))
        entry = make_entry(hook_id=2, hook_name="bind", arg0=0x1A4, data=sockaddr)

        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("memscope_mcp._contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        self.plugin._read_packets(100)

        conn = self.plugin._connections[0x1A4]
        # Existing remote fields preserved
        assert conn["remote_ip"] == "10.0.0.1"
        assert conn["remote_port"] == 443
        # New local fields added
        assert conn["local_ip"] == "192.168.1.100"
        assert conn["local_port"] == 12345


# ==================== getConnections Phase 3 ====================


class TestGetConnectionsPhase3:
    """Tests for getConnections with mixed connection types."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"send": 1}

    def test_mixed_connection_types(self):
        """getConnections returns type field for client, server, and UDP entries."""
        self.plugin._connections = {
            0x100: {"remote_ip": "10.0.0.1", "remote_port": 443, "family": "IPv4", "type": "client"},
            0x200: {"remote_ip": "10.0.0.5", "remote_port": 54321, "family": "IPv4", "type": "server"},
            0x300: {"ip": "8.8.8.8", "port": 53, "family": "IPv4", "type": "udp"},
        }

        result = self.plugin._get_connections()

        client = result["0x100"]
        assert client["type"] == "client"
        assert client["remote_ip"] == "10.0.0.1"

        server = result["0x200"]
        assert server["type"] == "server"
        assert server["remote_ip"] == "10.0.0.5"

        udp = result["0x300"]
        assert udp["type"] == "udp"
        # UDP connections stored via _extract_udp_peer use {ip, port} keys;
        # _get_connections normalizes them to remote_ip/remote_port
        assert udp["remote_ip"] == "8.8.8.8"
        assert udp["remote_port"] == 53
