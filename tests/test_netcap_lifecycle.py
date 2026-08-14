"""Tests for accept/bind connection tracking in the netcap plugin.

All tests use mocks for the injected hook manager. No process attachment required.
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
    hook_manager: Any = None


def make_plugin() -> NetcapPlugin:
    """Create a NetcapPlugin and register it with a mock context."""
    session = MagicMock()
    hook_manager = MagicMock()
    hook_manager.session = session
    plugin = NetcapPlugin()
    ctx = MockContext(
        session=session,
        table_factory=make_table,
        log_error=lambda *a: None,
        hook_manager=hook_manager,
    )
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
    """Build a ring buffer entry dict as returned by the injected hook manager.read_ring_buffer()."""
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

    def test_accept_tracks_connection(self):
        """Accept entry tracks new socket in _connections with type='server'."""
        sockaddr = make_sockaddr_in(54321, (10, 0, 0, 5))
        entry = make_entry(hook_id=1, hook_name="accept", arg0=0x100, result=0x2B8, data=sockaddr)

        mock_hm = self.plugin._hook_manager
        mock_hm.read_ring_buffer.return_value = [entry]

        self.plugin._read_packets(100)

        assert 0x2B8 in self.plugin._connections
        conn = self.plugin._connections[0x2B8]
        assert conn["remote_ip"] == "10.0.0.5"
        assert conn["remote_port"] == 54321
        assert conn["type"] == "server"

    def test_accept_invalid_socket(self):
        """Accept with INVALID_SOCKET (0xFFFFFFFF) adds no connection, emits no packet."""
        sockaddr = make_sockaddr_in(54321, (10, 0, 0, 5))
        # result as signed int32 = -1 -> & 0xFFFFFFFF = INVALID_SOCKET
        entry = make_entry(hook_id=1, hook_name="accept", arg0=0x100, result=0xFFFFFFFF, data=sockaddr)

        mock_hm = self.plugin._hook_manager
        mock_hm.read_ring_buffer.return_value = [entry]

        packets = self.plugin._read_packets(100)

        assert len(self.plugin._connections) == 0
        # No packet emitted (INVALID_SOCKET triggers continue)
        assert 1 not in packets

    def test_accept_packet_uses_new_socket(self):
        """Accept packet uses the new socket (result) not the listening socket (arg0)."""
        sockaddr = make_sockaddr_in(54321, (10, 0, 0, 5))
        entry = make_entry(hook_id=1, hook_name="accept", arg0=0x100, result=0x2B8, data=sockaddr)

        mock_hm = self.plugin._hook_manager
        mock_hm.read_ring_buffer.return_value = [entry]

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

    def test_bind_tracks_local(self):
        """Bind entry tracks local address on the socket."""
        sockaddr = make_sockaddr_in(8080, (0, 0, 0, 0))
        entry = make_entry(hook_id=2, hook_name="bind", arg0=0x1A4, data=sockaddr)

        mock_hm = self.plugin._hook_manager
        mock_hm.read_ring_buffer.return_value = [entry]

        self.plugin._read_packets(100)

        assert 0x1A4 in self.plugin._connections
        conn = self.plugin._connections[0x1A4]
        assert conn["local_ip"] == "0.0.0.0"
        assert conn["local_port"] == 8080

    def test_bind_adds_to_existing(self):
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

        mock_hm = self.plugin._hook_manager
        mock_hm.read_ring_buffer.return_value = [entry]

        self.plugin._read_packets(100)

        conn = self.plugin._connections[0x1A4]
        # Existing remote fields preserved
        assert conn["remote_ip"] == "10.0.0.1"
        assert conn["remote_port"] == 443
        # New local fields added
        assert conn["local_ip"] == "192.168.1.100"
        assert conn["local_port"] == 12345


# ==================== getConnections ====================


class TestGetConnections:
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


class TestDeadTargetLocalCleanup:
    def test_recording_only_state_is_cleared_without_remote_manager_calls(self):
        plugin = make_plugin()
        recording = MagicMock()
        plugin._recording_file = recording
        plugin._recording_path = "capture.jsonl"
        plugin._recording_count = 12
        plugin._hook_ids = {"send": 10}
        plugin._connections = {0x1A4: {"type": "tcp"}}
        plugin._pending_io = {0xDEAD: {"socket": 0x1A4}}
        plugin._streams = {0x1A4: {"send": bytearray(b"x")}}
        plugin._capture_active = False
        manager = plugin._hook_manager
        manager.reset_mock()

        plugin.on_process_detaching(plugin._session, process_alive=False)

        recording.close.assert_called_once_with()
        assert manager.remove_hook.call_count == 0
        assert manager.destroy_ring_buffer.call_count == 0
        assert plugin._recording_file is None
        assert plugin._hook_ids == {}
        assert plugin._connections == {}
        assert plugin._pending_io == {}
        assert plugin._streams == {}
        assert plugin._capture_active is False
