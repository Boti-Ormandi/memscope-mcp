"""Tests for the network capture plugin (contrib/plugins/netcap.py).

All tests use mocks for HOOK_MANAGER and resolve_export.
No process attachment required.
"""

import struct
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from contrib.plugins.netcap import AF_INET, AF_INET6, NetcapPlugin
from memscope_mcp.tools.hooking import RingBufferConfig

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


def make_sockaddr_in6(port: int, addr_bytes: bytes) -> bytes:
    """Build a sockaddr_in6 structure (28 bytes)."""
    buf = bytearray(28)
    struct.pack_into("<H", buf, 0, AF_INET6)
    struct.pack_into(">H", buf, 2, port)
    # flow info at 4-8 (zero)
    buf[8:24] = addr_bytes[:16]
    return bytes(buf)


def _make_rb_config(address: int = 0x1000, entry_count: int = 128, max_data_size: int = 4096) -> RingBufferConfig:
    """Create a RingBufferConfig for tests."""
    entry_total_size = 0x50 + max_data_size
    total_size = 0x100 + entry_count * entry_total_size
    return RingBufferConfig(
        address=address,
        entry_count=entry_count,
        max_data_size=max_data_size,
        entry_total_size=entry_total_size,
        total_size=total_size,
    )


def make_ring_buffer_entry(
    hook_id: int = 1,
    hook_name: str = "send",
    arg0: int = 0x1A4,
    data: bytes | None = b"hello",
    result: int = 5,
    is_marker: bool = False,
    sequence: int = 1,
    timestamp: int = 12345,
) -> dict:
    """Build a ring buffer entry dict as returned by HOOK_MANAGER.read_ring_buffer()."""
    captured = len(data) if data else 0
    return {
        "sequence": sequence,
        "hook_id": hook_id,
        "timestamp": timestamp,
        "return_addr": "0x7FFE1234",
        "arg0": arg0,
        "arg1": 0,
        "arg2": 0,
        "arg3": 0,
        "result": result,
        "data_length": captured,
        "captured_length": captured,
        "data": data,
        "is_marker": is_marker,
        "hook_name": hook_name,
    }


# ==================== sockaddr parsing ====================


class TestParseSockaddr:
    """Pure unit tests for _parse_sockaddr."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_ipv4_basic(self):
        """Parse valid IPv4 sockaddr_in -> correct IP, port, family."""
        data = make_sockaddr_in(443, (140, 82, 112, 22))
        result = self.plugin._parse_sockaddr(data)
        assert result is not None
        assert result["ip"] == "140.82.112.22"
        assert result["port"] == 443
        assert result["family"] == "IPv4"

    def test_ipv4_port_byte_order(self):
        """Port 443 = bytes 0x01 0xBB in network byte order."""
        data = make_sockaddr_in(443, (10, 0, 0, 1))
        # Verify the raw bytes have network byte order
        assert data[2] == 0x01
        assert data[3] == 0xBB
        result = self.plugin._parse_sockaddr(data)
        assert result["port"] == 443

    def test_ipv4_port_80(self):
        """Port 80 parses correctly."""
        data = make_sockaddr_in(80, (192, 168, 1, 1))
        result = self.plugin._parse_sockaddr(data)
        assert result["port"] == 80
        assert result["ip"] == "192.168.1.1"

    def test_ipv6_basic(self):
        """Parse valid IPv6 sockaddr_in6 -> correct IP, port, family."""
        # ::1 (loopback)
        addr_bytes = b"\x00" * 15 + b"\x01"
        data = make_sockaddr_in6(8080, addr_bytes)
        result = self.plugin._parse_sockaddr(data)
        assert result is not None
        assert result["ip"] == "::1"
        assert result["port"] == 8080
        assert result["family"] == "IPv6"

    def test_ipv6_full_address(self):
        """Parse a non-trivial IPv6 address."""
        # 2001:0db8::1
        addr_bytes = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x01])
        data = make_sockaddr_in6(443, addr_bytes)
        result = self.plugin._parse_sockaddr(data)
        assert result is not None
        assert result["family"] == "IPv6"
        assert result["port"] == 443
        # The compressed form should not have leading zeros in groups
        assert "2001:db8:" in result["ip"]

    def test_too_short_data(self):
        """Data shorter than 4 bytes returns None."""
        assert self.plugin._parse_sockaddr(b"\x02\x00") is None
        assert self.plugin._parse_sockaddr(b"\x02") is None
        assert self.plugin._parse_sockaddr(b"") is None

    def test_unknown_family(self):
        """Unknown address family returns None."""
        data = bytearray(16)
        struct.pack_into("<H", data, 0, 99)  # family = 99
        assert self.plugin._parse_sockaddr(bytes(data)) is None

    def test_ipv4_too_short_for_full_struct(self):
        """AF_INET but only 8 bytes (need 16) returns None."""
        data = bytearray(8)
        struct.pack_into("<H", data, 0, AF_INET)
        struct.pack_into(">H", data, 2, 80)
        assert self.plugin._parse_sockaddr(bytes(data)) is None

    def test_ipv6_too_short_for_full_struct(self):
        """AF_INET6 but only 16 bytes (need 28) returns None."""
        data = bytearray(16)
        struct.pack_into("<H", data, 0, AF_INET6)
        assert self.plugin._parse_sockaddr(bytes(data)) is None


# ==================== Buffer Unpack Helpers ====================


class TestUnpackHelpers:
    """Pure unit tests for buffer unpack functions."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_unpack_uint16(self):
        """unpackUInt16({1: 0x34, 2: 0x12}, 1) -> 0x1234."""
        data = {1: 0x34, 2: 0x12}
        assert self.plugin._unpack_uint16(data, 1) == 0x1234

    def test_unpack_uint16_default_offset(self):
        """Default offset is 1."""
        data = {1: 0x34, 2: 0x12}
        assert self.plugin._unpack_uint16(data) == 0x1234

    def test_unpack_int16_positive(self):
        """Positive int16 value."""
        data = {1: 0x01, 2: 0x00}
        assert self.plugin._unpack_int16(data, 1) == 1

    def test_unpack_int16_negative(self):
        """unpackInt16({1: 0xFF, 2: 0xFF}, 1) -> -1."""
        data = {1: 0xFF, 2: 0xFF}
        assert self.plugin._unpack_int16(data, 1) == -1

    def test_unpack_int16_min(self):
        """Int16 minimum value: -32768."""
        data = {1: 0x00, 2: 0x80}
        assert self.plugin._unpack_int16(data, 1) == -32768

    def test_unpack_uint32(self):
        """unpackUInt32 with known bytes."""
        data = {1: 0x78, 2: 0x56, 3: 0x34, 4: 0x12}
        assert self.plugin._unpack_uint32(data, 1) == 0x12345678

    def test_unpack_int32_negative(self):
        """Signed int32 = -1."""
        data = {1: 0xFF, 2: 0xFF, 3: 0xFF, 4: 0xFF}
        assert self.plugin._unpack_int32(data, 1) == -1

    def test_unpack_uint64(self):
        """unpackUInt64 with known bytes."""
        data = {}
        for i, b in enumerate(struct.pack("<Q", 0x123456789ABCDEF0), 1):
            data[i] = b
        assert self.plugin._unpack_uint64(data, 1) == 0x123456789ABCDEF0

    def test_unpack_float_one(self):
        """unpackFloat with IEEE 754 bytes for 1.0."""
        data = {1: 0x00, 2: 0x00, 3: 0x80, 4: 0x3F}
        result = self.plugin._unpack_float(data, 1)
        assert abs(result - 1.0) < 1e-6

    def test_unpack_float_negative(self):
        """unpackFloat for -2.5."""
        raw = struct.pack("<f", -2.5)
        data = {i + 1: b for i, b in enumerate(raw)}
        result = self.plugin._unpack_float(data, 1)
        assert abs(result - (-2.5)) < 1e-6

    def test_unpack_double(self):
        """unpackDouble with known bytes."""
        raw = struct.pack("<d", 3.14159)
        data = {i + 1: b for i, b in enumerate(raw)}
        result = self.plugin._unpack_double(data, 1)
        assert abs(result - 3.14159) < 1e-10

    def test_unpack_string_null_terminated(self):
        """unpackString stops at null terminator."""
        data = {1: ord("H"), 2: ord("i"), 3: 0, 4: ord("X")}
        assert self.plugin._unpack_string(data, 1) == "Hi"

    def test_unpack_string_maxlen(self):
        """unpackString respects maxlen."""
        data = {1: ord("A"), 2: ord("B"), 3: ord("C"), 4: ord("D")}
        assert self.plugin._unpack_string(data, 1, maxlen=2) == "AB"

    def test_unpack_string_no_null(self):
        """unpackString reads up to maxlen when no null found."""
        data = {1: ord("X"), 2: ord("Y"), 3: ord("Z")}
        result = self.plugin._unpack_string(data, 1, maxlen=3)
        assert result == "XYZ"

    def test_unpack_bytes(self):
        """unpackBytes returns a table-like dict of a sub-slice."""
        data = {1: 0xAA, 2: 0xBB, 3: 0xCC, 4: 0xDD}
        result = self.plugin._unpack_bytes(data, 2, 2)
        assert result[1] == 0xBB
        assert result[2] == 0xCC

    def test_unpack_vector3(self):
        """unpackVector3 returns {x, y, z} from 3 floats."""
        raw = struct.pack("<fff", 1.0, 2.0, 3.0)
        data = {i + 1: b for i, b in enumerate(raw)}
        result = self.plugin._unpack_vector3(data, 1)
        assert abs(result["x"] - 1.0) < 1e-6
        assert abs(result["y"] - 2.0) < 1e-6
        assert abs(result["z"] - 3.0) < 1e-6

    def test_unpack_at_offset(self):
        """unpackUInt16 at non-default offset."""
        data = {1: 0x00, 2: 0x00, 3: 0x34, 4: 0x12}
        assert self.plugin._unpack_uint16(data, 3) == 0x1234


# ==================== Buffer Pack Helpers ====================


class TestPackHelpers:
    """Pure unit tests for buffer pack functions."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_pack_uint16(self):
        """packUInt16(0x1234) -> table with (0x34, 0x12)."""
        result = self.plugin._pack_uint16(0x1234)
        assert result[1] == 0x34
        assert result[2] == 0x12

    def test_pack_uint32(self):
        """packUInt32 produces correct bytes."""
        result = self.plugin._pack_uint32(0x12345678)
        assert result[1] == 0x78
        assert result[2] == 0x56
        assert result[3] == 0x34
        assert result[4] == 0x12

    def test_pack_int32_negative(self):
        """packInt32(-1) == packUInt32(0xFFFFFFFF)."""
        result = self.plugin._pack_int32(-1)
        for i in range(1, 5):
            assert result[i] == 0xFF

    def test_pack_uint64(self):
        """packUInt64 produces 8 correct bytes."""
        result = self.plugin._pack_uint64(0x0102030405060708)
        expected = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        for i, exp in enumerate(expected, 1):
            assert result[i] == exp

    def test_pack_float_one(self):
        """packFloat(1.0) -> (0x00, 0x00, 0x80, 0x3F)."""
        result = self.plugin._pack_float(1.0)
        assert result[1] == 0x00
        assert result[2] == 0x00
        assert result[3] == 0x80
        assert result[4] == 0x3F

    def test_pack_float_negative(self):
        """packFloat(-2.5) matches struct.pack."""
        raw = struct.pack("<f", -2.5)
        result = self.plugin._pack_float(-2.5)
        for i, b in enumerate(raw, 1):
            assert result[i] == b


# ==================== Round-trip ====================


class TestPackUnpackRoundTrip:
    """Verify pack then unpack returns the original value."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_uint16_round_trip(self):
        val = 0xABCD
        packed = self.plugin._pack_uint16(val)
        assert self.plugin._unpack_uint16(packed, 1) == val

    def test_uint32_round_trip(self):
        val = 0xDEADBEEF
        packed = self.plugin._pack_uint32(val)
        assert self.plugin._unpack_uint32(packed, 1) == val

    def test_int32_round_trip(self):
        val = -42
        packed = self.plugin._pack_int32(val)
        assert self.plugin._unpack_int32(packed, 1) == val

    def test_uint64_round_trip(self):
        val = 0x123456789ABCDEF0
        packed = self.plugin._pack_uint64(val)
        assert self.plugin._unpack_uint64(packed, 1) == val

    def test_float_round_trip(self):
        val = 3.14
        packed = self.plugin._pack_float(val)
        result = self.plugin._unpack_float(packed, 1)
        assert abs(result - val) < 1e-6


# ==================== Buffer Search Helpers ====================


class TestBufferSearch:
    """Pure unit tests for buffer search functions."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_buffer_find_found(self):
        """bufferFind returns 1-indexed offset on match."""
        data = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5}
        pattern = {1: 3, 2: 4}
        assert self.plugin._buffer_find(data, pattern) == 3

    def test_buffer_find_at_start(self):
        """Match at the beginning returns 1."""
        data = {1: 0xAA, 2: 0xBB, 3: 0xCC}
        pattern = {1: 0xAA, 2: 0xBB}
        assert self.plugin._buffer_find(data, pattern) == 1

    def test_buffer_find_at_end(self):
        """Match at the end."""
        data = {1: 1, 2: 2, 3: 3}
        pattern = {1: 2, 2: 3}
        assert self.plugin._buffer_find(data, pattern) == 2

    def test_buffer_find_not_found(self):
        """bufferFind returns None when no match."""
        data = {1: 1, 2: 2, 3: 3}
        pattern = {1: 9, 2: 9}
        assert self.plugin._buffer_find(data, pattern) is None

    def test_buffer_find_all_multiple(self):
        """bufferFindAll returns all match offsets."""
        # Pattern {2, 3} appears at index 2 and 5
        data = {1: 1, 2: 2, 3: 3, 4: 4, 5: 2, 6: 3, 7: 7}
        pattern = {1: 2, 2: 3}
        result = self.plugin._buffer_find_all(data, pattern)
        assert result[1] == 2
        assert result[2] == 5

    def test_buffer_find_all_no_match(self):
        """bufferFindAll returns empty table when no match."""
        data = {1: 1, 2: 2, 3: 3}
        pattern = {1: 9}
        result = self.plugin._buffer_find_all(data, pattern)
        # Empty table -- no integer keys
        assert 1 not in result

    def test_buffer_contains_true(self):
        """bufferContains returns True when pattern found."""
        data = {1: 0x48, 2: 0x54, 3: 0x54, 4: 0x50}
        pattern = {1: 0x54, 2: 0x54}
        assert self.plugin._buffer_contains(data, pattern) is True

    def test_buffer_contains_false(self):
        """bufferContains returns False when not found."""
        data = {1: 1, 2: 2}
        pattern = {1: 9}
        assert self.plugin._buffer_contains(data, pattern) is False


# ==================== readPackets ====================


class TestReadPackets:
    """readPackets with mocked HOOK_MANAGER.read_ring_buffer."""

    def setup_method(self):
        self.plugin = make_plugin()

    def _activate_capture(self, hook_ids: dict[str, int] | None = None):
        """Put plugin into active capture state with given hook_ids."""
        self.plugin._capture_active = True
        self.plugin._hook_ids = hook_ids or {"send": 1, "recv": 2, "connect": 3, "closesocket": 4}
        self.plugin._connections = {}

    def test_send_entry(self, monkeypatch):
        """Send entry -> direction='send', socket, data_hex, data_ascii populated."""
        self._activate_capture()
        entry = make_ring_buffer_entry(hook_id=1, hook_name="send", data=b"hello", result=5, arg0=0x1A4)
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        p = packets[1]
        assert p["direction"] == "send"
        assert p["socket"] == 0x1A4
        assert p["socket_hex"] == "0x1a4"
        assert "68 65 6C 6C 6F" in p["data_hex"]
        assert "hello" in p["data_ascii"]
        assert p["result"] == 5

    def test_recv_entry(self, monkeypatch):
        """Recv entry -> direction='recv', result field populated."""
        self._activate_capture()
        entry = make_ring_buffer_entry(hook_id=2, hook_name="recv", data=b"\x01\x02\x03", result=3)
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        p = packets[1]
        assert p["direction"] == "recv"
        assert p["result"] == 3
        assert p["data"] is not None

    def test_connect_entry_adds_connection(self, monkeypatch):
        """Connect entry with sockaddr adds connection to internal state."""
        self._activate_capture()
        sockaddr = make_sockaddr_in(443, (140, 82, 112, 22))
        entry = make_ring_buffer_entry(hook_id=3, hook_name="connect", data=sockaddr, arg0=0x200)
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        self.plugin._read_packets(100)
        assert 0x200 in self.plugin._connections
        conn = self.plugin._connections[0x200]
        assert conn["remote_ip"] == "140.82.112.22"
        assert conn["remote_port"] == 443

    def test_closesocket_removes_connection(self, monkeypatch):
        """Closesocket entry removes connection from internal state."""
        self._activate_capture()
        self.plugin._connections[0x200] = {"remote_ip": "1.2.3.4", "remote_port": 80, "family": "IPv4"}

        entry = make_ring_buffer_entry(hook_id=4, hook_name="closesocket", data=None, arg0=0x200)
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        self.plugin._read_packets(100)
        assert 0x200 not in self.plugin._connections

    def test_marker_entry(self, monkeypatch):
        """Marker entry -> type='marker' in output."""
        self._activate_capture()
        entry = make_ring_buffer_entry(is_marker=True, data=b"checkpoint-1")
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        p = packets[1]
        assert p["type"] == "marker"
        assert p["label"] == "checkpoint-1"

    def test_empty_buffer(self, monkeypatch):
        """Empty buffer returns empty table."""
        self._activate_capture()
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = []
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        # No integer keys -> empty
        assert 1 not in packets

    def test_read_packets_without_capture_raises(self):
        """readPackets when capture not active raises RuntimeError."""
        with pytest.raises(RuntimeError, match="No capture active"):
            self.plugin._read_packets(100)

    def test_data_table_is_1_indexed(self, monkeypatch):
        """Packet data table uses 1-indexed keys."""
        self._activate_capture()
        entry = make_ring_buffer_entry(hook_id=1, hook_name="send", data=b"\xaa\xbb\xcc")
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        data = packets[1]["data"]
        assert data[1] == 0xAA
        assert data[2] == 0xBB
        assert data[3] == 0xCC

    def test_unknown_hook_id_uses_hook_name_field(self, monkeypatch):
        """When hook_id not in plugin's map, falls back to entry's hook_name."""
        self._activate_capture(hook_ids={"send": 1})
        entry = make_ring_buffer_entry(hook_id=99, hook_name="custom_hook", data=b"x")
        mock_hm = MagicMock()
        mock_hm.read_ring_buffer.return_value = [entry]
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        packets = self.plugin._read_packets(100)
        assert packets[1]["hook_name"] == "custom_hook"


# ==================== startCapture ====================


class TestStartCapture:
    """startCapture flow with mocked HOOK_MANAGER and resolve_export."""

    def test_default_options(self, monkeypatch):
        """Default options: resolves send+recv+connect+closesocket, installs 4 hooks."""
        plugin = make_plugin()

        mock_hm = MagicMock()
        mock_hm.ring_buffer = None
        mock_hm.create_ring_buffer.return_value = {"address": "0x1000", "entry_count": 128, "total_size": 65536}
        mock_hm.ring_buffer = None  # Before call

        hook_id_counter = [0]

        def mock_install_hook(**kwargs):
            hook_id_counter[0] += 1
            return {"hook_id": hook_id_counter[0]}

        mock_hm.install_hook.side_effect = mock_install_hook
        # After create_ring_buffer, ring_buffer should be set
        rb_config = _make_rb_config(0x1000)

        def create_rb_side_effect(**kwargs):
            mock_hm.ring_buffer = rb_config
            return {"address": "0x1000"}

        mock_hm.create_ring_buffer.side_effect = create_rb_side_effect
        mock_hm.ring_buffer = None  # Start with no ring buffer

        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", lambda mod, fn: 0x70001000 + hash(fn) % 0x1000)

        plugin._start_capture()

        # 4 hooks: send, recv, connect, closesocket
        assert mock_hm.install_hook.call_count == 4
        assert plugin._capture_active is True
        assert len(plugin._hook_ids) == 4
        assert "send" in plugin._hook_ids
        assert "recv" in plugin._hook_ids
        assert "connect" in plugin._hook_ids
        assert "closesocket" in plugin._hook_ids

    def test_custom_hooks_list(self, monkeypatch):
        """Custom hooks list: only hooks specified functions."""
        plugin = make_plugin()

        mock_hm = MagicMock()
        rb_config = _make_rb_config(0x1000)
        mock_hm.ring_buffer = rb_config  # Pre-existing ring buffer

        hook_id_counter = [0]

        def mock_install_hook(**kwargs):
            hook_id_counter[0] += 1
            return {"hook_id": hook_id_counter[0]}

        mock_hm.install_hook.side_effect = mock_install_hook
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", lambda mod, fn: 0x70001000)

        # Only hook "send", with connect tracking
        opts = {"hooks": {1: "send"}, "connect": True, "buffer_size": None, "max_packet_size": None}
        plugin._start_capture(opts)

        # 1 data hook + 2 connect hooks = 3
        assert mock_hm.install_hook.call_count == 3
        assert "send" in plugin._hook_ids
        assert "recv" not in plugin._hook_ids

    def test_connect_false(self, monkeypatch):
        """connect=false skips connect/closesocket hooks."""
        plugin = make_plugin()

        mock_hm = MagicMock()
        rb_config = _make_rb_config(0x1000)
        mock_hm.ring_buffer = rb_config

        hook_id_counter = [0]

        def mock_install_hook(**kwargs):
            hook_id_counter[0] += 1
            return {"hook_id": hook_id_counter[0]}

        mock_hm.install_hook.side_effect = mock_install_hook
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", lambda mod, fn: 0x70001000)

        opts = {"hooks": None, "connect": False, "buffer_size": None, "max_packet_size": None}
        plugin._start_capture(opts)

        # Only send + recv, no connect hooks
        assert mock_hm.install_hook.call_count == 2
        assert "connect" not in plugin._hook_ids
        assert "closesocket" not in plugin._hook_ids

    def test_resolve_failure_rolls_back(self, monkeypatch):
        """Resolve failure raises RuntimeError and rolls back installed hooks."""
        plugin = make_plugin()

        mock_hm = MagicMock()
        rb_config = _make_rb_config(0x1000)
        mock_hm.ring_buffer = rb_config
        mock_hm.install_hook.return_value = {"hook_id": 1}
        mock_hm.hooks = {}  # No hooks remain after rollback

        call_count = [0]

        def mock_resolve(mod, fn):
            call_count[0] += 1
            if call_count[0] == 1:
                return 0x70001000  # "send" resolves fine
            return None  # "recv" fails

        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", mock_resolve)

        with pytest.raises(RuntimeError, match="Cannot resolve"):
            plugin._start_capture()

        # Hook 1 (send) should have been rolled back
        mock_hm.remove_hook.assert_called_with(1)
        assert plugin._capture_active is False

    def test_already_active_raises(self, monkeypatch):
        """Starting capture when already active raises RuntimeError."""
        plugin = make_plugin()
        plugin._capture_active = True

        with pytest.raises(RuntimeError, match="already active"):
            plugin._start_capture()

    def test_ring_buffer_reuse(self, monkeypatch):
        """If HOOK_MANAGER.ring_buffer exists, doesn't create a new one."""
        plugin = make_plugin()

        mock_hm = MagicMock()
        rb_config = _make_rb_config(0x2000, entry_count=64)
        mock_hm.ring_buffer = rb_config

        hook_id_counter = [0]

        def mock_install_hook(**kwargs):
            hook_id_counter[0] += 1
            return {"hook_id": hook_id_counter[0]}

        mock_hm.install_hook.side_effect = mock_install_hook
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", lambda mod, fn: 0x70001000)

        plugin._start_capture()

        mock_hm.create_ring_buffer.assert_not_called()
        assert plugin._created_ring_buffer is False

    def test_creates_ring_buffer_when_none(self, monkeypatch):
        """Creates ring buffer when HOOK_MANAGER.ring_buffer is None."""
        plugin = make_plugin()

        mock_hm = MagicMock()
        rb_config = _make_rb_config(0x3000)

        def create_rb_side_effect(**kwargs):
            mock_hm.ring_buffer = rb_config

        mock_hm.ring_buffer = None
        mock_hm.create_ring_buffer.side_effect = create_rb_side_effect

        hook_id_counter = [0]

        def mock_install_hook(**kwargs):
            hook_id_counter[0] += 1
            return {"hook_id": hook_id_counter[0]}

        mock_hm.install_hook.side_effect = mock_install_hook
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", lambda mod, fn: 0x70001000)

        plugin._start_capture()

        mock_hm.create_ring_buffer.assert_called_once()
        assert plugin._created_ring_buffer is True

    def test_resolve_failure_destroys_created_ring_buffer(self, monkeypatch):
        """On failure, if plugin created the ring buffer and no hooks remain, destroys it."""
        plugin = make_plugin()

        mock_hm = MagicMock()

        def create_rb(**kwargs):
            mock_hm.ring_buffer = _make_rb_config(0x5000)

        mock_hm.ring_buffer = None
        mock_hm.create_ring_buffer.side_effect = create_rb
        mock_hm.hooks = {}  # No hooks remain after rollback

        # resolve_export always fails
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)
        monkeypatch.setattr("contrib.plugins.netcap.resolve_export", lambda mod, fn: None)

        with pytest.raises(RuntimeError):
            plugin._start_capture()

        mock_hm.destroy_ring_buffer.assert_called_once()
        assert plugin._created_ring_buffer is False

    def test_invalid_hook_name_raises(self, monkeypatch):
        """Unknown hook name raises ValueError."""
        plugin = make_plugin()
        mock_hm = MagicMock()
        mock_hm.ring_buffer = _make_rb_config(0x1000)
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        opts = {"hooks": {1: "invalid_hook"}, "connect": None, "buffer_size": None, "max_packet_size": None}
        with pytest.raises(ValueError, match="Unknown hook"):
            plugin._start_capture(opts)


# ==================== stopCapture ====================


class TestStopCapture:
    """stopCapture removes hooks and cleans up state."""

    def test_removes_only_netcap_hooks(self, monkeypatch):
        """stopCapture removes only netcap's hooks (not user's manual hooks)."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10, "recv": 11}
        plugin._created_ring_buffer = False

        mock_hm = MagicMock()
        mock_hm.hooks = {999: "some_user_hook"}  # Other hooks exist
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin._stop_capture()

        # Should remove hook IDs 10 and 11
        calls = [c.args[0] for c in mock_hm.remove_hook.call_args_list]
        assert 10 in calls
        assert 11 in calls
        assert mock_hm.remove_hook.call_count == 2

    def test_destroys_ring_buffer_if_created_and_no_hooks(self, monkeypatch):
        """Destroys ring buffer only if plugin created it and no other hooks remain."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10}
        plugin._created_ring_buffer = True

        mock_hm = MagicMock()
        mock_hm.hooks = {}  # No hooks remain after removal
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin._stop_capture()

        mock_hm.destroy_ring_buffer.assert_called_once()

    def test_keeps_ring_buffer_if_other_hooks_exist(self, monkeypatch):
        """Does NOT destroy ring buffer if other hooks still exist."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10}
        plugin._created_ring_buffer = True

        mock_hm = MagicMock()
        mock_hm.hooks = {999: "some_user_hook"}  # Other hooks exist
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin._stop_capture()

        mock_hm.destroy_ring_buffer.assert_not_called()

    def test_keeps_ring_buffer_if_not_created_by_plugin(self, monkeypatch):
        """Does NOT destroy ring buffer if plugin didn't create it."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10}
        plugin._created_ring_buffer = False

        mock_hm = MagicMock()
        mock_hm.hooks = {}
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin._stop_capture()

        mock_hm.destroy_ring_buffer.assert_not_called()

    def test_clears_internal_state(self, monkeypatch):
        """stopCapture clears hook_ids, connections, capture_active, created_ring_buffer."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10, "recv": 11}
        plugin._connections = {0x200: {"remote_ip": "1.2.3.4"}}
        plugin._created_ring_buffer = True

        mock_hm = MagicMock()
        mock_hm.hooks = {}
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin._stop_capture()

        assert plugin._capture_active is False
        assert plugin._hook_ids == {}
        assert plugin._connections == {}
        assert plugin._created_ring_buffer is False

    def test_stop_without_active_raises(self):
        """stopCapture when no capture active raises RuntimeError."""
        plugin = make_plugin()
        with pytest.raises(RuntimeError, match="No capture active"):
            plugin._stop_capture()


# ==================== Lifecycle ====================


class TestLifecycle:
    """on_process_detaching behavior."""

    def test_detaching_process_alive_calls_cleanup(self, monkeypatch):
        """on_process_detaching(process_alive=True) calls cleanup with hook removal."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10}
        plugin._created_ring_buffer = True

        mock_hm = MagicMock()
        mock_hm.hooks = {}
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin.on_process_detaching(session=None, process_alive=True)

        mock_hm.remove_hook.assert_called_with(10)
        mock_hm.destroy_ring_buffer.assert_called_once()
        assert plugin._capture_active is False

    def test_detaching_process_dead_clears_local_state(self, monkeypatch):
        """on_process_detaching(process_alive=False) clears local state only."""
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 10, "recv": 11}
        plugin._connections = {0x200: {"remote_ip": "1.2.3.4"}}
        plugin._created_ring_buffer = True

        mock_hm = MagicMock()
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin.on_process_detaching(session=None, process_alive=False)

        # Should NOT call remove_hook or destroy_ring_buffer (process is dead)
        mock_hm.remove_hook.assert_not_called()
        mock_hm.destroy_ring_buffer.assert_not_called()

        # But local state should be cleared
        assert plugin._capture_active is False
        assert plugin._hook_ids == {}
        assert plugin._connections == {}
        assert plugin._created_ring_buffer is False

    def test_detaching_when_not_active_is_noop(self, monkeypatch):
        """on_process_detaching when capture not active does nothing."""
        plugin = make_plugin()
        plugin._capture_active = False

        mock_hm = MagicMock()
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        plugin.on_process_detaching(session=None, process_alive=True)

        mock_hm.remove_hook.assert_not_called()
        mock_hm.destroy_ring_buffer.assert_not_called()


# ==================== captureStats ====================


class TestCaptureStats:
    """captureStats returns ring buffer stats augmented with hook/connection counts."""

    def test_stats_returned(self, monkeypatch):
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._hook_ids = {"send": 1, "recv": 2}
        plugin._connections = {0x100: {"remote_ip": "1.2.3.4"}}

        mock_hm = MagicMock()
        mock_hm.ring_buffer_stats.return_value = {
            "total_captured": 42,
            "total_dropped": 3,
            "entries_pending": 10,
            "utilization_pct": 15.6,
        }
        monkeypatch.setattr("contrib.plugins.netcap.HOOK_MANAGER", mock_hm)

        result = plugin._capture_stats()
        assert result["total"] == 42
        assert result["dropped"] == 3
        assert result["entries_pending"] == 10
        assert result["utilization_pct"] == 15.6
        assert result["active_hooks"] == 2
        assert result["connections"] == 1

    def test_stats_without_capture_raises(self):
        plugin = make_plugin()
        with pytest.raises(RuntimeError, match="No capture active"):
            plugin._capture_stats()


# ==================== getConnections ====================


class TestGetConnections:
    """getConnections returns tracked connections as a table."""

    def test_returns_connections(self):
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._connections = {
            0x1A4: {"remote_ip": "140.82.112.22", "remote_port": 443, "family": "IPv4"},
        }
        result = plugin._get_connections()
        conn = result["0x1a4"]
        assert conn["remote_ip"] == "140.82.112.22"
        assert conn["remote_port"] == 443
        assert conn["family"] == "IPv4"

    def test_empty_connections(self):
        plugin = make_plugin()
        plugin._capture_active = True
        plugin._connections = {}
        result = plugin._get_connections()
        assert "0x1a4" not in result

    def test_without_capture_raises(self):
        plugin = make_plugin()
        with pytest.raises(RuntimeError, match="No capture active"):
            plugin._get_connections()


# ==================== Registration ====================


class TestRegistration:
    """Plugin registers the expected Lua functions."""

    def test_register_returns_expected_count(self):
        plugin = NetcapPlugin()
        ctx = MockContext(table_factory=make_table, log_error=lambda *a: None)
        funcs = plugin.register(ctx)
        assert len(funcs) == 38

    def test_expected_function_names(self):
        plugin = NetcapPlugin()
        ctx = MockContext(table_factory=make_table, log_error=lambda *a: None)
        funcs = plugin.register(ctx)
        expected = {
            "startCapture",
            "stopCapture",
            "readPackets",
            "captureStats",
            "getConnections",
            "unpackUInt16",
            "unpackInt16",
            "unpackUInt32",
            "unpackInt32",
            "unpackUInt64",
            "unpackFloat",
            "unpackDouble",
            "unpackString",
            "unpackBytes",
            "unpackVector3",
            "packUInt16",
            "packUInt32",
            "packInt32",
            "packUInt64",
            "packFloat",
            "bufferFind",
            "bufferContains",
            "bufferFindAll",
            "filterPackets",
            "feedPackets",
            "getStream",
            "consumeStream",
            "listStreams",
            "clearStream",
            "splitLengthPrefixed",
            "splitDelimited",
            "splitFixed",
            "searchPackets",
            "searchPacketsForValue",
            "startRecording",
            "stopRecording",
            "loadRecording",
            "listRecordings",
        }
        assert set(funcs.keys()) == expected

    def test_plugin_metadata(self):
        plugin = NetcapPlugin()
        assert plugin.name == "netcap"
        assert plugin.description == "Winsock network capture"
        assert "startCapture" in plugin.instructions
