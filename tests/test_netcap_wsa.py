"""Tests for WSA and IOCP processing in the network capture plugin.

Tests WSASend/WSARecv sync and async paths, GQCS correlation,
WSABUF parsing, and edge cases.
"""

import struct
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from contrib.plugins.netcap import NetcapPlugin

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


def make_wsabuf(length: int, buf_ptr: int) -> bytes:
    """Build a WSABUF struct (16 bytes): uint32 len at 0, uint64 buf ptr at 8."""
    buf = bytearray(16)
    struct.pack_into("<I", buf, 0, length)
    struct.pack_into("<Q", buf, 8, buf_ptr)
    return bytes(buf)


def make_entry(
    hook_id=1,
    hook_name="WSASend",
    arg0=0x1A4,
    arg1=0,
    arg2=1,
    arg3=1024,
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


# ==================== WSABUF Parsing ====================


class TestParseWsabuf:
    """Pure unit tests for _parse_wsabuf."""

    def setup_method(self):
        self.plugin = make_plugin()

    def test_valid_wsabuf(self):
        """16-byte WSABUF with length=1024, buf_ptr=0x1234 -> (1024, 0x1234)."""
        data = make_wsabuf(1024, 0x1234)
        result = self.plugin._parse_wsabuf(data)
        assert result is not None
        assert result == (1024, 0x1234)

    def test_short_data(self):
        """Data shorter than 16 bytes -> None."""
        assert self.plugin._parse_wsabuf(b"\x00" * 15) is None
        assert self.plugin._parse_wsabuf(b"\x00" * 8) is None
        assert self.plugin._parse_wsabuf(b"") is None
        assert self.plugin._parse_wsabuf(None) is None

    def test_zero_length(self):
        """length=0, buf_ptr=0x5678 -> (0, 0x5678)."""
        data = make_wsabuf(0, 0x5678)
        result = self.plugin._parse_wsabuf(data)
        assert result == (0, 0x5678)

    def test_zero_buf_ptr(self):
        """length=512, buf_ptr=0 -> (512, 0)."""
        data = make_wsabuf(512, 0)
        result = self.plugin._parse_wsabuf(data)
        assert result == (512, 0)


# ==================== WSASend Sync ====================


class TestWsaSendSync:
    """WSASend with synchronous completion (result=0)."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"WSASend": 1}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_sync_send(self, mock_hm, mock_session):
        """Sync WSASend: result=0, reads buffer, produces send packet."""
        entry = make_entry(
            hook_id=1,
            hook_name="WSASend",
            arg0=0x1A4,
            arg2=1,
            arg3=1024,
            result=0,
            data=make_wsabuf(1024, 0xDEAD),
        )
        mock_hm.read_ring_buffer.return_value = [entry]
        mock_session.read_bytes.return_value = b"A" * 1024

        packets = self.plugin._read_packets(10)

        assert len([k for k in packets if isinstance(k, int)]) == 1
        pkt = packets[1]
        assert pkt["direction"] == "send"
        assert pkt["size"] == 1024
        assert pkt["captured"] == 1024
        assert "data" in pkt


# ==================== WSARecv Sync ====================


class TestWsaRecvSync:
    """WSARecv with synchronous completion (result=0)."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"WSARecv": 2}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_sync_recv(self, mock_hm, mock_session):
        """Sync WSARecv: result=0, reads buffer, produces recv packet."""
        entry = make_entry(
            hook_id=2,
            hook_name="WSARecv",
            arg0=0x1A4,
            arg2=1,
            arg3=512,
            result=0,
            data=make_wsabuf(4096, 0xBEEF),
        )
        mock_hm.read_ring_buffer.return_value = [entry]
        mock_session.read_bytes.return_value = b"B" * 512

        packets = self.plugin._read_packets(10)

        assert len([k for k in packets if isinstance(k, int)]) == 1
        pkt = packets[1]
        assert pkt["direction"] == "recv"
        assert pkt["size"] == 512
        assert pkt["captured"] == 512
        assert "data" in pkt


# ==================== WSARecv Async ====================


class TestWsaRecvAsync:
    """WSARecv with async I/O (result=-1) followed by GQCS completion."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"WSARecv": 2, "GetQueuedCompletionStatus": 3}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_async_pending_then_complete(self, mock_hm, mock_session):
        """Async WSARecv: step 1 stores pending, step 2 GQCS completes it."""
        # Step 1: WSARecv returns SOCKET_ERROR (-1) -> async pending
        wsabuf_data = make_wsabuf(4096, 0xCAFE)
        entry_recv = make_entry(
            hook_id=2,
            hook_name="WSARecv",
            arg0=0x1A4,
            arg2=1,
            arg3=0,
            result=-1,
            data=wsabuf_data,
            extra_args={"arg4": 0xBEEF},
            sequence=1,
        )
        mock_hm.read_ring_buffer.return_value = [entry_recv]

        packets = self.plugin._read_packets(10)

        # No packet emitted for pending async
        int_keys = [k for k in packets if isinstance(k, int)]
        assert len(int_keys) == 0
        # But the overlapped is stored in _pending_io
        assert 0xBEEF in self.plugin._pending_io

        # Step 2: GQCS returns with matching overlapped
        entry_gqcs = make_entry(
            hook_id=3,
            hook_name="GetQueuedCompletionStatus",
            arg0=0,
            arg1=512,
            arg2=0,
            arg3=0xBEEF,
            result=1,
            sequence=2,
        )
        mock_hm.read_ring_buffer.return_value = [entry_gqcs]
        mock_session.read_bytes.return_value = b"C" * 512

        packets = self.plugin._read_packets(10)

        int_keys = [k for k in packets if isinstance(k, int)]
        assert len(int_keys) == 1
        pkt = packets[1]
        assert pkt.get("async") is True
        assert pkt["direction"] == "recv"
        assert pkt["size"] == 512
        # Pending entry consumed
        assert len(self.plugin._pending_io) == 0


# ==================== GQCS Unmatched ====================


class TestGqcsUnmatched:
    """GQCS entry with overlapped_ptr not in _pending_io -> no packet."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"GetQueuedCompletionStatus": 3}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_unmatched_gqcs(self, mock_hm, mock_session):
        """GQCS with no matching pending IO -> no packet emitted."""
        entry = make_entry(
            hook_id=3,
            hook_name="GetQueuedCompletionStatus",
            arg0=0,
            arg1=256,
            arg2=0,
            arg3=0xDEAD,
            result=1,
        )
        mock_hm.read_ring_buffer.return_value = [entry]

        packets = self.plugin._read_packets(10)

        int_keys = [k for k in packets if isinstance(k, int)]
        assert len(int_keys) == 0


# ==================== GQCS Failure ====================


class TestGqcsFailure:
    """GQCS entry with result=0 (failed) -> no packet."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"GetQueuedCompletionStatus": 3}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_failed_gqcs(self, mock_hm, mock_session):
        """GQCS with result=0 -> no packet emitted."""
        # Add a pending entry to verify it's NOT consumed
        self.plugin._pending_io[0xBEEF] = {
            "socket": 0x1A4,
            "buf_ptr": 0xCAFE,
            "wsabuf_len": 4096,
            "hook_name": "WSARecv",
            "sequence": 1,
        }

        entry = make_entry(
            hook_id=3,
            hook_name="GetQueuedCompletionStatus",
            arg0=0,
            arg1=0,
            arg2=0,
            arg3=0xBEEF,
            result=0,
        )
        mock_hm.read_ring_buffer.return_value = [entry]

        packets = self.plugin._read_packets(10)

        int_keys = [k for k in packets if isinstance(k, int)]
        assert len(int_keys) == 0
        # Pending entry NOT consumed (GQCS failed, never reaches pop)
        assert 0xBEEF in self.plugin._pending_io


# ==================== Correlation Table Eviction ====================


class TestCorrelationTableEviction:
    """Verify oldest _pending_io entry is evicted when limit exceeded."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"WSARecv": 2}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_eviction(self, mock_hm, mock_session):
        """Fill _pending_io beyond _max_pending_io -> oldest entry evicted."""
        limit = self.plugin._max_pending_io

        # Pre-fill with entries 0..limit-1
        for i in range(limit):
            self.plugin._pending_io[i] = {
                "socket": 0x100 + i,
                "buf_ptr": 0x2000 + i,
                "wsabuf_len": 64,
                "hook_name": "WSARecv",
                "sequence": i,
            }

        assert len(self.plugin._pending_io) == limit
        assert 0 in self.plugin._pending_io  # oldest key present

        # Add one more via a WSARecv async entry
        new_overlapped = limit + 100
        entry = make_entry(
            hook_id=2,
            hook_name="WSARecv",
            arg0=0x1A4,
            arg2=1,
            arg3=0,
            result=-1,
            data=make_wsabuf(1024, 0xAAAA),
            extra_args={"arg4": new_overlapped},
        )
        mock_hm.read_ring_buffer.return_value = [entry]

        self.plugin._read_packets(10)

        # New entry is present
        assert new_overlapped in self.plugin._pending_io
        # Table is back at limit (evicted one)
        assert len(self.plugin._pending_io) == limit
        # Oldest key (0) was evicted
        assert 0 not in self.plugin._pending_io


# ==================== Server-Side Read Failure ====================


class TestServerSideReadFailure:
    """WSASend sync entry where SESSION.read_bytes raises -> packet with captured=0."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"WSASend": 1}
        self.plugin._max_packet_size = 4096
        self.plugin._header_only = False

    @patch("contrib.plugins.netcap.SESSION")
    @patch("contrib.plugins.netcap.HOOK_MANAGER")
    def test_read_failure(self, mock_hm, mock_session):
        """SESSION.read_bytes raises -> packet emitted with captured=0, no data."""
        entry = make_entry(
            hook_id=1,
            hook_name="WSASend",
            arg0=0x1A4,
            arg2=1,
            arg3=1024,
            result=0,
            data=make_wsabuf(1024, 0xDEAD),
        )
        mock_hm.read_ring_buffer.return_value = [entry]
        mock_session.read_bytes.side_effect = Exception("access denied")

        packets = self.plugin._read_packets(10)

        assert len([k for k in packets if isinstance(k, int)]) == 1
        pkt = packets[1]
        assert pkt["direction"] == "send"
        assert pkt["size"] == 1024
        assert pkt["captured"] == 0
        assert "data" not in pkt
