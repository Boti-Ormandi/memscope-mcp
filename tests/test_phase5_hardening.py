"""Phase 5 hardening tests.

Tests for:
- Already-hooked detection (prologue JMP check)
- Ring buffer read bounds checking (corrupt entries)
- IOCP correlation table TTL eviction
- Paginated loadRecording
"""

import json
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from contrib.plugins.netcap import NetcapPlugin
from memscope_mcp.tools.hooking import (
    ENTRY_ARG0,
    ENTRY_CAPTURED_LENGTH,
    ENTRY_DATA_LENGTH,
    ENTRY_DATA_OFFSET,
    ENTRY_FLAGS,
    ENTRY_HEADER_SIZE,
    ENTRY_HOOK_ID,
    ENTRY_RESULT,
    ENTRY_RETURN_ADDR,
    ENTRY_SEQUENCE,
    ENTRY_STATUS,
    ENTRY_TIMESTAMP,
    RB_CONTROL_SIZE,
    RB_ENTRY_COUNT,
    RB_ENTRY_COUNT_MASK,
    RB_ENTRY_TOTAL_SIZE,
    RB_FLAGS,
    RB_MAX_DATA_SIZE,
    RB_READ_INDEX,
    RB_WRITE_INDEX,
    STATUS_COMPLETE,
    HookManager,
    RingBufferConfig,
)

# ==================== Shared Helpers ====================


class MockBuffer:
    """Wraps a bytearray to act as target-process memory."""

    def __init__(self, size: int):
        self.data = bytearray(size)

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(self.data[address : address + size])

    def write_uint64(self, address: int, value: int) -> None:
        struct.pack_into("<Q", self.data, address, value)

    def write_bytes(self, address: int, data: bytes) -> None:
        self.data[address : address + len(data)] = data


def make_ring_buffer(
    entry_count: int = 16,
    max_data_size: int = 256,
) -> tuple[MockBuffer, RingBufferConfig, HookManager]:
    """Create a MockBuffer with an initialized control block and a HookManager wired to it."""
    entry_total_size = ENTRY_HEADER_SIZE + max_data_size
    total_size = RB_CONTROL_SIZE + entry_count * entry_total_size

    buf = MockBuffer(total_size)
    struct.pack_into("<Q", buf.data, RB_ENTRY_COUNT, entry_count)
    struct.pack_into("<Q", buf.data, RB_MAX_DATA_SIZE, max_data_size)
    struct.pack_into("<Q", buf.data, RB_ENTRY_TOTAL_SIZE, entry_total_size)
    struct.pack_into("<Q", buf.data, RB_ENTRY_COUNT_MASK, entry_count - 1)
    struct.pack_into("<Q", buf.data, RB_FLAGS, 1)

    cfg = RingBufferConfig(
        address=0,
        entry_count=entry_count,
        max_data_size=max_data_size,
        entry_total_size=entry_total_size,
        total_size=total_size,
    )

    mgr = HookManager()
    mgr.ring_buffer = cfg
    return buf, cfg, mgr


def entry_offset(cfg: RingBufferConfig, index: int) -> int:
    slot = index & (cfg.entry_count - 1)
    return RB_CONTROL_SIZE + slot * cfg.entry_total_size


def write_entry(
    buf: MockBuffer,
    cfg: RingBufferConfig,
    index: int,
    *,
    status: int = STATUS_COMPLETE,
    hook_id: int = 1,
    timestamp: int = 1000,
    return_addr: int = 0xDEAD,
    args: tuple[int, int, int, int] = (0xA0, 0xA1, 0xA2, 0xA3),
    result: int = 0,
    data: bytes | None = None,
    flags: int = 0,
    extra_args: list[int] | None = None,
):
    """Write a single entry header (and optional data) into the buffer."""
    off = entry_offset(cfg, index)
    header = bytearray(ENTRY_HEADER_SIZE)

    struct.pack_into("<Q", header, ENTRY_SEQUENCE, index)
    struct.pack_into("<I", header, ENTRY_STATUS, status)
    struct.pack_into("<I", header, ENTRY_HOOK_ID, hook_id)
    struct.pack_into("<Q", header, ENTRY_TIMESTAMP, timestamp)
    struct.pack_into("<Q", header, ENTRY_RETURN_ADDR, return_addr)
    struct.pack_into("<QQQQ", header, ENTRY_ARG0, *args)
    struct.pack_into("<i", header, ENTRY_RESULT, result)

    extra_args = extra_args or []
    extra_count = len(extra_args)
    prefix_size = extra_count * 8

    captured = len(data) if data else 0
    data_len = captured

    entry_flags = flags
    if extra_count:
        entry_flags |= (extra_count & 0xF) << 8
    if data or extra_count:
        entry_flags |= 1

    struct.pack_into("<I", header, ENTRY_DATA_LENGTH, data_len)
    struct.pack_into("<I", header, ENTRY_CAPTURED_LENGTH, captured)
    struct.pack_into("<I", header, ENTRY_FLAGS, entry_flags)

    buf.data[off : off + ENTRY_HEADER_SIZE] = header

    data_start = off + ENTRY_DATA_OFFSET
    for i, val in enumerate(extra_args):
        struct.pack_into("<Q", buf.data, data_start + i * 8, val)

    if data:
        buf.data[data_start + prefix_size : data_start + prefix_size + len(data)] = data


def set_indices(buf: MockBuffer, write_idx: int, read_idx: int) -> None:
    struct.pack_into("<Q", buf.data, RB_WRITE_INDEX, write_idx)
    struct.pack_into("<Q", buf.data, RB_READ_INDEX, read_idx)


# Netcap helpers


class LuaTable(dict):
    """Dict that returns None for missing keys, mirroring Lua table semantics."""

    def __missing__(self, key):
        return None


def make_table(*args, **kwargs):
    result = LuaTable()
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


# ==================== Already-Hooked Detection ====================


class TestAlreadyHookedDetection:
    """install_hook should refuse addresses that start with a JMP instruction."""

    def setup_method(self):
        self.mgr = HookManager()
        self.mgr.ring_buffer = RingBufferConfig(
            address=0x1000,
            entry_count=16,
            max_data_size=256,
            entry_total_size=ENTRY_HEADER_SIZE + 256,
            total_size=RB_CONTROL_SIZE + 16 * (ENTRY_HEADER_SIZE + 256),
        )

    def test_rejects_e9_jmp_prologue(self, monkeypatch):
        """E9 xx xx xx xx = rel32 JMP, typical inline hook."""
        prologue = b"\xe9\x12\x34\x56\x78" + b"\x90" * 27
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.read_bytes", lambda addr, size: prologue)

        with pytest.raises(RuntimeError, match="appears already hooked.*E9 rel32"):
            self.mgr.install_hook(0x7FF6A0010000, "test")

    def test_rejects_ff25_jmp_prologue(self, monkeypatch):
        """FF 25 xx xx xx xx = abs indirect JMP, typical 14-byte hook."""
        prologue = b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", 0xDEAD) + b"\x90" * 18
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.read_bytes", lambda addr, size: prologue)

        with pytest.raises(RuntimeError, match="appears already hooked.*FF25 abs"):
            self.mgr.install_hook(0x7FF6A0010000, "test")

    def test_allows_normal_prologue(self, monkeypatch):
        """Normal prologues should pass the JMP check (may fail later in decode_prologue)."""
        prologue = b"\x48\x89\x5c\x24\x08" + b"\x90" * 27  # mov [rsp+8], rbx
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.read_bytes", lambda addr, size: prologue)

        # Will fail at allocate_near, but that's after the JMP check -- meaning the check passed
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: None)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate", lambda *a, **kw: 0x2000)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.virtual_protect", lambda *a: 0x20)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.write_bytes", lambda *a: None)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.suspend_process_threads", lambda: [])
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.resume_process_threads", lambda threads: None)

        result = self.mgr.install_hook(0x7FF6A0010000, "test")
        assert result["hook_id"] == 1

    def test_duplicate_address_rejected(self, monkeypatch):
        """Same target_addr should be rejected by the existing check."""
        prologue = b"\x48\x89\x5c\x24\x08" + b"\x90" * 27
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.read_bytes", lambda addr, size: prologue)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: None)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate", lambda *a, **kw: 0x2000)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.virtual_protect", lambda *a: 0x20)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.write_bytes", lambda *a: None)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.suspend_process_threads", lambda: [])
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.resume_process_threads", lambda threads: None)

        self.mgr.install_hook(0x7FF6A0010000, "first")
        with pytest.raises(RuntimeError, match="already hooked"):
            self.mgr.install_hook(0x7FF6A0010000, "second")


# ==================== Ring Buffer Bounds Checking ====================


class TestRingBufferBoundsChecking:
    """read_ring_buffer should handle corrupt/oversized entry fields safely."""

    @pytest.fixture()
    def ring(self, monkeypatch):
        buf, cfg, mgr = make_ring_buffer(entry_count=16, max_data_size=256)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.read_bytes", buf.read_bytes)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.write_uint64", buf.write_uint64)
        return buf, cfg, mgr

    def test_captured_length_clamped_to_max_data_size(self, ring):
        """If captured_length exceeds max_data_size, it should be clamped."""
        buf, cfg, mgr = ring

        # Write entry with captured_length > max_data_size
        off = entry_offset(cfg, 0)
        header = bytearray(ENTRY_HEADER_SIZE)
        struct.pack_into("<Q", header, ENTRY_SEQUENCE, 0)
        struct.pack_into("<I", header, ENTRY_STATUS, STATUS_COMPLETE)
        struct.pack_into("<I", header, ENTRY_HOOK_ID, 1)
        struct.pack_into("<Q", header, ENTRY_TIMESTAMP, 1000)
        struct.pack_into("<Q", header, ENTRY_RETURN_ADDR, 0xDEAD)
        struct.pack_into("<QQQQ", header, ENTRY_ARG0, 1, 2, 3, 4)
        struct.pack_into("<i", header, ENTRY_RESULT, 0)

        # Set captured_length to 9999 (way beyond max_data_size=256)
        struct.pack_into("<I", header, ENTRY_DATA_LENGTH, 9999)
        struct.pack_into("<I", header, ENTRY_CAPTURED_LENGTH, 9999)
        struct.pack_into("<I", header, ENTRY_FLAGS, 1)  # has_data

        buf.data[off : off + ENTRY_HEADER_SIZE] = header

        # Write some actual data
        test_data = b"ABCD" * 10  # 40 bytes
        buf.data[off + ENTRY_DATA_OFFSET : off + ENTRY_DATA_OFFSET + len(test_data)] = test_data

        set_indices(buf, 1, 0)

        entries = mgr.read_ring_buffer(10)
        assert len(entries) == 1
        # captured_length should have been clamped to max_data_size (256)
        assert entries[0]["captured_length"] <= cfg.max_data_size

    def test_extra_args_count_clamped_to_7(self, ring):
        """extra_args_count > 7 should be clamped to 7."""
        buf, cfg, mgr = ring

        # Write entry with extra_args_count = 15 (max in 4 bits) in flags
        off = entry_offset(cfg, 0)
        header = bytearray(ENTRY_HEADER_SIZE)
        struct.pack_into("<Q", header, ENTRY_SEQUENCE, 0)
        struct.pack_into("<I", header, ENTRY_STATUS, STATUS_COMPLETE)
        struct.pack_into("<I", header, ENTRY_HOOK_ID, 1)
        struct.pack_into("<Q", header, ENTRY_TIMESTAMP, 1000)
        struct.pack_into("<Q", header, ENTRY_RETURN_ADDR, 0xDEAD)
        struct.pack_into("<QQQQ", header, ENTRY_ARG0, 1, 2, 3, 4)
        struct.pack_into("<i", header, ENTRY_RESULT, 0)
        struct.pack_into("<I", header, ENTRY_DATA_LENGTH, 0)
        struct.pack_into("<I", header, ENTRY_CAPTURED_LENGTH, 0)

        # Set flags: extra_args_count = 15 in bits 8-11 (0xF << 8 = 0xF00)
        struct.pack_into("<I", header, ENTRY_FLAGS, 0xF00 | 1)
        buf.data[off : off + ENTRY_HEADER_SIZE] = header

        # Write 7 x 8 = 56 bytes of extra arg data (the clamped max)
        for i in range(7):
            struct.pack_into("<Q", buf.data, off + ENTRY_DATA_OFFSET + i * 8, 0x100 + i)

        set_indices(buf, 1, 0)

        entries = mgr.read_ring_buffer(10)
        assert len(entries) == 1
        # Should have exactly 7 extra args (clamped from 15)
        assert len(entries[0].get("extra_args", {})) == 7

    def test_prefix_plus_captured_clamped(self, ring):
        """If extra_args prefix + captured exceeds max_data_size, captured is clamped."""
        buf, cfg, mgr = ring

        # 3 extra args = 24 bytes prefix; max_data_size = 256
        # Set captured = 250 -> prefix(24) + captured(250) = 274 > 256
        off = entry_offset(cfg, 0)
        header = bytearray(ENTRY_HEADER_SIZE)
        struct.pack_into("<Q", header, ENTRY_SEQUENCE, 0)
        struct.pack_into("<I", header, ENTRY_STATUS, STATUS_COMPLETE)
        struct.pack_into("<I", header, ENTRY_HOOK_ID, 1)
        struct.pack_into("<Q", header, ENTRY_TIMESTAMP, 1000)
        struct.pack_into("<Q", header, ENTRY_RETURN_ADDR, 0xDEAD)
        struct.pack_into("<QQQQ", header, ENTRY_ARG0, 1, 2, 3, 4)
        struct.pack_into("<i", header, ENTRY_RESULT, 0)
        struct.pack_into("<I", header, ENTRY_DATA_LENGTH, 250)
        struct.pack_into("<I", header, ENTRY_CAPTURED_LENGTH, 250)

        # 3 extra args in flags (bits 8-11), plus has_data
        struct.pack_into("<I", header, ENTRY_FLAGS, (3 << 8) | 1)
        buf.data[off : off + ENTRY_HEADER_SIZE] = header

        # Write 3 extra args
        for i in range(3):
            struct.pack_into("<Q", buf.data, off + ENTRY_DATA_OFFSET + i * 8, 0x42 + i)

        # Write some data after prefix
        prefix_end = off + ENTRY_DATA_OFFSET + 24
        fill = b"\xaa" * 232  # 256 - 24 = max that fits after prefix
        buf.data[prefix_end : prefix_end + len(fill)] = fill

        set_indices(buf, 1, 0)

        entries = mgr.read_ring_buffer(10)
        assert len(entries) == 1
        assert len(entries[0].get("extra_args", {})) == 3
        # captured should be clamped: max_data_size(256) - prefix(24) = 232
        assert entries[0]["captured_length"] <= 232

    def test_normal_entry_unchanged(self, ring):
        """Normal entries should pass through unchanged."""
        buf, cfg, mgr = ring

        test_data = b"hello world"
        write_entry(buf, cfg, 0, data=test_data, hook_id=1)
        set_indices(buf, 1, 0)

        entries = mgr.read_ring_buffer(10)
        assert len(entries) == 1
        assert entries[0]["data"] == test_data
        assert entries[0]["captured_length"] == len(test_data)


# ==================== IOCP Correlation Table TTL ====================


class TestIOCPCorrelationTTL:
    """Stale pending_io entries should be evicted based on TTL."""

    def setup_method(self):
        self.plugin = make_plugin()
        self.plugin._capture_active = True
        self.plugin._hook_ids = {"send": 1}
        self.plugin._header_only = False
        self.plugin._max_packet_size = 4096

    def test_stale_entries_evicted_on_read_packets(self, monkeypatch):
        """Entries older than TTL should be removed during readPackets."""
        # Set a very short TTL for testing
        self.plugin._pending_io_ttl = 0.1

        # Add a pending IO entry with old timestamp
        self.plugin._pending_io[0xABCD] = {
            "socket": 0x1A4,
            "buf_ptr": 0x5000,
            "wsabuf_len": 100,
            "hook_name": "WSARecv",
            "sequence": 1,
            "created_at": time.monotonic() - 10.0,  # 10 seconds ago, well past TTL
        }

        # Add a fresh entry
        self.plugin._pending_io[0xDEAD] = {
            "socket": 0x1A5,
            "buf_ptr": 0x6000,
            "wsabuf_len": 200,
            "hook_name": "WSARecv",
            "sequence": 2,
            "created_at": time.monotonic(),  # just now
        }

        # Mock HOOK_MANAGER.read_ring_buffer to return no entries
        monkeypatch.setattr(
            "contrib.plugins.netcap.HOOK_MANAGER.read_ring_buffer",
            lambda limit: [],
        )

        self.plugin._read_packets(10)

        # Stale entry should be gone, fresh one should remain
        assert 0xABCD not in self.plugin._pending_io
        assert 0xDEAD in self.plugin._pending_io

    def test_fresh_entries_not_evicted(self, monkeypatch):
        """Entries within TTL should not be evicted."""
        self.plugin._pending_io_ttl = 60.0

        self.plugin._pending_io[0x1111] = {
            "socket": 0x1A4,
            "buf_ptr": 0x5000,
            "wsabuf_len": 100,
            "hook_name": "WSARecv",
            "sequence": 1,
            "created_at": time.monotonic(),
        }

        monkeypatch.setattr(
            "contrib.plugins.netcap.HOOK_MANAGER.read_ring_buffer",
            lambda limit: [],
        )

        self.plugin._read_packets(10)
        assert 0x1111 in self.plugin._pending_io

    def test_empty_pending_io_no_error(self, monkeypatch):
        """Empty pending_io should not cause errors during eviction."""
        self.plugin._pending_io = {}

        monkeypatch.setattr(
            "contrib.plugins.netcap.HOOK_MANAGER.read_ring_buffer",
            lambda limit: [],
        )

        # Should not raise
        self.plugin._read_packets(10)


# ==================== Paginated loadRecording ====================


class TestPaginatedLoadRecording:
    """loadRecording should support offset and limit parameters."""

    def _write_recording(self, filepath: Path, count: int = 20):
        """Write a JSONL recording file with `count` entries."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            for i in range(count):
                record = {
                    "direction": "send",
                    "socket": 420,
                    "socket_hex": "0x1a4",
                    "timestamp": 1000 + i,
                    "sequence": i + 1,
                    "size": 5,
                    "captured": 5,
                    "result": 5,
                    "caller": "ws2_32.dll+0x1234",
                    "hook_name": "send",
                    "data_hex": "48 65 6C 6C 6F",
                }
                f.write(json.dumps(record) + "\n")

    def test_load_full_recording(self, tmp_path, monkeypatch):
        """Loading without offset/limit returns all entries."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 20)

        plugin = make_plugin()
        result = plugin._load_recording("session1")

        # Count entries (1-indexed Lua table)
        count = 0
        i = 1
        while result[i] is not None:
            count += 1
            i += 1
        assert count == 20

    def test_load_with_limit(self, tmp_path, monkeypatch):
        """Loading with limit=5 returns only 5 entries."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 20)

        plugin = make_plugin()
        opts = make_table(offset=None, limit=5)
        result = plugin._load_recording("session1", opts)

        count = 0
        i = 1
        while result[i] is not None:
            count += 1
            i += 1
        assert count == 5

    def test_load_with_offset(self, tmp_path, monkeypatch):
        """Loading with offset=15 skips first 15, returns remaining 5."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 20)

        plugin = make_plugin()
        opts = make_table(offset=15, limit=None)
        result = plugin._load_recording("session1", opts)

        count = 0
        i = 1
        while result[i] is not None:
            count += 1
            i += 1
        assert count == 5

    def test_load_with_offset_and_limit(self, tmp_path, monkeypatch):
        """Loading with offset=5, limit=3 returns entries 6-8."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 20)

        plugin = make_plugin()
        opts = make_table(offset=5, limit=3)
        result = plugin._load_recording("session1", opts)

        count = 0
        i = 1
        while result[i] is not None:
            count += 1
            i += 1
        assert count == 3
        # First returned entry should have sequence=6 (0-indexed line 5 -> seq 6)
        assert result[1]["sequence"] == 6

    def test_offset_beyond_file(self, tmp_path, monkeypatch):
        """Offset past end of file returns empty result."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 5)

        plugin = make_plugin()
        opts = make_table(offset=100, limit=None)
        result = plugin._load_recording("session1", opts)

        # Should be an empty table
        assert result[1] is None

    def test_limit_zero(self, tmp_path, monkeypatch):
        """Limit of 0 returns no entries."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 20)

        plugin = make_plugin()
        opts = make_table(offset=None, limit=0)
        result = plugin._load_recording("session1", opts)
        assert result[1] is None

    def test_no_opts_backward_compatible(self, tmp_path, monkeypatch):
        """Calling without opts (old API) still works."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("contrib.plugins.netcap.SESSION.target_process", "test.exe")

        filepath = tmp_path / "scripts" / "test.exe" / "recordings" / "session1.jsonl"
        self._write_recording(filepath, 3)

        plugin = make_plugin()
        result = plugin._load_recording("session1")

        count = 0
        i = 1
        while result[i] is not None:
            count += 1
            i += 1
        assert count == 3
