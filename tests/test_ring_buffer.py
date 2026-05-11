"""Tests for ring buffer reader in HookManager.

Simulates a ring buffer in local memory using a bytearray.
No process attachment needed -- SESSION is monkeypatched.
"""

import struct

import pytest

from src.tools.hooking import (
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
    RB_TOTAL_CAPTURED,
    RB_TOTAL_DROPPED,
    RB_WRITE_INDEX,
    STATUS_COMPLETE,
    STATUS_MARKER,
    STATUS_WRITING,
    HookManager,
    RingBufferConfig,
)


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


# ---------- Helpers ----------


def make_ring_buffer(
    entry_count: int = 16,
    max_data_size: int = 256,
) -> tuple[MockBuffer, RingBufferConfig, HookManager]:
    """Create a MockBuffer with an initialized control block and a HookManager wired to it."""
    entry_total_size = ENTRY_HEADER_SIZE + max_data_size
    total_size = RB_CONTROL_SIZE + entry_count * entry_total_size

    buf = MockBuffer(total_size)
    # Write control block
    struct.pack_into("<Q", buf.data, RB_ENTRY_COUNT, entry_count)
    struct.pack_into("<Q", buf.data, RB_MAX_DATA_SIZE, max_data_size)
    struct.pack_into("<Q", buf.data, RB_ENTRY_TOTAL_SIZE, entry_total_size)
    struct.pack_into("<Q", buf.data, RB_ENTRY_COUNT_MASK, entry_count - 1)
    struct.pack_into("<Q", buf.data, RB_FLAGS, 1)

    cfg = RingBufferConfig(
        address=0,  # base offset into the bytearray
        entry_count=entry_count,
        max_data_size=max_data_size,
        entry_total_size=entry_total_size,
        total_size=total_size,
    )

    mgr = HookManager()
    mgr.ring_buffer = cfg
    return buf, cfg, mgr


def entry_offset(cfg: RingBufferConfig, index: int) -> int:
    """Return the byte offset of the entry at the given logical index (wraps)."""
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

    # Merge extra_args_count into flags bits 8-11
    entry_flags = flags
    if extra_count:
        entry_flags |= (extra_count & 0xF) << 8
    if data or extra_count:
        entry_flags |= 1  # has_data

    struct.pack_into("<I", header, ENTRY_DATA_LENGTH, data_len)
    struct.pack_into("<I", header, ENTRY_CAPTURED_LENGTH, captured)
    struct.pack_into("<I", header, ENTRY_FLAGS, entry_flags)

    buf.data[off : off + ENTRY_HEADER_SIZE] = header

    # Write extra args prefix
    data_start = off + ENTRY_DATA_OFFSET
    for i, val in enumerate(extra_args):
        struct.pack_into("<Q", buf.data, data_start + i * 8, val)

    # Write buffer data after prefix
    if data:
        buf.data[data_start + prefix_size : data_start + prefix_size + len(data)] = data


def set_indices(buf: MockBuffer, write_idx: int, read_idx: int) -> None:
    """Set write_index and read_index in the control block."""
    struct.pack_into("<Q", buf.data, RB_WRITE_INDEX, write_idx)
    struct.pack_into("<Q", buf.data, RB_READ_INDEX, read_idx)


def set_stats(buf: MockBuffer, total_captured: int = 0, total_dropped: int = 0) -> None:
    """Set total_captured and total_dropped in the control block."""
    struct.pack_into("<Q", buf.data, RB_TOTAL_CAPTURED, total_captured)
    struct.pack_into("<Q", buf.data, RB_TOTAL_DROPPED, total_dropped)


# ---------- Fixtures ----------


@pytest.fixture()
def ring(monkeypatch):
    """Yield (MockBuffer, RingBufferConfig, HookManager) with SESSION patched."""
    buf, cfg, mgr = make_ring_buffer()
    monkeypatch.setattr("src.tools.hooking.SESSION.read_bytes", buf.read_bytes)
    monkeypatch.setattr("src.tools.hooking.SESSION.write_uint64", buf.write_uint64)
    return buf, cfg, mgr


# ---------- Tests ----------


class TestReadEmpty:
    def test_empty_buffer_returns_nothing(self, ring):
        buf, cfg, mgr = ring
        set_indices(buf, write_idx=0, read_idx=0)
        assert mgr.read_ring_buffer() == []

    def test_equal_indices_returns_nothing(self, ring):
        buf, cfg, mgr = ring
        set_indices(buf, write_idx=5, read_idx=5)
        assert mgr.read_ring_buffer() == []


class TestReadSingleEntry:
    def test_parses_all_fields(self, ring):
        buf, cfg, mgr = ring
        write_entry(
            buf,
            cfg,
            index=0,
            status=STATUS_COMPLETE,
            hook_id=7,
            timestamp=42000,
            return_addr=0x7FFF1234,
            args=(0x10, 0x20, 0x30, 0x40),
            result=-1,
            data=b"hello",
        )
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1

        e = entries[0]
        assert e["sequence"] == 0
        assert e["hook_id"] == 7
        assert e["timestamp"] == 42000
        assert e["return_addr"] == "0x7FFF1234"
        assert e["arg0"] == 0x10
        assert e["arg1"] == 0x20
        assert e["arg2"] == 0x30
        assert e["arg3"] == 0x40
        assert e["result"] == -1
        assert e["data"] == b"hello"
        assert e["captured_length"] == 5
        assert e["data_length"] == 5
        assert e["is_marker"] is False

    def test_entry_without_data(self, ring):
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0, data=None, flags=0)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1
        assert entries[0]["data"] is None
        assert entries[0]["captured_length"] == 0

    def test_advances_read_index(self, ring):
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0)
        set_indices(buf, write_idx=1, read_idx=0)
        mgr.read_ring_buffer()

        # read_index should now be 1
        new_read_idx = struct.unpack_from("<Q", buf.data, RB_READ_INDEX)[0]
        assert new_read_idx == 1


class TestReadMultipleEntries:
    def test_returns_entries_in_order(self, ring):
        buf, cfg, mgr = ring
        for i in range(5):
            write_entry(buf, cfg, index=i, hook_id=i + 1, timestamp=1000 + i)
        set_indices(buf, write_idx=5, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 5
        assert [e["hook_id"] for e in entries] == [1, 2, 3, 4, 5]
        assert [e["sequence"] for e in entries] == [0, 1, 2, 3, 4]

    def test_respects_limit(self, ring):
        buf, cfg, mgr = ring
        for i in range(10):
            write_entry(buf, cfg, index=i, hook_id=i)
        set_indices(buf, write_idx=10, read_idx=0)

        entries = mgr.read_ring_buffer(limit=3)
        assert len(entries) == 3

        # Read index advanced by 3
        new_read_idx = struct.unpack_from("<Q", buf.data, RB_READ_INDEX)[0]
        assert new_read_idx == 3


class TestSkipWritingEntries:
    def test_stops_at_writing_status(self, ring):
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0, hook_id=1, status=STATUS_COMPLETE)
        write_entry(buf, cfg, index=1, hook_id=2, status=STATUS_WRITING)
        write_entry(buf, cfg, index=2, hook_id=3, status=STATUS_COMPLETE)
        set_indices(buf, write_idx=3, read_idx=0)

        entries = mgr.read_ring_buffer()
        # Should stop at the WRITING entry, so only index 0 is returned
        assert len(entries) == 1
        assert entries[0]["hook_id"] == 1

        # Read index advanced to 1 (stopped before the WRITING entry)
        new_read_idx = struct.unpack_from("<Q", buf.data, RB_READ_INDEX)[0]
        assert new_read_idx == 1

    def test_stops_at_empty_status(self, ring):
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0, hook_id=1, status=STATUS_COMPLETE)
        # index=1 left as STATUS_EMPTY (default zero-initialized)
        set_indices(buf, write_idx=3, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1


class TestMarkerEntries:
    def test_marker_is_marker_true(self, ring):
        buf, cfg, mgr = ring
        label = b"checkpoint_alpha"
        write_entry(
            buf,
            cfg,
            index=0,
            status=STATUS_MARKER,
            hook_id=0,
            timestamp=0,
            data=label,
        )
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1
        assert entries[0]["is_marker"] is True
        assert entries[0]["data"] == label

    def test_marker_with_no_data(self, ring):
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0, status=STATUS_MARKER, hook_id=0, data=None)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1
        assert entries[0]["is_marker"] is True
        assert entries[0]["data"] is None


class TestWraparound:
    def test_wraps_around_entry_count(self, ring):
        buf, cfg, mgr = ring
        # entry_count=16, so index 17 maps to slot 1
        write_entry(buf, cfg, index=16, hook_id=99, timestamp=5000)
        write_entry(buf, cfg, index=17, hook_id=100, timestamp=5001)
        set_indices(buf, write_idx=18, read_idx=16)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 2
        assert entries[0]["hook_id"] == 99
        assert entries[1]["hook_id"] == 100

    def test_slot_calculation_matches_mask(self, ring):
        buf, cfg, mgr = ring
        # Write at index 33 (slot = 33 & 15 = 1)
        write_entry(buf, cfg, index=33, hook_id=42)
        set_indices(buf, write_idx=34, read_idx=33)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1
        assert entries[0]["hook_id"] == 42
        assert entries[0]["sequence"] == 33


class TestStats:
    def test_basic_stats(self, ring):
        buf, cfg, mgr = ring
        set_indices(buf, write_idx=10, read_idx=3)
        set_stats(buf, total_captured=100, total_dropped=5)

        stats = mgr.ring_buffer_stats()
        assert stats["total_captured"] == 100
        assert stats["total_dropped"] == 5
        assert stats["entries_pending"] == 7
        assert stats["utilization_pct"] == pytest.approx(43.8, abs=0.1)

    def test_empty_stats(self, ring):
        buf, cfg, mgr = ring
        set_indices(buf, write_idx=0, read_idx=0)
        set_stats(buf, total_captured=0, total_dropped=0)

        stats = mgr.ring_buffer_stats()
        assert stats["entries_pending"] == 0
        assert stats["utilization_pct"] == 0.0

    def test_full_utilization(self, ring):
        buf, cfg, mgr = ring
        # entry_count=16, all slots pending
        set_indices(buf, write_idx=16, read_idx=0)

        stats = mgr.ring_buffer_stats()
        assert stats["utilization_pct"] == 100.0

    def test_no_ring_buffer_raises(self):
        mgr = HookManager()
        with pytest.raises(RuntimeError, match="No ring buffer"):
            mgr.ring_buffer_stats()


class TestExtraArgs:
    def test_extra_args_parsed(self, ring):
        buf, cfg, mgr = ring
        extra = [0xBEEF0001, 0xBEEF0002, 0xBEEF0003]
        write_entry(
            buf,
            cfg,
            index=0,
            hook_id=5,
            extra_args=extra,
            data=b"payload",
        )
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert len(entries) == 1
        e = entries[0]
        assert "extra_args" in e
        assert e["extra_args"]["arg4"] == 0xBEEF0001
        assert e["extra_args"]["arg5"] == 0xBEEF0002
        assert e["extra_args"]["arg6"] == 0xBEEF0003

    def test_extra_args_data_offset_correct(self, ring):
        """Buffer data must start AFTER the extra args prefix."""
        buf, cfg, mgr = ring
        extra = [0x1111, 0x2222]
        payload = b"ABCDEF"
        write_entry(buf, cfg, index=0, extra_args=extra, data=payload)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        e = entries[0]
        assert e["data"] == payload
        assert e["extra_args"]["arg4"] == 0x1111
        assert e["extra_args"]["arg5"] == 0x2222

    def test_no_extra_args_no_key(self, ring):
        """Entries without extra args should not have the extra_args key."""
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert "extra_args" not in entries[0]

    def test_extra_args_only_no_data(self, ring):
        """Extra args with no buffer data -- data should be None."""
        buf, cfg, mgr = ring
        extra = [0xAAAA]
        write_entry(buf, cfg, index=0, extra_args=extra, data=None)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        e = entries[0]
        assert e["extra_args"]["arg4"] == 0xAAAA
        assert e["data"] is None


class TestNoRingBuffer:
    def test_read_without_buffer_raises(self):
        mgr = HookManager()
        with pytest.raises(RuntimeError, match="No ring buffer"):
            mgr.read_ring_buffer()

    def test_stats_without_buffer_raises(self):
        mgr = HookManager()
        with pytest.raises(RuntimeError, match="No ring buffer"):
            mgr.ring_buffer_stats()


class TestHookNameLookup:
    def test_entry_includes_hook_name(self, ring):
        buf, cfg, mgr = ring
        from src.tools.hooking import HookInfo

        hook = HookInfo(
            hook_id=7,
            target_addr=0x1000,
            saved_bytes=b"\x90",
            saved_length=1,
            trampoline_addr=0x2000,
            trampoline_size=4096,
            original_protection=0x20,
            hook_type="pre",
            name="my_func",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=4096,
        )
        mgr._hooks_by_id[7] = hook

        write_entry(buf, cfg, index=0, hook_id=7)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert entries[0]["hook_name"] == "my_func"

    def test_entry_without_known_hook_has_no_name(self, ring):
        buf, cfg, mgr = ring
        write_entry(buf, cfg, index=0, hook_id=999)
        set_indices(buf, write_idx=1, read_idx=0)

        entries = mgr.read_ring_buffer()
        assert "hook_name" not in entries[0]
