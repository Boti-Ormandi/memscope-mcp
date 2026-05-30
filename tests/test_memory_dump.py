"""Tests for smart_dump validation, annotation, and pagination."""

import struct

import pytest

from memscope_mcp.tools import memory


class FakeSession:
    def __init__(self, data: bytes, base: int = 0x1000):
        self.data = data
        self.base = base
        self.reads = []

    def ensure_attached(self):
        return True

    def read_bytes(self, address: int, size: int) -> bytes:
        self.reads.append((address, size))
        offset = address - self.base
        if offset < 0 or offset + size > len(self.data):
            raise OSError(f"unmapped read: 0x{address:X}+0x{size:X}")
        return self.data[offset : offset + size]


def pack_values(*values: int) -> bytes:
    return b"".join(struct.pack("<Q", value) for value in values)


def install_session(monkeypatch, data: bytes) -> FakeSession:
    session = FakeSession(data.ljust(0x1000, b"\x00"))
    monkeypatch.setattr(memory, "SESSION", session)
    return session


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"start_offset": -1}, "INVALID_START_OFFSET"),
        ({"start_offset": 0x1000}, "INVALID_START_OFFSET"),
        ({"size": 0}, "INVALID_SIZE"),
        ({"size": -1}, "INVALID_SIZE"),
        ({"max_entries": 0}, "INVALID_MAX_ENTRIES"),
        ({"max_entries": -1}, "INVALID_MAX_ENTRIES"),
        ({"annotation_level": "verbose"}, "INVALID_ANNOTATION_LEVEL"),
        ({"annotation_level": 1}, "INVALID_ANNOTATION_LEVEL"),
    ],
)
def test_smart_dump_rejects_invalid_parameters_before_reading(monkeypatch, kwargs, error):
    session = install_session(monkeypatch, pack_values(1, 2, 3))

    result = memory.smart_dump("0x1000", **kwargs)

    assert result["success"] is False
    assert result["error"] == error
    assert result["error_detail"]
    assert session.reads == []


def test_smart_dump_clamps_size_to_remaining_window(monkeypatch):
    data = bytes(i % 256 for i in range(0x1000))
    session = install_session(monkeypatch, data)

    result = memory.smart_dump("0x1000", size=0x2000, start_offset=0x800, max_entries=300)

    assert result["success"] is True
    assert session.reads == [(0x1800, 0x800)]
    assert result["dump_start"] == "0x1800"
    assert result["size"] == 0x800
    assert result["_pagination"] == {
        "total_size": 0x800,
        "dumped_range": {"start": 0x800, "end": 0x1000},
        "entries_returned": 0x100,
        "entries_total": 0x100,
        "entries_scanned": 0x100,
        "has_more": False,
        "next_start_offset": None,
    }


def test_smart_dump_max_entries_cursor_resumes_after_processed_entry(monkeypatch):
    install_session(monkeypatch, pack_values(1, 2, 3, 4, 5, 6, 7, 8))

    result = memory.smart_dump("0x1000", size=0x40, max_entries=2)

    assert result["success"] is True
    assert [entry["raw"] for entry in result["entries"]] == ["0x0000000000000001", "0x0000000000000002"]
    assert result["_pagination"] == {
        "total_size": 0x40,
        "dumped_range": {"start": 0, "end": 0x10},
        "entries_returned": 2,
        "entries_total": 8,
        "entries_scanned": 2,
        "has_more": True,
        "next_start_offset": 0x10,
    }


def test_smart_dump_filtered_cursor_uses_processed_range_not_return_count(monkeypatch):
    install_session(monkeypatch, pack_values(0, 0, 7, 0))

    result = memory.smart_dump("0x1000", size=0x20, non_null_only=True, max_entries=10)

    assert result["success"] is True
    assert len(result["entries"]) == 1
    assert result["entries"][0]["offset"] == "+0x10"
    assert result["_pagination"] == {
        "total_size": 0x20,
        "dumped_range": {"start": 0, "end": 0x20},
        "entries_returned": 1,
        "entries_total": 4,
        "entries_scanned": 4,
        "has_more": True,
        "next_start_offset": 0x20,
    }


def test_smart_dump_annotation_levels_control_entry_shape(monkeypatch):
    install_session(monkeypatch, pack_values(0))

    normal = memory.smart_dump("0x1000", size=8, annotation_level="normal")
    full = memory.smart_dump("0x1000", size=8, annotation_level="FULL")
    minimal = memory.smart_dump("0x1000", size=8, annotation_level="minimal")

    assert "confidence" not in normal["entries"][0]
    assert full["entries"][0]["confidence"] == 1.0
    assert set(minimal["entries"][0]) == {"offset", "raw", "type"}
