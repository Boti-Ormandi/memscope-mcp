"""Tests for AOB scanning region selection and metadata."""

from dataclasses import dataclass

from src.tools import scanning
from src.tools.lua import engine as lua_engine_module


@dataclass
class FakeMbi:
    BaseAddress: int
    RegionSize: int
    State: int
    Protect: int
    Type: int = 0x20000  # MEM_PRIVATE


class FakePm:
    process_handle = 1


class FakeSession:
    def __init__(self, memory: dict[int, bytes], modules: dict[str, dict]):
        self.pm = FakePm()
        self.memory = memory
        self.modules = modules

    def ensure_attached(self):
        return True

    def read_bytes(self, address: int, size: int) -> bytes:
        for base, data in self.memory.items():
            end = base + len(data)
            if base <= address and address + size <= end:
                offset = address - base
                return data[offset : offset + size]
        raise OSError(f"unmapped read: 0x{address:X}+0x{size:X}")


def make_virtual_query(regions: list[FakeMbi]):
    def fake_virtual_query(_handle, address: int):
        for region in regions:
            start = region.BaseAddress
            end = start + region.RegionSize
            if start <= address < end:
                return region
        raise OSError(f"unmapped query: 0x{address:X}")

    return fake_virtual_query


def install_fake_target(monkeypatch, regions: list[FakeMbi]):
    module_data = bytearray(0x100)
    module_data[0x10:0x14] = b"\xde\xad\xbe\xef"

    heap_data = bytearray(0x1000)
    heap_data[0x20:0x24] = b"\xde\xad\xbe\xef"
    heap_data[0x40:0x44] = b"\xde\xad\xbe\xef"

    second_heap = bytearray(0x1000)
    second_heap[0x20:0x24] = b"\xde\xad\xbe\xef"

    fake_session = FakeSession(
        {
            0x1000: bytes(module_data),
            0x5000: bytes(heap_data),
            0x7000: bytes(second_heap),
        },
        {"target.dll": {"base": 0x1000, "size": len(module_data), "path": "target.dll"}},
    )

    monkeypatch.setattr(scanning, "SESSION", fake_session)
    monkeypatch.setattr(lua_engine_module, "SESSION", fake_session)
    monkeypatch.setattr(scanning.pymem.memory, "virtual_query", make_virtual_query(regions))
    return fake_session


def test_unbounded_aob_scan_keeps_module_only_behavior(monkeypatch):
    install_fake_target(monkeypatch, [])

    result = scanning.scan_aob_addresses("DE AD BE EF", max_results=10)

    assert result["success"] is True
    assert result["matches"] == [0x1010]
    assert result["metadata"]["mode"] == "modules"
    assert result["metadata"]["scanned_region_count"] == 1
    assert result["metadata"]["result_count"] == 1


def test_bounded_aob_scan_uses_readable_private_regions(monkeypatch):
    install_fake_target(
        monkeypatch,
        [FakeMbi(0x5000, 0x100, scanning.MEM_COMMIT, 0x04)],
    )

    result = scanning.scan_aob_addresses("DE AD BE EF", start_addr=0x5000, end_addr=0x50FF, max_results=10)

    assert result["success"] is True
    assert result["matches"] == [0x5020, 0x5040]
    assert result["metadata"]["mode"] == "range"
    assert result["metadata"]["scanned_region_count"] == 1
    assert result["metadata"]["skipped_region_count"] == 0
    assert result["metadata"]["bytes_scanned"] == 0x100
    assert result["metadata"]["result_count"] == 2


def test_bounded_aob_scan_clips_to_requested_bounds(monkeypatch):
    install_fake_target(
        monkeypatch,
        [FakeMbi(0x5000, 0x100, scanning.MEM_COMMIT, 0x04)],
    )

    result = scanning.scan_aob_addresses("DE AD BE EF", start_addr=0x5030, end_addr=0x50FF, max_results=10)

    assert result["success"] is True
    assert result["matches"] == [0x5040]
    assert result["metadata"]["bytes_scanned"] == 0xD0


def test_bounded_aob_scan_skips_unreadable_regions(monkeypatch):
    install_fake_target(
        monkeypatch,
        [
            FakeMbi(0x5000, 0x1000, scanning.MEM_COMMIT, 0x04),
            FakeMbi(0x6000, 0x1000, scanning.MEM_COMMIT, 0x01),
            FakeMbi(0x7000, 0x1000, scanning.MEM_COMMIT, 0x04),
        ],
    )

    result = scanning.scan_aob_addresses("DE AD BE EF", start_addr=0x5000, end_addr=0x7FFF, max_results=10)

    assert result["success"] is True
    assert result["matches"] == [0x5020, 0x5040, 0x7020]
    assert result["metadata"]["scanned_region_count"] == 2
    assert result["metadata"]["skipped_region_count"] == 1
    assert result["metadata"]["bytes_scanned"] == 0x2000


def test_scan_aob_response_includes_scan_metadata(monkeypatch):
    install_fake_target(
        monkeypatch,
        [FakeMbi(0x5000, 0x100, scanning.MEM_COMMIT, 0x04)],
    )

    result = scanning.scan_aob("DE AD BE EF", address_min="0x5000", address_max="0x50FF", limit=1)

    assert result["success"] is True
    assert result["data"] == [{"address": "0x5020"}]
    assert result["_pagination"]["total"] == 2
    assert result["scan_metadata"]["mode"] == "range"
    assert result["scan_metadata"]["result_count"] == 2


def test_lua_aob_scan_bounds_return_metadata(monkeypatch):
    install_fake_target(
        monkeypatch,
        [FakeMbi(0x5000, 0x100, scanning.MEM_COMMIT, 0x04)],
    )

    result = lua_engine_module.LUA_ENGINE.execute(
        """
        local hits = AOBScan("DE AD BE EF", 0x5000, 0x50FF, 10)
        addResult("count", #hits)
        addResult("first", hits[1])
        addResult("mode", hits.metadata.mode)
        addResult("scanned", hits.metadata.scanned_region_count)
        addResult("bytes", hits.metadata.bytes_scanned)
        """
    )

    assert result["success"] is True
    assert result["results"]["count"] == 2
    assert result["results"]["first"] == 0x5020
    assert result["results"]["mode"] == "range"
    assert result["results"]["scanned"] == 1
    assert result["results"]["bytes"] == 0x100
