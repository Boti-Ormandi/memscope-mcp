"""Production Lua scanning cutover tests over the unified engine."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import memscope_mcp.server as server
from memscope_mcp.scanning.execution import ScanExecutor
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease, build_module_records
from memscope_mcp.scanning.planner import MEM_COMMIT, MEM_IMAGE, PAGE_READWRITE
from memscope_mcp.tools.lua.engine import LUA_ENGINE


class FakeSession:
    def __init__(self, lease: ScanLease) -> None:
        self.lease = lease

    @contextmanager
    def acquire_scan_lease(self):
        yield self.lease


def make_executor(
    memory: bytes,
    *,
    base: int = 0x1000,
    chunk_size: int = 128 * 1024,
    read_hook=None,
    clock=time.monotonic_ns,
) -> ScanExecutor:
    module = SimpleNamespace(
        name="target.dll",
        lpBaseOfDll=base,
        SizeOfImage=len(memory),
        filename=r"C:\Target\target.dll",
    )
    modules = ModuleSnapshot.create(build_module_records((module,)), generation=1)
    lease = ScanLease(
        generation=1,
        pid=123,
        process_handle=1,
        target_process="Target.exe",
        modules=modules,
        lifecycle_cancel=threading.Event(),
    )

    def query(_handle: int, address: int):
        if not base <= address < base + len(memory):
            raise OSError(f"unmapped address 0x{address:X}")
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(memory),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_IMAGE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        if read_hook is not None:
            read_hook(address, size)
        offset = address - base
        return memory[offset : offset + size]

    return ScanExecutor(
        FakeSession(lease),
        query_memory=query,
        read_memory=read,
        target_alive=lambda _handle: True,
        chunk_size=chunk_size,
        page_size=1,
        clock=clock,
    )


def install_executor(
    monkeypatch,
    memory: bytes,
    *,
    base: int = 0x1000,
    chunk_size: int = 128 * 1024,
    read_hook=None,
    clock=time.monotonic_ns,
):
    extension = next(item for item in server._extensions if item.name == "module_scan")
    executor = make_executor(
        memory,
        base=base,
        chunk_size=chunk_size,
        read_hook=read_hook,
        clock=clock,
    )
    monkeypatch.setattr(extension._scan_adapter, "_executor", executor)
    return executor


def test_lua_aob_options_table_returns_bounded_addresses_and_status(monkeypatch):
    install_executor(monkeypatch, b"AAAAA")

    result = LUA_ENGINE.execute(
        """
        local hits, err = AOBScan("41 41", {
            scope = {kind = "modules", names = {"target.dll"}},
            mode = "addresses",
            max_matches = 2,
            diagnostics = true
        })
        addResult("has_error", err ~= nil)
        addResult("count", #hits)
        addResult("first", hits[1])
        addResult("second", hits[2])
        addResult("mode", hits.metadata.mode)
        addResult("termination", hits.metadata.status.termination)
        addResult("reads", hits.metadata.diagnostics.physical_read_calls)
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "has_error": False,
        "count": 2,
        "first": 0x1000,
        "second": 0x1001,
        "mode": "addresses",
        "termination": "match_limit",
        "reads": 1,
    }


def test_lua_first_count_and_valid_no_match_have_distinct_shapes(monkeypatch):
    install_executor(monkeypatch, b"ABABA")

    result = LUA_ENGINE.execute(
        """
        local first = AOBScan("41 42", {mode = "first"})
        local counted = AOBScan("41", {mode = "count", max_matches = 10})
        local missing = AOBScan("FF", {mode = "addresses"})
        addResult("first_count", #first)
        addResult("first_addr", first[1])
        addResult("first_stop", first.metadata.status.termination)
        addResult("count_entries", #counted)
        addResult("count", counted.metadata.count)
        addResult("observation", counted.metadata.observation)
        addResult("missing_is_table", missing ~= nil)
        addResult("missing_count", #missing)
        addResult("missing_stop", missing.metadata.status.termination)
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "first_count": 1,
        "first_addr": 0x1000,
        "first_stop": "first_hit",
        "count_entries": 0,
        "count": 3,
        "observation": "complete_traversal",
        "missing_is_table": True,
        "missing_count": 0,
        "missing_stop": "scope_exhausted",
    }


def test_lua_string_and_pointer_queries_share_the_engine(monkeypatch):
    target = 0x123456789ABC
    memory = bytearray(64)
    memory[3:5] = b"Hi"
    memory[16:20] = "Hi".encode("utf-16le")
    memory[24:32] = target.to_bytes(8, "little")
    memory[36:44] = target.to_bytes(8, "little")
    install_executor(monkeypatch, bytes(memory))

    result = LUA_ENGINE.execute(
        f"""
        local ascii = scanString("Hi", {{encoding = "ascii", mode = "first"}})
        local wide = scanString("Hi", {{encoding = "utf-16le", mode = "first"}})
        local refs = scanPointer("0x{target:X}", {{alignment = 8, max_matches = 10}})
        addResult("ascii", ascii[1])
        addResult("wide", wide[1])
        addResult("ref_count", #refs)
        addResult("ref", refs[1])
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "ascii": 0x1003,
        "wide": 0x1010,
        "ref_count": 1,
        "ref": 0x1018,
    }


def test_lua_expected_failures_return_nil_and_error_table(monkeypatch):
    install_executor(monkeypatch, b"AAAA")

    result = LUA_ENGINE.execute(
        """
        local positional, positional_err = AOBScan("41", 0x1000, 0x1004)
        local unknown, unknown_err = AOBScan("41", {legacy = true})
        local bad_encoding, encoding_err = scanString("x", {encoding = "wide"})
        addResult("positional_nil", positional == nil)
        addResult("positional_code", positional_err.error)
        addResult("positional_success_absent", positional_err.success == nil)
        addResult("unknown_nil", unknown == nil)
        addResult("unknown_field", unknown_err.field)
        addResult("encoding_nil", bad_encoding == nil)
        addResult("encoding_field", encoding_err.field)
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "positional_nil": True,
        "positional_code": "INVALID_ARGUMENT",
        "positional_success_absent": True,
        "unknown_nil": True,
        "unknown_field": "options.legacy",
        "encoding_nil": True,
        "encoding_field": "options.encoding",
    }


def test_lua_local_timeout_returns_partial_status_instead_of_aborting(monkeypatch):
    class AdvancingClock:
        def __init__(self):
            self.value = 0

        def __call__(self):
            self.value += 40_000_000
            return self.value

    install_executor(monkeypatch, b"A" * 64, chunk_size=1, clock=AdvancingClock())

    result = LUA_ENGINE.execute(
        """
        local hits = AOBScan("42", {timeout_ms = 100})
        addResult("termination", hits.metadata.status.termination)
        addResult("count", #hits)
        """
    )

    assert result["success"] is True
    assert result["results"]["termination"] == "timeout"
    assert result["results"]["count"] == 0


def test_lua_outer_timeout_aborts_direct_scan(monkeypatch):
    def slow_read(_address, _size):
        time.sleep(0.01)

    install_executor(monkeypatch, b"A" * 128, chunk_size=1, read_hook=slow_read)

    result = LUA_ENGINE.execute('AOBScan("42", {timeout_ms = 30000})', timeout=0.05)

    assert result["success"] is False
    assert result["error"] == "TIMEOUT"
    assert "execution time limit" in result["detail"]


def test_removed_lua_module_scan_global_is_absent():
    assert LUA_ENGINE.lua.globals()["AOBScanModule"] is None


def test_lua_aob_scan_many_returns_ordered_keyed_items_and_shared_metadata(monkeypatch):
    install_executor(monkeypatch, b"ABABA")

    result = LUA_ENGINE.execute(
        """
        local items, err = AOBScanMany({
            {key = "ab", pattern = "41 42"},
            {key = "ba", pattern = "42 41"}
        }, {
            scope = {kind = "modules", names = {"target.dll"}},
            mode = "first",
            diagnostics = true
        })
        addResult("has_error", err ~= nil)
        addResult("count", #items)
        addResult("first_key", items[1].key)
        addResult("first_match", items[1].match)
        addResult("second_key", items[2].key)
        addResult("second_match", items[2].match)
        addResult("mode", items.metadata.mode)
        addResult("termination", items.metadata.shared.termination)
        addResult("reads", items.metadata.shared.diagnostics.physical_read_calls)
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "has_error": False,
        "count": 2,
        "first_key": "ab",
        "first_match": 0x1000,
        "second_key": "ba",
        "second_match": 0x1001,
        "mode": "first",
        "termination": "first_hit",
        "reads": 1,
    }
