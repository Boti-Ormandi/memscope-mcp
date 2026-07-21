"""One-pass batch scanning and remote PE-section filter tests."""

from __future__ import annotations

import asyncio
import struct
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from memscope_mcp.scanning.contract import (
    CountScanManySuccess,
    FirstScanManySuccess,
    ModulesScopeInput,
    RangeScopeInput,
    ScanFailure,
    ScanFiltersInput,
    ScanInput,
    ScanManyInput,
)
from memscope_mcp.scanning.execution import ScanExecutor, execute_scan_many_async
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease, build_module_records
from memscope_mcp.scanning.planner import MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_READWRITE


class FakeSession:
    def __init__(self, lease: ScanLease) -> None:
        self.lease = lease
        self.acquire_count = 0

    @contextmanager
    def acquire_scan_lease(self):
        self.acquire_count += 1
        yield self.lease


def _lease(module_values=(), *, generation: int = 1) -> ScanLease:
    snapshot = ModuleSnapshot.create(build_module_records(module_values), generation=generation)
    return ScanLease(
        generation=generation,
        pid=123,
        process_handle=1,
        target_process="Target.exe",
        modules=snapshot,
        lifecycle_cancel=threading.Event(),
    )


def _module(name: str, base: int, image: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        lpBaseOfDll=base,
        SizeOfImage=len(image),
        filename=rf"C:\Target\{name}",
    )


def _range_executor(
    memory: bytes,
    *,
    base: int = 0x1000,
    chunk_size: int = 128 * 1024,
):
    session = FakeSession(_lease())
    reads: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        if not base <= address < base + len(memory):
            raise OSError("unmapped")
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(memory),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_PRIVATE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        reads.append((address, size))
        offset = address - base
        return memory[offset : offset + size]

    executor = ScanExecutor(
        session,
        query_memory=query,
        read_memory=read,
        target_alive=lambda _handle: True,
        chunk_size=chunk_size,
        page_size=1,
    )
    scope = RangeScopeInput(kind="range", start=base, end_exclusive=base + len(memory))
    return executor, session, reads, scope


def _pe_image(section_names: tuple[str, ...] = (".text", ".data")) -> bytearray:
    image = bytearray(0x500)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x86, len(section_names))
    struct.pack_into("<H", image, 0x94, 0xF0)
    table = 0x80 + 24 + 0xF0
    for index, name in enumerate(section_names):
        offset = table + index * 40
        encoded = name.encode("ascii")[:8]
        image[offset : offset + len(encoded)] = encoded
        virtual_address = 0x200 + index * 0x100
        struct.pack_into("<III", image, offset + 8, 0x40, virtual_address, 0x40)
    return image


def test_scan_many_first_mode_uses_one_physical_read_and_preserves_input_order():
    executor, _session, reads, scope = _range_executor(b"ABABA")
    request = ScanManyInput.model_validate(
        {
            "patterns": [
                {"key": "ab", "pattern": "41 42"},
                {"key": "ba", "pattern": "42 41"},
            ],
            "scope": scope.model_dump(mode="python"),
            "mode": "first",
            "diagnostics": True,
        }
    )

    response = executor.execute_many(request)
    assert isinstance(response.root, FirstScanManySuccess)
    assert [item.key for item in response.root.results] == ["ab", "ba"]
    assert [item.match.address for item in response.root.results if item.match is not None] == ["0x1000", "0x1001"]
    assert response.root.shared.termination == "first_hit"
    assert response.root.shared.diagnostics is not None
    assert response.root.shared.diagnostics.physical_read_calls == 1
    assert reads == [(0x1000, 5)]


def test_scan_many_shared_tail_shrinks_after_longest_query_completes():
    executor, _session, reads, scope = _range_executor(b"ABCDEF0YZA", chunk_size=2)
    response = executor.execute_many(
        ScanManyInput.model_validate(
            {
                "patterns": [
                    {"key": "long", "pattern": "41 42 43 44 45 46"},
                    {"key": "later", "pattern": "59 5A 41"},
                ],
                "scope": scope.model_dump(mode="python"),
                "mode": "first",
            }
        )
    )

    assert isinstance(response.root, FirstScanManySuccess)
    assert [item.match.address for item in response.root.results if item.match is not None] == [
        "0x1000",
        "0x1007",
    ]
    assert reads == [
        (0x1000, 2),
        (0x1002, 2),
        (0x1004, 2),
        (0x1006, 2),
        (0x1008, 2),
    ]


def test_scan_many_count_caps_each_pattern_independently():
    executor, _session, reads, scope = _range_executor(b"AAAAAA")
    request = ScanManyInput.model_validate(
        {
            "patterns": [
                {"key": "single", "pattern": "41"},
                {"key": "triple", "pattern": "41 41 41"},
            ],
            "scope": scope.model_dump(mode="python"),
            "mode": "count",
            "max_matches": 2,
            "diagnostics": True,
        }
    )

    response = executor.execute_many(request)
    assert isinstance(response.root, CountScanManySuccess)
    assert [(item.key, item.count, item.status.termination) for item in response.root.results] == [
        ("single", 2, "match_limit"),
        ("triple", 2, "match_limit"),
    ]
    assert response.root.shared.termination == "match_limit"
    assert response.root.shared.diagnostics is not None
    assert response.root.shared.diagnostics.physical_read_calls == 1
    assert reads == [(0x1000, 6)]


def test_scan_many_first_mode_keeps_per_item_completion_status():
    executor, _session, _reads, scope = _range_executor(b"ABCD")
    request = ScanManyInput.model_validate(
        {
            "patterns": [
                {"key": "found", "pattern": "41 42"},
                {"key": "missing", "pattern": "FF"},
            ],
            "scope": scope.model_dump(mode="python"),
            "mode": "first",
        }
    )

    response = executor.execute_many(request)
    assert isinstance(response.root, FirstScanManySuccess)
    assert response.root.results[0].status.termination == "first_hit"
    assert response.root.results[1].status.termination == "scope_exhausted"
    assert response.root.shared.termination == "scope_exhausted"


def test_scan_many_rejects_duplicate_keys_and_address_mode_at_validation():
    with pytest.raises(ValidationError):
        ScanManyInput.model_validate(
            {
                "patterns": [
                    {"key": "same", "pattern": "41"},
                    {"key": "same", "pattern": "42"},
                ]
            }
        )
    with pytest.raises(ValidationError):
        ScanManyInput.model_validate(
            {
                "patterns": [{"key": "one", "pattern": "41"}],
                "mode": "addresses",
            }
        )


def test_scan_many_compiles_every_pattern_before_acquiring_a_lease():
    executor, session, _reads, scope = _range_executor(b"AAAA")
    request = ScanManyInput.model_validate(
        {
            "patterns": [
                {"key": "valid", "pattern": "41"},
                {"key": "invalid", "pattern": "GG"},
            ],
            "scope": scope.model_dump(mode="python"),
        }
    )

    response = executor.execute_many(request)
    assert isinstance(response.root, ScanFailure)
    assert response.root.error == "INVALID_PATTERN"
    assert response.root.field == "patterns[1].pattern"
    assert session.acquire_count == 0


def test_section_filter_reads_only_selected_scan_bytes_and_reports_remote_name():
    base = 0x1000
    image = _pe_image()
    image[0x210:0x212] = b"\xde\xad"
    image[0x310:0x312] = b"\xde\xad"
    module = _module("target.dll", base, image)
    session = FakeSession(_lease((module,)))
    reads: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(image),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_IMAGE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        reads.append((address, size))
        offset = address - base
        return bytes(image[offset : offset + size])

    executor = ScanExecutor(session, query_memory=query, read_memory=read, target_alive=lambda _handle: True)
    request = ScanInput(
        pattern="DE AD",
        scope=ModulesScopeInput(
            kind="modules",
            names=["target.dll"],
            filters=ScanFiltersInput(sections=[".TEXT"]),
        ),
        diagnostics=True,
    )

    first = executor.execute(request)
    assert first.root.success is True
    assert [hit.address for hit in first.root.matches] == ["0x1210"]
    assert first.root.diagnostics is not None
    assert first.root.diagnostics.sections == [".text"]
    assert len(first.root.diagnostics.scope_fingerprint) == 64
    assert first.root.diagnostics.physical_read_calls == 4
    assert reads[-1] == (0x1200, 0x40)
    assert not any(address < 0x1340 and address + size > 0x1300 for address, size in reads)

    reads_before = len(reads)
    second = executor.execute(request)
    assert second.root.success is True
    assert second.root.diagnostics is not None
    assert second.root.diagnostics.physical_read_calls == 1
    assert len(reads) == reads_before + 1


def test_missing_section_in_any_selected_module_fails_before_virtual_query():
    first_base = 0x1000
    second_base = 0x2000
    first_image = _pe_image((".text",))
    second_image = _pe_image((".rdata",))
    modules = (
        _module("first.dll", first_base, first_image),
        _module("second.dll", second_base, second_image),
    )
    session = FakeSession(_lease(modules))
    query_calls: list[int] = []

    def query(_handle: int, address: int):
        query_calls.append(address)
        raise AssertionError("VirtualQuery must not run before all section names resolve")

    def read(_handle: int, address: int, size: int) -> bytes:
        if first_base <= address < first_base + len(first_image):
            image = first_image
            base = first_base
        else:
            image = second_image
            base = second_base
        offset = address - base
        return bytes(image[offset : offset + size])

    executor = ScanExecutor(session, query_memory=query, read_memory=read, target_alive=lambda _handle: True)
    response = executor.execute(
        ScanInput(
            pattern="41",
            scope=ModulesScopeInput(
                kind="modules",
                names=["first.dll", "second.dll"],
                filters=ScanFiltersInput(sections=[".text"]),
            ),
        )
    )

    assert isinstance(response.root, ScanFailure)
    assert response.root.error == "SECTION_NOT_FOUND"
    assert "second.dll" in response.root.detail
    assert query_calls == []


class TrackingSession(FakeSession):
    def __init__(self, lease: ScanLease) -> None:
        super().__init__(lease)
        self.active = 0
        self.acquired = threading.Event()
        self.released = threading.Event()
        self._lock = threading.Lock()

    @contextmanager
    def acquire_scan_lease(self):
        with self._lock:
            self.acquire_count += 1
            self.active += 1
            self.acquired.set()
            self.released.clear()
        try:
            yield self.lease
        finally:
            with self._lock:
                self.active -= 1
                if self.active == 0:
                    self.released.set()


def test_scan_many_matches_independent_scans_under_section_filters():
    base = 0x1000
    image = _pe_image()
    image[0x200:0x220] = b"ABABACABABADABAB" + b"\x00" * 4
    image[0x300:0x320] = b"ABABABABABABABAB" + b"\x00" * 4
    module = _module("target.dll", base, image)
    session = FakeSession(_lease((module,)))
    corpus_reads: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(image),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_IMAGE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        corpus_reads.append((address, size))
        offset = address - base
        return bytes(image[offset : offset + size])

    executor = ScanExecutor(session, query_memory=query, read_memory=read, target_alive=lambda _handle: True)
    scope = ModulesScopeInput(
        kind="modules",
        names=["target.dll"],
        filters=ScanFiltersInput(sections=[".text"]),
    )
    patterns = [
        ("exact", "41 42 41"),
        ("masked", "41 ?? 41"),
        ("wildcard", "?? ??"),
        ("missing", "FF EE"),
    ]

    for mode in ("first", "count"):
        payload = {
            "patterns": [{"key": key, "pattern": pattern} for key, pattern in patterns],
            "scope": scope.model_dump(mode="python"),
            "mode": mode,
            "diagnostics": True,
        }
        if mode == "count":
            payload["max_matches"] = 100
        corpus_reads.clear()
        batch = executor.execute_many(ScanManyInput.model_validate(payload))
        batch_corpus_reads = [item for item in corpus_reads if item[0] >= base + 0x200]
        assert batch_corpus_reads == [(base + 0x200, 0x40)]

        if mode == "first":
            assert isinstance(batch.root, FirstScanManySuccess)
            for batch_item, (key, pattern) in zip(batch.root.results, patterns, strict=True):
                independent = executor.execute(ScanInput(pattern=pattern, scope=scope, mode="first"))
                assert independent.root.success is True
                assert batch_item.key == key
                assert batch_item.match == independent.root.match
                assert batch_item.status == independent.root.status
        else:
            assert isinstance(batch.root, CountScanManySuccess)
            for batch_item, (key, pattern) in zip(batch.root.results, patterns, strict=True):
                independent = executor.execute(
                    ScanInput(
                        pattern=pattern,
                        scope=scope,
                        mode="count",
                        max_matches=100,
                    )
                )
                assert independent.root.success is True
                assert batch_item.key == key
                assert batch_item.count == independent.root.count
                assert batch_item.observation == independent.root.observation
                assert batch_item.status == independent.root.status


def test_section_cache_invalidates_when_attachment_fingerprint_changes():
    base = 0x1000
    first_image = _pe_image((".text",))
    second_image = _pe_image((".rdata",))
    active_image = first_image
    first_module = _module("target.dll", base, first_image)
    session = FakeSession(_lease((first_module,), generation=1))
    reads: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(active_image),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_IMAGE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        reads.append((address, size))
        offset = address - base
        return bytes(active_image[offset : offset + size])

    executor = ScanExecutor(session, query_memory=query, read_memory=read, target_alive=lambda _handle: True)
    request = ScanInput(
        pattern="41",
        scope=ModulesScopeInput(
            kind="modules",
            names=["target.dll"],
            filters=ScanFiltersInput(sections=[".text"]),
        ),
    )
    assert executor.execute(request).root.success is True

    active_image = second_image
    second_module = _module("target.dll", base, second_image)
    session.lease = _lease((second_module,), generation=2)
    reads_before = len(reads)
    response = executor.execute(request)

    assert isinstance(response.root, ScanFailure)
    assert response.root.error == "SECTION_NOT_FOUND"
    assert len(reads) > reads_before


def test_scan_many_async_cancellation_waits_for_lease_release():
    base = 0x1000
    memory = b"A" * 512
    session = TrackingSession(_lease())

    def query(_handle: int, address: int):
        if not base <= address < base + len(memory):
            raise OSError("unmapped")
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(memory),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_PRIVATE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        time.sleep(0.005)
        offset = address - base
        return memory[offset : offset + size]

    executor = ScanExecutor(
        session,
        query_memory=query,
        read_memory=read,
        target_alive=lambda _handle: True,
        chunk_size=1,
        page_size=1,
    )
    request = ScanManyInput.model_validate(
        {
            "patterns": [
                {"key": "missing-a", "pattern": "42"},
                {"key": "missing-b", "pattern": "43"},
            ],
            "scope": {
                "kind": "range",
                "start": base,
                "end_exclusive": base + len(memory),
            },
            "mode": "first",
            "timeout_ms": 30_000,
        }
    )

    async def scenario():
        task = asyncio.create_task(execute_scan_many_async(executor, request))
        while not session.acquired.is_set():
            await asyncio.sleep(0)
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert session.released.is_set()
        assert session.active == 0

    asyncio.run(scenario())
