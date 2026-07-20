"""Continuation cursor, exact resume, and asynchronous scan execution tests."""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP

from memscope_mcp.scanning.boundary import register_strict_model_tool
from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanSuccess,
    FirstScanSuccess,
    RangeScopeInput,
    ScanFailure,
    ScanInput,
    ScanResponse,
    scan_input_validation_failure,
)
from memscope_mcp.scanning.cursor import CursorCodec, CursorError
from memscope_mcp.scanning.execution import ScanExecutor, execute_scan_async
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease, build_module_records
from memscope_mcp.scanning.planner import MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_READWRITE


class FakeSession:
    def __init__(self, lease: ScanLease) -> None:
        self.lease = lease
        self.active = 0
        self.acquired = threading.Event()
        self.released = threading.Event()
        self._lock = threading.Lock()

    @contextmanager
    def acquire_scan_lease(self):
        with self._lock:
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


def make_lease(*, generation: int = 1, pid: int = 123, module_values=()) -> ScanLease:
    modules = ModuleSnapshot.create(build_module_records(module_values), generation=generation)
    return ScanLease(
        generation=generation,
        pid=pid,
        process_handle=1,
        target_process="Target.exe",
        modules=modules,
        lifecycle_cancel=threading.Event(),
    )


def make_executor(
    memory: bytes,
    *,
    base: int = 0x1000,
    session: FakeSession | None = None,
    codec: CursorCodec | None = None,
    chunk_size: int = 128 * 1024,
    memory_type: int = MEM_PRIVATE,
    read_hook=None,
):
    active_session = session or FakeSession(make_lease())
    read_calls: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        if not base <= address < base + len(memory):
            raise OSError(f"unmapped address 0x{address:X}")
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(memory),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=memory_type,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        read_calls.append((address, size))
        if read_hook is not None:
            read_hook(address, size)
        offset = address - base
        return memory[offset : offset + size]

    executor = ScanExecutor(
        active_session,
        cursor_codec=codec or CursorCodec(secret=b"s" * 32, instance_id=b"i" * 16),
        query_memory=query,
        read_memory=read,
        target_alive=lambda _handle: True,
        chunk_size=chunk_size,
        page_size=1,
    )
    return executor, active_session, read_calls


def range_scope(base: int, size: int) -> RangeScopeInput:
    return RangeScopeInput(kind="range", start=base, end_exclusive=base + size)


def address_result(response) -> AddressScanSuccess:
    assert isinstance(response.root, AddressScanSuccess)
    return response.root


def failure_result(response) -> ScanFailure:
    assert isinstance(response.root, ScanFailure)
    return response.root


def first_result(response) -> FirstScanSuccess:
    assert isinstance(response.root, FirstScanSuccess)
    return response.root


def count_result(response) -> CountScanSuccess:
    assert isinstance(response.root, CountScanSuccess)
    return response.root


def test_cursor_round_trip_is_self_contained_and_tamper_evident():
    executor, _session, _reads = make_executor(b"AAAAA")
    first = address_result(
        executor.execute(
            ScanInput(
                pattern="41 41",
                scope=range_scope(0x1000, 5),
                limit=2,
                max_matches=10,
            )
        )
    )

    assert first.next_cursor is not None
    state = executor.cursor_codec.decode(first.next_cursor)
    assert state.session_generation == 1
    assert state.pid == 123
    assert state.resume_address == 0x1002
    assert state.matches_returned_before == 2
    assert state.max_matches == 10
    assert state.query.pattern_bytes == b"AA"
    assert state.query.mask == b"\xff\xff"
    assert state.scope.range_start == 0x1000
    assert state.scope.range_end_exclusive == 0x1005

    parts = first.next_cursor.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(CursorError) as captured:
        executor.cursor_codec.decode(".".join(parts))
    assert captured.value.error == "INVALID_CURSOR"


def test_cursor_from_another_server_instance_is_stale():
    executor, session, _reads = make_executor(b"AAAA")
    first = address_result(executor.execute(ScanInput(pattern="41", scope=range_scope(0x1000, 4), limit=2)))
    other, _same_session, _other_reads = make_executor(
        b"AAAA",
        session=session,
        codec=CursorCodec(secret=b"t" * 32, instance_id=b"j" * 16),
    )

    failure = failure_result(other.execute(ScanInput(cursor=first.next_cursor)))

    assert failure.error == "CURSOR_STALE"
    assert failure.field == "cursor"


def test_generation_pid_and_module_refresh_identity_make_cursor_stale():
    executor, session, _reads = make_executor(b"AAAA")
    first = address_result(executor.execute(ScanInput(pattern="41", scope=range_scope(0x1000, 4), limit=2)))
    session.lease = make_lease(generation=2, pid=123)

    failure = failure_result(executor.execute(ScanInput(cursor=first.next_cursor)))

    assert failure.error == "CURSOR_STALE"
    assert "generation" in failure.detail


def test_continuation_starts_reads_and_logical_candidates_at_resume_address():
    executor, _session, reads = make_executor(b"AAAAA")
    first = address_result(
        executor.execute(
            ScanInput(
                pattern="41 41",
                scope=range_scope(0x1000, 5),
                limit=2,
                diagnostics=True,
            )
        )
    )
    reads.clear()

    second = address_result(
        executor.execute(
            ScanInput(
                cursor=first.next_cursor,
                limit=2,
                diagnostics=True,
            )
        )
    )

    assert [hit.address for hit in first.matches] == ["0x1000", "0x1001"]
    assert [hit.address for hit in second.matches] == ["0x1002", "0x1003"]
    assert reads and min(address for address, _size in reads) == 0x1002
    assert second.diagnostics is not None
    assert second.diagnostics.candidate_count == 2
    assert second.diagnostics.physical_cursor_prefix_bytes == 0
    assert second.sequence_returned_count == 4
    assert second.next_cursor is not None

    reads.clear()
    terminal = address_result(executor.execute(ScanInput(cursor=second.next_cursor)))
    assert terminal.matches == []
    assert terminal.status.termination == "scope_exhausted"
    assert terminal.next_cursor is None
    assert reads == [(0x1004, 1)]


def test_cumulative_match_cap_stops_without_a_cursor_or_hidden_match():
    executor, _session, _reads = make_executor(b"AAAAA")
    first = address_result(
        executor.execute(
            ScanInput(
                pattern="41 41",
                scope=range_scope(0x1000, 5),
                limit=2,
                max_matches=3,
            )
        )
    )

    second = address_result(executor.execute(ScanInput(cursor=first.next_cursor, limit=2, diagnostics=True)))

    assert [hit.address for hit in second.matches] == ["0x1002"]
    assert second.sequence_returned_count == 3
    assert second.status.termination == "match_limit"
    assert second.next_cursor is None
    assert second.diagnostics is not None
    assert second.diagnostics.candidate_count == 1


def test_sticky_read_gap_state_survives_a_later_clean_page():
    executor, _session, _reads = make_executor(b"AAAAA")
    first = address_result(executor.execute(ScanInput(pattern="41 41", scope=range_scope(0x1000, 5), limit=2)))
    state = executor.cursor_codec.decode(first.next_cursor)
    sticky_cursor = executor.cursor_codec.encode(replace(state, read_gaps_detected=True))

    second = address_result(executor.execute(ScanInput(cursor=sticky_cursor, limit=2)))

    assert second.status.read_gaps_detected is True
    assert second.next_cursor is not None
    carried = executor.cursor_codec.decode(second.next_cursor)
    assert carried.read_gaps_detected is True


def test_async_worker_keeps_the_request_loop_responsive():
    read_started = threading.Event()
    release_read = threading.Event()

    def block_read(_address: int, _size: int) -> None:
        read_started.set()
        assert release_read.wait(2)

    executor, _session, _reads = make_executor(b"A" * 16, read_hook=block_read)
    request = ScanInput(pattern="42", scope=range_scope(0x1000, 16), timeout_ms=1000)

    async def scenario():
        task = asyncio.create_task(execute_scan_async(executor, request))
        while not read_started.is_set():
            await asyncio.sleep(0)
        await asyncio.sleep(0.01)
        assert not task.done()
        release_read.set()
        response = await task
        assert address_result(response).status.termination == "scope_exhausted"

    asyncio.run(scenario())


def test_task_cancellation_waits_for_worker_lease_release_then_propagates():
    def slow_read(_address: int, _size: int) -> None:
        time.sleep(0.005)

    executor, session, _reads = make_executor(
        b"A" * 512,
        chunk_size=1,
        read_hook=slow_read,
    )
    request = ScanInput(pattern="42", scope=range_scope(0x1000, 512), timeout_ms=30_000)

    async def scenario():
        task = asyncio.create_task(execute_scan_async(executor, request))
        while not session.acquired.is_set():
            await asyncio.sleep(0)
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert session.released.is_set()
        assert session.active == 0

    asyncio.run(scenario())


def test_async_logger_receives_only_the_validated_frozen_response():
    executor, _session, _reads = make_executor(b"ABCD")
    logged = []

    async def scenario():
        response = await execute_scan_async(
            executor,
            ScanInput(pattern="41", scope=range_scope(0x1000, 4)),
            logger=logged.append,
        )
        assert logged == [response]
        with pytest.raises(Exception):
            response.root.success = False

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("pattern", "memory", "expected_offsets"),
    [
        ("41 41", b"AAAA", [0, 1, 2]),
        ("41 ??", b"AxAyAz", [0, 2, 4]),
        ("?? ??", b"ABCD", [0, 1, 2]),
        ("41 ?? 43", b"AqCxxArC", [0, 5]),
    ],
)
def test_cursor_pages_preserve_dense_masked_and_all_wildcard_matches(pattern, memory, expected_offsets):
    executor, _session, _reads = make_executor(memory, chunk_size=2)
    cursor = None
    addresses = []

    while True:
        request = (
            ScanInput(pattern=pattern, scope=range_scope(0x1000, len(memory)), limit=1)
            if cursor is None
            else ScanInput(cursor=cursor, limit=1)
        )
        page = address_result(executor.execute(request))
        addresses.extend(int(hit.address, 16) for hit in page.matches)
        cursor = page.next_cursor
        if cursor is None:
            break

    assert addresses == [0x1000 + offset for offset in expected_offsets]
    assert len(addresses) == len(set(addresses))


def test_continuation_preserves_cross_chunk_matches_without_revisiting_prior_candidates():
    executor, _session, reads = make_executor(b"XXABCABC", chunk_size=4)
    first = address_result(executor.execute(ScanInput(pattern="41 42 43", scope=range_scope(0x1000, 8), limit=1)))
    reads.clear()

    second = address_result(executor.execute(ScanInput(cursor=first.next_cursor, limit=1, diagnostics=True)))

    assert [hit.address for hit in first.matches] == ["0x1002"]
    assert [hit.address for hit in second.matches] == ["0x1005"]
    assert reads and min(address for address, _size in reads) == 0x1003
    assert second.diagnostics is not None
    assert second.diagnostics.candidate_count == 1


def test_first_count_and_module_hit_formatting_use_one_validated_output_contract():
    base = 0x1000
    module_value = SimpleNamespace(
        name="target.dll",
        lpBaseOfDll=base,
        SizeOfImage=5,
        filename=r"C:\Target\target.dll",
    )
    session = FakeSession(make_lease(module_values=(module_value,)))
    executor, _session, _reads = make_executor(
        b"ABABA",
        session=session,
        memory_type=MEM_IMAGE,
    )

    first = first_result(executor.execute(ScanInput(pattern="41 42", mode="first")))
    counted = count_result(executor.execute(ScanInput(pattern="41", mode="count", diagnostics=True)))

    assert first.match is not None
    assert first.match.address == "0x1000"
    assert first.match.module == "target.dll"
    assert first.match.module_offset == "0x0"
    assert first.status.termination == "first_hit"
    assert counted.count == 3
    assert counted.observation == "complete_traversal"
    assert counted.diagnostics is not None
    assert counted.diagnostics.physical_bytes_read == 5


def test_unsafe_cancellation_and_target_change_never_issue_a_cursor():
    executor, session, _reads = make_executor(b"AAAA")
    cancellation = threading.Event()
    cancellation.set()

    cancelled = address_result(
        executor.execute(
            ScanInput(pattern="41", scope=range_scope(0x1000, 4), limit=1),
            request_cancel=cancellation,
        )
    )
    assert cancelled.status.termination == "cancelled"
    assert cancelled.next_cursor is None

    session.lease.lifecycle_cancel.set()
    changed = failure_result(executor.execute(ScanInput(pattern="41", scope=range_scope(0x1000, 4), limit=1)))
    assert changed.error == "TARGET_CHANGED"


def test_cursor_rejects_oversized_malformed_and_unknown_token_versions():
    codec = CursorCodec(secret=b"s" * 32, instance_id=b"i" * 16)
    executor, _session, _reads = make_executor(b"AAAA", codec=codec)
    page = address_result(executor.execute(ScanInput(pattern="41", scope=range_scope(0x1000, 4), limit=1)))

    for token in (
        "x" * 65_537,
        "m1.not-base64.payload.signature",
        page.next_cursor.replace("m1.", "m2.", 1),
        page.next_cursor + "=",
    ):
        with pytest.raises(CursorError) as captured:
            codec.decode(token)
        assert captured.value.error == "INVALID_CURSOR"


def test_real_fastmcp_boundary_runs_the_async_executor_without_route_specific_mutation():
    executor, _session, _reads = make_executor(b"AAAA")
    server = FastMCP("scan-execution-test")

    async def handler(request, _context):
        return await execute_scan_async(executor, request)

    register_strict_model_tool(
        server,
        name="scan",
        description="Internal scan execution proof",
        input_model=ScanInput,
        output_model=ScanResponse,
        handler=handler,
        validation_failure_mapper=scan_input_validation_failure,
    )

    first_result_value = asyncio.run(
        server.call_tool(
            "scan",
            {
                "pattern": "41",
                "scope": {"kind": "range", "start": 0x1000, "end_exclusive": 0x1004},
                "limit": 2,
            },
        )
    )
    _first_content, first_structured = first_result_value
    assert first_structured["matches"] == [
        {"address": "0x1000", "module": None, "module_offset": None},
        {"address": "0x1001", "module": None, "module_offset": None},
    ]
    assert first_structured["next_cursor"] is not None

    second_result_value = asyncio.run(server.call_tool("scan", {"cursor": first_structured["next_cursor"], "limit": 2}))
    _second_content, second_structured = second_result_value
    assert [item["address"] for item in second_structured["matches"]] == ["0x1002", "0x1003"]
    assert second_structured["sequence_returned_count"] == 4
