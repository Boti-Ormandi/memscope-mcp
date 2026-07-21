"""Deterministic cursor, batch, and control evidence for the scanning engine."""

from __future__ import annotations

import argparse
import asyncio
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.common import (
    environment_metadata,
    sha256_bytes,
    sha256_json,
    summarize,
    validate_raw_artifact,
    write_raw_artifact,
)
from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanManySuccess,
    CountScanSuccess,
    FirstScanManySuccess,
    RangeScopeInput,
    ScanFailure,
    ScanInput,
    ScanManyInput,
)
from memscope_mcp.scanning.cursor import CursorCodec
from memscope_mcp.scanning.execution import ScanExecutor, execute_scan_async
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease
from memscope_mcp.scanning.planner import MEM_COMMIT, MEM_PRIVATE, PAGE_READWRITE

_BASE_ADDRESS = 0x1000


class EvidenceFailure(RuntimeError):
    """Raised when a deterministic evidence invariant is violated."""


@dataclass(frozen=True, slots=True)
class EvidenceCase:
    case_id: str
    group: str
    comparison_class: str
    description: str
    tier: str = "headline"
    layer: str = "engine"

    def manifest(self, profile: str) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "group": self.group,
            "comparison_class": self.comparison_class,
            "description": self.description,
            "profile": profile,
            "layer": self.layer,
        }


CASES: tuple[EvidenceCase, ...] = (
    EvidenceCase(
        "cursor.pages10.limit50.no_earlier_work",
        "Cursor",
        "eliminated_work",
        (
            "Ten dense pages resume at the first unexamined address with no earlier logical work "
            "or continuation lookahead."
        ),
    ),
    EvidenceCase(
        "batch.first16.one_pass",
        "Batch",
        "eliminated_work",
        "Sixteen first-hit queries share one traversal and match independent scans.",
    ),
    EvidenceCase(
        "batch.count4.one_pass",
        "Batch",
        "eliminated_work",
        "Four no-hit count queries share one traversal and avoid repeated physical reads.",
    ),
    EvidenceCase(
        "control.injected_deadline",
        "Control",
        "new_capability",
        "An injected clock terminates work at a deterministic deadline checkpoint and releases the lease.",
    ),
    EvidenceCase(
        "control.in_band_cancellation",
        "Control",
        "new_capability",
        "An already-signalled request cancellation performs no target read and releases the lease.",
    ),
    EvidenceCase(
        "control.target_change",
        "Control",
        "new_capability",
        "A changed attachment returns a stable failure without a cursor or target read and releases the lease.",
    ),
    EvidenceCase(
        "control.async_responsiveness",
        "Control",
        "new_capability",
        "A blocked worker read does not block unrelated request-loop progress.",
    ),
    EvidenceCase(
        "control.task_cancellation_cleanup",
        "Control",
        "new_capability",
        "Transport task cancellation waits for cooperative worker cleanup and then propagates.",
    ),
)
CASE_BY_ID = {case.case_id: case for case in CASES}


class TrackingSession:
    def __init__(self, lease: ScanLease) -> None:
        self.lease = lease
        self.active = 0
        self.acquire_count = 0
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


class StepClock:
    def __init__(self) -> None:
        self.value = 0
        self.calls = 0

    def __call__(self) -> int:
        current = self.value
        self.value += 1
        self.calls += 1
        return current


def run_engine_suite(
    *,
    repo_root: Path,
    profile: str,
    warmups: int,
    repetitions: int,
    implementation_label: str = "candidate",
    case_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Run selected deterministic engine cases and return a validated raw artifact."""

    if profile not in {"smoke", "release"}:
        raise ValueError("profile must be 'smoke' or 'release'")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
        raise ValueError("warmups must be a non-negative integer")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if not implementation_label:
        raise ValueError("implementation_label must be non-empty")

    selected = _select_cases(case_ids)
    environment = environment_metadata(
        target_root=repo_root,
        implementation=implementation_label,
        profile=profile,
    )
    git = environment["git"]
    if not isinstance(git, dict) or not isinstance(git.get("commit"), str) or not isinstance(git.get("dirty"), bool):
        raise EvidenceFailure("Git identity is required for raw benchmark evidence")

    artifact = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "suite": "scanning.engine-control",
        "implementation": {
            "label": implementation_label,
            "git_commit": git["commit"],
            "git_dirty": git["dirty"],
        },
        "generated_at": environment["timestamp_utc"],
        "environment": environment,
        "runner": {
            "profile": profile,
            "warmups": warmups,
            "repetitions": repetitions,
            "selected_case_ids": [case.case_id for case in selected],
        },
        "cases": [_run_case(case, profile=profile, warmups=warmups, repetitions=repetitions) for case in selected],
    }
    validate_raw_artifact(artifact)
    return artifact


def _run_case(
    case: EvidenceCase,
    *,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    exercise = _EXERCISES[case.case_id]
    validation = exercise()
    if not validation["work"].get("correct"):
        raise EvidenceFailure(f"{case.case_id}: deterministic validation failed")
    for _ in range(warmups):
        exercise()
    observations = [exercise() for _ in range(repetitions)]
    if not all(observation["work"].get("correct") for observation in observations):
        raise EvidenceFailure(f"{case.case_id}: an observation failed correctness")

    manifest = case.manifest(profile)
    expected = validation["expected"]
    corpus = validation["corpus"]
    return {
        "case_id": case.case_id,
        "tier": case.tier,
        "layer": case.layer,
        "comparison_class": case.comparison_class,
        "semantic_fingerprint": sha256_json(
            {
                "manifest_version": MANIFEST_VERSION,
                "corpus_version": CORPUS_VERSION,
                "manifest": manifest,
                "corpus": corpus,
                "expected": expected,
            }
        ),
        "manifest": manifest,
        "corpus": corpus,
        "expected": expected,
        "observations": [
            {
                "duration_ns": max(1, int(observation["duration_ns"])),
                "throughput_mib_s": float(observation.get("throughput_mib_s", 0.0)),
                "work": observation["work"],
            }
            for observation in observations
        ],
        "summary": {
            "duration_ns": summarize([float(observation["duration_ns"]) for observation in observations]),
            "throughput_mib_s": summarize(
                [float(observation.get("throughput_mib_s", 0.0)) for observation in observations]
            ),
            "all_correct": True,
        },
        "status": "complete",
    }


def _cursor_pages() -> dict[str, Any]:
    memory = b"A" * 601
    executor, session, reads, scope = _make_executor(memory, chunk_size=64)
    cursor: str | None = None
    addresses: list[int] = []
    page_reads: list[list[tuple[int, int]]] = []
    page_candidates: list[int] = []
    resume_addresses: list[int] = []
    started = time.perf_counter_ns()
    for page_index in range(10):
        reads.clear()
        request = (
            ScanInput(
                pattern="41",
                scope=scope,
                mode="addresses",
                limit=50,
                max_matches=1000,
                diagnostics=True,
            )
            if cursor is None
            else ScanInput(cursor=cursor, limit=50, diagnostics=True)
        )
        response = executor.execute(request)
        if not isinstance(response.root, AddressScanSuccess):
            raise EvidenceFailure("cursor case did not return an address page")
        page = response.root
        expected_page = list(range(_BASE_ADDRESS + page_index * 50, _BASE_ADDRESS + (page_index + 1) * 50))
        actual_page = [int(hit.address, 16) for hit in page.matches]
        if actual_page != expected_page:
            raise EvidenceFailure("cursor page addresses differ from the deterministic sequence")
        if page.diagnostics is None or page.diagnostics.candidate_count != 50:
            raise EvidenceFailure("cursor page performed candidate work beyond its declared limit")
        if page.diagnostics.physical_cursor_prefix_bytes != 0:
            raise EvidenceFailure("cursor page reported an earlier physical prefix")
        if page.next_cursor is None or page.status.termination != "page_limit":
            raise EvidenceFailure("cursor page did not stop exactly at its page boundary")
        state = executor.cursor_codec.decode(page.next_cursor)
        expected_resume = _BASE_ADDRESS + (page_index + 1) * 50
        if state.resume_address != expected_resume:
            raise EvidenceFailure("cursor resume address is not the first unexamined candidate")
        if reads and min(address for address, _size in reads) < _BASE_ADDRESS + page_index * 50:
            raise EvidenceFailure("cursor continuation reread an earlier logical address")
        addresses.extend(actual_page)
        page_reads.append(list(reads))
        page_candidates.append(page.diagnostics.candidate_count)
        resume_addresses.append(state.resume_address)
        cursor = page.next_cursor
    duration_ns = time.perf_counter_ns() - started
    if session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("cursor scan retained its lease")

    physical_bytes = sum(size for group in page_reads for _address, size in group)
    throughput = len(addresses) / (1024 * 1024) / (duration_ns / 1_000_000_000) if duration_ns else 0.0
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": throughput,
        "corpus": {"kind": "dense-bytes", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {
            "pages": 10,
            "matches": 500,
            "last_resume_address": _BASE_ADDRESS + 500,
            "post_limit_candidate_work": 0,
            "logical_bytes_before_resume": 0,
        },
        "work": {
            "correct": addresses == list(range(_BASE_ADDRESS, _BASE_ADDRESS + 500)),
            "pages": 10,
            "matches": len(addresses),
            "candidate_counts": page_candidates,
            "resume_addresses": resume_addresses,
            "physical_read_calls": sum(len(group) for group in page_reads),
            "physical_bytes_read": physical_bytes,
            "logical_bytes_before_resume": 0,
            "post_limit_candidate_work": 0,
            "lease_acquisitions": session.acquire_count,
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _batch_first() -> dict[str, Any]:
    memory = bytearray(4096)
    patterns: list[tuple[str, str, int]] = []
    for index in range(16):
        data = bytes((0xE0, index + 1, 0xD0, 0xC0))
        offset = 32 + index * 96
        memory[offset : offset + len(data)] = data
        patterns.append((f"p{index:02d}", data.hex(" ").upper(), _BASE_ADDRESS + offset))
    return _batch_observation(bytes(memory), patterns, mode="first", max_matches=None)


def _batch_count() -> dict[str, Any]:
    memory = bytes(4096)
    patterns = [(f"p{index:02d}", bytes((0xF0, index + 1, 0xEE)).hex(" ").upper(), 0) for index in range(4)]
    return _batch_observation(memory, patterns, mode="count", max_matches=5000)


def _batch_observation(
    memory: bytes,
    patterns: list[tuple[str, str, int]],
    *,
    mode: str,
    max_matches: int | None,
) -> dict[str, Any]:
    batch_executor, batch_session, batch_reads, scope = _make_executor(memory, chunk_size=256)
    payload: dict[str, Any] = {
        "patterns": [{"key": key, "pattern": pattern} for key, pattern, _expected in patterns],
        "scope": scope.model_dump(mode="python"),
        "mode": mode,
        "diagnostics": True,
    }
    if max_matches is not None:
        payload["max_matches"] = max_matches
    started = time.perf_counter_ns()
    batch_response = batch_executor.execute_many(ScanManyInput.model_validate(payload))
    batch_duration_ns = time.perf_counter_ns() - started
    if not isinstance(batch_response.root, (FirstScanManySuccess, CountScanManySuccess)):
        raise EvidenceFailure("batch evidence did not return a successful batch")
    shared = batch_response.root.shared
    if shared.diagnostics is None:
        raise EvidenceFailure("batch evidence requires shared diagnostics")

    batch_values: dict[str, int] = {}
    if isinstance(batch_response.root, FirstScanManySuccess):
        for item in batch_response.root.results:
            batch_values[item.key] = 0 if item.match is None else int(item.match.address, 16)
    else:
        for item in batch_response.root.results:
            batch_values[item.key] = item.count

    separate_values: dict[str, int] = {}
    separate_reads = 0
    separate_bytes = 0
    separate_duration_ns = 0
    for key, pattern, _expected in patterns:
        executor, session, reads, independent_scope = _make_executor(memory, chunk_size=256)
        request_payload: dict[str, Any] = {
            "pattern": pattern,
            "scope": independent_scope.model_dump(mode="python"),
            "mode": mode,
            "diagnostics": True,
        }
        if mode == "count":
            request_payload["max_matches"] = max_matches
        request = ScanInput.model_validate(request_payload)
        started = time.perf_counter_ns()
        response = executor.execute(request)
        separate_duration_ns += time.perf_counter_ns() - started
        if mode == "first":
            if response.root.mode != "first":
                raise EvidenceFailure("independent first scan returned the wrong mode")
            separate_values[key] = 0 if response.root.match is None else int(response.root.match.address, 16)
        else:
            if not isinstance(response.root, CountScanSuccess):
                raise EvidenceFailure("independent count scan returned the wrong mode")
            separate_values[key] = response.root.count
        separate_reads += len(reads)
        separate_bytes += sum(size for _address, size in reads)
        if session.active != 0 or not session.released.is_set():
            raise EvidenceFailure("independent scan retained its lease")

    expected_values = {key: (expected if mode == "first" else 0) for key, _pattern, expected in patterns}
    batch_bytes = sum(size for _address, size in batch_reads)
    correct = batch_values == expected_values == separate_values
    if not correct:
        raise EvidenceFailure("batch and independent scans differ")
    if not batch_reads or separate_reads <= len(batch_reads) or separate_bytes <= batch_bytes:
        raise EvidenceFailure("batch did not eliminate repeated physical reads")
    if batch_session.active != 0 or not batch_session.released.is_set():
        raise EvidenceFailure("batch scan retained its lease")

    throughput = len(memory) / (1024 * 1024) / (batch_duration_ns / 1_000_000_000) if batch_duration_ns else 0.0
    return {
        "duration_ns": batch_duration_ns,
        "throughput_mib_s": throughput,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {
            "mode": mode,
            "patterns": len(patterns),
            "values": expected_values,
            "region_passes": 1,
        },
        "work": {
            "correct": correct,
            "mode": mode,
            "patterns": len(patterns),
            "batch_values": batch_values,
            "independent_values": separate_values,
            "batch_duration_ns": batch_duration_ns,
            "separate_duration_ns": separate_duration_ns,
            "batch_physical_read_calls": len(batch_reads),
            "separate_physical_read_calls": separate_reads,
            "batch_physical_bytes_read": batch_bytes,
            "separate_physical_bytes_read": separate_bytes,
            "region_passes": 1,
            "read_reduction_fraction": 1.0 - batch_bytes / separate_bytes,
            "lease_released": batch_session.active == 0 and batch_session.released.is_set(),
        },
    }


def _injected_deadline() -> dict[str, Any]:
    memory = b"A" * 4096
    clock = StepClock()
    executor, session, reads, scope = _make_executor(memory, chunk_size=32, clock=clock)
    started = time.perf_counter_ns()
    response = executor.execute(
        ScanInput(pattern="42", scope=scope, mode="count", max_matches=5000, diagnostics=True),
        deadline_ns=12,
    )
    duration_ns = time.perf_counter_ns() - started
    if not isinstance(response.root, CountScanSuccess) or response.root.status.termination != "timeout":
        raise EvidenceFailure("injected deadline did not produce a timeout response")
    if response.root.diagnostics is None:
        raise EvidenceFailure("injected deadline evidence requires diagnostics")
    if session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("deadline termination retained its lease")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {"termination": "timeout", "deadline_tick": 12, "lease_released": True},
        "work": {
            "correct": True,
            "termination": response.root.status.termination,
            "clock_calls": clock.calls,
            "clock_tick_after_stop": clock.value,
            "deadline_tick": 12,
            "logical_tick_overshoot": max(0, clock.value - 12),
            "control_polls": response.root.diagnostics.control_polls,
            "physical_read_calls": len(reads),
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _in_band_cancellation() -> dict[str, Any]:
    memory = b"A" * 64
    executor, session, reads, scope = _make_executor(memory)
    cancellation = threading.Event()
    cancellation.set()
    started = time.perf_counter_ns()
    response = executor.execute(
        ScanInput(pattern="41", scope=scope, mode="addresses", limit=1, diagnostics=True),
        request_cancel=cancellation,
    )
    duration_ns = time.perf_counter_ns() - started
    if not isinstance(response.root, AddressScanSuccess) or response.root.status.termination != "cancelled":
        raise EvidenceFailure("in-band cancellation did not produce a cancelled response")
    if response.root.next_cursor is not None or reads:
        raise EvidenceFailure("cancelled scan produced a cursor or target read")
    if session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("cancelled scan retained its lease")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {"termination": "cancelled", "physical_read_calls": 0, "next_cursor": None},
        "work": {
            "correct": True,
            "termination": response.root.status.termination,
            "physical_read_calls": 0,
            "next_cursor": response.root.next_cursor,
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _target_change() -> dict[str, Any]:
    memory = b"A" * 64
    executor, session, reads, scope = _make_executor(memory)
    session.lease.lifecycle_cancel.set()
    started = time.perf_counter_ns()
    response = executor.execute(ScanInput(pattern="41", scope=scope, mode="addresses", limit=1))
    duration_ns = time.perf_counter_ns() - started
    if not isinstance(response.root, ScanFailure) or response.root.error != "TARGET_CHANGED":
        raise EvidenceFailure("target change did not produce the stable application failure")
    if reads:
        raise EvidenceFailure("target-changed scan performed a target read")
    if session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("target-changed scan retained its lease")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {"error": "TARGET_CHANGED", "physical_read_calls": 0},
        "work": {
            "correct": True,
            "error": response.root.error,
            "physical_read_calls": 0,
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _async_responsiveness() -> dict[str, Any]:
    memory = b"A" * 64
    read_started = threading.Event()
    release_read = threading.Event()

    def block_read(_address: int, _size: int) -> None:
        read_started.set()
        if not release_read.wait(2):
            raise EvidenceFailure("blocked read was not released")

    executor, session, reads, scope = _make_executor(memory, read_hook=block_read)

    async def scenario() -> tuple[bool, str]:
        task = asyncio.create_task(
            execute_scan_async(
                executor,
                ScanInput(pattern="42", scope=scope, mode="count", max_matches=5000, timeout_ms=1000),
            )
        )
        while not read_started.is_set():
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        unrelated_progress = not task.done()
        release_read.set()
        response = await task
        if not isinstance(response.root, CountScanSuccess):
            raise EvidenceFailure("async scan returned the wrong response type")
        return unrelated_progress, response.root.status.termination

    started = time.perf_counter_ns()
    unrelated_progress, termination = asyncio.run(scenario())
    duration_ns = time.perf_counter_ns() - started
    if not unrelated_progress or termination != "scope_exhausted":
        raise EvidenceFailure("request loop did not progress independently of the scan worker")
    if session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("async scan retained its lease")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {"unrelated_progress": True, "termination": "scope_exhausted"},
        "work": {
            "correct": True,
            "unrelated_progress": unrelated_progress,
            "scan_completed_after_progress": True,
            "termination": termination,
            "physical_read_calls": len(reads),
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _task_cancellation_cleanup() -> dict[str, Any]:
    memory = b"A" * 64
    read_started = threading.Event()
    release_read = threading.Event()

    def block_read(_address: int, _size: int) -> None:
        read_started.set()
        if not release_read.wait(2):
            raise EvidenceFailure("cancelled worker read was not released")

    executor, session, reads, scope = _make_executor(memory, read_hook=block_read, chunk_size=1)

    async def scenario() -> bool:
        task = asyncio.create_task(
            execute_scan_async(
                executor,
                ScanInput(pattern="42", scope=scope, mode="count", max_matches=5000, timeout_ms=30_000),
            )
        )
        while not read_started.is_set():
            await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        propagated_before_cleanup = task.done()
        release_read.set()
        try:
            await task
        except asyncio.CancelledError:
            return not propagated_before_cleanup
        raise EvidenceFailure("transport cancellation did not propagate")

    started = time.perf_counter_ns()
    waited_for_cleanup = asyncio.run(scenario())
    duration_ns = time.perf_counter_ns() - started
    if not waited_for_cleanup or session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("transport cancellation abandoned the active lease")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(memory)},
        "expected": {"cancelled_error_propagated": True, "worker_cleanup_precedes_propagation": True},
        "work": {
            "correct": True,
            "cancelled_error_propagated": True,
            "worker_cleanup_precedes_propagation": waited_for_cleanup,
            "physical_read_calls": len(reads),
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _make_lease() -> ScanLease:
    return ScanLease(
        generation=1,
        pid=123,
        process_handle=1,
        target_process="Target.exe",
        modules=ModuleSnapshot.create((), generation=1),
        lifecycle_cancel=threading.Event(),
    )


def _make_executor(
    memory: bytes,
    *,
    base: int = _BASE_ADDRESS,
    chunk_size: int = 128 * 1024,
    clock: Callable[[], int] = time.monotonic_ns,
    read_hook: Callable[[int, int], None] | None = None,
) -> tuple[ScanExecutor, TrackingSession, list[tuple[int, int]], RangeScopeInput]:
    session = TrackingSession(_make_lease())
    reads: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        if not base <= address < base + len(memory):
            raise OSError(f"unmapped address 0x{address:X}")
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(memory),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_PRIVATE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        reads.append((address, size))
        if read_hook is not None:
            read_hook(address, size)
        offset = address - base
        return memory[offset : offset + size]

    executor = ScanExecutor(
        session,
        cursor_codec=CursorCodec(secret=b"e" * 32, instance_id=b"v" * 16),
        query_memory=query,
        read_memory=read,
        target_alive=lambda _handle: True,
        chunk_size=chunk_size,
        page_size=1,
        clock=clock,
    )
    return executor, session, reads, RangeScopeInput(kind="range", start=base, end_exclusive=base + len(memory))


_EXERCISES: dict[str, Callable[[], dict[str, Any]]] = {
    "cursor.pages10.limit50.no_earlier_work": _cursor_pages,
    "batch.first16.one_pass": _batch_first,
    "batch.count4.one_pass": _batch_count,
    "control.injected_deadline": _injected_deadline,
    "control.in_band_cancellation": _in_band_cancellation,
    "control.target_change": _target_change,
    "control.async_responsiveness": _async_responsiveness,
    "control.task_cancellation_cleanup": _task_cancellation_cleanup,
}


def _select_cases(case_ids: tuple[str, ...] | None) -> tuple[EvidenceCase, ...]:
    if case_ids is None:
        return CASES
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("case_ids must not contain duplicates")
    unknown = sorted(set(case_ids) - CASE_BY_ID.keys())
    if unknown:
        raise ValueError(f"unknown engine evidence case_ids: {', '.join(unknown)}")
    wanted = set(case_ids)
    return tuple(case for case in CASES if case.case_id in wanted)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--warmups", type=int, default=0)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--implementation-label", default="candidate")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    artifact = run_engine_suite(
        repo_root=repo_root,
        profile=arguments.profile,
        warmups=arguments.warmups,
        repetitions=arguments.repetitions,
        implementation_label=arguments.implementation_label,
        case_ids=None if arguments.case_ids is None else tuple(arguments.case_ids),
    )
    if arguments.output is not None:
        write_raw_artifact(arguments.output, artifact)
    else:
        import json

        print(json.dumps(artifact, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
