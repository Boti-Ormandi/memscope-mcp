"""Run live-process scanning and reader benchmarks for the checked-out source tree."""

from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pymem.memory
from pydantic import BaseModel

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.allocation import measure_peak_python_bytes
from benchmarks.scanning.common import (
    address_checksum,
    environment_metadata,
    percentile,
    sha256_json,
    summarize,
    validate_raw_artifact,
    write_raw_artifact,
)
from benchmarks.scanning.manifest import CASES, BenchmarkCase
from benchmarks.scanning.process_target import (
    PAGE_NOACCESS,
    PAGE_READWRITE,
    ControlledProcessTarget,
    TargetMetadata,
)
from memscope_mcp.scanning.contract import ScanInput
from memscope_mcp.scanning.execution import ScanExecutor
from memscope_mcp.scanning.reader import READ_CHUNK_SIZE
from memscope_mcp.session import DebugSession

PROCESS_CASE_KINDS = frozenset(
    {
        "reader_ceiling",
        "e2e",
        "fragmented",
        "boundary",
        "allocation",
        "writable_filter",
        "section_filter",
        "chunk_sweep",
        "chunk_salvage",
        "chunk_timeout",
    }
)
CHUNK_SELECTION_BASELINE = 128 * 1024
PRODUCTION_CHUNK_SIZE = READ_CHUNK_SIZE
_CHUNK_THROUGHPUT_PREFIX = "chunk.exact.nohit."
_CHUNK_SALVAGE_PREFIX = "chunk.salvage.holes."
_CHUNK_TIMEOUT_PREFIX = "chunk.timeout100.masked."

if ctypes.sizeof(ctypes.c_void_p) == 8:
    _SIZE_T = ctypes.c_uint64
else:
    _SIZE_T = ctypes.c_uint32

if hasattr(ctypes, "WinDLL"):
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        _SIZE_T,
        ctypes.POINTER(_SIZE_T),
    ]
    _kernel32.ReadProcessMemory.restype = ctypes.c_int
    _kernel32.VirtualProtectEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        _SIZE_T,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    _kernel32.VirtualProtectEx.restype = ctypes.c_int
else:
    _kernel32 = None


class BenchmarkFailure(RuntimeError):
    """Raised when live evidence fails correctness or selection policy."""


class _InstrumentedIO:
    def __init__(self, after_query_memory: Callable[[Any], None] | None = None) -> None:
        self.after_query_memory = after_query_memory
        self.virtual_query_calls = 0
        self.read_calls = 0
        self.bytes_requested = 0
        self.bytes_returned = 0
        self.failed_read_calls = 0
        self.read_ranges: list[tuple[int, int]] = []
        self.read_call_durations_ns: list[int] = []

    def query_memory(self, process_handle: int, address: int):
        self.virtual_query_calls += 1
        result = pymem.memory.virtual_query(process_handle, address)
        if self.after_query_memory is not None:
            self.after_query_memory(result)
        return result

    def read_memory(self, process_handle: int, address: int, size: int) -> bytes:
        self.read_calls += 1
        self.bytes_requested += size
        started = time.perf_counter_ns()
        try:
            payload = pymem.memory.read_bytes(process_handle, address, size)
        except Exception:
            self.failed_read_calls += 1
            raise
        finally:
            self.read_call_durations_ns.append(time.perf_counter_ns() - started)
        data = bytes(payload)
        self.bytes_returned += len(data)
        self.read_ranges.append((address, address + len(data)))
        return data

    def metrics(self) -> dict[str, Any]:
        return {
            "virtual_query_calls": self.virtual_query_calls,
            "physical_read_calls": self.read_calls,
            "physical_bytes_requested": self.bytes_requested,
            "physical_bytes_read": self.bytes_returned,
            "failed_read_calls": self.failed_read_calls,
            "read_call_p95_ns": percentile(self.read_call_durations_ns, 95),
            "read_call_max_ns": max(self.read_call_durations_ns, default=0),
            "read_ranges_sha256": sha256_json(self.read_ranges),
        }


class _RawReader:
    def __init__(self, process_handle: int, chunk_size: int, *, capture_sha256: bool = False) -> None:
        if _kernel32 is None:
            raise RuntimeError("raw ReadProcessMemory benchmarks require Windows")
        self.process_handle = process_handle
        self.chunk_size = chunk_size
        self.buffer = ctypes.create_string_buffer(chunk_size)
        self.call_durations_ns: list[int] = []
        self.calls = 0
        self.bytes_read = 0
        self._hasher = hashlib.sha256() if capture_sha256 else None

    @property
    def sha256(self) -> str | None:
        return None if self._hasher is None else self._hasher.hexdigest()

    def read_range(self, start: int, end_exclusive: int) -> None:
        cursor = start
        while cursor < end_exclusive:
            size = min(self.chunk_size, end_exclusive - cursor)
            transferred = _SIZE_T()
            started = time.perf_counter_ns()
            succeeded = _kernel32.ReadProcessMemory(
                self.process_handle,
                cursor,
                self.buffer,
                size,
                ctypes.byref(transferred),
            )
            duration = time.perf_counter_ns() - started
            self.call_durations_ns.append(duration)
            self.calls += 1
            if not succeeded or transferred.value != size:
                raise OSError(
                    ctypes.get_last_error(),
                    f"ReadProcessMemory returned {transferred.value} of {size} bytes at 0x{cursor:X}",
                )
            self.bytes_read += size
            if self._hasher is not None:
                self._hasher.update(memoryview(self.buffer)[:size])
            cursor += size


def run_process_suite(
    *,
    repo_root: Path,
    profile: str,
    warmups: int,
    repetitions: int,
    implementation_label: str = "candidate",
    case_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Run selected controlled-process cases and return one validated raw artifact."""

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
        raise BenchmarkFailure("Git identity is required for raw benchmark evidence")

    cases = [_run_case(case, profile=profile, warmups=warmups, repetitions=repetitions) for case in selected]
    chunk_selection = _chunk_selection_for_run(
        cases,
        profile=profile,
        warmups=warmups,
        repetitions=repetitions,
    )
    artifact = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "suite": "scanning.process",
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
            "chunk_selection": chunk_selection,
        },
        "cases": cases,
    }
    validate_raw_artifact(artifact)
    return artifact


def select_production_chunk(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Apply the locked throughput-plus-latency chunk selection policy."""

    by_size: dict[int, dict[str, dict[str, Any]]] = {}
    for case in cases:
        case_id = str(case.get("case_id", ""))
        role = None
        if case_id.startswith(_CHUNK_THROUGHPUT_PREFIX):
            role = "throughput"
        elif case_id.startswith(_CHUNK_SALVAGE_PREFIX):
            role = "salvage"
        elif case_id.startswith(_CHUNK_TIMEOUT_PREFIX):
            role = "timeout"
        if role is None:
            continue
        manifest = case.get("manifest")
        if not isinstance(manifest, dict):
            raise BenchmarkFailure(f"{case_id}: manifest is missing")
        parameters = manifest.get("parameters")
        if not isinstance(parameters, dict):
            raise BenchmarkFailure(f"{case_id}: manifest parameters are missing")
        chunk_size = int(parameters["chunk_size"])
        by_size.setdefault(chunk_size, {})[role] = case

    if not by_size or any(set(roles) != {"throughput", "salvage", "timeout"} for roles in by_size.values()):
        raise BenchmarkFailure("chunk selection requires throughput, salvage, and timeout evidence for every size")
    if CHUNK_SELECTION_BASELINE not in by_size:
        raise BenchmarkFailure("chunk selection requires the 128 KiB provisional baseline")

    candidates: dict[int, dict[str, Any]] = {}
    for chunk_size, roles in sorted(by_size.items()):
        throughput = _summary_median(roles["throughput"], "throughput_mib_s")
        salvage = _summary_p95(roles["salvage"], "duration_ns")
        timeout = _work_summary_p95(roles["timeout"], "timeout_overshoot_ns")
        correct = all(_case_complete_and_correct(case) for case in roles.values())
        candidates[chunk_size] = {
            "chunk_size": chunk_size,
            "throughput_mib_s": throughput,
            "salvage_p95_ns": salvage,
            "timeout_overshoot_p95_ns": timeout,
            "correct": correct,
        }

    best_throughput = max(float(candidate["throughput_mib_s"]) for candidate in candidates.values())
    baseline = candidates[CHUNK_SELECTION_BASELINE]
    throughput_floor = best_throughput * 0.90
    salvage_ceiling = float(baseline["salvage_p95_ns"]) * 1.10
    timeout_ceiling = max(25_000_000.0, float(baseline["timeout_overshoot_p95_ns"]) * 1.10)

    eligible = [
        candidate
        for candidate in candidates.values()
        if candidate["correct"]
        and float(candidate["throughput_mib_s"]) >= throughput_floor
        and float(candidate["salvage_p95_ns"]) <= salvage_ceiling
        and float(candidate["timeout_overshoot_p95_ns"]) <= timeout_ceiling
    ]
    if not eligible:
        return {
            "policy": "smallest_within_10_percent_of_best_preserving_128k_latency",
            "status": "inconclusive",
            "selected_chunk_size": None,
            "reason": "no chunk size satisfies throughput, salvage, and timeout constraints",
            "best_throughput_mib_s": best_throughput,
            "throughput_floor_mib_s": throughput_floor,
            "salvage_ceiling_ns": salvage_ceiling,
            "timeout_overshoot_ceiling_ns": timeout_ceiling,
            "provisional_chunk_size": CHUNK_SELECTION_BASELINE,
            "candidates": [candidates[size] for size in sorted(candidates)],
        }
    selected = min(eligible, key=lambda candidate: int(candidate["chunk_size"]))
    return {
        "policy": "smallest_within_10_percent_of_best_preserving_128k_latency",
        "status": "selected",
        "selected_chunk_size": int(selected["chunk_size"]),
        "best_throughput_mib_s": best_throughput,
        "throughput_floor_mib_s": throughput_floor,
        "salvage_ceiling_ns": salvage_ceiling,
        "timeout_overshoot_ceiling_ns": timeout_ceiling,
        "provisional_chunk_size": CHUNK_SELECTION_BASELINE,
        "candidates": [candidates[size] for size in sorted(candidates)],
    }


def _chunk_selection_for_run(
    cases: list[dict[str, Any]],
    *,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any] | None:
    if not _has_complete_chunk_matrix(cases):
        return None
    selection = select_production_chunk(cases)
    if profile == "release" and warmups >= 1 and repetitions >= 3:
        return selection
    diagnostic_selection = selection.get("selected_chunk_size")
    return {
        **selection,
        "status": "insufficient_protocol",
        "selected_chunk_size": None,
        "diagnostic_selected_chunk_size": diagnostic_selection,
        "reason": "production selection requires release profile, at least one warmup, and three repetitions",
    }


def _run_case(
    case: BenchmarkCase,
    *,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    with ControlledProcessTarget(case, profile) as target:
        metadata = _require_metadata(target)
        _validate_target_metadata(case, profile, metadata)
        session = DebugSession()
        if not session.switch_process("", pid=metadata.pid):
            raise BenchmarkFailure(f"{case.case_id}: could not attach to controlled child {metadata.pid}")
        try:
            _preflight(case, target, metadata, session)
            for _ in range(warmups):
                _measure_case_once(case, metadata, session, trace_allocations=False)
            observations = [
                _measure_case_once(
                    case,
                    metadata,
                    session,
                    trace_allocations=case.kind == "allocation",
                )
                for _ in range(repetitions)
            ]
        finally:
            session.detach()

    manifest = case.semantic_descriptor(profile)
    semantic_fingerprint = sha256_json(
        {
            "case": manifest,
            "fixture_version": metadata.fixture_version,
            "fixture_source_sha256": metadata.fixture_source_sha256,
            "topology_fingerprint": metadata.topology_fingerprint,
            "corpus_sha256": metadata.corpus_sha256,
            "expected_count": len(metadata.expected_addresses),
            "expected_checksum": metadata.expected_checksum,
        }
    )
    return {
        "case_id": case.case_id,
        "tier": case.tier,
        "layer": case.layer,
        "comparison_class": case.comparison_class,
        "semantic_fingerprint": semantic_fingerprint,
        "manifest": manifest,
        "corpus": {
            "corpus_version": CORPUS_VERSION,
            "profile": profile,
            "size": metadata.logical_size,
            "sha256": metadata.corpus_sha256,
            "fixture_version": metadata.fixture_version,
            "fixture_source_sha256": metadata.fixture_source_sha256,
            "topology": metadata.topology,
            "topology_fingerprint": metadata.topology_fingerprint,
        },
        "expected": {
            "returned_count": len(metadata.expected_addresses),
            "address_checksum": metadata.expected_checksum,
            "inaccessible_ranges": [list(item) for item in metadata.inaccessible_ranges],
            "readonly_ranges": [list(item) for item in metadata.readonly_ranges],
        },
        "observations": observations,
        "summary": _summarize_observations(observations),
        "status": "complete",
    }


def _preflight(
    case: BenchmarkCase,
    target: ControlledProcessTarget,
    metadata: TargetMetadata,
    session: DebugSession,
) -> None:
    target.ping()
    if case.kind == "reader_ceiling":
        with session.acquire_scan_lease() as lease:
            reader = _RawReader(
                lease.process_handle,
                int(case.parameters["chunk_size"]),
                capture_sha256=True,
            )
            reader.read_range(metadata.base_address, metadata.end_exclusive)
            if reader.bytes_read != metadata.logical_size:
                raise BenchmarkFailure(f"{case.case_id}: raw reader did not cover the complete target")
            if reader.sha256 != metadata.corpus_sha256:
                raise BenchmarkFailure(f"{case.case_id}: raw reader corpus hash mismatch")
        return
    if case.kind in {"chunk_timeout"}:
        return

    io = _InstrumentedIO()
    executor = ScanExecutor(
        session,
        chunk_size=int(case.parameters.get("chunk_size", PRODUCTION_CHUNK_SIZE)),
        query_memory=io.query_memory,
        read_memory=io.read_memory,
    )
    request = _scan_request(case, metadata, mode_override="addresses")
    payload = _response_payload(executor.execute(request))
    if not payload.get("success"):
        raise BenchmarkFailure(f"{case.case_id}: preflight scan failed: {payload}")
    addresses = _response_addresses(payload)
    expected = list(metadata.expected_addresses)
    if addresses != expected:
        observed_checksum = address_checksum(addresses)
        raise BenchmarkFailure(
            f"{case.case_id}: preflight address mismatch ({observed_checksum} != {metadata.expected_checksum})"
        )
    _assert_excluded_ranges_not_read(case, metadata, io.read_ranges)


def _measure_case_once(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    session: DebugSession,
    *,
    trace_allocations: bool,
) -> dict[str, Any]:
    if case.kind == "reader_ceiling":
        return _measure_raw_reader(case, metadata, session)

    mutation_done = False
    mutation_address = metadata.base_address + 8 * metadata.page_size
    process_handle = _session_process_handle(session)

    def mutate_after_query(memory_info: Any) -> None:
        nonlocal mutation_done
        if case.kind != "chunk_salvage" or mutation_done:
            return
        region_base = int(getattr(memory_info, "BaseAddress"))
        region_size = int(getattr(memory_info, "RegionSize"))
        if region_base <= mutation_address < region_base + region_size:
            _virtual_protect_ex(
                process_handle,
                mutation_address,
                metadata.page_size,
                PAGE_NOACCESS,
            )
            mutation_done = True

    io = _InstrumentedIO(mutate_after_query if case.kind == "chunk_salvage" else None)
    executor = ScanExecutor(
        session,
        chunk_size=int(case.parameters.get("chunk_size", PRODUCTION_CHUNK_SIZE)),
        query_memory=io.query_memory,
        read_memory=io.read_memory,
    )
    request = _scan_request(case, metadata)

    def operation() -> tuple[dict[str, Any], int]:
        gc_was_enabled = gc.isenabled()
        if gc_was_enabled:
            gc.disable()
        try:
            started = time.perf_counter_ns()
            response = _response_payload(executor.execute(request))
            duration_ns = time.perf_counter_ns() - started
        finally:
            if gc_was_enabled:
                gc.enable()
        return response, duration_ns

    peak_python_bytes = None
    try:
        if trace_allocations:
            (payload, duration_ns), peak_python_bytes = measure_peak_python_bytes(operation)
        else:
            payload, duration_ns = operation()
    finally:
        if mutation_done:
            _virtual_protect_ex(
                process_handle,
                mutation_address,
                metadata.page_size,
                PAGE_READWRITE,
            )
    if not payload.get("success"):
        raise BenchmarkFailure(f"{case.case_id}: candidate scan failed: {payload}")

    termination = str(payload["status"]["termination"])
    timeout_case = case.kind == "chunk_timeout"
    if timeout_case:
        correct = termination in {"timeout", "scope_exhausted", "match_limit"}
    else:
        correct = _response_matches_expected(case, payload, metadata)
    if not correct:
        raise BenchmarkFailure(f"{case.case_id}: candidate result differs from controlled target expectation")
    _assert_excluded_ranges_not_read(case, metadata, io.read_ranges)

    diagnostics = payload.get("diagnostics") or {}
    logical_bytes = int(diagnostics.get("unique_bytes_examined", 0))
    throughput = _throughput_mib_s(logical_bytes, duration_ns)
    timeout_overshoot_ns = max(0, duration_ns - case.timeout_ms * 1_000_000) if termination == "timeout" else 0
    return {
        "duration_ns": max(1, duration_ns),
        "throughput_mib_s": throughput,
        "work": {
            **io.metrics(),
            "unique_bytes_examined": logical_bytes,
            "candidate_count": int(diagnostics.get("candidate_count", 0)),
            "verification_count": int(diagnostics.get("verification_count", 0)),
            "control_polls": int(diagnostics.get("control_polls", 0)),
            "region_count": int(diagnostics.get("region_count", 0)),
            "span_count": int(diagnostics.get("span_count", 0)),
            "strategy_counts": dict(diagnostics.get("strategy_counts", {})),
            "sections": list(diagnostics.get("sections", [])),
            "read_gaps_detected": bool(payload["status"]["read_gaps_detected"]),
            "termination": termination,
            "actual_count": _response_count(payload),
            "expected_count": len(metadata.expected_addresses),
            "actual_checksum": address_checksum(_response_addresses(payload)) if case.mode != "count" else None,
            "expected_checksum": metadata.expected_checksum if case.mode != "count" else None,
            "correct": correct,
            "chunk_size": int(case.parameters.get("chunk_size", PRODUCTION_CHUNK_SIZE)),
            "timeout_overshoot_ns": timeout_overshoot_ns,
            "peak_python_bytes": peak_python_bytes,
        },
    }


def _measure_raw_reader(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    session: DebugSession,
) -> dict[str, Any]:
    chunk_size = int(case.parameters["chunk_size"])
    with session.acquire_scan_lease() as lease:
        reader = _RawReader(lease.process_handle, chunk_size)
        started = time.perf_counter_ns()
        reader.read_range(metadata.base_address, metadata.end_exclusive)
        duration_ns = time.perf_counter_ns() - started
    correct = reader.bytes_read == metadata.logical_size
    if not correct:
        raise BenchmarkFailure(f"{case.case_id}: raw reader returned incomplete data")
    return {
        "duration_ns": max(1, duration_ns),
        "throughput_mib_s": _throughput_mib_s(metadata.logical_size, duration_ns),
        "work": {
            "physical_read_calls": reader.calls,
            "physical_bytes_requested": reader.bytes_read,
            "physical_bytes_read": reader.bytes_read,
            "read_call_p95_ns": percentile(reader.call_durations_ns, 95),
            "read_call_max_ns": max(reader.call_durations_ns, default=0),
            "correct": correct,
            "chunk_size": chunk_size,
        },
    }


def _scan_request(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    *,
    mode_override: str | None = None,
) -> ScanInput:
    mode = mode_override or case.mode
    if case.kind == "section_filter":
        scope: dict[str, Any] = {
            "kind": "modules",
            "names": [str(metadata.module["name"])],
            "filters": {"sections": [str(case.parameters["section"])]},
        }
    else:
        filters: dict[str, Any] = {}
        if case.kind == "writable_filter":
            filters["writable"] = "required"
        scope = {
            "kind": "range",
            "start": metadata.base_address,
            "end_exclusive": metadata.end_exclusive,
            "filters": filters,
        }

    payload: dict[str, Any] = {
        "pattern": case.pattern,
        "scope": scope,
        "mode": mode,
        "timeout_ms": 30_000 if mode_override is not None else case.timeout_ms,
        "diagnostics": True,
    }
    if mode == "addresses":
        expected_count = len(metadata.expected_addresses)
        if expected_count > 500:
            raise BenchmarkFailure(f"{case.case_id}: address preflight exceeds the public 500-result page bound")
        payload["limit"] = max(1, min(500, expected_count))
        payload["max_matches"] = max(1, expected_count)
    elif mode == "count":
        payload["max_matches"] = case.max_matches or 100_000
    return ScanInput.model_validate(payload)


def _response_payload(response: BaseModel) -> dict[str, Any]:
    root = getattr(response, "root", response)
    if not isinstance(root, BaseModel):
        raise TypeError("scan response must contain a Pydantic model")
    return root.model_dump(mode="json")


def _response_addresses(payload: dict[str, Any]) -> list[int]:
    if payload.get("mode") == "addresses":
        return [int(item["address"], 16) for item in payload["matches"]]
    if payload.get("mode") == "first":
        match = payload.get("match")
        return [] if match is None else [int(match["address"], 16)]
    return []


def _response_count(payload: dict[str, Any]) -> int:
    if payload.get("mode") == "count":
        return int(payload["count"])
    return len(_response_addresses(payload))


def _response_matches_expected(case: BenchmarkCase, payload: dict[str, Any], metadata: TargetMetadata) -> bool:
    expected = list(metadata.expected_addresses)
    if case.mode == "count":
        return _response_count(payload) == len(expected)
    if case.mode == "first":
        expected = expected[:1]
    elif case.mode == "addresses":
        expected = expected[: case.limit or len(expected)]
    addresses = _response_addresses(payload)
    return addresses == expected and address_checksum(addresses) == address_checksum(expected)


def _assert_excluded_ranges_not_read(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    read_ranges: list[tuple[int, int]],
) -> None:
    excluded = metadata.inaccessible_ranges
    if case.kind == "writable_filter":
        excluded = (*excluded, *metadata.readonly_ranges)
    for read_start, read_end in read_ranges:
        for excluded_start, excluded_end in excluded:
            if read_start < excluded_end and excluded_start < read_end:
                raise BenchmarkFailure(
                    f"{case.case_id}: read 0x{read_start:X}-0x{read_end:X} overlaps excluded "
                    f"0x{excluded_start:X}-0x{excluded_end:X}"
                )


def _validate_target_metadata(case: BenchmarkCase, profile: str, metadata: TargetMetadata) -> None:
    if metadata.pid <= 0 or metadata.base_address <= 0 or metadata.end_exclusive <= metadata.base_address:
        raise BenchmarkFailure(f"{case.case_id}: controlled target identity is invalid")
    if metadata.logical_size != metadata.end_exclusive - metadata.base_address:
        raise BenchmarkFailure(f"{case.case_id}: controlled target range is inconsistent")
    if metadata.expected_checksum != address_checksum(metadata.expected_addresses):
        raise BenchmarkFailure(f"{case.case_id}: controlled target expected checksum is invalid")
    if metadata.topology_fingerprint != sha256_json(metadata.topology):
        raise BenchmarkFailure(f"{case.case_id}: controlled target topology fingerprint is invalid")
    if metadata.topology.get("case_id") != case.case_id or metadata.topology.get("profile") != profile:
        raise BenchmarkFailure(f"{case.case_id}: controlled target topology identity is invalid")


def _require_metadata(target: ControlledProcessTarget) -> TargetMetadata:
    if target.metadata is None:
        raise RuntimeError("controlled target did not publish metadata")
    return target.metadata


def _summarize_observations(observations: list[dict[str, Any]]) -> dict[str, Any]:
    work = [observation["work"] for observation in observations]
    work_fields = (
        "physical_read_calls",
        "physical_bytes_requested",
        "physical_bytes_read",
        "failed_read_calls",
        "unique_bytes_examined",
        "candidate_count",
        "verification_count",
        "control_polls",
        "timeout_overshoot_ns",
        "peak_python_bytes",
    )
    return {
        "duration_ns": summarize([float(observation["duration_ns"]) for observation in observations]),
        "throughput_mib_s": summarize([float(observation["throughput_mib_s"]) for observation in observations]),
        "work": {
            field: summarize([float(item[field]) for item in work if isinstance(item.get(field), (int, float))])
            for field in work_fields
        },
        "all_correct": all(bool(item.get("correct")) for item in work),
    }


def _case_complete_and_correct(case: dict[str, Any]) -> bool:
    summary = case.get("summary")
    return case.get("status") == "complete" and isinstance(summary, dict) and summary.get("all_correct") is True


def _summary_median(case: dict[str, Any], field: str) -> float:
    summary = case["summary"][field]
    value = summary["median"]
    if value is None:
        raise BenchmarkFailure(f"{case['case_id']}: {field} median is missing")
    return float(value)


def _summary_p95(case: dict[str, Any], field: str) -> float:
    summary = case["summary"][field]
    value = summary["p95"]
    if value is None:
        raise BenchmarkFailure(f"{case['case_id']}: {field} p95 is missing")
    return float(value)


def _work_summary_p95(case: dict[str, Any], field: str) -> float:
    summary = case["summary"]["work"][field]
    value = summary["p95"]
    if value is None:
        raise BenchmarkFailure(f"{case['case_id']}: work.{field} p95 is missing")
    return float(value)


def _has_complete_chunk_matrix(cases: list[dict[str, Any]]) -> bool:
    ids = {case["case_id"] for case in cases}
    throughput = {
        case_id.removeprefix(_CHUNK_THROUGHPUT_PREFIX)
        for case_id in ids
        if case_id.startswith(_CHUNK_THROUGHPUT_PREFIX)
    }
    salvage = {
        case_id.removeprefix(_CHUNK_SALVAGE_PREFIX) for case_id in ids if case_id.startswith(_CHUNK_SALVAGE_PREFIX)
    }
    timeout = {
        case_id.removeprefix(_CHUNK_TIMEOUT_PREFIX) for case_id in ids if case_id.startswith(_CHUNK_TIMEOUT_PREFIX)
    }
    return bool(throughput) and throughput == salvage == timeout


def _throughput_mib_s(byte_count: int, duration_ns: int) -> float:
    if duration_ns <= 0:
        return 0.0
    return byte_count / (1024 * 1024) / (duration_ns / 1_000_000_000)


def _session_process_handle(session: DebugSession) -> int:
    if session.pm is None:
        raise BenchmarkFailure("controlled target session is detached")
    raw = session.pm.process_handle
    value = getattr(raw, "value", raw)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BenchmarkFailure("controlled target process handle is unavailable")
    return value


def _virtual_protect_ex(
    process_handle: int,
    address: int,
    size: int,
    protection: int,
) -> int:
    if _kernel32 is None:
        raise RuntimeError("VirtualProtectEx requires Windows")
    old = ctypes.c_uint32()
    if not _kernel32.VirtualProtectEx(
        process_handle,
        address,
        size,
        protection,
        ctypes.byref(old),
    ):
        raise OSError(ctypes.get_last_error(), f"VirtualProtectEx failed at 0x{address:X}")
    return int(old.value)


def _select_cases(case_ids: tuple[str, ...] | None) -> tuple[BenchmarkCase, ...]:
    available = tuple(case for case in CASES if case.kind in PROCESS_CASE_KINDS)
    if case_ids is None:
        return available
    requested = set(case_ids)
    if len(requested) != len(case_ids):
        raise ValueError("case_ids must not contain duplicates")
    selected = tuple(case for case in available if case.case_id in requested)
    missing = requested - {case.case_id for case in selected}
    if missing:
        raise ValueError(f"unknown process benchmark case_ids: {', '.join(sorted(missing))}")
    return selected


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--implementation-label", default="candidate")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    output = arguments.output or repo_root / "benchmark-results" / f"process-{arguments.profile}.json"
    artifact = run_process_suite(
        repo_root=repo_root,
        profile=arguments.profile,
        warmups=arguments.warmups,
        repetitions=arguments.repetitions,
        implementation_label=arguments.implementation_label,
        case_ids=None if arguments.case_ids is None else tuple(arguments.case_ids),
    )
    write_raw_artifact(output, artifact)
    for case in artifact["cases"]:
        duration = case["summary"]["duration_ns"]["median"]
        throughput = case["summary"]["throughput_mib_s"]["median"]
        print(f"{case['case_id']}: {duration / 1_000_000:.3f} ms, {throughput:.2f} MiB/s")
    selection = artifact["runner"].get("chunk_selection")
    if selection is not None and selection["selected_chunk_size"] is not None:
        print(f"selected production chunk: {selection['selected_chunk_size'] // 1024} KiB")
    elif selection is not None:
        print(f"chunk selection inconclusive: {selection['reason']}")
    print(f"wrote {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
