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
    candidate_watchdog_metrics,
    environment_metadata,
    is_exact_int,
    is_finite_number,
    percentile,
    range_union_size,
    semantic_fingerprint,
    semantic_fingerprint_payload,
    sha256_json,
    summarize,
    timeout_control_error,
    validate_raw_artifact,
    write_raw_artifact,
)
from benchmarks.scanning.manifest import CASES, BenchmarkCase, preflight_protocol, requires_exact_preflight
from benchmarks.scanning.process_target import (
    PAGE_NOACCESS,
    PAGE_READWRITE,
    ControlledProcessTarget,
    TargetMetadata,
    comparison_identity,
    operation_identity,
    relative_address_checksum,
    relative_addresses,
)
from memscope_mcp.scanning.contract import ScanInput
from memscope_mcp.scanning.execution import ScanExecutor
from memscope_mcp.scanning.reader import READ_CHUNK_SIZE
from memscope_mcp.scanning.sections import SectionCache
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
        "section_filter_warm",
        "timeout",
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
_CHUNK_MATRIX_KINDS = frozenset({"chunk_sweep", "chunk_salvage", "chunk_timeout"})
_CHUNK_MATRIX_CASE_IDS = tuple(case.case_id for case in CASES if case.kind in _CHUNK_MATRIX_KINDS)
_CHUNK_MATRIX_SIZES = tuple(int(case.parameters["chunk_size"]) for case in CASES if case.kind == "chunk_sweep")

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
        self.request_sizes: list[int] = []
        self.read_operations: list[dict[str, Any]] = []
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
        self.request_sizes.append(size)
        started = time.perf_counter_ns()
        try:
            payload = pymem.memory.read_bytes(process_handle, address, size)
        except Exception:
            self.failed_read_calls += 1
            self.read_operations.append(
                {"address": address, "requested_size": size, "returned_size": 0, "success": False}
            )
            raise
        finally:
            self.read_call_durations_ns.append(time.perf_counter_ns() - started)
        data = bytes(payload)
        self.bytes_returned += len(data)
        self.read_operations.append(
            {"address": address, "requested_size": size, "returned_size": len(data), "success": True}
        )
        self.read_ranges.append((address, address + len(data)))
        return data

    def metrics(self) -> dict[str, Any]:
        return {
            "virtual_query_calls": self.virtual_query_calls,
            "physical_read_calls": self.read_calls,
            "physical_bytes_requested": self.bytes_requested,
            "physical_bytes_read": self.bytes_returned,
            "physical_read_operations": list(self.read_operations),
            "physical_read_operations_sha256": sha256_json(self.read_operations),
            "physical_request_sizes": list(self.request_sizes),
            "physical_read_sizes": [end - start for start, end in self.read_ranges],
            "physical_read_ranges": [list(item) for item in self.read_ranges],
            "unique_logical_bytes": range_union_size(self.read_ranges),
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
    enforced_outer_watchdog_s: float | None = None,
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
    if enforced_outer_watchdog_s is not None:
        if type(enforced_outer_watchdog_s) is not float:
            raise ValueError("enforced_outer_watchdog_s must be an exact float")
        expected_watchdogs = {
            float(case.semantic_descriptor(profile)["candidate_watchdog_timeout_s"]) for case in selected
        }
        if expected_watchdogs != {enforced_outer_watchdog_s}:
            raise ValueError("enforced outer watchdog does not match every selected case")
    environment = environment_metadata(
        target_root=repo_root,
        implementation=implementation_label,
        profile=profile,
    )
    git = environment["git"]
    if not isinstance(git, dict) or not isinstance(git.get("commit"), str) or not isinstance(git.get("dirty"), bool):
        raise BenchmarkFailure("Git identity is required for raw benchmark evidence")

    cases = [
        _run_case(
            case,
            profile=profile,
            warmups=warmups,
            repetitions=repetitions,
            enforced_outer_watchdog_s=enforced_outer_watchdog_s,
        )
        for case in selected
    ]
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
            "candidate_outer_watchdog": {
                "enforced": enforced_outer_watchdog_s is not None,
                "context": (
                    "paired_parent_outer_watchdog"
                    if enforced_outer_watchdog_s is not None
                    else "standalone_diagnostic_no_outer_watchdog"
                ),
                "timeout_s": enforced_outer_watchdog_s,
            },
            "chunk_selection": chunk_selection,
        },
        "cases": cases,
    }
    validate_raw_artifact(artifact)
    return artifact


def select_production_chunk(
    cases: Iterable[dict[str, Any]],
    *,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    """Apply the production policy only to the exact validated manifest-v5 matrix."""

    if profile not in {"smoke", "release"}:
        raise BenchmarkFailure("chunk selection profile is invalid")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
        raise BenchmarkFailure("chunk selection warmups are invalid")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions < 1:
        raise BenchmarkFailure("chunk selection repetitions are invalid")

    chunk_cases = [
        case
        for case in cases
        if str(case.get("case_id", "")).startswith(
            (_CHUNK_THROUGHPUT_PREFIX, _CHUNK_SALVAGE_PREFIX, _CHUNK_TIMEOUT_PREFIX)
        )
    ]
    case_ids = [str(case.get("case_id", "")) for case in chunk_cases]
    if len(case_ids) != len(set(case_ids)):
        raise BenchmarkFailure("chunk selection contains duplicate case IDs")
    unknown = [case_id for case_id in case_ids if case_id not in _CHUNK_MATRIX_CASE_IDS]
    if unknown:
        raise BenchmarkFailure(f"chunk selection contains unknown manifest case {unknown[0]}")

    by_size: dict[int, dict[str, dict[str, Any]]] = {}
    for case in chunk_cases:
        case_id = str(case["case_id"])
        role = (
            "throughput"
            if case_id.startswith(_CHUNK_THROUGHPUT_PREFIX)
            else "salvage"
            if case_id.startswith(_CHUNK_SALVAGE_PREFIX)
            else "timeout"
        )
        manifest = case.get("manifest")
        if not isinstance(manifest, dict):
            raise BenchmarkFailure(f"{case_id}: manifest is missing")
        parameters = manifest.get("parameters")
        if not isinstance(parameters, dict) or not is_exact_int(parameters.get("chunk_size"), minimum=1):
            raise BenchmarkFailure(f"{case_id}: manifest chunk size is invalid")
        chunk_size = int(parameters["chunk_size"])
        if role in by_size.setdefault(chunk_size, {}):
            raise BenchmarkFailure(f"chunk selection has duplicate {role} evidence for {chunk_size}")
        by_size[chunk_size][role] = case

    candidates: dict[int, dict[str, Any]] = {}
    for chunk_size, roles in sorted(by_size.items()):
        if set(roles) != {"throughput", "salvage", "timeout"}:
            continue
        throughput = _observation_median(roles["throughput"], "throughput_mib_s")
        salvage = _observation_p95(roles["salvage"], "duration_ns")
        timeout = _validated_timeout_p95(roles["timeout"])
        correct = all(_case_complete_and_correct(case) for case in roles.values())
        candidates[chunk_size] = {
            "chunk_size": chunk_size,
            "throughput_mib_s": throughput,
            "salvage_p95_ns": salvage,
            "timeout_overshoot_p95_ns": timeout,
            "correct": correct,
        }

    exact_matrix = case_ids == list(_CHUNK_MATRIX_CASE_IDS)
    complete_sizes = tuple(sorted(candidates)) == tuple(sorted(_CHUNK_MATRIX_SIZES))
    production_protocol = (
        profile == "release" and warmups >= 1 and repetitions >= 3 and _chunk_timeout_watchdogs_enforced(chunk_cases)
    )
    base = {
        "policy": "smallest_within_10_percent_of_best_preserving_128k_latency",
        "profile": profile,
        "warmups": warmups,
        "repetitions": repetitions,
        "timeout_watchdogs_enforced": _chunk_timeout_watchdogs_enforced(chunk_cases),
        "exact_manifest_matrix": exact_matrix and complete_sizes,
        "required_case_ids": list(_CHUNK_MATRIX_CASE_IDS),
        "observed_case_ids": case_ids,
        "provisional_chunk_size": CHUNK_SELECTION_BASELINE,
        "candidates": [candidates[size] for size in sorted(candidates)],
    }
    if not candidates or CHUNK_SELECTION_BASELINE not in candidates:
        return {
            **base,
            "status": "insufficient_matrix",
            "selected_chunk_size": None,
            "diagnostic_selected_chunk_size": None,
            "reason": "the exact complete manifest-v5 chunk matrix is unavailable",
        }

    valid = [candidate for candidate in candidates.values() if candidate["correct"]]
    if not valid:
        return {
            **base,
            "status": "inconclusive" if exact_matrix and production_protocol else "insufficient_matrix",
            "selected_chunk_size": None,
            "diagnostic_selected_chunk_size": None,
            "reason": "no complete correct chunk observations are available",
        }
    best_throughput = max(float(candidate["throughput_mib_s"]) for candidate in valid)
    baseline = candidates[CHUNK_SELECTION_BASELINE]
    throughput_floor = best_throughput * 0.90
    salvage_ceiling = float(baseline["salvage_p95_ns"]) * 1.10
    timeout_ceiling = max(25_000_000.0, float(baseline["timeout_overshoot_p95_ns"]) * 1.10)
    eligible = [
        candidate
        for candidate in valid
        if float(candidate["throughput_mib_s"]) >= throughput_floor
        and float(candidate["salvage_p95_ns"]) <= salvage_ceiling
        and float(candidate["timeout_overshoot_p95_ns"]) <= timeout_ceiling
    ]
    diagnostic = min(eligible, key=lambda candidate: int(candidate["chunk_size"])) if eligible else None
    measured = {
        **base,
        "best_throughput_mib_s": best_throughput,
        "throughput_floor_mib_s": throughput_floor,
        "salvage_ceiling_ns": salvage_ceiling,
        "timeout_overshoot_ceiling_ns": timeout_ceiling,
    }
    if not exact_matrix or not complete_sizes:
        return {
            **measured,
            "status": "insufficient_matrix",
            "selected_chunk_size": None,
            "diagnostic_selected_chunk_size": None if diagnostic is None else int(diagnostic["chunk_size"]),
            "reason": "production selection requires the exact complete manifest-v5 chunk matrix",
        }
    if not production_protocol:
        return {
            **measured,
            "status": "insufficient_protocol",
            "selected_chunk_size": None,
            "diagnostic_selected_chunk_size": None if diagnostic is None else int(diagnostic["chunk_size"]),
            "reason": (
                "production selection requires release profile, at least one warmup, three repetitions, "
                "and enforced candidate timeout watchdogs"
            ),
        }
    if diagnostic is None:
        return {
            **measured,
            "status": "inconclusive",
            "selected_chunk_size": None,
            "diagnostic_selected_chunk_size": None,
            "reason": "no chunk size satisfies throughput, salvage, and timeout constraints",
        }
    return {
        **measured,
        "status": "selected",
        "selected_chunk_size": int(diagnostic["chunk_size"]),
        "diagnostic_selected_chunk_size": int(diagnostic["chunk_size"]),
        "reason": None,
    }


def _chunk_selection_for_run(
    cases: list[dict[str, Any]],
    *,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any] | None:
    if not any(
        str(case.get("case_id", "")).startswith(
            (_CHUNK_THROUGHPUT_PREFIX, _CHUNK_SALVAGE_PREFIX, _CHUNK_TIMEOUT_PREFIX)
        )
        for case in cases
    ):
        return None
    return select_production_chunk(
        cases,
        profile=profile,
        warmups=warmups,
        repetitions=repetitions,
    )


def _run_case(
    case: BenchmarkCase,
    *,
    profile: str,
    warmups: int,
    repetitions: int,
    enforced_outer_watchdog_s: float | None,
) -> dict[str, Any]:
    with ControlledProcessTarget(case, profile) as target:
        metadata = _require_metadata(target)
        _validate_target_metadata(case, profile, metadata)
        session = DebugSession()
        if not session.switch_process("", pid=metadata.pid):
            raise BenchmarkFailure(f"{case.case_id}: could not attach to controlled child {metadata.pid}")
        try:
            preflight_evidence = _preflight(case, target, metadata, session)
            for _ in range(warmups):
                _measure_case_once(
                    case,
                    metadata,
                    session,
                    trace_allocations=False,
                    enforced_outer_watchdog_s=enforced_outer_watchdog_s,
                )

            section_cache = None
            cache_token = None
            setup_evidence = None
            if case.kind == "section_filter_warm":
                section_cache = SectionCache()
                cache_token = sha256_json(
                    {"run_id": metadata.run_id, "attachment_generation": 1, "purpose": "section-cache"}
                )
                setup_observation = _measure_case_once(
                    case,
                    metadata,
                    session,
                    trace_allocations=False,
                    section_cache=section_cache,
                    cache_token=cache_token,
                    enforced_outer_watchdog_s=enforced_outer_watchdog_s,
                )
                setup_evidence = _candidate_warm_setup_evidence(
                    case,
                    metadata,
                    setup_observation,
                    cache_token=cache_token,
                )

            observations = [
                _measure_case_once(
                    case,
                    metadata,
                    session,
                    trace_allocations=case.kind == "allocation",
                    section_cache=section_cache,
                    cache_token=cache_token,
                    preflight_evidence=preflight_evidence,
                    setup_evidence=setup_evidence,
                    enforced_outer_watchdog_s=enforced_outer_watchdog_s,
                )
                for _ in range(repetitions)
            ]
        finally:
            session.detach()

    manifest = case.semantic_descriptor(profile)
    corpus_record = {
        "corpus_version": CORPUS_VERSION,
        "profile": profile,
        "size": metadata.logical_size,
        "sha256": metadata.corpus_sha256,
        "fixture_version": metadata.fixture_version,
        "fixture_source_sha256": metadata.fixture_source_sha256,
        "topology": metadata.topology,
        "topology_fingerprint": metadata.topology_fingerprint,
    }
    expected_record = {
        "returned_count": len(metadata.expected_addresses),
        "address_checksum": metadata.expected_checksum,
        "relative_address_checksum": relative_address_checksum(metadata, metadata.expected_addresses),
        "inaccessible_ranges": [list(item) for item in metadata.inaccessible_ranges],
        "readonly_ranges": [list(item) for item in metadata.readonly_ranges],
    }
    fingerprint_payload = semantic_fingerprint_payload(manifest, corpus_record, expected_record)
    return {
        "case_id": case.case_id,
        "tier": case.tier,
        "layer": case.layer,
        "comparison_class": case.comparison_class,
        "semantic_fingerprint_payload": fingerprint_payload,
        "semantic_fingerprint": semantic_fingerprint(fingerprint_payload),
        "manifest": manifest,
        "corpus": corpus_record,
        "expected": expected_record,
        "observations": observations,
        "summary": _summarize_observations(observations),
        "status": "complete",
    }


_READ_EVIDENCE_FIELDS = (
    "physical_read_calls",
    "physical_bytes_requested",
    "physical_bytes_read",
    "physical_read_operations",
    "physical_read_operations_sha256",
    "physical_request_sizes",
    "physical_read_sizes",
    "physical_read_ranges",
    "unique_logical_bytes",
    "failed_read_calls",
    "read_call_p95_ns",
    "read_call_max_ns",
    "read_ranges_sha256",
)


def _read_evidence(work: dict[str, Any]) -> dict[str, Any]:
    return {field: work[field] for field in _READ_EVIDENCE_FIELDS}


def _candidate_warm_setup_evidence(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    setup_observation: dict[str, Any],
    *,
    cache_token: str,
) -> dict[str, Any]:
    work = setup_observation.get("work")
    if not isinstance(work, dict) or work.get("correct") is not True:
        raise BenchmarkFailure(f"{case.case_id}: warm-cache setup did not complete correctly")
    return {
        **case.setup_protocol,
        "implementation_state": case.setup_protocol["candidate_state"],
        "correct": True,
        "comparison_identity": comparison_identity(metadata),
        "operation_identity": operation_identity(metadata, phase="setup", cache_token=cache_token),
        "actual_count": work.get("actual_count"),
        "expected_count": work.get("expected_count"),
        "read": _read_evidence(work),
        "logical_scanned_region_count": work.get("logical_scanned_region_count"),
        "unique_bytes_examined": work.get("unique_bytes_examined"),
        "sections": work.get("sections"),
    }


def _preflight(
    case: BenchmarkCase,
    target: ControlledProcessTarget,
    metadata: TargetMetadata,
    session: DebugSession,
) -> dict[str, Any] | None:
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
        return None
    if not requires_exact_preflight(case):
        return None

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
    checksum = address_checksum(addresses)
    if addresses != expected:
        raise BenchmarkFailure(
            f"{case.case_id}: preflight address mismatch ({checksum} != {metadata.expected_checksum})"
        )
    _assert_excluded_ranges_not_read(case, metadata, io.read_ranges)
    diagnostics = payload.get("diagnostics") or {}
    return {
        **preflight_protocol(case.kind),
        "correct": True,
        "addresses": addresses,
        "address_checksum": checksum,
        "address_base": metadata.base_address,
        "relative_addresses": relative_addresses(metadata, addresses),
        "relative_address_checksum": relative_address_checksum(metadata, addresses),
        "expected_addresses": expected,
        "expected_count": len(expected),
        "expected_checksum": metadata.expected_checksum,
        "expected_relative_checksum": relative_address_checksum(metadata, expected),
        "comparison_identity": comparison_identity(metadata),
        "operation_identity": operation_identity(metadata, phase="preflight"),
        "read": io.metrics(),
        "logical_scanned_region_count": int(diagnostics.get("region_count", 0)),
        "unique_bytes_examined": int(diagnostics.get("unique_bytes_examined", 0)),
        "sections": list(diagnostics.get("sections", [])),
    }


def _measure_case_once(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    session: DebugSession,
    *,
    trace_allocations: bool,
    section_cache: SectionCache | None = None,
    cache_token: str | None = None,
    preflight_evidence: dict[str, Any] | None = None,
    setup_evidence: dict[str, Any] | None = None,
    enforced_outer_watchdog_s: float | None = None,
) -> dict[str, Any]:
    if case.kind == "reader_ceiling":
        return _measure_raw_reader(
            case,
            metadata,
            session,
            enforced_outer_watchdog_s=enforced_outer_watchdog_s,
        )

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
        section_cache=section_cache,
        clock=time.perf_counter_ns,
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
    if case.kind == "timeout":
        correct = termination == "timeout"
    elif case.kind == "chunk_timeout":
        correct = termination == "timeout"
    else:
        correct = _response_matches_expected(case, payload, metadata)
    if not correct:
        raise BenchmarkFailure(f"{case.case_id}: candidate result differs from controlled target expectation")
    _assert_excluded_ranges_not_read(case, metadata, io.read_ranges)

    diagnostics = payload.get("diagnostics") or {}
    logical_bytes = int(diagnostics.get("unique_bytes_examined", 0))
    throughput = _throughput_mib_s(logical_bytes, duration_ns)
    timeout_overshoot_ns = max(0, duration_ns - case.timeout_ms * 1_000_000) if termination == "timeout" else 0
    work = {
        **io.metrics(),
        **candidate_watchdog_metrics(case.process_timeout_s, enforced_outer_watchdog_s),
        "operation_identity": operation_identity(metadata, phase="timed", cache_token=cache_token),
        "unique_bytes_examined": logical_bytes,
        "candidate_count": int(diagnostics.get("candidate_count", 0)),
        "verification_count": int(diagnostics.get("verification_count", 0)),
        "control_polls": int(diagnostics.get("control_polls", 0)),
        "logical_scanned_region_count": int(diagnostics.get("region_count", 0)),
        "span_count": int(diagnostics.get("span_count", 0)),
        "strategy_counts": dict(diagnostics.get("strategy_counts", {})),
        "sections": list(diagnostics.get("sections", [])),
        "read_gaps_detected": bool(payload["status"]["read_gaps_detected"]),
        "termination": termination,
        "timed_out": termination == "timeout",
        "timeout_budget_ns": case.timeout_ms * 1_000_000,
        "actual_count": _response_count(payload),
        "expected_count": len(metadata.expected_addresses),
        "actual_checksum": address_checksum(_response_addresses(payload)) if case.mode != "count" else None,
        "expected_checksum": metadata.expected_checksum if case.mode != "count" else None,
        "correct": correct,
        "chunk_size": int(case.parameters.get("chunk_size", PRODUCTION_CHUNK_SIZE)),
        "timeout_overshoot_ns": timeout_overshoot_ns,
        "peak_python_bytes": peak_python_bytes,
    }
    if preflight_evidence is not None:
        work["preflight"] = preflight_evidence
    if setup_evidence is not None:
        work["setup"] = setup_evidence
    return {
        "duration_ns": max(1, duration_ns),
        "throughput_mib_s": throughput,
        "work": work,
    }


def _measure_raw_reader(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    session: DebugSession,
    *,
    enforced_outer_watchdog_s: float | None,
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
            **candidate_watchdog_metrics(case.process_timeout_s, enforced_outer_watchdog_s),
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
    if case.kind in {"section_filter", "section_filter_warm"}:
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
    observations = case.get("observations")
    return bool(
        case.get("status") == "complete"
        and isinstance(observations, list)
        and observations
        and all(
            isinstance(observation, dict)
            and isinstance(observation.get("work"), dict)
            and observation["work"].get("correct") is True
            for observation in observations
        )
    )


def _observation_median(case: dict[str, Any], field: str) -> float:
    observations = case.get("observations")
    if not isinstance(observations, list) or not observations:
        raise BenchmarkFailure(f"{case.get('case_id', '<unknown>')}: observations are missing")
    values = [observation.get(field) for observation in observations if isinstance(observation, dict)]
    if len(values) != len(observations) or any(not is_finite_number(value) for value in values):
        raise BenchmarkFailure(f"{case['case_id']}: observation {field} values are invalid")
    value = summarize([float(item) for item in values])["median"]
    if value is None:
        raise BenchmarkFailure(f"{case['case_id']}: observation {field} median is missing")
    return float(value)


def _observation_p95(case: dict[str, Any], field: str) -> float:
    observations = case.get("observations")
    if not isinstance(observations, list) or not observations:
        raise BenchmarkFailure(f"{case.get('case_id', '<unknown>')}: observations are missing")
    values = [observation.get(field) for observation in observations if isinstance(observation, dict)]
    if len(values) != len(observations) or any(not is_finite_number(value) for value in values):
        raise BenchmarkFailure(f"{case['case_id']}: observation {field} values are invalid")
    value = percentile([float(item) for item in values], 95)
    if value is None:
        raise BenchmarkFailure(f"{case['case_id']}: observation {field} p95 is missing")
    return float(value)


def _validated_timeout_p95(case: dict[str, Any]) -> float:
    manifest = case.get("manifest")
    observations = case.get("observations")
    if not isinstance(manifest, dict) or manifest.get("kind") != "chunk_timeout":
        raise BenchmarkFailure(f"{case.get('case_id', '<unknown>')}: timeout manifest is invalid")
    if not isinstance(observations, list) or not observations:
        raise BenchmarkFailure(f"{case['case_id']}: timeout observations are missing")
    overshoots: list[float] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise BenchmarkFailure(f"{case['case_id']}: timeout observation {index} is invalid")
        work = observation.get("work")
        error = timeout_control_error(
            f"{case['case_id']} observation {index}",
            duration_ns=observation.get("duration_ns"),
            termination=work.get("termination") if isinstance(work, dict) else None,
            metrics=work,
            timeout_ms=manifest.get("timeout_ms"),
            process_timeout_s=manifest.get("process_timeout_s"),
            require_control_polls=True,
            require_timeout_hit=False,
            candidate_watchdog_timeout_s=manifest.get("candidate_watchdog_timeout_s"),
            require_candidate_watchdog_enforced=False,
        )
        if error is not None:
            raise BenchmarkFailure(error)
        if not isinstance(work, dict) or work.get("correct") is not True:
            raise BenchmarkFailure(f"{case['case_id']} observation {index} correctness is invalid")
        overshoots.append(float(work["timeout_overshoot_ns"]))
    measured = percentile(overshoots, 95)
    if measured is None:
        raise BenchmarkFailure(f"{case['case_id']}: timeout overshoot p95 is missing")
    return measured


def _chunk_timeout_watchdogs_enforced(cases: list[dict[str, Any]]) -> bool:
    timeout_cases = [case for case in cases if str(case.get("case_id", "")).startswith(_CHUNK_TIMEOUT_PREFIX)]
    return bool(
        timeout_cases
        and all(
            isinstance(case.get("observations"), list)
            and case["observations"]
            and all(
                isinstance(observation, dict)
                and isinstance(observation.get("work"), dict)
                and observation["work"].get("candidate_watchdog_enforced") is True
                for observation in case["observations"]
            )
            for case in timeout_cases
        )
    )


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
