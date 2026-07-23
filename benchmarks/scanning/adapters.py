"""Cross-version adapters for one paired scanning benchmark observation."""

from __future__ import annotations

import ctypes
import inspect
import time
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from benchmarks.scanning import CORPUS_VERSION, HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S
from benchmarks.scanning.common import (
    address_checksum,
    candidate_watchdog_metrics,
    percentile,
    range_union_size,
    sha256_json,
)
from benchmarks.scanning.corpus import build_batch_patterns, build_corpus
from benchmarks.scanning.manifest import BenchmarkCase, preflight_protocol, requires_exact_preflight
from benchmarks.scanning.process_target import (
    ControlledProcessTarget,
    TargetMetadata,
    comparison_identity,
    operation_identity,
    relative_address_checksum,
    relative_addresses,
)

_PROCESS_CASE_KINDS = {
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


class _HistoricalReadProbe:
    def __init__(
        self,
        read_bytes: Callable[[int, int], bytes] | None = None,
        *,
        read_memory: Callable[[int, int, int], bytes] | None = None,
    ) -> None:
        if (read_bytes is None) == (read_memory is None):
            raise ValueError("exactly one read function is required")
        self._read_bytes = read_bytes
        self._read_memory = read_memory
        self.calls = 0
        self.failed_calls = 0
        self.bytes_requested = 0
        self.bytes_read = 0
        self.request_sizes: list[int] = []
        self.read_operations: list[dict[str, Any]] = []
        self.read_sizes: list[int] = []
        self.read_ranges: list[tuple[int, int]] = []
        self.call_durations_ns: list[int] = []

    def _record(self, address: int, size: int, operation: Callable[[], bytes]) -> bytes:
        self.calls += 1
        self.bytes_requested += size
        self.request_sizes.append(size)
        started = time.perf_counter_ns()
        try:
            payload = operation()
        except Exception:
            self.failed_calls += 1
            self.read_operations.append(
                {"address": address, "requested_size": size, "returned_size": 0, "success": False}
            )
            raise
        finally:
            self.call_durations_ns.append(time.perf_counter_ns() - started)
        data = bytes(payload)
        self.bytes_read += len(data)
        self.read_operations.append(
            {"address": address, "requested_size": size, "returned_size": len(data), "success": True}
        )
        self.read_sizes.append(len(data))
        self.read_ranges.append((address, address + len(data)))
        return data

    def read_bytes(self, address: int, size: int) -> bytes:
        if self._read_bytes is None:
            raise RuntimeError("read_bytes probe is not configured")
        return self._record(address, size, lambda: self._read_bytes(address, size))

    def read_memory(self, process_handle: int, address: int, size: int) -> bytes:
        if self._read_memory is None:
            raise RuntimeError("read_memory probe is not configured")
        return self._record(address, size, lambda: self._read_memory(process_handle, address, size))

    def metrics(self) -> dict[str, Any]:
        return {
            "physical_read_calls": self.calls,
            "physical_bytes_requested": self.bytes_requested,
            "physical_bytes_read": self.bytes_read,
            "physical_read_operations": list(self.read_operations),
            "physical_read_operations_sha256": sha256_json(self.read_operations),
            "physical_request_sizes": list(self.request_sizes),
            "physical_read_sizes": list(self.read_sizes),
            "physical_read_ranges": [list(item) for item in self.read_ranges],
            "unique_logical_bytes": range_union_size(self.read_ranges),
            "failed_read_calls": self.failed_calls,
            "read_call_p95_ns": percentile(self.call_durations_ns, 95) or 0.0,
            "read_call_max_ns": max(self.call_durations_ns, default=0),
            "read_ranges_sha256": sha256_json(self.read_ranges),
        }


@contextmanager
def _capture_session_reads(session: Any) -> Iterator[_HistoricalReadProbe]:
    original = session.read_bytes
    probe = _HistoricalReadProbe(original)
    session.read_bytes = probe.read_bytes
    try:
        yield probe
    finally:
        session.read_bytes = original


_PREPARATION_EVIDENCE = {
    "imports_complete": True,
    "setup_complete": True,
    "warmups_complete": True,
    "validation_complete": True,
    "timed_statement_pending": True,
}


def _historical_ready_evidence(
    *,
    logical_bytes: int,
    expected_count: int,
    expected_checksum: str | None,
    comparison_identity: dict[str, Any] | None,
    metrics: dict[str, Any] | None = None,
    expected_historical_failure: bool = False,
) -> dict[str, Any]:
    return {
        "comparison_identity": comparison_identity,
        "logical_bytes": logical_bytes,
        "expected_count": expected_count,
        "expected_checksum": expected_checksum,
        "expected_historical_failure": expected_historical_failure,
        "preparation": dict(_PREPARATION_EVIDENCE),
        "metrics": {} if metrics is None else metrics,
    }


def _authorize_timed_phase(
    before_timed: Callable[[dict[str, Any]], None] | None,
    evidence: dict[str, Any],
) -> None:
    if before_timed is not None:
        before_timed(evidence)


def run_case(
    case: BenchmarkCase,
    *,
    implementation: str,
    profile: str,
    target_root: Path,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
    candidate_outer_watchdog_s: float | None = None,
) -> dict[str, Any]:
    """Run one declared case against the selected implementation checkout."""

    if implementation not in {"before", "after"}:
        raise ValueError("implementation must be 'before' or 'after'")
    if implementation == "after" and before_timed is not None:
        raise ValueError("before_timed is only valid for historical execution")
    if implementation == "before" and candidate_outer_watchdog_s is not None:
        raise ValueError("candidate_outer_watchdog_s is only valid for candidate execution")
    if case.kind == "compile":
        return _run_compile(case, implementation, before_timed=before_timed)
    if case.kind in {"matcher", "pointer_matcher"}:
        if implementation == "after":
            return _run_current_evidence(
                case,
                profile,
                target_root,
                suite="matcher",
                candidate_outer_watchdog_s=candidate_outer_watchdog_s,
            )
        return _run_legacy_matcher(case, profile, before_timed=before_timed)
    if case.kind == "reader_ceiling":
        return _run_reader_ceiling(case, profile, before_timed=before_timed)
    if case.kind in _PROCESS_CASE_KINDS:
        if implementation == "after":
            return _run_current_evidence(
                case,
                profile,
                target_root,
                suite="process",
                candidate_outer_watchdog_s=candidate_outer_watchdog_s,
            )
        return _run_legacy_process(case, profile, before_timed=before_timed)
    if case.kind == "cursor":
        return _run_cursor(
            case,
            implementation,
            profile,
            target_root,
            before_timed=before_timed,
            candidate_outer_watchdog_s=candidate_outer_watchdog_s,
        )
    if case.kind == "batch":
        return _run_batch(
            case,
            implementation,
            profile,
            target_root,
            before_timed=before_timed,
            candidate_outer_watchdog_s=candidate_outer_watchdog_s,
        )
    if case.kind == "strict_unknown":
        return _run_strict_unknown(implementation, profile, target_root, before_timed=before_timed)
    raise ValueError(f"unsupported benchmark case kind {case.kind!r}")


def _run_compile(
    case: BenchmarkCase,
    implementation: str,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    iterations = int(case.parameters["iterations"])
    cold_unique_patterns = int(case.parameters["cold_unique_patterns"])
    reset_compile_cache = None
    if implementation == "before":
        from memscope_mcp.utils.pattern import parse_aob_pattern

        compile_pattern = parse_aob_pattern
    else:
        from memscope_mcp.scanning.pattern import _clear_pattern_compile_caches, compile_aob_pattern

        compile_pattern = compile_aob_pattern
        reset_compile_cache = _clear_pattern_compile_caches

    compiled = compile_pattern(case.pattern)
    for _ in range(10):
        compile_pattern(case.pattern)
    length = int(getattr(compiled, "length"))
    cold_inputs = _cold_exact_patterns(case.pattern, cold_unique_patterns)
    _authorize_timed_phase(
        before_timed,
        _historical_ready_evidence(
            logical_bytes=length * iterations,
            expected_count=length,
            expected_checksum=None,
            comparison_identity=None,
            metrics={"prepared_kind": "compile", "warmups": 10},
        ),
    )
    started = time.perf_counter_ns()
    for _ in range(iterations):
        compile_pattern(case.pattern)
    duration_ns = time.perf_counter_ns() - started

    if reset_compile_cache is not None:
        reset_compile_cache()
    cold_started = time.perf_counter_ns()
    for pattern in cold_inputs:
        if int(getattr(compile_pattern(pattern), "length")) != length:
            raise RuntimeError("cold exact compile variant changed the compiled length")
    cold_duration_ns = time.perf_counter_ns() - cold_started

    return _observation(
        duration_ns=duration_ns,
        logical_bytes=length * iterations,
        actual_count=length,
        expected_count=length,
        termination="complete",
        metrics={
            "iterations": iterations,
            "warmups": 10,
            "latency_per_operation_ns": duration_ns / iterations,
            "cold_unique_patterns": cold_unique_patterns,
            "cold_unique_duration_ns": cold_duration_ns,
            "cold_unique_latency_per_operation_ns": cold_duration_ns / cold_unique_patterns,
        },
    )


def _cold_exact_patterns(pattern: str, count: int) -> tuple[str, ...]:
    if not 1 <= count < 1 << 32:
        raise ValueError("cold_unique_patterns must fit in an unsigned 32-bit value")
    base = bytes.fromhex(pattern)
    if len(base) < 4:
        raise ValueError("cold exact compile variants require at least four bytes")
    prefix = base[:-4]
    variant_bytes = tuple(prefix + index.to_bytes(4, "little") for index in range(1, count + 1))
    if base in variant_bytes:
        raise RuntimeError("cold exact compile variants must exclude the primary pattern")
    return tuple(value.hex(" ").upper() for value in variant_bytes)


def _run_legacy_matcher(
    case: BenchmarkCase,
    profile: str,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from memscope_mcp.utils.pattern import match_pattern, parse_aob_pattern

    base_address = 0x10000000
    corpus = build_corpus(case, profile, base_address=base_address)
    parsed = parse_aob_pattern(case.pattern)
    identity = {
        "corpus_version": CORPUS_VERSION,
        "profile": profile,
        "base_address": base_address,
        "size": len(corpus.data),
        "sha256": corpus.data_sha256,
        "expected_count": len(corpus.expected_addresses),
    }
    _authorize_timed_phase(
        before_timed,
        _historical_ready_evidence(
            logical_bytes=len(corpus.data),
            expected_count=len(corpus.expected_addresses),
            expected_checksum=corpus.expected_checksum if case.mode != "count" else None,
            comparison_identity=identity,
            metrics={"prepared_kind": "matcher"},
        ),
    )
    trace_allocations = case.kind == "allocation"
    if trace_allocations:
        tracemalloc.start()
    started = time.perf_counter_ns()
    if case.kind == "pointer_matcher":
        target = parsed.pattern_bytes
        alignment = int(case.parameters.get("alignment", 8))
        addresses = [
            base_address + offset
            for offset in range(0, len(corpus.data) - len(target) + 1, alignment)
            if corpus.data[offset : offset + len(target)] == target
        ]
    else:
        addresses = match_pattern(corpus.data, parsed, start=base_address)
    retained = _retain_addresses(case, addresses)
    duration_ns = time.perf_counter_ns() - started
    peak_bytes = None
    if trace_allocations:
        _current, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return _observation(
        duration_ns=duration_ns,
        logical_bytes=len(corpus.data),
        actual_count=len(retained),
        expected_count=len(corpus.expected_addresses),
        actual_checksum=address_checksum(retained) if case.mode != "count" else None,
        expected_checksum=corpus.expected_checksum if case.mode != "count" else None,
        termination=_collector_termination(case, len(retained)),
        peak_bytes=peak_bytes,
        comparison_identity=identity,
        metrics={
            "corpus_sha256": corpus.data_sha256,
            "strategy_counts": {"nested_python": 1},
            "candidate_count": max(0, len(corpus.data) - parsed.length + 1),
        },
    )


def _run_current_evidence(
    case: BenchmarkCase,
    profile: str,
    target_root: Path,
    *,
    suite: str,
    candidate_outer_watchdog_s: float | None,
) -> dict[str, Any]:
    if suite == "matcher":
        from benchmarks.scanning.matcher import run_matcher_suite

        artifact = run_matcher_suite(
            repo_root=target_root,
            profile=profile,
            warmups=0,
            repetitions=1,
            implementation_label="after",
            case_ids=(case.case_id,),
        )
    elif suite == "process":
        from benchmarks.scanning.process_scan import run_process_suite

        artifact = run_process_suite(
            repo_root=target_root,
            profile=profile,
            warmups=0,
            repetitions=1,
            implementation_label="after",
            case_ids=(case.case_id,),
            enforced_outer_watchdog_s=candidate_outer_watchdog_s,
        )
    else:
        raise ValueError(f"unknown current evidence suite {suite!r}")
    return _normalize_evidence_case(case, artifact["cases"][0])


def _normalize_evidence_case(case: BenchmarkCase, evidence: dict[str, Any]) -> dict[str, Any]:
    observations = evidence.get("observations")
    if not isinstance(observations, list) or len(observations) != 1:
        raise RuntimeError(f"{case.case_id}: current evidence must contain exactly one observation")
    measured = observations[0]
    work = measured.get("work")
    expected = evidence.get("expected")
    if not isinstance(work, dict) or not isinstance(expected, dict):
        raise RuntimeError(f"{case.case_id}: current evidence is incomplete")
    actual_count = int(work.get("actual_count", work.get("observed_count", expected.get("returned_count", 0))))
    expected_count = int(expected.get("returned_count", work.get("expected_count", actual_count)))
    actual_checksum = work.get("actual_checksum")
    expected_checksum = (
        None if case.mode == "count" else expected.get("address_checksum", work.get("expected_checksum"))
    )
    corpus = dict(evidence.get("corpus", {}))
    logical_bytes = int(corpus.get("size", evidence.get("manifest", {}).get("size_bytes", 0)))
    metrics = {
        **work,
        "evidence_semantic_fingerprint_payload": evidence.get("semantic_fingerprint_payload"),
        "evidence_semantic_fingerprint": evidence.get("semantic_fingerprint"),
        "evidence_status": evidence.get("status"),
    }
    return _observation(
        duration_ns=int(measured["duration_ns"]),
        logical_bytes=logical_bytes,
        actual_count=actual_count,
        expected_count=expected_count,
        actual_checksum=actual_checksum,
        expected_checksum=expected_checksum,
        termination=str(work.get("termination", "complete")),
        peak_bytes=work.get("peak_python_bytes"),
        correctness_override=evidence.get("status") == "complete" and work.get("correct", True) is True,
        comparison_identity=_corpus_comparison_identity(corpus, expected),
        metrics=metrics,
        throughput_mib_s=measured.get("throughput_mib_s"),
    )


def _run_reader_ceiling(
    case: BenchmarkCase,
    profile: str,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    chunk_size = int(case.parameters["chunk_size"])
    with ControlledProcessTarget(case, profile) as target:
        metadata = _require_metadata(target)
        handle = _open_process(metadata.pid)
        try:
            calls = 0
            bytes_read = 0
            checksum = 0
            identity = _target_comparison_identity(metadata)
            _authorize_timed_phase(
                before_timed,
                _historical_ready_evidence(
                    logical_bytes=metadata.logical_size,
                    expected_count=metadata.logical_size,
                    expected_checksum=None,
                    comparison_identity=identity,
                    metrics={"operation_identity": operation_identity(metadata, phase="timed")},
                ),
            )
            started = time.perf_counter_ns()
            cursor = metadata.base_address
            while cursor < metadata.end_exclusive:
                size = min(chunk_size, metadata.end_exclusive - cursor)
                payload = _read_process_bytes(handle, cursor, size)
                checksum ^= payload[0]
                calls += 1
                bytes_read += len(payload)
                cursor += size
            duration_ns = time.perf_counter_ns() - started
        finally:
            _close_handle(handle)
    return _observation(
        duration_ns=duration_ns,
        logical_bytes=metadata.logical_size,
        actual_count=bytes_read,
        expected_count=metadata.logical_size,
        termination="scope_exhausted",
        comparison_identity=identity,
        metrics={
            "operation_identity": operation_identity(metadata, phase="timed"),
            "physical_read_calls": calls,
            "physical_bytes_read": bytes_read,
            "reader_checksum": checksum,
            "chunk_size": chunk_size,
            "fixture_version": metadata.fixture_version,
            "topology_fingerprint": metadata.topology_fingerprint,
        },
    )


class HistoricalProcessExecution:
    def __init__(self, case: BenchmarkCase, profile: str) -> None:
        from memscope_mcp.session import DebugSession
        from memscope_mcp.tools import scanning

        self.case = case
        self.profile = profile
        self._stack = ExitStack()
        self.target = self._stack.enter_context(ControlledProcessTarget(case, profile))
        self.metadata = _require_metadata(self.target)
        self.session = DebugSession()
        if not self.session.switch_process("", pid=self.metadata.pid):
            self._stack.close()
            raise RuntimeError(f"could not attach historical scanner to controlled child {self.metadata.pid}")
        self._stack.callback(self.session.detach)
        self.scanning = scanning
        self.scanning.SESSION = self.session
        self.cache_token = (
            sha256_json(
                {
                    "run_id": self.metadata.run_id,
                    "attachment_generation": 1,
                    "purpose": "historical-section-cache-state",
                }
            )
            if case.kind == "section_filter_warm"
            else None
        )
        self.preflight_evidence = _legacy_exact_preflight(case, self.metadata, self.scanning, self.session)
        self.setup_evidence = None
        if case.kind == "section_filter_warm":
            with _capture_session_reads(self.session) as setup_probe:
                setup_response = _legacy_scan_once(case, self.metadata, self.scanning)
            self.setup_evidence = _legacy_warm_setup_evidence(
                case,
                self.metadata,
                setup_response,
                setup_probe,
                cache_token=self.cache_token,
            )
        self.comparison_identity = comparison_identity(self.metadata)
        self.timed_operation_identity = operation_identity(
            self.metadata,
            phase="timed",
            cache_token=self.cache_token,
        )
        self.logical_bytes = (
            int(self.metadata.module["size"]) if case.kind.startswith("section_filter") else self.metadata.logical_size
        )

    def close(self) -> None:
        self._stack.close()

    def ready_evidence(self) -> dict[str, Any]:
        metrics: dict[str, Any] = {
            "preflight": self.preflight_evidence,
            "operation_identity": self.timed_operation_identity,
        }
        if self.setup_evidence is not None:
            metrics["setup"] = self.setup_evidence
        retained = _retain_addresses(self.case, list(self.metadata.expected_addresses))
        return _historical_ready_evidence(
            logical_bytes=self.logical_bytes,
            expected_count=len(retained),
            expected_checksum=None if self.case.mode == "count" else address_checksum(retained),
            comparison_identity=self.comparison_identity,
            expected_historical_failure=bool(self.case.parameters.get("historical_expected_failure")),
            metrics=metrics,
        )

    def run_timed(self) -> dict[str, Any]:
        trace_allocations = self.case.kind == "allocation"
        if trace_allocations:
            tracemalloc.start()
        try:
            with _capture_session_reads(self.session) as timed_probe:
                started = time.perf_counter_ns()
                response = _legacy_scan_once(self.case, self.metadata, self.scanning)
                duration_ns = time.perf_counter_ns() - started
            peak_bytes = None
            if trace_allocations:
                _current, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            if trace_allocations and tracemalloc.is_tracing():
                tracemalloc.stop()
        if not response.get("success"):
            raise RuntimeError(f"historical scan failed: {response}")
        scan_metadata = response["scan_metadata"]
        addresses = [int(item["address"], 16) for item in response["data"]]
        expected = _retain_addresses(self.case, list(self.metadata.expected_addresses))
        actual_count = int(scan_metadata["result_count"]) if self.case.mode == "count" else len(addresses)
        timeout_hit = bool(scan_metadata.get("timeout_hit"))
        termination = "timeout" if timeout_hit else _legacy_termination(scan_metadata, self.case.mode)
        timed_read = timed_probe.metrics()
        metrics = {
            **timed_read,
            "operation_identity": self.timed_operation_identity,
            "unique_bytes_examined": timed_read["unique_logical_bytes"],
            "logical_scanned_region_count": int(scan_metadata.get("scanned_region_count", 0)),
            "logical_bytes_scanned_with_overlap": int(scan_metadata.get("bytes_scanned", 0)),
            "read_error_count": int(scan_metadata.get("read_error_count", 0)),
            "timed_out": timeout_hit,
            "timeout_hit": timeout_hit,
            "termination": termination,
            "timeout_budget_ns": self.case.timeout_ms * 1_000_000,
            "process_watchdog_ns": int(self.case.process_timeout_s * 1_000_000_000),
            "timeout_overshoot_ns": (max(0, duration_ns - self.case.timeout_ms * 1_000_000) if timeout_hit else 0),
            "chunk_size": 1024 * 1024,
            "fixture_version": self.metadata.fixture_version,
            "topology_fingerprint": self.metadata.topology_fingerprint,
            "preflight": self.preflight_evidence,
        }
        if self.setup_evidence is not None:
            metrics["setup"] = self.setup_evidence
        return _observation(
            duration_ns=duration_ns,
            logical_bytes=self.logical_bytes,
            actual_count=actual_count,
            expected_count=len(expected),
            actual_checksum=address_checksum(addresses) if self.case.mode != "count" else None,
            expected_checksum=address_checksum(expected) if self.case.mode != "count" else None,
            termination=termination,
            peak_bytes=peak_bytes,
            correctness_override=(True if self.case.kind == "timeout" and timeout_hit else None),
            expected_historical_failure=(
                bool(self.case.parameters.get("historical_expected_failure")) and actual_count != len(expected)
            ),
            comparison_identity=self.comparison_identity,
            metrics=metrics,
        )


def prepare_historical_process(case: BenchmarkCase, profile: str) -> HistoricalProcessExecution:
    return HistoricalProcessExecution(case, profile)


def _run_legacy_process(
    case: BenchmarkCase,
    profile: str,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    execution = prepare_historical_process(case, profile)
    try:
        _authorize_timed_phase(before_timed, execution.ready_evidence())
        return execution.run_timed()
    finally:
        execution.close()


def _legacy_exact_preflight(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    scanning: Any,
    session: Any,
) -> dict[str, Any] | None:
    if not requires_exact_preflight(case):
        return None
    kwargs = _legacy_scan_address_kwargs(case, metadata)
    with _capture_session_reads(session) as probe:
        result = scanning.scan_aob_addresses(
            case.pattern,
            max_results=case.max_matches or 5000,
            timeout_ms=int(HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S * 1000),
            **kwargs,
        )
    scan_metadata = result.get("metadata")
    if isinstance(scan_metadata, dict) and scan_metadata.get("timeout_hit") is True:
        raise RuntimeError(
            "historical exact preflight timed out before readiness "
            f"(metadata.timeout_hit=true, timeout_ms={int(HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S * 1000)}, "
            f"scanned_region_count={scan_metadata.get('scanned_region_count')}, "
            f"bytes_scanned={scan_metadata.get('bytes_scanned')})"
        )
    if not result.get("success"):
        raise RuntimeError(f"historical preflight failed: {result}")
    if not isinstance(scan_metadata, dict):
        raise RuntimeError("historical preflight metadata is missing")
    addresses = [int(value) for value in result["matches"]]
    expected = list(metadata.expected_addresses)
    checksum = address_checksum(addresses)
    correct = addresses == expected
    expected_failure = (
        not correct
        and case.comparison_class == "new_capability"
        and bool(case.parameters.get("historical_expected_failure"))
    )
    if not correct and not expected_failure:
        raise RuntimeError(f"historical preflight address mismatch ({checksum} != {metadata.expected_checksum})")
    return {
        **preflight_protocol(case.kind),
        "correct": correct,
        "expected_historical_failure": expected_failure,
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
        "read": probe.metrics(),
        "logical_scanned_region_count": int(scan_metadata.get("scanned_region_count", 0)),
        "logical_bytes_scanned_with_overlap": int(scan_metadata.get("bytes_scanned", 0)),
    }


def _legacy_scan_address_kwargs(case: BenchmarkCase, metadata: TargetMetadata) -> dict[str, Any]:
    if case.kind.startswith("section_filter"):
        return {"module": str(metadata.module["name"])}
    return {
        "start_addr": metadata.base_address,
        "end_addr": metadata.end_exclusive - 1,
    }


def _legacy_warm_setup_evidence(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    response: dict[str, Any],
    probe: _HistoricalReadProbe,
    *,
    cache_token: str,
) -> dict[str, Any]:
    if not response.get("success"):
        raise RuntimeError(f"historical warm setup failed: {response}")
    scan_metadata = response["scan_metadata"]
    actual_count = int(scan_metadata.get("result_count", 0))
    expected_count = len(_retain_addresses(case, list(metadata.expected_addresses)))
    if actual_count != expected_count:
        raise RuntimeError(f"historical warm setup returned {actual_count} results; expected {expected_count}")
    return {
        **case.setup_protocol,
        "implementation_state": case.setup_protocol["historical_state"],
        "correct": True,
        "comparison_identity": comparison_identity(metadata),
        "operation_identity": operation_identity(metadata, phase="setup", cache_token=cache_token),
        "actual_count": actual_count,
        "expected_count": expected_count,
        "read": probe.metrics(),
        "logical_scanned_region_count": int(scan_metadata.get("scanned_region_count", 0)),
        "logical_bytes_scanned_with_overlap": int(scan_metadata.get("bytes_scanned", 0)),
    }


def _legacy_scan_once(case: BenchmarkCase, metadata: TargetMetadata, scanning: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "pattern": case.pattern,
        "offset": 0,
        "limit": case.limit or (1 if case.mode == "first" else 50),
        "summary_only": case.mode == "count",
        "max_results": case.max_matches or case.limit or (1 if case.mode == "first" else 5000),
        "timeout_ms": case.timeout_ms,
    }
    if case.kind.startswith("section_filter"):
        kwargs["module"] = str(metadata.module["name"])
    else:
        kwargs["address_min"] = f"0x{metadata.base_address:X}"
        kwargs["address_max"] = f"0x{metadata.end_exclusive - 1:X}"
    return scanning.scan_aob(**kwargs)


def _run_cursor(
    case: BenchmarkCase,
    implementation: str,
    profile: str,
    target_root: Path,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
    candidate_outer_watchdog_s: float | None = None,
) -> dict[str, Any]:
    if implementation == "after":
        from benchmarks.scanning.engine import run_engine_suite

        proof = run_engine_suite(
            repo_root=target_root,
            profile=profile,
            warmups=0,
            repetitions=1,
            implementation_label="after",
            case_ids=("cursor.pages10.limit50.no_earlier_work",),
        )["cases"][0]
    else:
        proof = None

    with ControlledProcessTarget(case, profile) as target:
        metadata = _require_metadata(target)
        if implementation == "before":
            return _legacy_cursor(case, metadata, before_timed=before_timed)
        return _current_cursor(
            case,
            metadata,
            proof,
            candidate_outer_watchdog_s=candidate_outer_watchdog_s,
        )


def _legacy_cursor(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from memscope_mcp.session import DebugSession
    from memscope_mcp.tools import scanning

    session = DebugSession()
    if not session.switch_process("", pid=metadata.pid):
        raise RuntimeError(f"could not attach historical scanner to controlled child {metadata.pid}")
    scanning.SESSION = session
    pages = int(case.parameters["pages"])
    limit = case.limit or 50
    expected = list(metadata.expected_addresses)[: pages * limit]
    identity = _target_comparison_identity(metadata)
    timed_identity = operation_identity(metadata, phase="timed")
    _authorize_timed_phase(
        before_timed,
        _historical_ready_evidence(
            logical_bytes=metadata.logical_size,
            expected_count=len(expected),
            expected_checksum=address_checksum(expected),
            comparison_identity=identity,
            metrics={"operation_identity": timed_identity},
        ),
    )
    addresses: list[int] = []
    logical_regions = 0
    try:
        with _capture_session_reads(session) as probe:
            started = time.perf_counter_ns()
            for page in range(pages):
                response = scanning.scan_aob(
                    case.pattern,
                    offset=page * limit,
                    limit=limit,
                    address_min=f"0x{metadata.base_address:X}",
                    address_max=f"0x{metadata.end_exclusive - 1:X}",
                    max_results=(page + 1) * limit,
                    timeout_ms=case.timeout_ms,
                )
                if not response.get("success"):
                    raise RuntimeError(f"historical cursor scan failed: {response}")
                addresses.extend(int(item["address"], 16) for item in response["data"])
                logical_regions += int(response["scan_metadata"].get("scanned_region_count", 0))
            duration_ns = time.perf_counter_ns() - started
    finally:
        session.detach()
    timed_read = probe.metrics()
    return _observation(
        duration_ns=duration_ns,
        logical_bytes=metadata.logical_size,
        actual_count=len(addresses),
        expected_count=len(expected),
        actual_checksum=address_checksum(addresses),
        expected_checksum=address_checksum(expected),
        termination="page_limit",
        comparison_identity=identity,
        metrics={
            **timed_read,
            "operation_identity": timed_identity,
            "logical_scanned_region_count": logical_regions,
            "pages": pages,
            "legacy_offset_rescans": pages,
            "fixture_version": metadata.fixture_version,
            "topology_fingerprint": metadata.topology_fingerprint,
        },
    )


def _current_cursor(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    proof: dict[str, Any],
    *,
    candidate_outer_watchdog_s: float | None,
) -> dict[str, Any]:
    import pymem.memory

    from memscope_mcp.scanning.contract import ScanInput
    from memscope_mcp.scanning.execution import ScanExecutor
    from memscope_mcp.session import DebugSession

    session = DebugSession()
    if not session.switch_process("", pid=metadata.pid):
        raise RuntimeError(f"could not attach candidate scanner to controlled child {metadata.pid}")
    probe = _HistoricalReadProbe(read_memory=pymem.memory.read_bytes)
    executor = ScanExecutor(session, read_memory=probe.read_memory)
    pages = int(case.parameters["pages"])
    limit = case.limit or 50
    addresses: list[int] = []
    logical_regions = 0
    cursor: str | None = None
    termination = "scope_exhausted"
    try:
        started = time.perf_counter_ns()
        for page in range(pages):
            if page == 0:
                payload: dict[str, Any] = {
                    "pattern": case.pattern,
                    "scope": {
                        "kind": "range",
                        "start": metadata.base_address,
                        "end_exclusive": metadata.end_exclusive,
                    },
                    "mode": "addresses",
                    "limit": limit,
                    "max_matches": case.max_matches,
                    "diagnostics": True,
                }
            else:
                if cursor is None:
                    break
                payload = {"cursor": cursor, "limit": limit, "diagnostics": True}
            response = _dump_response(executor.execute(ScanInput.model_validate(payload)))
            if not response["success"]:
                raise RuntimeError(f"candidate cursor scan failed: {response}")
            addresses.extend(int(item["address"], 16) for item in response["matches"])
            diagnostics = response.get("diagnostics") or {}
            logical_regions += int(diagnostics.get("region_count", 0))
            cursor = response.get("next_cursor")
            termination = response["status"]["termination"]
        duration_ns = time.perf_counter_ns() - started
    finally:
        session.detach()
    timed_read = probe.metrics()
    expected = list(metadata.expected_addresses)[: pages * limit]
    proof_correct = bool(proof.get("summary", {}).get("all_correct"))
    return _observation(
        duration_ns=duration_ns,
        logical_bytes=metadata.logical_size,
        actual_count=len(addresses),
        expected_count=len(expected),
        actual_checksum=address_checksum(addresses),
        expected_checksum=address_checksum(expected),
        termination=termination,
        correctness_override=proof_correct and addresses == expected,
        comparison_identity=_target_comparison_identity(metadata),
        metrics={
            **timed_read,
            **candidate_watchdog_metrics(case.process_timeout_s, candidate_outer_watchdog_s),
            "operation_identity": operation_identity(metadata, phase="timed"),
            "logical_scanned_region_count": logical_regions,
            "pages": pages,
            "cursor_prefix_bytes": 0,
            "committed_engine_case_id": proof["case_id"],
            "committed_engine_fingerprint": proof["semantic_fingerprint"],
            "fixture_version": metadata.fixture_version,
            "topology_fingerprint": metadata.topology_fingerprint,
        },
    )


def _run_batch(
    case: BenchmarkCase,
    implementation: str,
    profile: str,
    target_root: Path,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
    candidate_outer_watchdog_s: float | None = None,
) -> dict[str, Any]:
    evidence_case_id = "batch.first16.one_pass" if case.mode == "first" else "batch.count4.one_pass"
    proof = None
    if implementation == "after":
        from benchmarks.scanning.engine import run_engine_suite

        proof = run_engine_suite(
            repo_root=target_root,
            profile=profile,
            warmups=0,
            repetitions=1,
            implementation_label="after",
            case_ids=(evidence_case_id,),
        )["cases"][0]
    with ControlledProcessTarget(case, profile) as target:
        metadata = _require_metadata(target)
        if implementation == "before":
            return _legacy_batch(case, metadata, before_timed=before_timed)
        assert proof is not None
        return _current_batch(
            case,
            metadata,
            proof,
            candidate_outer_watchdog_s=candidate_outer_watchdog_s,
        )


def _legacy_batch(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from memscope_mcp.session import DebugSession
    from memscope_mcp.tools import scanning

    patterns = build_batch_patterns(int(case.parameters["patterns"]))
    expected = metadata.batch_expected
    session = DebugSession()
    if not session.switch_process("", pid=metadata.pid):
        raise RuntimeError(f"could not attach historical scanner to controlled child {metadata.pid}")
    scanning.SESSION = session
    identity = _target_comparison_identity(metadata)
    timed_identity = operation_identity(metadata, phase="timed")
    expected_count = sum(len(value) for value in expected.values())
    _authorize_timed_phase(
        before_timed,
        _historical_ready_evidence(
            logical_bytes=metadata.logical_size,
            expected_count=expected_count,
            expected_checksum=None,
            comparison_identity=identity,
            metrics={"operation_identity": timed_identity},
        ),
    )
    results: dict[str, list[int] | int] = {}
    logical_regions = 0
    try:
        with _capture_session_reads(session) as probe:
            started = time.perf_counter_ns()
            for key, pattern in patterns:
                response = scanning.scan_aob(
                    pattern,
                    offset=0,
                    limit=1 if case.mode == "first" else 50,
                    summary_only=case.mode == "count",
                    address_min=f"0x{metadata.base_address:X}",
                    address_max=f"0x{metadata.end_exclusive - 1:X}",
                    max_results=1 if case.mode == "first" else case.max_matches or 5000,
                    timeout_ms=case.timeout_ms,
                )
                if not response.get("success"):
                    raise RuntimeError(f"historical batch member failed: {response}")
                logical_regions += int(response["scan_metadata"].get("scanned_region_count", 0))
                if case.mode == "first":
                    results[key] = [int(item["address"], 16) for item in response["data"]]
                else:
                    results[key] = int(response["scan_metadata"]["result_count"])
            duration_ns = time.perf_counter_ns() - started
    finally:
        session.detach()
    timed_read = probe.metrics()
    correct = _batch_correct(results, expected, case.mode)
    return _observation(
        duration_ns=duration_ns,
        logical_bytes=metadata.logical_size,
        actual_count=sum(len(value) if isinstance(value, list) else value for value in results.values()),
        expected_count=expected_count,
        termination="scope_exhausted",
        correctness_override=correct,
        comparison_identity=identity,
        metrics={
            **timed_read,
            "operation_identity": timed_identity,
            "logical_scanned_region_count": logical_regions,
            "patterns": len(patterns),
            "region_passes": len(patterns),
            "per_key": results,
            "fixture_version": metadata.fixture_version,
            "topology_fingerprint": metadata.topology_fingerprint,
        },
    )


def _current_batch(
    case: BenchmarkCase,
    metadata: TargetMetadata,
    proof: dict[str, Any],
    *,
    candidate_outer_watchdog_s: float | None,
) -> dict[str, Any]:
    import pymem.memory

    from memscope_mcp.scanning.contract import ScanManyInput
    from memscope_mcp.scanning.execution import ScanExecutor
    from memscope_mcp.session import DebugSession

    patterns = build_batch_patterns(int(case.parameters["patterns"]))
    expected = metadata.batch_expected
    payload: dict[str, Any] = {
        "patterns": [{"key": key, "pattern": pattern} for key, pattern in patterns],
        "scope": {
            "kind": "range",
            "start": metadata.base_address,
            "end_exclusive": metadata.end_exclusive,
        },
        "mode": case.mode,
        "timeout_ms": case.timeout_ms,
        "diagnostics": True,
    }
    if case.mode == "count":
        payload["max_matches"] = case.max_matches or 5000
    session = DebugSession()
    if not session.switch_process("", pid=metadata.pid):
        raise RuntimeError(f"could not attach candidate scanner to controlled child {metadata.pid}")
    probe = _HistoricalReadProbe(read_memory=pymem.memory.read_bytes)
    executor = ScanExecutor(session, read_memory=probe.read_memory)
    try:
        started = time.perf_counter_ns()
        response = _dump_response(executor.execute_many(ScanManyInput.model_validate(payload)))
        duration_ns = time.perf_counter_ns() - started
    finally:
        session.detach()
    timed_read = probe.metrics()
    if not response["success"]:
        raise RuntimeError(f"candidate batch failed: {response}")
    results: dict[str, list[int] | int] = {}
    for item in response["results"]:
        if case.mode == "first":
            results[item["key"]] = [] if item["match"] is None else [int(item["match"]["address"], 16)]
        else:
            results[item["key"]] = int(item["count"])
    diagnostics = response["shared"].get("diagnostics") or {}
    correct = _batch_correct(results, expected, case.mode)
    proof_correct = bool(proof.get("summary", {}).get("all_correct"))
    return _observation(
        duration_ns=duration_ns,
        logical_bytes=metadata.logical_size,
        actual_count=sum(len(value) if isinstance(value, list) else value for value in results.values()),
        expected_count=sum(len(value) for value in expected.values()),
        termination=response["shared"]["termination"],
        correctness_override=correct and proof_correct,
        comparison_identity=_target_comparison_identity(metadata),
        metrics={
            **timed_read,
            **candidate_watchdog_metrics(case.process_timeout_s, candidate_outer_watchdog_s),
            "operation_identity": operation_identity(metadata, phase="timed"),
            "logical_scanned_region_count": int(diagnostics.get("region_count", 0)),
            "patterns": len(patterns),
            "region_passes": 1,
            "per_key": results,
            "committed_engine_case_id": proof["case_id"],
            "committed_engine_fingerprint": proof["semantic_fingerprint"],
            "fixture_version": metadata.fixture_version,
            "topology_fingerprint": metadata.topology_fingerprint,
        },
    )


def _run_strict_unknown(
    implementation: str,
    profile: str,
    target_root: Path,
    *,
    before_timed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    proof = None
    if implementation == "before":
        from memscope_mcp.tools.scanning import scan_aob

        _signature = inspect.signature(scan_aob)
        strict = False
        expected = False
        _authorize_timed_phase(
            before_timed,
            _historical_ready_evidence(
                logical_bytes=0,
                expected_count=0,
                expected_checksum=None,
                comparison_identity=None,
                metrics={"prepared_kind": "strict_unknown"},
            ),
        )
    else:
        from pydantic import ValidationError

        from benchmarks.scanning.public_api import run_public_api_suite
        from memscope_mcp.scanning.contract import ScanInput

        proof = run_public_api_suite(
            repo_root=target_root,
            profile=profile,
            warmups=0,
            repetitions=1,
            implementation_label="after",
            case_ids=("public.fastmcp.strict_flat_contract",),
        )["cases"][0]
        try:
            ScanInput.model_validate({"pattern": "AA", "unknown_field": True})
        except ValidationError:
            strict = True
        else:
            strict = False
        expected = True
    return _observation(
        duration_ns=0,
        logical_bytes=0,
        actual_count=int(strict),
        expected_count=int(expected),
        termination="complete",
        correctness_override=strict is expected,
        metrics={
            "strict_unknown_rejection": strict,
            "historical_signature": None if implementation == "after" else str(_signature),
            "committed_public_case_id": None if proof is None else proof["case_id"],
            "committed_public_fingerprint": None if proof is None else proof["semantic_fingerprint"],
        },
    )


def _observation(
    *,
    duration_ns: int,
    logical_bytes: int,
    actual_count: int,
    expected_count: int,
    termination: str,
    metrics: dict[str, Any],
    actual_checksum: str | None = None,
    expected_checksum: str | None = None,
    peak_bytes: int | None = None,
    correctness_override: bool | None = None,
    throughput_mib_s: float | None = None,
    comparison_identity: dict[str, Any] | None = None,
    expected_historical_failure: bool = False,
) -> dict[str, Any]:
    correctness = actual_count == expected_count
    if actual_checksum is not None or expected_checksum is not None:
        correctness = correctness and actual_checksum == expected_checksum
    if correctness_override is not None:
        correctness = correctness_override
    if throughput_mib_s is None and duration_ns > 0 and logical_bytes > 0:
        throughput_mib_s = logical_bytes / (1024 * 1024) / (duration_ns / 1_000_000_000)
    return {
        "status": "ok",
        "duration_ns": duration_ns,
        "logical_bytes": logical_bytes,
        "throughput_mib_s": throughput_mib_s,
        "peak_python_bytes": peak_bytes,
        "actual_count": actual_count,
        "expected_count": expected_count,
        "actual_checksum": actual_checksum,
        "expected_checksum": expected_checksum,
        "correct": correctness,
        "termination": termination,
        "comparison_identity": comparison_identity,
        "expected_historical_failure": expected_historical_failure,
        "metrics": metrics,
    }


def _corpus_comparison_identity(
    corpus: dict[str, Any],
    expected: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    fields = (
        "corpus_version",
        "profile",
        "base_address",
        "size",
        "sha256",
        "fixture_version",
        "fixture_source_sha256",
        "topology_fingerprint",
    )
    identity = {field: corpus[field] for field in fields if corpus.get(field) is not None}
    if expected is not None:
        returned_count = expected.get("returned_count")
        relative_checksum = expected.get("relative_address_checksum")
        if returned_count is not None:
            identity["expected_count"] = returned_count
        if relative_checksum is not None:
            identity["expected_relative_checksum"] = relative_checksum
    return identity or None


def _target_comparison_identity(metadata: TargetMetadata) -> dict[str, Any]:
    return comparison_identity(metadata)


def _retain_addresses(case: BenchmarkCase, addresses: list[int]) -> list[int]:
    if case.mode == "first":
        return addresses[:1]
    if case.mode == "addresses":
        return addresses[: case.limit or case.max_matches or 50]
    return addresses[: case.max_matches or len(addresses)]


def _collector_termination(case: BenchmarkCase, count: int) -> str:
    if case.mode == "first" and count:
        return "first_hit"
    if case.max_matches is not None and count >= case.max_matches:
        return "match_limit"
    if case.mode == "addresses" and count >= (case.limit or 50):
        return "page_limit"
    return "scope_exhausted"


def _legacy_termination(metadata: dict[str, Any], mode: str) -> str:
    if metadata.get("limit_hit"):
        return "first_hit" if mode == "first" else "match_limit"
    return "scope_exhausted"


def _dump_response(response: Any) -> dict[str, Any]:
    root = getattr(response, "root", response)
    return root.model_dump(mode="json")


def _batch_correct(
    results: dict[str, list[int] | int],
    expected: dict[str, tuple[int, ...]],
    mode: str,
) -> bool:
    for key, expected_addresses in expected.items():
        actual = results.get(key)
        if mode == "first":
            if actual != list(expected_addresses[:1]):
                return False
        elif actual != len(expected_addresses):
            return False
    return True


def _require_metadata(target: ControlledProcessTarget) -> TargetMetadata:
    if target.metadata is None:
        raise RuntimeError("controlled target did not publish metadata")
    return target.metadata


if ctypes.sizeof(ctypes.c_void_p) == 8:
    _SIZE_T = ctypes.c_uint64
else:
    _SIZE_T = ctypes.c_uint32

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if hasattr(ctypes, "WinDLL") else None
if _kernel32 is not None:
    _kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        _SIZE_T,
        ctypes.POINTER(_SIZE_T),
    ]
    _kernel32.ReadProcessMemory.restype = ctypes.c_int
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = ctypes.c_int


def _open_process(pid: int) -> int:
    if _kernel32 is None:
        raise RuntimeError("raw reader evidence requires Windows")
    handle = _kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for PID {pid}")
    return int(handle)


def _read_process_bytes(handle: int, address: int, size: int) -> bytes:
    if _kernel32 is None:
        raise RuntimeError("raw reader evidence requires Windows")
    buffer = ctypes.create_string_buffer(size)
    read = _SIZE_T()
    if not _kernel32.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(read)):
        raise OSError(ctypes.get_last_error(), f"ReadProcessMemory failed at 0x{address:X}")
    if int(read.value) != size:
        raise RuntimeError(f"short ReadProcessMemory at 0x{address:X}: {read.value} != {size}")
    return buffer.raw


def _close_handle(handle: int) -> None:
    if _kernel32 is not None and handle:
        _kernel32.CloseHandle(handle)
