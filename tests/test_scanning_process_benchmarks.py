"""Controlled-process and chunk-policy tests for scanning benchmarks."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from benchmarks.scanning.allocation import measure_peak_python_bytes
from benchmarks.scanning.common import (
    ArtifactValidationError,
    semantic_fingerprint,
    semantic_fingerprint_payload,
    sha256_json,
    validate_raw_artifact,
)
from benchmarks.scanning.manifest import CASES
from benchmarks.scanning.process_scan import BenchmarkFailure, run_process_suite, select_production_chunk
from benchmarks.scanning.process_target import PAGE_READONLY, PAGE_READWRITE, ControlledProcessTarget


def test_controlled_process_target_has_stable_topology_and_exit_command():
    case = next(case for case in CASES if case.case_id == "e2e.exact16.late.contiguous64m")

    with ControlledProcessTarget(case, "smoke") as first:
        assert first.metadata is not None
        first_metadata = first.metadata
        assert first.ping()["pid"] == first_metadata.pid
        assert first_metadata.topology_fingerprint == sha256_json(first_metadata.topology)
        assert first_metadata.expected_addresses
        assert first_metadata.expected_checksum
        protection = first.change_protection(
            offset=4 * first_metadata.page_size,
            size=first_metadata.page_size,
            protection=PAGE_READONLY,
        )
        assert protection["old_protection"] == PAGE_READWRITE
        restored = first.change_protection(
            offset=4 * first_metadata.page_size,
            size=first_metadata.page_size,
            protection=PAGE_READWRITE,
        )
        assert restored["old_protection"] == PAGE_READONLY

    with ControlledProcessTarget(case, "smoke") as second:
        assert second.metadata is not None
        second_metadata = second.metadata
        assert second_metadata.corpus_sha256 == first_metadata.corpus_sha256
        assert second_metadata.topology_fingerprint == first_metadata.topology_fingerprint
        second.exit_now()
        assert second.process is not None
        assert second.process.poll() == 0


def test_controlled_process_target_publishes_batch_expectations():
    case = next(case for case in CASES if case.case_id == "batch.first16.early")

    with ControlledProcessTarget(case, "smoke") as target:
        assert target.metadata is not None
        expected = target.metadata.batch_expected
        assert len(expected) == 16
        assert all(len(addresses) == 1 for addresses in expected.values())
        assert all(
            target.metadata.base_address <= addresses[0] < target.metadata.end_exclusive
            for addresses in expected.values()
        )


def test_process_runner_executes_declared_live_timeout_case():
    repo_root = Path(__file__).resolve().parents[1]

    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=("control.timeout100.common_masked",),
    )

    case = artifact["cases"][0]
    observation = case["observations"][0]
    assert case["summary"]["all_correct"] is True
    assert observation["work"]["termination"] == "timeout"
    assert observation["work"]["timed_out"] is True
    assert observation["work"]["control_polls"] >= 1
    assert observation["work"]["timeout_overshoot_ns"] == observation["duration_ns"] - 100_000_000
    assert observation["work"]["candidate_watchdog_timeout_ns"] == 30_000_000_000
    assert observation["work"]["candidate_watchdog_enforced"] is False
    assert observation["work"]["candidate_watchdog_context"] == "standalone_diagnostic_no_outer_watchdog"
    assert observation["work"]["process_watchdog_ns"] is None
    assert artifact["runner"]["candidate_outer_watchdog"] == {
        "enforced": False,
        "context": "standalone_diagnostic_no_outer_watchdog",
        "timeout_s": None,
    }

    tampered = deepcopy(artifact)
    tampered_work = tampered["cases"][0]["observations"][0]["work"]
    tampered_work["termination"] = "scope_exhausted"
    tampered_work["timed_out"] = False
    with pytest.raises(ArtifactValidationError, match="timeout control termination is not timeout"):
        validate_raw_artifact(tampered)


def test_process_runner_keeps_preflight_setup_and_timed_counters_isolated():
    repo_root = Path(__file__).resolve().parents[1]

    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(
            "scope.section.text.current_exe",
            "scope.section.text.current_exe.warm",
        ),
    )

    cold, warm = artifact["cases"]
    cold_work = cold["observations"][0]["work"]
    warm_work = warm["observations"][0]["work"]
    cold_preflight = cold_work["preflight"]
    warm_preflight = warm_work["preflight"]
    setup = warm_work["setup"]

    section_bytes = cold_work["unique_bytes_examined"]
    uncached_sizes = cold_work["physical_read_sizes"]
    uncached_bytes = sum(uncached_sizes)
    assert cold["summary"]["all_correct"] is True
    assert cold_work["sections"] == [".text"]
    assert section_bytes > 0
    assert len(uncached_sizes) == 4
    assert uncached_sizes[:2] == [64, 24]
    assert uncached_sizes[2] > 0 and uncached_sizes[2] % 40 == 0
    assert uncached_sizes[3] == section_bytes
    assert cold_preflight["correct"] is True
    assert cold_preflight["unique_bytes_examined"] == section_bytes

    assert warm["summary"]["all_correct"] is True
    assert warm_work["sections"] == [".text"]
    assert warm_work["physical_read_calls"] == 1
    assert warm_work["physical_bytes_requested"] == section_bytes
    assert warm_work["physical_bytes_read"] == section_bytes
    assert warm_work["physical_read_sizes"] == [section_bytes]
    assert warm_work["unique_bytes_examined"] == section_bytes
    assert warm_preflight["correct"] is True
    assert warm_preflight["unique_bytes_examined"] == section_bytes
    assert setup["untimed_operations"] == 1
    assert setup["operation"] == "identical"
    assert setup["attachment"] == "same"
    assert setup["setup_excluded_from_timing"] is True
    assert setup["implementation_state"] == "shared_section_cache_hot"
    assert setup["correct"] is True
    assert setup["unique_bytes_examined"] == section_bytes
    assert setup["sections"] == [".text"]

    for read in (cold_work, cold_preflight["read"], warm_preflight["read"], setup["read"]):
        assert read["physical_read_calls"] == 4
        assert read["physical_bytes_requested"] == uncached_bytes
        assert read["physical_bytes_read"] == uncached_bytes
        assert read["physical_read_sizes"] == uncached_sizes

    assert (
        warm_preflight["read"]["physical_read_calls"]
        + setup["read"]["physical_read_calls"]
        + warm_work["physical_read_calls"]
        == 9
    )


def test_process_raw_schema_rejects_invalid_mandatory_preflight_read_evidence():
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=("scope.section.text.current_exe.warm",),
    )
    tampered = deepcopy(artifact)
    tampered["cases"][0]["observations"][0]["work"]["preflight"]["read"]["physical_read_calls"] = True

    with pytest.raises(ArtifactValidationError, match="physical_read_calls is not a non-negative integer"):
        validate_raw_artifact(tampered)


def test_process_raw_schema_rejects_rehashed_absolute_expectation_mutation():
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=("e2e.exact16.late.contiguous64m",),
    )
    invalid = deepcopy(artifact)
    case = invalid["cases"][0]
    case["expected"]["address_checksum"] = "0" * 64
    payload = semantic_fingerprint_payload(case["manifest"], case["corpus"], case["expected"])
    case["semantic_fingerprint_payload"] = payload
    case["semantic_fingerprint"] = semantic_fingerprint(payload)

    with pytest.raises(ArtifactValidationError, match="canonical preflight addresses"):
        validate_raw_artifact(invalid)


@pytest.mark.parametrize(
    "case_id",
    ("result.page50.dense", "dense.allwildcard.page100"),
)
def test_live_equal_page_and_match_caps_use_match_limit(case_id: str):
    repo_root = Path(__file__).resolve().parents[1]

    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(case_id,),
    )
    work = artifact["cases"][0]["observations"][0]["work"]

    assert work["actual_count"] == work["expected_count"]
    assert work["termination"] == "match_limit"
    assert work["correct"] is True


@pytest.mark.parametrize(
    "case_id",
    ("result.first.early.exact", "result.page50.dense", "dense.allwildcard.page100"),
)
def test_non_count_timed_checksums_are_bound_to_canonical_preflight(case_id: str):
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(case_id,),
    )
    work = artifact["cases"][0]["observations"][0]["work"]
    preflight = work["preflight"]

    assert work["expected_count"] == preflight["expected_count"]
    assert work["expected_checksum"] == preflight["expected_checksum"]
    assert work["actual_checksum"] == preflight["expected_checksum"]

    forged = deepcopy(artifact)
    forged_work = forged["cases"][0]["observations"][0]["work"]
    fabricated = "f" * 64
    assert fabricated != preflight["expected_checksum"]
    forged_work["expected_checksum"] = fabricated
    forged_work["actual_checksum"] = fabricated

    with pytest.raises(ArtifactValidationError, match="timed expected checksum differs from canonical preflight"):
        validate_raw_artifact(forged)


def test_process_runner_emits_schema_valid_reader_and_e2e_artifact():
    repo_root = Path(__file__).resolve().parents[1]

    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(
            "reader.ceiling.contiguous64m",
            "e2e.exact16.late.contiguous64m",
        ),
    )

    validate_raw_artifact(artifact)
    assert artifact["suite"] == "scanning.process"
    assert artifact["runner"]["chunk_selection"] is None
    assert [case["case_id"] for case in artifact["cases"]] == [
        "reader.ceiling.contiguous64m",
        "e2e.exact16.late.contiguous64m",
    ]
    assert all(case["summary"]["all_correct"] for case in artifact["cases"])
    reader, scanner = artifact["cases"]
    assert reader["observations"][0]["work"]["physical_read_calls"] > 0
    assert scanner["observations"][0]["work"]["physical_read_calls"] > 0
    assert scanner["observations"][0]["work"]["actual_count"] == 1


def test_salvage_case_records_failed_reads_and_truthful_gap_status():
    repo_root = Path(__file__).resolve().parents[1]

    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=("chunk.salvage.holes.128k",),
    )

    observation = artifact["cases"][0]["observations"][0]
    assert observation["work"]["correct"] is True
    assert observation["work"]["failed_read_calls"] > 0
    assert observation["work"]["read_gaps_detected"] is True
    assert observation["work"]["physical_bytes_requested"] > observation["work"]["physical_bytes_read"]


def test_manifest_declares_complete_chunk_matrix():
    case_ids = {case.case_id for case in CASES}
    labels = {"16k", "32k", "64k", "128k", "256k", "512k", "1m", "2m", "4m"}

    assert {f"chunk.exact.nohit.{label}" for label in labels} <= case_ids
    assert {f"chunk.salvage.holes.{label}" for label in labels} <= case_ids
    assert {f"chunk.timeout100.masked.{label}" for label in labels} <= case_ids


def test_one_size_release_chunk_subset_is_diagnostic_only():
    chunk_size = 128 * 1024
    cases = [
        _synthetic_case(
            "chunk.exact.nohit.128k",
            chunk_size,
            throughput_mib_s=1000.0,
            duration_ns=10_000_000,
            timeout_overshoot_ns=0,
        ),
        _synthetic_case(
            "chunk.salvage.holes.128k",
            chunk_size,
            throughput_mib_s=100.0,
            duration_ns=10_000_000,
            timeout_overshoot_ns=0,
        ),
        _synthetic_case(
            "chunk.timeout100.masked.128k",
            chunk_size,
            throughput_mib_s=100.0,
            duration_ns=105_000_000,
            timeout_overshoot_ns=5_000_000,
        ),
    ]

    selection = select_production_chunk(cases, profile="release", warmups=1, repetitions=3)

    assert selection["status"] == "insufficient_matrix"
    assert selection["exact_manifest_matrix"] is False
    assert selection["selected_chunk_size"] is None
    assert selection["diagnostic_selected_chunk_size"] == 128 * 1024


def test_full_chunk_matrix_requires_release_sampling_protocol():
    cases = _synthetic_chunk_matrix()

    selection = select_production_chunk(cases, profile="smoke", warmups=0, repetitions=1)

    assert selection["exact_manifest_matrix"] is True
    assert selection["status"] == "insufficient_protocol"
    assert selection["selected_chunk_size"] is None
    assert selection["diagnostic_selected_chunk_size"] == 128 * 1024


def test_full_release_chunk_matrix_requires_enforced_timeout_watchdogs():
    cases = _synthetic_chunk_matrix()
    for case in cases:
        if case["case_id"].startswith("chunk.timeout100.masked."):
            work = case["observations"][0]["work"]
            work["candidate_watchdog_enforced"] = False
            work["candidate_watchdog_context"] = "standalone_diagnostic_no_outer_watchdog"
            work["process_watchdog_ns"] = None

    selection = select_production_chunk(cases, profile="release", warmups=1, repetitions=3)

    assert selection["exact_manifest_matrix"] is True
    assert selection["timeout_watchdogs_enforced"] is False
    assert selection["status"] == "insufficient_protocol"
    assert selection["selected_chunk_size"] is None


def test_raw_process_artifact_rejects_forged_subset_selection_and_summary():
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_process_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(
            "chunk.exact.nohit.128k",
            "chunk.salvage.holes.128k",
        ),
    )
    assert artifact["runner"]["chunk_selection"]["status"] == "insufficient_matrix"
    assert artifact["runner"]["chunk_selection"]["selected_chunk_size"] is None

    forged_selection = deepcopy(artifact)
    forged_selection["runner"]["chunk_selection"]["status"] = "selected"
    forged_selection["runner"]["chunk_selection"]["selected_chunk_size"] = 128 * 1024
    with pytest.raises(ArtifactValidationError, match="chunk_selection differs"):
        validate_raw_artifact(forged_selection)

    forged_summary = deepcopy(artifact)
    forged_summary["cases"][0]["summary"]["throughput_mib_s"]["median"] += 1
    with pytest.raises(ArtifactValidationError, match="summary differs from observations"):
        validate_raw_artifact(forged_summary)


def test_chunk_policy_selects_smallest_fast_candidate_that_preserves_latency():
    throughput = {
        16 * 1024: 300.0,
        32 * 1024: 500.0,
        64 * 1024: 820.0,
        128 * 1024: 920.0,
        256 * 1024: 1000.0,
        512 * 1024: 980.0,
        1024 * 1024: 970.0,
        2 * 1024 * 1024: 960.0,
        4 * 1024 * 1024: 950.0,
    }
    cases = []
    for chunk_size, value in throughput.items():
        label = _chunk_label(chunk_size)
        cases.extend(
            (
                _synthetic_case(
                    f"chunk.exact.nohit.{label}",
                    chunk_size,
                    throughput_mib_s=value,
                    duration_ns=10_000_000,
                    timeout_overshoot_ns=0,
                ),
                _synthetic_case(
                    f"chunk.salvage.holes.{label}",
                    chunk_size,
                    throughput_mib_s=100.0,
                    duration_ns=10_000_000 if chunk_size <= 256 * 1024 else 20_000_000,
                    timeout_overshoot_ns=0,
                ),
                _synthetic_case(
                    f"chunk.timeout100.masked.{label}",
                    chunk_size,
                    throughput_mib_s=100.0,
                    duration_ns=100_000_000,
                    timeout_overshoot_ns=5_000_000 if chunk_size <= 256 * 1024 else 40_000_000,
                ),
            )
        )

    selection = select_production_chunk(cases, profile="release", warmups=1, repetitions=3)

    assert selection["status"] == "selected"
    assert selection["selected_chunk_size"] == 128 * 1024
    assert selection["policy"] == "smallest_within_10_percent_of_best_preserving_128k_latency"


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("scope_exhausted", "timeout control termination is not timeout"),
        ("timed_out_false", "timeout control timed_out flag is not true"),
        ("overshoot", "timeout overshoot is inconsistent"),
        ("control_polls", "timeout control has no control-poll evidence"),
    ),
)
def test_chunk_policy_rejects_unvalidated_timeout_rows(mutation: str, message: str):
    chunk_size = 128 * 1024
    cases = [
        _synthetic_case(
            "chunk.exact.nohit.128k",
            chunk_size,
            throughput_mib_s=1000.0,
            duration_ns=10_000_000,
            timeout_overshoot_ns=0,
        ),
        _synthetic_case(
            "chunk.salvage.holes.128k",
            chunk_size,
            throughput_mib_s=100.0,
            duration_ns=10_000_000,
            timeout_overshoot_ns=0,
        ),
        _synthetic_case(
            "chunk.timeout100.masked.128k",
            chunk_size,
            throughput_mib_s=100.0,
            duration_ns=105_000_000,
            timeout_overshoot_ns=5_000_000,
        ),
    ]
    work = cases[-1]["observations"][0]["work"]
    if mutation == "scope_exhausted":
        work["termination"] = "scope_exhausted"
    elif mutation == "timed_out_false":
        work["timed_out"] = False
    elif mutation == "overshoot":
        work["timeout_overshoot_ns"] += 1
    else:
        work["control_polls"] = 0

    with pytest.raises(BenchmarkFailure, match=message):
        select_production_chunk(cases, profile="release", warmups=1, repetitions=3)


def test_chunk_policy_recomputes_timeout_summary_from_validated_observations():
    chunk_size = 128 * 1024
    cases = [
        _synthetic_case(
            "chunk.exact.nohit.128k",
            chunk_size,
            throughput_mib_s=1000.0,
            duration_ns=10_000_000,
            timeout_overshoot_ns=0,
        ),
        _synthetic_case(
            "chunk.salvage.holes.128k",
            chunk_size,
            throughput_mib_s=100.0,
            duration_ns=10_000_000,
            timeout_overshoot_ns=0,
        ),
        _synthetic_case(
            "chunk.timeout100.masked.128k",
            chunk_size,
            throughput_mib_s=100.0,
            duration_ns=105_000_000,
            timeout_overshoot_ns=5_000_000,
        ),
    ]
    cases[-1]["summary"]["work"]["timeout_overshoot_ns"]["p95"] = 1.0

    selection = select_production_chunk(cases, profile="release", warmups=1, repetitions=3)

    assert selection["status"] == "insufficient_matrix"
    assert selection["selected_chunk_size"] is None
    assert selection["candidates"][0]["timeout_overshoot_p95_ns"] == 5_000_000


def test_allocation_probe_returns_result_and_positive_peak():
    result, peak = measure_peak_python_bytes(lambda: bytearray(64 * 1024))

    assert len(result) == 64 * 1024
    assert peak >= 64 * 1024


def _synthetic_chunk_matrix() -> list[dict]:
    throughput = {
        16 * 1024: 300.0,
        32 * 1024: 500.0,
        64 * 1024: 820.0,
        128 * 1024: 920.0,
        256 * 1024: 1000.0,
        512 * 1024: 980.0,
        1024 * 1024: 970.0,
        2 * 1024 * 1024: 960.0,
        4 * 1024 * 1024: 950.0,
    }
    cases: list[dict] = []
    for chunk_size, value in throughput.items():
        label = _chunk_label(chunk_size)
        cases.extend(
            (
                _synthetic_case(
                    f"chunk.exact.nohit.{label}",
                    chunk_size,
                    throughput_mib_s=value,
                    duration_ns=10_000_000,
                    timeout_overshoot_ns=0,
                ),
                _synthetic_case(
                    f"chunk.salvage.holes.{label}",
                    chunk_size,
                    throughput_mib_s=100.0,
                    duration_ns=10_000_000 if chunk_size <= 256 * 1024 else 20_000_000,
                    timeout_overshoot_ns=0,
                ),
                _synthetic_case(
                    f"chunk.timeout100.masked.{label}",
                    chunk_size,
                    throughput_mib_s=100.0,
                    duration_ns=100_000_000,
                    timeout_overshoot_ns=5_000_000 if chunk_size <= 256 * 1024 else 40_000_000,
                ),
            )
        )
    return cases


def _synthetic_case(
    case_id: str,
    chunk_size: int,
    *,
    throughput_mib_s: float,
    duration_ns: int,
    timeout_overshoot_ns: int,
) -> dict:
    timeout_case = case_id.startswith("chunk.timeout100.masked.")
    manifest = {
        "kind": "chunk_timeout" if timeout_case else "chunk_salvage" if ".salvage." in case_id else "chunk_sweep",
        "timeout_ms": 100 if timeout_case else 30_000,
        "process_timeout_s": 5.0 if timeout_case else 12.0,
        "parameters": {"chunk_size": chunk_size},
    }
    manifest["candidate_watchdog_timeout_s"] = 30.0
    measured_duration = 100_000_000 + timeout_overshoot_ns if timeout_case else duration_ns
    work = {"correct": True}
    if timeout_case:
        work.update(
            {
                "termination": "timeout",
                "timed_out": True,
                "timeout_budget_ns": 100_000_000,
                "candidate_watchdog_timeout_ns": 30_000_000_000,
                "candidate_watchdog_enforced": True,
                "candidate_watchdog_context": "paired_parent_outer_watchdog",
                "process_watchdog_ns": 30_000_000_000,
                "timeout_overshoot_ns": timeout_overshoot_ns,
                "control_polls": 8,
            }
        )
    observations = [
        {
            "duration_ns": measured_duration,
            "throughput_mib_s": throughput_mib_s,
            "work": work,
        }
    ]
    return {
        "case_id": case_id,
        "status": "complete",
        "manifest": manifest,
        "observations": observations,
        "summary": {
            "throughput_mib_s": {"median": throughput_mib_s},
            "duration_ns": {"p95": duration_ns},
            "work": {"timeout_overshoot_ns": {"p95": float(timeout_overshoot_ns)}},
            "all_correct": True,
        },
    }


def _chunk_label(chunk_size: int) -> str:
    labels = {
        16 * 1024: "16k",
        32 * 1024: "32k",
        64 * 1024: "64k",
        128 * 1024: "128k",
        256 * 1024: "256k",
        512 * 1024: "512k",
        1024 * 1024: "1m",
        2 * 1024 * 1024: "2m",
        4 * 1024 * 1024: "4m",
    }
    return labels[chunk_size]
