"""Controlled-process and chunk-policy tests for scanning benchmarks."""

from __future__ import annotations

from pathlib import Path

from benchmarks.scanning.allocation import measure_peak_python_bytes
from benchmarks.scanning.common import sha256_json, validate_raw_artifact
from benchmarks.scanning.manifest import CASES
from benchmarks.scanning.process_scan import run_process_suite, select_production_chunk
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

    selection = select_production_chunk(cases)

    assert selection["status"] == "selected"
    assert selection["selected_chunk_size"] == 128 * 1024
    assert selection["policy"] == "smallest_within_10_percent_of_best_preserving_128k_latency"


def test_allocation_probe_returns_result_and_positive_peak():
    result, peak = measure_peak_python_bytes(lambda: bytearray(64 * 1024))

    assert len(result) == 64 * 1024
    assert peak >= 64 * 1024


def _synthetic_case(
    case_id: str,
    chunk_size: int,
    *,
    throughput_mib_s: float,
    duration_ns: int,
    timeout_overshoot_ns: int,
) -> dict:
    return {
        "case_id": case_id,
        "status": "complete",
        "manifest": {"parameters": {"chunk_size": chunk_size}},
        "summary": {
            "throughput_mib_s": {"median": throughput_mib_s},
            "duration_ns": {"p95": duration_ns},
            "work": {"timeout_overshoot_ns": {"p95": timeout_overshoot_ns}},
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
