"""Paired scanning comparison, reporting, and worktree-safety tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.scanning import (
    BENCHMARK_SCHEMA_VERSION,
    CANDIDATE_WATCHDOG_FLOOR_S,
    CORPUS_VERSION,
    DRIVER_PROTOCOL,
    HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S,
    HISTORICAL_PREPARATION_ERROR_MARGIN_S,
    MANIFEST_VERSION,
    PAIRING_PROTOCOL,
)
from benchmarks.scanning.adapters import _HistoricalReadProbe, _legacy_exact_preflight, run_case
from benchmarks.scanning.common import (
    address_checksum,
    candidate_watchdog_metrics,
    git_identity,
    pair_order_label,
    pair_seed,
    paired_semantic_fingerprint_payload,
    range_union_size,
    read_evidence_error,
    semantic_fingerprint,
    sha256_json,
    timeout_duration_ns,
)
from benchmarks.scanning.compare import compare_artifacts, comparison_content_digest
from benchmarks.scanning.manifest import (
    CASE_BY_ID,
    CASES,
    BenchmarkCase,
    is_candidate_only,
    preflight_protocol,
    requires_exact_preflight,
    uses_controlled_target,
)
from benchmarks.scanning.report import generate_bundle
from benchmarks.scanning.report import main as report_main
from benchmarks.scanning.run import (
    _cleanup_owned_worktree,
    _cleanup_stale_owned_worktrees,
    _environment_metadata_for_python,
    _historical_preparation_timeout_seconds,
    _observation_timeout_seconds,
    _parse_driver_output,
    _run_observation,
)


def test_comparator_preserves_exact_process_censorship_and_selects_chunk_policy():
    before, after = _paired_artifacts()
    case = CASE_BY_ID["e2e.exact16.late.contiguous64m"]
    index = next(i for i, item in enumerate(before["observations"]) if item["case_id"] == case.case_id)
    before["observations"][index] = _censored_observation(before["observations"][index], case)

    comparison = compare_artifacts(before, after)

    assert comparison["complete"] is True
    assert comparison["blocking"] is False
    assert comparison["chunk_recommendation"]["selected_chunk_size"] == 256 * 1024
    chunk = next(row for row in comparison["rows"] if row["case_id"] == "chunk.exact.nohit.256k")
    assert chunk["status"] == "candidate_only"
    row = next(row for row in comparison["rows"] if row["case_id"] == case.case_id)
    assert row["status"] == "censored"
    assert row["censored_speedup_lower_bound"] == timeout_duration_ns(case.process_timeout_s) / 1_000_000


def test_declared_historical_capability_gap_is_visible_but_not_blocking():
    before, after = _paired_artifacts()
    case_id = "e2e.boundary.split_protection.exact"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    historical["correct"] = False
    historical["expected_historical_failure"] = True
    historical["actual_count"] = 0
    preflight = historical["metrics"]["preflight"]
    preflight["correct"] = False
    preflight["expected_historical_failure"] = True
    preflight["addresses"] = []
    preflight["address_checksum"] = address_checksum([])
    preflight["relative_addresses"] = []
    preflight["relative_address_checksum"] = address_checksum([])

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "ok"
    assert row["blocking"] is False
    assert row["paired_speedup"]["median"] is None
    assert row["notes"] == ["1 historical observations demonstrate the declared capability gap"]


def test_candidate_correctness_failure_blocks_comparison():
    before, after = _paired_artifacts()
    candidate = next(item for item in after["observations"] if item["case_id"] == "matcher.exact16.uniform")
    candidate["correct"] = False

    comparison = compare_artifacts(before, after)

    assert comparison["blocking"] is True
    assert comparison["blocking_cases"] == ["matcher.exact16.uniform"]


def test_warm_section_candidate_with_metadata_reads_blocks_comparison():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"].update(
        _read_evidence([(0x4000, 0x4040), (0x5000, 0x5018), (0x6000, 0x60F0), (0x7000, 0x8000)])
    )

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert row["notes"] == ["candidate block 0 warm timed scan did not use exactly one physical read"]


def test_warm_section_candidate_setup_state_tampering_blocks_comparison():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["setup"]["implementation_state"] = "fresh_section_cache"

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert row["notes"] == ["candidate block 0 warm setup implementation state differs"]


def test_warm_section_historical_setup_protocol_tampering_blocks_comparison():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    historical["metrics"]["setup"]["untimed_operations"] = 0

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert row["notes"] == ["historical block 0 warm setup protocol field untimed_operations differs"]


def test_warm_section_setup_correctness_tampering_blocks_comparison():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["setup"]["correct"] = False

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert row["notes"] == ["candidate block 0 warm setup did not produce the expected result"]


def test_historical_preflight_rejects_same_count_wrong_address():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    preflight = historical["metrics"]["preflight"]
    preflight["addresses"] = [0x1010, 0x1030]
    preflight["address_checksum"] = address_checksum(preflight["addresses"])
    preflight["relative_addresses"] = [0x10, 0x30]
    preflight["relative_address_checksum"] = address_checksum(preflight["relative_addresses"])

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["notes"] == ["historical block 0 preflight result differs from expectation"]


def test_historical_preflight_rejects_wrong_address_order():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    preflight = historical["metrics"]["preflight"]
    expected = [0x1010, 0x1020]
    preflight["expected_count"] = 2
    preflight["expected_checksum"] = address_checksum(expected)
    preflight["addresses"] = list(reversed(expected))
    preflight["address_checksum"] = address_checksum(preflight["addresses"])
    preflight["relative_addresses"] = [0x20, 0x10]
    preflight["relative_address_checksum"] = address_checksum(preflight["relative_addresses"])

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["notes"] == ["historical block 0 preflight result differs from expectation"]


def test_warm_validation_rejects_boolean_numeric_fields():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["physical_read_calls"] = True

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["notes"] == ["candidate block 0 timed read field physical_read_calls is not a non-negative integer"]


def test_warm_validation_rejects_missing_comparison_identity():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["comparison_identity"] = None
    _rebind_semantic_identity(candidate)

    with pytest.raises(ValueError, match="controlled-target identity has invalid fields"):
        compare_artifacts(before, after)


def test_warm_validation_rejects_changed_setup_identity():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    historical["metrics"]["setup"]["comparison_identity"]["sha256"] = "9" * 64

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["notes"] == ["historical block 0 warm setup comparison identity differs"]


def test_warm_validation_rejects_inconsistent_historical_probe_totals():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    historical["metrics"]["setup"]["read"]["physical_bytes_read"] += 1

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["notes"] == ["historical block 0 warm setup returned-byte total differs from read sizes"]


def test_historical_read_probe_counts_overlap_without_double_counting_union():
    probe = _HistoricalReadProbe(lambda _address, size: b"x" * size)
    first_size = 1024 * 1024 + 64
    probe.read_bytes(0x1000, first_size)
    probe.read_bytes(0x1000 + 1024 * 1024, 128)

    metrics = probe.metrics()

    assert metrics["physical_read_calls"] == 2
    assert metrics["physical_bytes_requested"] == first_size + 128
    assert metrics["physical_bytes_read"] == first_size + 128
    assert metrics["unique_logical_bytes"] == 1024 * 1024 + 128
    assert metrics["physical_read_ranges"] == [
        [0x1000, 0x1000 + first_size],
        [0x1000 + 1024 * 1024, 0x1000 + 1024 * 1024 + 128],
    ]
    assert metrics["physical_read_operations"] == [
        {
            "address": 0x1000,
            "requested_size": first_size,
            "returned_size": first_size,
            "success": True,
        },
        {
            "address": 0x1000 + 1024 * 1024,
            "requested_size": 128,
            "returned_size": 128,
            "success": True,
        },
    ]
    assert metrics["physical_read_operations_sha256"] == sha256_json(metrics["physical_read_operations"])
    assert read_evidence_error("historical probe", metrics) is None


@pytest.mark.parametrize(
    ("field", "unsupported"),
    (
        ("benchmark_schema_version", 99),
        ("manifest_version", "scanning-manifest-future"),
        ("corpus_version", "scanning-corpus-future"),
    ),
)
def test_matching_unsupported_versions_are_rejected(field: str, unsupported: object):
    before, after = _paired_artifacts()
    for artifact in (before, after):
        artifact["metadata"][field] = unsupported
        artifact["metadata"]["runner"][field] = unsupported

    with pytest.raises(ValueError, match=f"before artifact uses unsupported {field}"):
        compare_artifacts(before, after)


def test_candidate_only_declaration_must_match_selected_manifest_cases():
    before, after = _paired_artifacts()
    for artifact in (before, after):
        artifact["metadata"]["runner"]["candidate_only_case_ids"] = []

    with pytest.raises(ValueError, match="before artifact candidate-only declaration is invalid"):
        compare_artifacts(before, after)


def test_smoke_bundle_is_complete_but_not_release_eligible():
    before, after = _paired_artifacts()

    comparison = compare_artifacts(before, after)

    assert comparison["complete"] is True
    assert comparison["release_eligibility"]["eligible"] is False
    assert "profile is not release" in comparison["release_eligibility"]["reasons"]
    assert "fewer than seven paired blocks were declared" in comparison["release_eligibility"]["reasons"]


def test_release_subset_is_not_release_eligible():
    before, after = _paired_artifacts(profile="release", blocks=7, cases=CASES[:2])

    comparison = compare_artifacts(before, after)

    assert comparison["complete"] is True
    assert comparison["release_eligibility"]["eligible"] is False
    assert comparison["release_eligibility"]["reasons"] == [
        "selected cases are not the exact full manifest order",
        "candidate-only declaration does not match the full manifest",
    ]


def test_one_block_release_is_not_release_eligible():
    before, after = _paired_artifacts(profile="release", blocks=1)

    comparison = compare_artifacts(before, after)

    assert comparison["release_eligibility"] == {
        "eligible": False,
        "reasons": ["fewer than seven paired blocks were declared"],
    }


def test_dirty_release_is_diagnostic_only():
    before, after = _paired_artifacts(profile="release", blocks=7, candidate_dirty=True)

    comparison = compare_artifacts(before, after)

    assert comparison["release_eligibility"]["eligible"] is False
    assert "candidate source Git tree is not clean" in comparison["release_eligibility"]["reasons"]
    assert "tooling Git tree is not clean" in comparison["release_eligibility"]["reasons"]


def test_release_tooling_identity_must_match_candidate_source():
    before, after = _paired_artifacts(profile="release", blocks=7)
    for artifact in (before, after):
        artifact["metadata"]["runner"]["tooling_git"] = {
            "commit": "e" * 40,
            "tree": "f" * 40,
            "dirty": False,
        }

    comparison = compare_artifacts(before, after)

    assert comparison["release_eligibility"] == {
        "eligible": False,
        "reasons": ["tooling Git identity does not match candidate source"],
    }


def test_release_requires_exact_candidate_git_tree_identity():
    before, after = _paired_artifacts(profile="release", blocks=7)
    after["metadata"]["git"]["tree"] = None

    comparison = compare_artifacts(before, after)

    assert comparison["release_eligibility"] == {
        "eligible": False,
        "reasons": ["candidate source Git tree identity is not exact"],
    }


def test_clean_full_release_is_release_eligible():
    before, after = _paired_artifacts(profile="release", blocks=7)

    comparison = compare_artifacts(before, after)

    assert comparison["complete"] is True
    assert comparison["blocking"] is False
    assert comparison["release_eligibility"] == {"eligible": True, "reasons": []}


def test_separate_environment_paths_are_recorded_but_not_compatibility_keys():
    before, after = _paired_artifacts()
    after["metadata"]["python"]["executable"] = "D:/candidate-venv/python.exe"
    after["metadata"]["runner"]["python"] = "D:/candidate-venv/python.exe"

    comparison = compare_artifacts(before, after)

    assert comparison["compatible"] is True


def test_git_identity_does_not_inherit_a_parent_repository():
    root = Path(__file__).resolve().parents[1]

    identity = git_identity(root / "benchmarks")

    assert identity["commit"] is None
    assert identity["tree"] is None
    assert identity["dirty"] is None


def test_environment_metadata_comes_from_selected_interpreter():
    root = Path(__file__).resolve().parents[1]

    metadata = _environment_metadata_for_python(
        python=Path(sys.executable),
        tooling_root=root,
        target_root=root,
        implementation="after",
        profile="smoke",
    )

    assert Path(metadata["python"]["executable"]).resolve() == Path(sys.executable).resolve()
    assert metadata["packages"]["pydantic"]
    assert metadata["execution_policy"]["process_affinity_mask"]


def test_compile_adapter_records_repeated_and_cold_unique_latency():
    case = CASE_BY_ID["compile.exact16"]
    root = Path(__file__).resolve().parents[1]

    observation = run_case(
        case,
        implementation="after",
        profile="smoke",
        target_root=root,
    )

    metrics = observation["metrics"]
    assert observation["correct"] is True
    assert metrics["iterations"] == case.parameters["iterations"]
    assert metrics["warmups"] == 10
    assert metrics["latency_per_operation_ns"] > 0
    assert metrics["cold_unique_patterns"] == case.parameters["cold_unique_patterns"]
    assert metrics["cold_unique_duration_ns"] > 0
    assert metrics["cold_unique_latency_per_operation_ns"] > 0


def test_current_warm_section_adapter_preserves_cache_evidence():
    case = CASE_BY_ID["scope.section.text.current_exe.warm"]
    root = Path(__file__).resolve().parents[1]

    observation = run_case(
        case,
        implementation="after",
        profile="smoke",
        target_root=root,
    )

    metrics = observation["metrics"]
    setup = metrics["setup"]
    section_bytes = metrics["unique_bytes_examined"]
    setup_sizes = setup["read"]["physical_read_sizes"]
    assert observation["correct"] is True
    assert section_bytes > 0
    assert metrics["physical_read_calls"] == 1
    assert metrics["physical_bytes_requested"] == section_bytes
    assert metrics["physical_bytes_read"] == section_bytes
    assert metrics["physical_read_sizes"] == [section_bytes]
    assert setup["implementation_state"] == case.setup_protocol["candidate_state"]
    assert setup["correct"] is True
    assert setup["unique_bytes_examined"] == section_bytes
    assert setup["read"]["physical_read_calls"] == 4
    assert setup_sizes[:2] == [64, 24]
    assert setup_sizes[2] > 0 and setup_sizes[2] % 40 == 0
    assert setup_sizes[3] == section_bytes
    assert setup["read"]["physical_bytes_requested"] == sum(setup_sizes)
    assert setup["read"]["physical_bytes_read"] == sum(setup_sizes)


@pytest.mark.parametrize("observed", ([0x1010, 0x2030], [0x2020, 0x1010]))
def test_historical_count_preflight_rejects_wrong_exact_addresses(observed: list[int]):
    case = CASE_BY_ID["scope.section.text.current_exe.warm"]
    expected = (0x1010, 0x2020)
    metadata = SimpleNamespace(
        expected_addresses=expected,
        expected_checksum=address_checksum(expected),
        topology={"profile": "smoke"},
        logical_size=65_536,
        corpus_sha256="1" * 64,
        fixture_version="test-fixture-v1",
        fixture_source_sha256="2" * 64,
        topology_fingerprint="3" * 64,
        module={"name": "python.exe"},
        base_address=0x1000,
        end_exclusive=0x3000,
    )
    session = SimpleNamespace(read_bytes=lambda _address, size: b"x" * size)

    class FakeScanning:
        @staticmethod
        def scan_aob_addresses(*_args, **_kwargs):
            session.read_bytes(0x1000, 32)
            return {
                "success": True,
                "matches": list(observed),
                "metadata": {
                    "scanned_region_count": 1,
                    "bytes_scanned": 32,
                },
            }

    with pytest.raises(RuntimeError, match="historical preflight address mismatch"):
        _legacy_exact_preflight(case, metadata, FakeScanning, session)


def test_historical_preflight_attributes_timeout_before_checksum_mismatch():
    case = CASE_BY_ID["e2e.selective16.late.contiguous64m"]
    metadata = SimpleNamespace(
        expected_addresses=(0x1010,),
        expected_checksum=address_checksum([0x1010]),
        module={"name": "python.exe"},
        base_address=0x1000,
        end_exclusive=0x3000,
    )
    session = SimpleNamespace(read_bytes=lambda _address, size: b"x" * size)
    captured: dict[str, object] = {}

    class FakeScanning:
        @staticmethod
        def scan_aob_addresses(*_args, **kwargs):
            captured.update(kwargs)
            session.read_bytes(0x1000, 32)
            return {
                "success": True,
                "matches": [],
                "metadata": {
                    "timeout_hit": True,
                    "scanned_region_count": 7,
                    "bytes_scanned": 4096,
                },
            }

    with pytest.raises(RuntimeError, match="metadata.timeout_hit=true") as error:
        _legacy_exact_preflight(case, metadata, FakeScanning, session)

    assert "address mismatch" not in str(error.value)
    assert captured["timeout_ms"] == int(HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S * 1000)


def test_expected_strategy_is_enforced_separately_from_semantic_identity():
    before, after = _paired_artifacts()
    case_id = "matcher.exact16.uniform"
    case = CASE_BY_ID[case_id]
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["strategy_counts"] = {"regex": 1}

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["notes"] == ["candidate block 0 strategy map differs from {'exact': 1}"]
    assert replace(case, expected_strategy="regex").semantic_fingerprint("smoke") == case.semantic_fingerprint("smoke")


def test_environment_cpu_mismatch_is_rejected():
    before, after = _paired_artifacts()
    after["metadata"]["cpu"]["logical_count"] += 1

    with pytest.raises(ValueError, match="environment cpu differs"):
        compare_artifacts(before, after)


def test_runtime_comparison_identity_mismatch_blocks_case():
    before, after = _paired_artifacts()
    case_id = "matcher.exact16.uniform"
    before_item = next(item for item in before["observations"] if item["case_id"] == case_id)
    after_item = next(item for item in after["observations"] if item["case_id"] == case_id)
    before_item["comparison_identity"] = {"sha256": "a" * 64, "size": 1024}
    after_item["comparison_identity"] = {"sha256": "b" * 64, "size": 1024}
    _rebind_semantic_identity(before_item)
    _rebind_semantic_identity(after_item)

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert row["notes"] == ["semantic comparison fingerprint payload mismatch"]


def test_duplicate_observation_block_is_rejected_before_comparison():
    before, after = _paired_artifacts()
    original = next(item for item in before["observations"] if item["case_id"] == "compile.exact16")
    before["observations"].append(deepcopy(original))

    with pytest.raises(ValueError, match="duplicate case/block observation"):
        compare_artifacts(before, after)


def test_declared_block_matrix_must_be_complete_for_every_selected_case():
    before, after = _paired_artifacts()
    before["metadata"]["runner"]["blocks"] = 2
    after["metadata"]["runner"]["blocks"] = 2

    with pytest.raises(ValueError, match="before artifact observation matrix is incomplete"):
        compare_artifacts(before, after)


def test_observation_profile_must_match_artifact_profile():
    before, after = _paired_artifacts()
    before["observations"][0]["profile"] = "release"

    with pytest.raises(ValueError, match="before observation profile differs"):
        compare_artifacts(before, after)


def test_pair_order_label_must_be_valid():
    before, after = _paired_artifacts()
    before["observations"][0]["pair_order"] = "AA"

    with pytest.raises(ValueError, match="before observation pair order differs from deterministic protocol"):
        compare_artifacts(before, after)


def test_pair_order_must_be_consistent_across_artifacts():
    before, after = _paired_artifacts()
    after["observations"][0]["pair_order"] = "BA"

    with pytest.raises(ValueError, match="after observation pair order differs from deterministic protocol"):
        compare_artifacts(before, after)


def test_incompatible_runner_identity_is_rejected():
    before, after = _paired_artifacts()
    after["metadata"]["runner"]["manifest_version"] = "scanning-manifest-future"

    with pytest.raises(ValueError, match="after runner uses unsupported manifest_version"):
        compare_artifacts(before, after)


def test_report_bundle_keeps_every_declared_case_visible(tmp_path: Path):
    before, after = _paired_artifacts()
    comparison = compare_artifacts(before, after)

    generate_bundle(comparison, tmp_path)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert all(case.case_id in report for case in CASES)
    assert "Diagnostic selection: `256.00 KiB`" in report
    assert "Diagnostic evidence does not change the production reader" in report
    assert "Candidate correctness" in report
    assert f"checksum `{address_checksum([0x1010, 0x1020])}`" in report
    assert "checksum `ffffffffffff?`" not in report
    post = (tmp_path / "post.md").read_text(encoding="utf-8")
    assert "diagnostic and not release eligible" in post
    assert {
        "allocation.svg",
        "end-to-end-throughput.svg",
        "latency-speedup.svg",
        "matcher-throughput.svg",
        "read-reduction.svg",
    } == {path.name for path in (tmp_path / "charts").iterdir()}


def test_candidate_process_deadline_has_margin_but_historical_censorship_stays_fixed():
    case = CASE_BY_ID["matcher.sparse_common16.skew"]

    assert _observation_timeout_seconds(case, "before") == case.process_timeout_s
    assert _observation_timeout_seconds(case, "after") == 30.0


def test_historical_preparation_timeout_includes_bounded_error_margin():
    case = CASE_BY_ID["e2e.selective16.late.contiguous64m"]

    assert _historical_preparation_timeout_seconds(case) == (
        max(case.process_timeout_s, HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S) + HISTORICAL_PREPARATION_ERROR_MARGIN_S
    )
    assert _historical_preparation_timeout_seconds(case) == 35.0


def test_candidate_subprocess_timeout_is_blocking_not_censored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = CASE_BY_ID["matcher.sparse_common16.skew"]

    def expire(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=args[0],
            timeout=kwargs["timeout"],
            output="partial stdout",
            stderr="partial stderr",
        )

    monkeypatch.setattr("benchmarks.scanning.run.subprocess.run", expire)

    candidate = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="after",
        profile="release",
        block=0,
        pair_order="AB",
    )
    historical = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="release",
        block=0,
        pair_order="AB",
    )

    assert candidate["status"] == "driver_error"
    assert candidate["correct"] is False
    assert "30.0 seconds" in candidate["error"]
    assert "candidate benchmark subprocess exceeded" in candidate["error"]
    assert historical["status"] == "driver_error"
    assert historical["correct"] is False
    assert "historical preparation" in historical["error"] or "driver produced no parseable" in historical["error"]


def test_driver_protocol_rejects_mismatched_identity():
    payload = {
        "case_id": "different.case",
        "implementation": "after",
        "profile": "smoke",
        "block": 0,
        "pair_seed": pair_seed("different.case", 0),
        "pair_order": pair_order_label("different.case", 0),
        "status": "ok",
        "correct": True,
    }

    result = _parse_driver_output(
        json.dumps(payload),
        expected_case_id="compile.exact16",
        expected_implementation="after",
        expected_profile="smoke",
        expected_block=0,
        expected_pair_seed=pair_seed("compile.exact16", 0),
        expected_pair_order=pair_order_label("compile.exact16", 0),
    )

    assert result["status"] == "driver_error"
    assert result["correct"] is False
    assert "identity mismatch" in result["error"]


def test_censorship_rejects_inflated_lower_bound():
    before, after = _paired_artifacts()
    case = CASE_BY_ID["e2e.exact16.late.contiguous64m"]
    index = next(i for i, item in enumerate(before["observations"]) if item["case_id"] == case.case_id)
    censored = _censored_observation(before["observations"][index], case)
    censored["censorship"]["lower_bound_duration_ns"] += 1
    before["observations"][index] = censored

    with pytest.raises(ValueError, match="censorship lower bound is not exactly derived"):
        compare_artifacts(before, after)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("timeout_seconds", True, "censorship timeout does not match"),
        ("lower_bound_duration_ns", True, "censorship lower bound is not exactly derived"),
    ),
)
def test_censorship_rejects_boolean_numeric_fields(field: str, value: object, message: str):
    before, after = _paired_artifacts()
    case = CASE_BY_ID["e2e.exact16.late.contiguous64m"]
    index = next(i for i, item in enumerate(before["observations"]) if item["case_id"] == case.case_id)
    censored = _censored_observation(before["observations"][index], case)
    censored["censorship"][field] = value
    before["observations"][index] = censored

    with pytest.raises(ValueError, match=message):
        compare_artifacts(before, after)


def test_censored_exact_process_still_validates_preflight_provenance():
    before, after = _paired_artifacts()
    case = CASE_BY_ID["e2e.exact16.late.contiguous64m"]
    index = next(i for i, item in enumerate(before["observations"]) if item["case_id"] == case.case_id)
    censored = _censored_observation(before["observations"][index], case)
    censored["metrics"]["preflight"]["relative_addresses"] = [0x10, 0x30]
    before["observations"][index] = censored

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case.case_id)
    assert row["status"] == "invalid"
    assert row["blocking"] is True


def test_controlled_target_identity_rejects_reduced_shape():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["comparison_identity"].pop("fixture_source_sha256")
    _rebind_semantic_identity(candidate)

    with pytest.raises(ValueError, match="controlled-target identity has invalid fields"):
        compare_artifacts(before, after)


def test_warm_setup_timed_continuity_mismatch_blocks_row():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["operation_identity"]["attachment_generation"] = 2

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert "continuity differs" in row["notes"][0]


def test_warm_cache_token_mismatch_blocks_row():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["operation_identity"]["cache_token"] = "e" * 64

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert "cache token differs" in row["notes"][0]


def test_false_correct_count_is_recomputed_and_rejected():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["actual_count"] = 1
    candidate["correct"] = True

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert row["notes"] == ["candidate block 0 timed correctness flag differs from exact fields"]


def test_strict_unknown_candidate_producer_emits_declared_non_timing_capability():
    case = CASE_BY_ID["public.strict_unknown_field"]

    observation = run_case(
        case,
        implementation="after",
        profile="smoke",
        target_root=Path(__file__).resolve().parents[1],
    )

    assert case.observation_metric_contract == "non_timing_capability"
    assert observation["status"] == "ok"
    assert observation["correct"] is True
    assert observation["duration_ns"] == 0
    assert observation["logical_bytes"] == 0
    assert observation["throughput_mib_s"] is None
    assert observation["termination"] == "complete"
    assert observation["metrics"]["strict_unknown_rejection"] is True


def test_strict_unknown_paired_comparison_accepts_zero_work_null_throughput():
    case = CASE_BY_ID["public.strict_unknown_field"]
    before, after = _paired_artifacts(cases=(case,), blocks=2)

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "ok"
    assert row["blocking"] is False
    assert row["before"]["duration_ns"]["count"] == 2
    assert row["before"]["duration_ns"]["median"] == 0
    assert row["after"]["duration_ns"]["median"] == 0
    assert row["before"]["throughput_mib_s"]["count"] == 0
    assert row["after"]["throughput_mib_s"]["count"] == 0
    assert row["after"]["throughput_mib_s"]["median"] is None


@pytest.mark.parametrize(
    ("field", "value"),
    (("duration_ns", 1), ("logical_bytes", 1), ("throughput_mib_s", 0.0)),
)
def test_strict_unknown_non_timing_contract_rejects_nonzero_work_or_numeric_throughput(field: str, value: object):
    case = CASE_BY_ID["public.strict_unknown_field"]
    before, after = _paired_artifacts(cases=(case,))
    after["observations"][0][field] = value

    with pytest.raises(ValueError, match="zero duration/logical bytes and null throughput"):
        compare_artifacts(before, after)


def test_strict_unknown_non_timing_contract_requires_validation_metrics():
    case = CASE_BY_ID["public.strict_unknown_field"]
    before, after = _paired_artifacts(cases=(case,))
    after["observations"][0]["metrics"]["strict_unknown_rejection"] = False

    with pytest.raises(ValueError, match="strict-validation capability correctness evidence is invalid"):
        compare_artifacts(before, after)


@pytest.mark.parametrize("case_id", ("matcher.exact16.uniform", "e2e.boundary.split_protection.exact"))
def test_timed_contract_rejects_null_throughput_even_for_invariant_capability(case_id: str):
    case = CASE_BY_ID[case_id]
    before, after = _paired_artifacts(cases=(case,))
    after["observations"][0]["throughput_mib_s"] = None

    assert case.observation_metric_contract == "timed"
    with pytest.raises(ValueError, match="throughput must be finite and non-negative"):
        compare_artifacts(before, after)


def test_report_accepts_non_timing_capability_empty_throughput_summary(tmp_path: Path):
    case = CASE_BY_ID["public.strict_unknown_field"]
    comparison = compare_artifacts(*_paired_artifacts(cases=(case,), blocks=2))

    generate_bundle(comparison, tmp_path)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "`public.strict_unknown_field`" in report
    assert "n/a" in report


def test_report_rejects_empty_throughput_summary_for_timed_case(tmp_path: Path):
    case = CASE_BY_ID["matcher.exact16.uniform"]
    comparison = compare_artifacts(*_paired_artifacts(cases=(case,)))
    comparison["rows"][0]["after"]["throughput_mib_s"] = {
        "count": 0,
        "median": None,
        "p95": None,
        "minimum": None,
        "maximum": None,
        "mad": None,
    }
    comparison["content_digest"] = comparison_content_digest(comparison)

    with pytest.raises(ValueError, match="primary summary counts are inconsistent"):
        generate_bundle(comparison, tmp_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("duration_ns", True, "duration_ns must be a non-negative integer"),
        ("throughput_mib_s", float("inf"), "throughput must be finite"),
        ("throughput_mib_s", float("nan"), "throughput must be finite"),
    ),
)
def test_observation_rejects_bool_and_nonfinite_numbers(field: str, value: object, message: str):
    before, after = _paired_artifacts()
    after["observations"][0][field] = value

    with pytest.raises(ValueError, match=message):
        compare_artifacts(before, after)


def test_observation_rejects_extra_fields():
    before, after = _paired_artifacts()
    after["observations"][0]["unexpected"] = 1

    with pytest.raises(ValueError, match="ok observation fields are invalid"):
        compare_artifacts(before, after)


def test_report_recomputes_forged_release_eligibility(tmp_path: Path):
    before, after = _paired_artifacts()
    comparison = compare_artifacts(before, after)
    comparison["release_eligibility"] = {"eligible": True, "reasons": []}
    comparison["complete"] = True
    comparison["blocking"] = False

    generate_bundle(comparison, tmp_path)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    post = (tmp_path / "post.md").read_text(encoding="utf-8")
    assert "Comparison status: `diagnostic; not release eligible`" in report
    assert "Release eligible: `no`" in report
    assert "diagnostic and not release eligible" in post


def test_runner_pairing_protocol_mutation_is_rejected():
    before, after = _paired_artifacts()
    before["metadata"]["runner"]["pairing"] = {**PAIRING_PROTOCOL, "algorithm": "different"}

    with pytest.raises(ValueError, match="before runner pairing protocol is unsupported"):
        compare_artifacts(before, after)


def test_runner_driver_protocol_mutation_is_rejected():
    before, after = _paired_artifacts()
    after["metadata"]["runner"]["driver"] = {**DRIVER_PROTOCOL, "version": 999}

    with pytest.raises(ValueError, match="after runner driver protocol is unsupported"):
        compare_artifacts(before, after)


def test_observation_pair_seed_mutation_is_rejected():
    before, after = _paired_artifacts()
    before["observations"][0]["pair_seed"] += 1

    with pytest.raises(ValueError, match="pair seed differs from the deterministic protocol"):
        compare_artifacts(before, after)


def test_extra_strategy_entry_is_rejected():
    before, after = _paired_artifacts()
    case_id = "matcher.exact16.uniform"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"]["strategy_counts"] = {"exact": 1, "regex": 1}

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert "strategy map differs" in row["notes"][0]


def test_swapped_read_sizes_are_rejected_against_per_call_evidence():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    sizes = candidate["metrics"]["setup"]["read"]["physical_read_sizes"]
    sizes[0], sizes[1] = sizes[1], sizes[0]

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert "read sizes differ from per-call evidence" in row["notes"][0]


def test_per_call_returned_size_cannot_exceed_request():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    operation = candidate["metrics"]["setup"]["read"]["physical_read_operations"][0]
    operation["returned_size"] = operation["requested_size"] + 1

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert "returned size exceeds its request" in row["notes"][0]


def test_warm_setup_final_corpus_range_must_match_timed_range():
    before, after = _paired_artifacts()
    case_id = "scope.section.text.current_exe.warm"
    candidate = next(item for item in after["observations"] if item["case_id"] == case_id)
    candidate["metrics"].update(_read_evidence([(0x8000, 0x9000)]))

    comparison = compare_artifacts(before, after)
    row = next(row for row in comparison["rows"] if row["case_id"] == case_id)
    assert row["status"] == "invalid"
    assert "final corpus range differs from timed" in row["notes"][0]


def test_subset_report_uses_selected_case_wording(tmp_path: Path):
    selected = CASES[:2]
    comparison = compare_artifacts(*_paired_artifacts(cases=selected))

    generate_bundle(comparison, tmp_path)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Every selected case remains visible" in report
    assert "Unselected manifest cases are outside this diagnostic subset" in report
    assert "Every manifest case remains visible" not in report


def _ready_from_paired_observation(case: BenchmarkCase, source: dict) -> dict:
    descriptor = case.semantic_descriptor(source["profile"])
    identity = deepcopy(source.get("comparison_identity"))
    payload = paired_semantic_fingerprint_payload(descriptor, identity)
    return {
        "case_id": case.case_id,
        "implementation": "before",
        "profile": source["profile"],
        "block": source["block"],
        "pair_seed": source["pair_seed"],
        "pair_order": source["pair_order"],
        "semantic_fingerprint_payload": payload,
        "semantic_fingerprint": semantic_fingerprint(payload),
        "semantic_descriptor": descriptor,
        "event": "historical_ready",
        "status": "ready",
        "correct": True,
        "comparison_identity": identity,
        "logical_bytes": source["logical_bytes"],
        "expected_count": source["expected_count"],
        "expected_checksum": source["expected_checksum"],
        "expected_historical_failure": source["expected_historical_failure"],
        "preparation": {
            "imports_complete": True,
            "setup_complete": True,
            "warmups_complete": True,
            "validation_complete": True,
            "timed_statement_pending": True,
        },
        "metrics": deepcopy(source["metrics"]),
    }


@pytest.mark.parametrize(
    ("case_id", "comparison_identity", "logical_bytes", "expected_count", "expected_checksum"),
    (
        ("compile.exact16", None, 1600, 16, None),
        (
            "matcher.exact16.uniform",
            {
                "corpus_version": CORPUS_VERSION,
                "profile": "smoke",
                "base_address": 0x10000000,
                "size": 65_536,
                "sha256": "7" * 64,
            },
            65_536,
            2,
            address_checksum([0x10000010, 0x10000020]),
        ),
    ),
)
def test_historical_compile_and_matcher_censorship_starts_after_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_id: str,
    comparison_identity: dict | None,
    logical_bytes: int,
    expected_count: int,
    expected_checksum: str | None,
):
    case = replace(CASE_BY_ID[case_id], process_timeout_s=0.05)
    profile = "smoke"
    block = 0
    pair_order = pair_order_label(case.case_id, block)
    descriptor = case.semantic_descriptor(profile)
    fingerprint_payload = paired_semantic_fingerprint_payload(descriptor, comparison_identity)
    ready = {
        "case_id": case.case_id,
        "implementation": "before",
        "profile": profile,
        "block": block,
        "pair_seed": pair_seed(case.case_id, block),
        "pair_order": pair_order,
        "semantic_fingerprint_payload": fingerprint_payload,
        "semantic_fingerprint": semantic_fingerprint(fingerprint_payload),
        "semantic_descriptor": descriptor,
        "event": "historical_ready",
        "status": "ready",
        "correct": True,
        "comparison_identity": comparison_identity,
        "logical_bytes": logical_bytes,
        "expected_count": expected_count,
        "expected_checksum": expected_checksum,
        "expected_historical_failure": False,
        "preparation": {
            "imports_complete": True,
            "setup_complete": True,
            "warmups_complete": True,
            "validation_complete": True,
            "timed_statement_pending": True,
        },
        "metrics": {"prepared_kind": case.kind},
    }
    timed_start = {
        **ready,
        "event": "historical_timed_start",
        "metrics": {**ready["metrics"], "timed_phase_started": True},
    }
    script = tmp_path / f"{case.kind}-phased-timeout.py"
    script.write_text(
        "import sys, time\n"
        f"print({json.dumps(ready)!r}, flush=True)\n"
        "assert sys.stdin.readline().strip() == 'run-timed'\n"
        f"print({json.dumps(timed_start)!r}, flush=True)\n"
        "time.sleep(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "benchmarks.scanning.run._driver_command",
        lambda **_kwargs: [sys.executable, str(script)],
    )

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile=profile,
        block=block,
        pair_order=pair_order,
    )

    assert observation["status"] == "censored"
    assert observation["correct"] is None
    assert observation["metrics"]["timed_phase_started"] is True
    assert observation["preparation"]["validation_complete"] is True
    assert observation["censorship"] == {
        "phase": "timed",
        "reason": "process_timeout",
        "timeout_seconds": 0.05,
        "lower_bound_duration_ns": 50_000_000,
    }


def test_historical_timeout_without_ready_is_driver_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = replace(CASE_BY_ID["compile.exact16"], process_timeout_s=0.05)
    script = tmp_path / "no-ready-timeout.py"
    script.write_text("import time\ntime.sleep(1)\n", encoding="utf-8")
    monkeypatch.setattr(
        "benchmarks.scanning.run._driver_command",
        lambda **_kwargs: [sys.executable, str(script)],
    )
    monkeypatch.setattr("benchmarks.scanning.run.HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S", 0.05)
    monkeypatch.setattr("benchmarks.scanning.run.HISTORICAL_PREPARATION_ERROR_MARGIN_S", 0.02)

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "driver_error"
    assert observation["correct"] is False
    assert "historical preparation phase exceeded" in observation["error"]
    assert "censorship" not in observation


def test_historical_preparation_margin_captures_delayed_child_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = replace(CASE_BY_ID["compile.exact16"], process_timeout_s=0.05)
    before, _after = _paired_artifacts(cases=(case,))
    source = before["observations"][0]
    error_record = {
        key: deepcopy(source[key])
        for key in (
            "case_id",
            "implementation",
            "profile",
            "block",
            "pair_seed",
            "pair_order",
            "semantic_fingerprint_payload",
            "semantic_fingerprint",
            "semantic_descriptor",
        )
    }
    error_record.update(
        {
            "status": "error",
            "correct": False,
            "error_type": "RuntimeError",
            "error": "historical exact preflight timed out before readiness (metadata.timeout_hit=true)",
            "traceback": "synthetic delayed preflight timeout",
        }
    )
    script = tmp_path / "delayed-preparation-error.py"
    script.write_text(
        f"import time\ntime.sleep(0.08)\nprint({json.dumps(error_record)!r}, flush=True)\nraise SystemExit(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])
    monkeypatch.setattr("benchmarks.scanning.run.HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S", 0.05)
    monkeypatch.setattr("benchmarks.scanning.run.HISTORICAL_PREPARATION_ERROR_MARGIN_S", 0.20)

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "error"
    assert observation["correct"] is False
    assert "metadata.timeout_hit=true" in observation["error"]
    assert "censorship" not in observation


def test_historical_pre_ready_error_is_preserved_as_blocking_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = CASE_BY_ID["compile.exact16"]
    before, _after = _paired_artifacts(cases=(case,))
    source = before["observations"][0]
    error_record = {
        key: deepcopy(source[key])
        for key in (
            "case_id",
            "implementation",
            "profile",
            "block",
            "pair_seed",
            "pair_order",
            "semantic_fingerprint_payload",
            "semantic_fingerprint",
            "semantic_descriptor",
        )
    }
    error_record.update(
        {
            "status": "error",
            "correct": False,
            "error_type": "RuntimeError",
            "error": "historical import failed",
            "traceback": "synthetic traceback",
        }
    )
    script = tmp_path / "pre-ready-error.py"
    script.write_text(
        f"print({json.dumps(error_record)!r}, flush=True)\nraise SystemExit(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "error"
    assert observation["correct"] is False
    assert observation["error"] == "historical import failed"
    assert "censorship" not in observation


def test_historical_final_observation_without_ready_is_driver_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = CASE_BY_ID["compile.exact16"]
    before, _after = _paired_artifacts(cases=(case,))
    final_observation = before["observations"][0]
    script = tmp_path / "final-without-ready.py"
    script.write_text(f"print({json.dumps(final_observation)!r}, flush=True)\n", encoding="utf-8")
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "driver_error"
    assert "without readiness proof" in observation["error"]
    assert "censorship" not in observation


def test_historical_invalid_ready_is_driver_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = CASE_BY_ID["compile.exact16"]
    before, _after = _paired_artifacts(cases=(case,))
    ready = _ready_from_paired_observation(case, before["observations"][0])
    ready["preparation"]["validation_complete"] = False
    script = tmp_path / "invalid-ready.py"
    script.write_text(
        f"import time\nprint({json.dumps(ready)!r}, flush=True)\ntime.sleep(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "driver_error"
    assert "readiness proof is invalid" in observation["error"]
    assert "censorship" not in observation


def test_historical_exact_process_censorship_requires_flushed_timed_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    case = replace(CASE_BY_ID["e2e.exact16.late.contiguous64m"], process_timeout_s=0.05)
    before, _after = _paired_artifacts(cases=(case,))
    ready = _ready_from_paired_observation(case, before["observations"][0])
    timed_start = {
        **ready,
        "event": "historical_timed_start",
        "metrics": {**ready["metrics"], "timed_phase_started": True},
    }
    script = tmp_path / "exact-process-phased-timeout.py"
    script.write_text(
        "import sys, time\n"
        f"print({json.dumps(ready)!r}, flush=True)\n"
        "assert sys.stdin.readline().strip() == 'run-timed'\n"
        f"print({json.dumps(timed_start)!r}, flush=True)\n"
        "time.sleep(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "censored"
    assert observation["metrics"]["timed_phase_started"] is True
    assert observation["metrics"]["preflight"] == ready["metrics"]["preflight"]
    assert observation["comparison_identity"] == ready["comparison_identity"]


def test_historical_timeout_after_ready_without_timed_start_is_blocking_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    case = replace(CASE_BY_ID["e2e.exact16.late.contiguous64m"], process_timeout_s=0.05)
    before, _after = _paired_artifacts(cases=(case,))
    ready = _ready_from_paired_observation(case, before["observations"][0])
    script = tmp_path / "ready-without-timed-start.py"
    script.write_text(
        "import sys, time\n"
        f"print({json.dumps(ready)!r}, flush=True)\n"
        "assert sys.stdin.readline().strip() == 'run-timed'\n"
        "time.sleep(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])
    monkeypatch.setattr("benchmarks.scanning.run.CANDIDATE_WATCHDOG_FLOOR_S", 0.05)

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "driver_error"
    assert observation["correct"] is False
    assert "timed-start phase exceeded" in observation["error"]
    assert "censorship" not in observation
    assert observation["metrics"]["preflight"] == ready["metrics"]["preflight"]


def test_historical_forged_timed_start_is_blocking_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    case = replace(CASE_BY_ID["compile.exact16"], process_timeout_s=0.05)
    before, _after = _paired_artifacts(cases=(case,))
    ready = _ready_from_paired_observation(case, before["observations"][0])
    forged = {
        **ready,
        "event": "historical_timed_start",
        "expected_count": ready["expected_count"] + 1,
        "metrics": {**ready["metrics"], "timed_phase_started": True},
    }
    script = tmp_path / "forged-timed-start.py"
    script.write_text(
        "import sys, time\n"
        f"print({json.dumps(ready)!r}, flush=True)\n"
        "assert sys.stdin.readline().strip() == 'run-timed'\n"
        f"print({json.dumps(forged)!r}, flush=True)\n"
        "time.sleep(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("benchmarks.scanning.run._driver_command", lambda **_kwargs: [sys.executable, str(script)])

    observation = _run_observation(
        repo_root=tmp_path,
        python=Path(sys.executable),
        target_root=tmp_path,
        case=case,
        implementation="before",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "driver_error"
    assert "timed-start proof is invalid" in observation["error"]
    assert "censorship" not in observation


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("scope_exhausted", "timeout control termination is not timeout"),
        ("timed_out_false", "timeout control timed_out flag is not true"),
        ("overshoot", "timeout overshoot is inconsistent"),
        ("control_polls", "timeout control has no control-poll evidence"),
    ),
)
def test_timeout_control_mutations_block_candidate_row(mutation: str, message: str):
    case = CASE_BY_ID["control.timeout100.common_masked"]
    before, after = _paired_artifacts(cases=(case,))
    candidate = after["observations"][0]
    if mutation == "scope_exhausted":
        candidate["termination"] = "scope_exhausted"
        candidate["metrics"]["termination"] = "scope_exhausted"
    elif mutation == "timed_out_false":
        candidate["metrics"]["timed_out"] = False
    elif mutation == "overshoot":
        candidate["metrics"]["timeout_overshoot_ns"] += 1
    else:
        candidate["metrics"]["control_polls"] = 0

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert message in row["notes"][0]


def test_candidate_timeout_control_rejects_historical_watchdog_substitution():
    case = CASE_BY_ID["control.timeout100.common_masked"]
    before, after = _paired_artifacts(cases=(case,))
    metrics = after["observations"][0]["metrics"]
    metrics["candidate_watchdog_timeout_ns"] = timeout_duration_ns(case.process_timeout_s)
    metrics["process_watchdog_ns"] = timeout_duration_ns(case.process_timeout_s)

    with pytest.raises(ValueError, match="candidate watchdog deadline differs from the manifest"):
        compare_artifacts(before, after)


def test_candidate_only_chunk_timeout_requires_enforced_outer_watchdog():
    case = CASE_BY_ID["chunk.timeout100.masked.128k"]
    before, after = _paired_artifacts(cases=(case,))
    metrics = after["observations"][0]["metrics"]
    metrics["candidate_watchdog_enforced"] = False
    metrics["candidate_watchdog_context"] = "standalone_diagnostic_no_outer_watchdog"
    metrics["process_watchdog_ns"] = None

    with pytest.raises(ValueError, match="candidate outer watchdog was not enforced"):
        compare_artifacts(before, after)


@pytest.mark.parametrize(
    "case_id",
    ("control.timeout100.common_masked", "chunk.timeout100.masked.128k"),
)
def test_live_candidate_timeout_rows_record_effective_outer_watchdog(case_id: str):
    case = CASE_BY_ID[case_id]
    root = Path(__file__).resolve().parents[1]

    observation = _run_observation(
        repo_root=root,
        python=Path(sys.executable),
        target_root=root,
        case=case,
        implementation="after",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    assert observation["status"] == "ok", observation
    assert observation["correct"] is True
    metrics = observation["metrics"]
    watchdog_ns = timeout_duration_ns(case.semantic_descriptor("smoke")["candidate_watchdog_timeout_s"])
    assert metrics["candidate_watchdog_timeout_ns"] == watchdog_ns
    assert metrics["candidate_watchdog_enforced"] is True
    assert metrics["candidate_watchdog_context"] == "paired_parent_outer_watchdog"
    assert metrics["process_watchdog_ns"] == watchdog_ns


def test_live_paired_candidate_reader_ceiling_records_enforced_watchdog():
    case = CASE_BY_ID["reader.ceiling.contiguous64m"]
    root = Path(__file__).resolve().parents[1]

    observation = _run_observation(
        repo_root=root,
        python=Path(sys.executable),
        target_root=root,
        case=case,
        implementation="after",
        profile="smoke",
        block=0,
        pair_order=pair_order_label(case.case_id, 0),
    )

    metrics = observation["metrics"]
    assert observation["status"] == "ok"
    assert observation["correct"] is True
    assert metrics["candidate_watchdog_timeout_ns"] == 30_000_000_000
    assert metrics["candidate_watchdog_enforced"] is True
    assert metrics["candidate_watchdog_context"] == "paired_parent_outer_watchdog"
    assert metrics["process_watchdog_ns"] == 30_000_000_000
    assert "timed_out" not in metrics
    assert "timeout_budget_ns" not in metrics
    assert "control_polls" not in metrics
    assert "timeout_overshoot_ns" not in metrics


def test_standalone_candidate_reader_ceiling_records_unenforced_watchdog():
    case = CASE_BY_ID["reader.ceiling.contiguous64m"]

    observation = run_case(
        case,
        implementation="after",
        profile="smoke",
        target_root=Path(__file__).resolve().parents[1],
    )

    metrics = observation["metrics"]
    assert observation["status"] == "ok"
    assert observation["correct"] is True
    assert metrics["candidate_watchdog_timeout_ns"] == 30_000_000_000
    assert metrics["candidate_watchdog_enforced"] is False
    assert metrics["candidate_watchdog_context"] == "standalone_diagnostic_no_outer_watchdog"
    assert metrics["process_watchdog_ns"] is None
    assert "timed_out" not in metrics
    assert "timeout_budget_ns" not in metrics
    assert "control_polls" not in metrics
    assert "timeout_overshoot_ns" not in metrics


def test_candidate_reader_ceiling_rejects_forged_watchdog_provenance():
    case = CASE_BY_ID["reader.ceiling.contiguous64m"]
    before, after = _paired_artifacts(cases=(case,))
    metrics = after["observations"][0]["metrics"]
    metrics["candidate_watchdog_enforced"] = False
    metrics["candidate_watchdog_context"] = "standalone_diagnostic_no_outer_watchdog"
    metrics["process_watchdog_ns"] = None

    with pytest.raises(ValueError, match="candidate outer watchdog was not enforced"):
        compare_artifacts(before, after)


def test_historical_timeout_control_requires_timeout_hit_evidence():
    case = CASE_BY_ID["control.timeout100.common_masked"]
    before, after = _paired_artifacts(cases=(case,))
    before["observations"][0]["metrics"]["timeout_hit"] = False

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert row["notes"] == ["historical block 0 timeout control has no timeout-hit evidence"]


def test_chunk_policy_rejects_invalid_timeout_control_row():
    cases = tuple(case for case in CASES if case.kind in {"chunk_sweep", "chunk_salvage", "chunk_timeout"})
    before, after = _paired_artifacts(cases=cases)
    timeout = next(item for item in after["observations"] if item["case_id"] == "chunk.timeout100.masked.128k")
    timeout["metrics"]["timed_out"] = False

    comparison = compare_artifacts(before, after)

    assert comparison["chunk_recommendation"]["status"] == "inconclusive"
    assert comparison["chunk_recommendation"]["selected_chunk_size"] is None
    control = next(row for row in comparison["rows"] if row["case_id"] == "chunk.timeout100.masked.128k")
    assert control["blocking"] is True


@pytest.mark.parametrize("case_id", ("cursor.pages10.limit50.dense", "batch.count4.nohit"))
def test_current_cursor_and_batch_emit_validated_physical_read_operations(case_id: str):
    case = CASE_BY_ID[case_id]
    observation = run_case(
        case,
        implementation="after",
        profile="smoke",
        target_root=Path(__file__).resolve().parents[1],
    )
    metrics = observation["metrics"]

    assert observation["status"] == "ok"
    assert observation["correct"] is True
    assert metrics["physical_read_calls"] == len(metrics["physical_read_operations"])
    assert metrics["physical_read_operations_sha256"] == sha256_json(metrics["physical_read_operations"])
    assert read_evidence_error(f"candidate {case_id}", metrics) is None


@pytest.mark.parametrize("case_id", ("cursor.pages10.limit50.dense", "batch.count4.nohit"))
@pytest.mark.parametrize("side", ("before", "after"))
def test_cursor_and_batch_require_per_call_read_evidence(case_id: str, side: str):
    case = CASE_BY_ID[case_id]
    before, after = _paired_artifacts(cases=(case,))
    artifact = before if side == "before" else after
    artifact["observations"][0]["metrics"].pop("physical_read_operations")

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert "per-call read evidence is invalid" in row["notes"][0]


@pytest.mark.parametrize("case_id", ("cursor.pages10.limit50.dense", "batch.count4.nohit"))
def test_cursor_and_batch_reject_forged_read_aggregates(case_id: str):
    case = CASE_BY_ID[case_id]
    before, after = _paired_artifacts(cases=(case,))
    after["observations"][0]["metrics"]["physical_bytes_read"] += 1

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert "returned-byte total differs from read sizes" in row["notes"][0]


@pytest.mark.parametrize("case_id", ("cursor.pages10.limit50.dense", "batch.count4.nohit"))
def test_cursor_and_batch_reject_missing_per_call_checksum(case_id: str):
    case = CASE_BY_ID[case_id]
    before, after = _paired_artifacts(cases=(case,))
    after["observations"][0]["metrics"].pop("physical_read_operations_sha256")

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert "per-call read checksum is invalid" in row["notes"][0]


@pytest.mark.parametrize("case_id", ("cursor.pages10.limit50.dense", "batch.count4.nohit"))
def test_cursor_and_batch_reject_forged_per_call_address(case_id: str):
    case = CASE_BY_ID[case_id]
    before, after = _paired_artifacts(cases=(case,))
    after["observations"][0]["metrics"]["physical_read_operations"][0]["address"] += 1

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert "per-call read checksum is invalid" in row["notes"][0]


@pytest.mark.parametrize("case_id", ("cursor.pages10.limit50.dense", "batch.count4.nohit"))
def test_cursor_and_batch_reject_inconsistent_read_ranges(case_id: str):
    case = CASE_BY_ID[case_id]
    before, after = _paired_artifacts(cases=(case,))
    metrics = after["observations"][0]["metrics"]
    metrics["physical_read_ranges"][0][1] += 1
    metrics["read_ranges_sha256"] = sha256_json(metrics["physical_read_ranges"])

    comparison = compare_artifacts(before, after)
    row = comparison["rows"][0]

    assert row["status"] == "invalid"
    assert "read ranges differ from per-call evidence" in row["notes"][0]


def test_report_rejects_supported_digest_with_unsupported_environment(tmp_path: Path):
    comparison = compare_artifacts(*_paired_artifacts())
    comparison["after_environment"]["manifest_version"] = "scanning-manifest-future"
    comparison["content_digest"] = comparison_content_digest(comparison)

    with pytest.raises(ValueError, match="candidate comparison environment uses unsupported manifest_version"):
        generate_bundle(comparison, tmp_path)


def test_report_recomputes_zero_correct_row_as_blocking(tmp_path: Path):
    comparison = compare_artifacts(*_paired_artifacts())
    row = comparison["rows"][0]
    row["after"]["correct_count"] = 0
    row["blocking"] = False
    comparison["blocking"] = False
    comparison["blocking_cases"] = []
    comparison["release_eligibility"] = {"eligible": True, "reasons": []}
    comparison["content_digest"] = comparison_content_digest(comparison)

    generate_bundle(comparison, tmp_path)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Comparison status: `blocking`" in report
    assert "Release eligible: `no`" in report


def test_report_rejects_inconsistent_row_counts_even_with_matching_digest(tmp_path: Path):
    comparison = compare_artifacts(*_paired_artifacts())
    row = comparison["rows"][0]
    row["after"]["correct_count"] = row["after"]["observation_count"] + 1
    comparison["content_digest"] = comparison_content_digest(comparison)

    with pytest.raises(ValueError, match="counts are inconsistent"):
        generate_bundle(comparison, tmp_path)


def test_report_cli_rejects_tampered_canonical_row_before_rendering(tmp_path: Path):
    comparison = compare_artifacts(*_paired_artifacts())
    comparison["rows"][0]["group"] = "Forged group"
    comparison["content_digest"] = comparison_content_digest(comparison)
    comparison_path = tmp_path / "comparison.json"
    comparison_path.write_text(json.dumps(comparison), encoding="utf-8")
    output_dir = tmp_path / "report"

    with pytest.raises(ValueError, match="manifest fields differ"):
        report_main(["--comparison", str(comparison_path), "--output-dir", str(output_dir)])

    assert not output_dir.exists()


def test_report_rejects_forged_status_counts_with_matching_digest(tmp_path: Path):
    comparison = compare_artifacts(*_paired_artifacts())
    comparison["rows"][0]["after_status_counts"] = {"ok": 2}
    comparison["content_digest"] = comparison_content_digest(comparison)

    with pytest.raises(ValueError, match="status counts are inconsistent"):
        generate_bundle(comparison, tmp_path)


def test_report_rejects_forged_summary_ordering_with_matching_digest(tmp_path: Path):
    comparison = compare_artifacts(*_paired_artifacts())
    stats = comparison["rows"][0]["after"]["duration_ns"]
    stats["minimum"] = stats["maximum"] + 1
    comparison["content_digest"] = comparison_content_digest(comparison)

    with pytest.raises(ValueError, match="summary ordering is invalid"):
        generate_bundle(comparison, tmp_path)


def test_owned_worktree_cleanup_refuses_dirty_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    owned_root = tmp_path / "owned"
    run_root = owned_root / "run-test"
    worktree = run_root / "before"
    worktree.mkdir(parents=True)
    owner = {
        "schema_version": 1,
        "repo_root": str(tmp_path / "repo"),
        "worktree": str(worktree),
        "expected_commit": "a" * 40,
        "owner_pid": os.getpid(),
        "state": "active",
    }

    def fake_git(_root: Path, *arguments: str) -> str:
        return "a" * 40 + "\n" if arguments[:2] == ("rev-parse", "HEAD") else "1 .M N... dirty.py\n"

    monkeypatch.setattr("benchmarks.scanning.run._git", fake_git)

    with pytest.raises(RuntimeError, match="unexpected state"):
        _cleanup_owned_worktree(tmp_path / "repo", owned_root, run_root, owner)

    retained = json.loads((run_root / "owner.json").read_text(encoding="utf-8"))
    assert retained["state"] == "retained-unexpected-state"
    assert worktree.is_dir()


def test_pytest_excludes_generated_benchmark_sources(request: pytest.FixtureRequest):
    assert "benchmark-results" in request.config.getini("norecursedirs")


def test_stale_owned_worktree_detection_uses_bounded_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo_root = (tmp_path / "repo").resolve()
    repo_root.mkdir()
    owned_root = (tmp_path / "owned").resolve()
    run_root = owned_root / "run-stale"
    worktree = run_root / "before"
    worktree.mkdir(parents=True)
    (run_root / "owner.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repo_root": str(repo_root),
                "worktree": str(worktree),
                "expected_commit": "a" * 40,
                "owner_pid": 123456789,
                "state": "active",
            }
        ),
        encoding="utf-8",
    )
    calls: list[tuple[Path, Path, Path]] = []

    monkeypatch.setattr("benchmarks.scanning.run._pid_is_running", lambda _pid: False)
    monkeypatch.setattr(
        "benchmarks.scanning.run._cleanup_owned_worktree",
        lambda repo, owned, run, _owner: calls.append((repo, owned, run)),
    )

    _cleanup_stale_owned_worktrees(repo_root, owned_root)

    assert calls == [(repo_root, owned_root, run_root)]


def test_stale_cleanup_recreates_owned_root_for_the_next_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo_root = (tmp_path / "repo").resolve()
    repo_root.mkdir()
    owned_root = (tmp_path / "owned").resolve()
    run_root = owned_root / "run-stale"
    worktree = run_root / "before"
    worktree.mkdir(parents=True)
    (run_root / "owner.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repo_root": str(repo_root),
                "worktree": str(worktree),
                "expected_commit": "a" * 40,
                "owner_pid": 123456789,
                "state": "active",
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("benchmarks.scanning.run._pid_is_running", lambda _pid: False)
    monkeypatch.setattr(
        "benchmarks.scanning.run._cleanup_owned_worktree",
        lambda _repo, owned, _run, _owner: shutil.rmtree(owned),
    )

    _cleanup_stale_owned_worktrees(repo_root, owned_root)

    assert owned_root.is_dir()
    assert list(owned_root.iterdir()) == []


def _paired_artifacts(
    *,
    profile: str = "smoke",
    blocks: int = 1,
    cases: tuple[BenchmarkCase, ...] = CASES,
    candidate_dirty: bool = False,
    tooling_dirty: bool | None = None,
) -> tuple[dict, dict]:
    tooling_dirty = candidate_dirty if tooling_dirty is None else tooling_dirty
    before_metadata = _metadata(
        "before",
        profile=profile,
        blocks=blocks,
        cases=cases,
        dirty=False,
        tooling_dirty=tooling_dirty,
    )
    after_metadata = _metadata(
        "after",
        profile=profile,
        blocks=blocks,
        cases=cases,
        dirty=candidate_dirty,
        tooling_dirty=tooling_dirty,
    )
    before_observations: list[dict] = []
    after_observations: list[dict] = []
    chunk_throughput = {
        16 * 1024: 300.0,
        32 * 1024: 500.0,
        64 * 1024: 700.0,
        128 * 1024: 880.0,
        256 * 1024: 1000.0,
        512 * 1024: 950.0,
        1024 * 1024: 850.0,
        2 * 1024 * 1024: 800.0,
        4 * 1024 * 1024: 760.0,
    }
    for case in cases:
        for block in range(blocks):
            if case.observation_metric_contract == "non_timing_capability":
                before_observations.append(
                    _strict_unknown_observation(case, implementation="before", profile=profile, block=block)
                )
                after_observations.append(
                    _strict_unknown_observation(case, implementation="after", profile=profile, block=block)
                )
                continue
            if is_candidate_only(case):
                before_observations.append(_not_applicable(case, profile=profile, block=block))
            else:
                before_observations.append(
                    _observation(
                        case,
                        implementation="before",
                        profile=profile,
                        block=block,
                        duration_ns=2_000_000,
                        throughput_mib_s=100.0,
                        physical_bytes_read=1_048_576,
                    )
                )

            chunk_size = int(case.parameters.get("chunk_size", 0))
            duration_ns = 1_000_000
            timeout_overshoot_ns = 0
            timed_out = False
            if case.kind == "chunk_salvage":
                duration_ns = 1_000_000 if chunk_size == 128 * 1024 else 1_050_000
            elif case.kind == "chunk_timeout":
                timeout_overshoot_ns = 10_000_000 if chunk_size == 128 * 1024 else 10_500_000
                timed_out = True
            after_observations.append(
                _observation(
                    case,
                    implementation="after",
                    profile=profile,
                    block=block,
                    duration_ns=duration_ns,
                    throughput_mib_s=chunk_throughput.get(chunk_size, 200.0),
                    physical_bytes_read=524_288,
                    timeout_overshoot_ns=timeout_overshoot_ns,
                    timed_out=timed_out,
                )
            )
    return (
        {"metadata": before_metadata, "observations": before_observations},
        {"metadata": after_metadata, "observations": after_observations},
    )


def _target_identity(*, profile: str = "smoke") -> dict:
    return {
        "corpus_version": CORPUS_VERSION,
        "profile": profile,
        "size": 65_536,
        "sha256": "1" * 64,
        "fixture_version": "test-fixture-v1",
        "fixture_source_sha256": "2" * 64,
        "topology_fingerprint": "3" * 64,
        "expected_count": 2,
        "expected_relative_checksum": address_checksum([0x10, 0x20]),
    }


def _operation_identity(
    identity: dict,
    *,
    phase: str,
    implementation: str,
    cache_token: str | None = None,
) -> dict:
    return {
        "run_id": ("a" if implementation == "before" else "b") * 32,
        "pid": 1234 if implementation == "before" else 5678,
        "attachment_generation": 1,
        "module_fingerprint": "4" * 64,
        "target_identity_sha256": sha256_json(identity),
        "phase": phase,
        "cache_token": cache_token,
    }


def _read_evidence(ranges: list[tuple[int, int]]) -> dict:
    request_sizes = [end - start for start, end in ranges]
    serialized = [list(item) for item in ranges]
    operations = [
        {
            "address": start,
            "requested_size": end - start,
            "returned_size": end - start,
            "success": True,
        }
        for start, end in ranges
    ]
    return {
        "physical_read_calls": len(ranges),
        "physical_bytes_requested": sum(request_sizes),
        "physical_bytes_read": sum(request_sizes),
        "physical_read_operations": operations,
        "physical_read_operations_sha256": sha256_json(operations),
        "physical_request_sizes": list(request_sizes),
        "physical_read_sizes": list(request_sizes),
        "physical_read_ranges": serialized,
        "unique_logical_bytes": range_union_size(ranges),
        "failed_read_calls": 0,
        "read_call_p95_ns": 10.0,
        "read_call_max_ns": 10,
        "read_ranges_sha256": sha256_json(ranges),
    }


def _preflight(case: BenchmarkCase, identity: dict, *, implementation: str) -> dict:
    addresses = [0x1010, 0x1020]
    checksum = address_checksum(addresses)
    return {
        **preflight_protocol(case.kind),
        "correct": True,
        "expected_historical_failure": False,
        "addresses": addresses,
        "address_checksum": checksum,
        "address_base": 0x1000,
        "relative_addresses": [0x10, 0x20],
        "relative_address_checksum": identity["expected_relative_checksum"],
        "expected_addresses": addresses,
        "expected_count": len(addresses),
        "expected_checksum": checksum,
        "expected_relative_checksum": identity["expected_relative_checksum"],
        "comparison_identity": deepcopy(identity),
        "operation_identity": _operation_identity(identity, phase="preflight", implementation=implementation),
        "read": _read_evidence([(0x1000, 0x2000)]),
        "logical_scanned_region_count": 1,
        "logical_bytes_scanned_with_overlap": 4096,
        "unique_bytes_examined": 4096,
        "sections": [".text"] if case.kind.startswith("section_filter") else [],
    }


def _warm_setup(case: BenchmarkCase, identity: dict, *, implementation: str) -> dict:
    cache_token = ("c" if implementation == "before" else "d") * 64
    ranges = (
        [(0x4000, 0x1E000)]
        if implementation == "before"
        else [(0x4000, 0x4040), (0x5000, 0x5018), (0x6000, 0x60F0), (0x7000, 0x8000)]
    )
    return {
        **case.setup_protocol,
        "implementation_state": case.setup_protocol[
            "historical_state" if implementation == "before" else "candidate_state"
        ],
        "correct": True,
        "comparison_identity": deepcopy(identity),
        "operation_identity": _operation_identity(
            identity,
            phase="setup",
            implementation=implementation,
            cache_token=cache_token,
        ),
        "actual_count": 2,
        "expected_count": 2,
        "read": _read_evidence(ranges),
        "logical_scanned_region_count": 1,
        "logical_bytes_scanned_with_overlap": sum(end - start for start, end in ranges),
        "unique_bytes_examined": 4096,
        "sections": [".text"] if implementation == "after" else None,
    }


def _metadata(
    implementation: str,
    *,
    profile: str,
    blocks: int,
    cases: tuple[BenchmarkCase, ...],
    dirty: bool,
    tooling_dirty: bool,
) -> dict:
    candidate_git = {"commit": "a" * 40, "tree": "b" * 40, "dirty": dirty}
    source_git = {"commit": "c" * 40, "tree": "d" * 40, "dirty": dirty} if implementation == "before" else candidate_git
    tooling_git = {"commit": "a" * 40, "tree": "b" * 40, "dirty": tooling_dirty}
    return {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "implementation": implementation,
        "profile": profile,
        "python": {
            "executable": "C:/Python313/python.exe",
            "implementation": "CPython",
            "version": "3.13.0",
            "bitness": 64,
        },
        "os": {"system": "Windows", "release": "10", "version": "test-build", "machine": "AMD64"},
        "cpu": {"processor": "test-cpu", "logical_count": 8},
        "packages": {"mcp": "1", "pydantic": "2", "pymem": "1", "lupa": "2"},
        "execution_policy": {
            "process_affinity_mask": "0xFF",
            "process_priority_class": 32,
            "power_plan": "test-plan",
        },
        "git": source_git,
        "runner": {
            "blocks": blocks,
            "case_ids": [case.case_id for case in cases],
            "candidate_only_case_ids": [case.case_id for case in cases if is_candidate_only(case)],
            "pairing": PAIRING_PROTOCOL,
            "driver": DRIVER_PROTOCOL,
            "python": "C:/Python313/python.exe",
            "source_root": "C:/source",
            "tooling_git": tooling_git,
            "candidate_watchdog_floor_s": CANDIDATE_WATCHDOG_FLOOR_S,
            "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
            "manifest_version": MANIFEST_VERSION,
            "corpus_version": CORPUS_VERSION,
        },
    }


def _rebind_semantic_identity(observation: dict) -> None:
    payload = paired_semantic_fingerprint_payload(
        observation["semantic_descriptor"],
        observation.get("comparison_identity"),
    )
    observation["semantic_fingerprint_payload"] = payload
    observation["semantic_fingerprint"] = semantic_fingerprint(payload)


def _censored_observation(source: dict, case: BenchmarkCase) -> dict:
    metrics = {
        "preflight": deepcopy(source["metrics"]["preflight"]),
        "operation_identity": deepcopy(source["metrics"]["operation_identity"]),
        "timed_phase_started": True,
    }
    if "setup" in source["metrics"]:
        metrics["setup"] = deepcopy(source["metrics"]["setup"])
    return {
        "case_id": source["case_id"],
        "implementation": "before",
        "profile": source["profile"],
        "block": source["block"],
        "pair_seed": source["pair_seed"],
        "pair_order": source["pair_order"],
        "semantic_fingerprint_payload": deepcopy(source["semantic_fingerprint_payload"]),
        "semantic_fingerprint": source["semantic_fingerprint"],
        "semantic_descriptor": deepcopy(source["semantic_descriptor"]),
        "status": "censored",
        "correct": None,
        "comparison_identity": deepcopy(source["comparison_identity"]),
        "logical_bytes": source["logical_bytes"],
        "expected_count": source["expected_count"],
        "expected_checksum": source["expected_checksum"],
        "expected_historical_failure": source["expected_historical_failure"],
        "preparation": {
            "imports_complete": True,
            "setup_complete": True,
            "warmups_complete": True,
            "validation_complete": True,
            "timed_statement_pending": True,
        },
        "metrics": metrics,
        "censorship": {
            "phase": "timed",
            "reason": "process_timeout",
            "timeout_seconds": case.process_timeout_s,
            "lower_bound_duration_ns": timeout_duration_ns(case.process_timeout_s),
        },
        "wall_duration_ns": timeout_duration_ns(case.process_timeout_s) + 10_000,
        "timed_wall_duration_ns": timeout_duration_ns(case.process_timeout_s),
        "stdout": "",
        "stderr": "",
    }


def _not_applicable(case: BenchmarkCase, *, profile: str, block: int) -> dict:
    descriptor = case.semantic_descriptor(profile)
    payload = paired_semantic_fingerprint_payload(descriptor, None)
    return {
        "case_id": case.case_id,
        "implementation": "before",
        "profile": profile,
        "block": block,
        "pair_seed": pair_seed(case.case_id, block),
        "pair_order": pair_order_label(case.case_id, block),
        "semantic_fingerprint_payload": payload,
        "semantic_fingerprint": semantic_fingerprint(payload),
        "semantic_descriptor": descriptor,
        "status": "not_applicable",
        "correct": None,
        "reason": "the historical scanner exposes no configurable reader chunk",
    }


def _strict_unknown_observation(
    case: BenchmarkCase,
    *,
    implementation: str,
    profile: str,
    block: int,
) -> dict:
    strict = implementation == "after"
    descriptor = case.semantic_descriptor(profile)
    fingerprint_payload = paired_semantic_fingerprint_payload(descriptor, None)
    return {
        "case_id": case.case_id,
        "implementation": implementation,
        "profile": profile,
        "block": block,
        "pair_seed": pair_seed(case.case_id, block),
        "pair_order": pair_order_label(case.case_id, block),
        "semantic_fingerprint_payload": fingerprint_payload,
        "semantic_fingerprint": semantic_fingerprint(fingerprint_payload),
        "semantic_descriptor": descriptor,
        "status": "ok",
        "correct": True,
        "duration_ns": 0,
        "logical_bytes": 0,
        "throughput_mib_s": None,
        "peak_python_bytes": None,
        "actual_count": int(strict),
        "expected_count": int(strict),
        "actual_checksum": None,
        "expected_checksum": None,
        "termination": "complete",
        "comparison_identity": None,
        "expected_historical_failure": False,
        "metrics": {
            "strict_unknown_rejection": strict,
            "historical_signature": "(pattern: str) -> dict" if implementation == "before" else None,
            "committed_public_case_id": "public.fastmcp.strict_flat_contract" if strict else None,
            "committed_public_fingerprint": "f" * 64 if strict else None,
        },
        "wall_duration_ns": 1_000_000,
        "driver_returncode": 0,
    }


def _observation(
    case: BenchmarkCase,
    *,
    implementation: str,
    profile: str,
    block: int,
    duration_ns: int,
    throughput_mib_s: float,
    physical_bytes_read: int,
    timeout_overshoot_ns: int = 0,
    timed_out: bool = False,
) -> dict:
    identity = _target_identity(profile=profile) if uses_controlled_target(case) else None
    if case.kind in {"timeout", "chunk_timeout"}:
        timed_out = True
        timeout_overshoot_ns = timeout_overshoot_ns or 10_000_000
        duration_ns = case.timeout_ms * 1_000_000 + timeout_overshoot_ns
    ranges = [(0x100000, 0x100000 + physical_bytes_read)] if physical_bytes_read else []
    metrics = {
        **_read_evidence(ranges),
        "logical_scanned_region_count": 1,
        "operation_identity": (
            _operation_identity(identity, phase="timed", implementation=implementation)
            if identity is not None
            else None
        ),
        "timeout_overshoot_ns": timeout_overshoot_ns,
        "timed_out": timed_out,
        "timeout_hit": timed_out if implementation == "before" else False,
        "timeout_budget_ns": case.timeout_ms * 1_000_000,
        "control_polls": 8 if timed_out else 0,
        "termination": "timeout" if timed_out else "scope_exhausted",
        "strategy_counts": ({case.expected_strategy: 1} if case.expected_strategy is not None else {}),
        "matcher_invocations": 1,
        "span_count": 1,
    }
    if implementation == "after" and identity is not None:
        metrics.update(
            candidate_watchdog_metrics(
                case.process_timeout_s,
                float(case.semantic_descriptor(profile)["candidate_watchdog_timeout_s"]),
            )
        )
    else:
        metrics["process_watchdog_ns"] = timeout_duration_ns(case.process_timeout_s)
    full_addresses = [0x1010, 0x1020]
    retained = full_addresses
    if case.mode == "first":
        retained = full_addresses[:1]
    elif case.mode == "addresses":
        retained = full_addresses[: case.limit or case.max_matches or 50]
    expected_count = len(retained) if requires_exact_preflight(case) else 2
    expected_checksum = None if case.mode == "count" else address_checksum(retained)
    actual_checksum = expected_checksum
    termination = "scope_exhausted"
    if case.mode == "first" and retained:
        termination = "first_hit"
    elif case.max_matches is not None and len(full_addresses) >= case.max_matches:
        termination = "match_limit"
    elif case.mode == "addresses" and len(retained) >= (case.limit or 50):
        termination = "page_limit"
    if timed_out:
        termination = "timeout"
    if requires_exact_preflight(case):
        metrics["preflight"] = _preflight(case, identity, implementation=implementation)
    if case.kind == "section_filter_warm":
        setup = _warm_setup(case, identity, implementation=implementation)
        if implementation == "after":
            metrics.update(_read_evidence([(0x7000, 0x8000)]))
            metrics["unique_bytes_examined"] = 4096
            metrics["sections"] = [".text"]
        else:
            metrics.update(_read_evidence([(0x4000, 0x1E000)]))
        cache_token = setup["operation_identity"]["cache_token"]
        metrics["operation_identity"] = _operation_identity(
            identity,
            phase="timed",
            implementation=implementation,
            cache_token=cache_token,
        )
        metrics["setup"] = setup
    descriptor = case.semantic_descriptor(profile)
    fingerprint_payload = paired_semantic_fingerprint_payload(descriptor, identity)
    return {
        "case_id": case.case_id,
        "implementation": implementation,
        "profile": profile,
        "block": block,
        "pair_seed": pair_seed(case.case_id, block),
        "pair_order": pair_order_label(case.case_id, block),
        "semantic_fingerprint_payload": fingerprint_payload,
        "semantic_fingerprint": semantic_fingerprint(fingerprint_payload),
        "semantic_descriptor": descriptor,
        "status": "ok",
        "correct": True,
        "duration_ns": duration_ns,
        "logical_bytes": 65_536,
        "throughput_mib_s": throughput_mib_s,
        "peak_python_bytes": 4096,
        "actual_count": expected_count,
        "expected_count": expected_count,
        "actual_checksum": actual_checksum,
        "expected_checksum": expected_checksum,
        "termination": termination,
        "comparison_identity": identity,
        "expected_historical_failure": False,
        "metrics": metrics,
        "wall_duration_ns": duration_ns + 1000,
        "driver_returncode": 0,
    }
