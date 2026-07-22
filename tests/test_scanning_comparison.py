"""Paired scanning comparison, reporting, and worktree-safety tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.adapters import run_case
from benchmarks.scanning.compare import compare_artifacts
from benchmarks.scanning.manifest import CASE_BY_ID, CASES
from benchmarks.scanning.report import generate_bundle
from benchmarks.scanning.run import (
    _cleanup_owned_worktree,
    _cleanup_stale_owned_worktrees,
    _environment_metadata_for_python,
    _observation_timeout_seconds,
    _parse_driver_output,
    _run_observation,
)


def test_comparator_preserves_censorship_and_selects_accepted_chunk_policy():
    before, after = _paired_artifacts()
    historical_batch = next(item for item in before["observations"] if item["case_id"] == "batch.count4.nohit")
    historical_batch.update(
        {
            "status": "censored",
            "correct": None,
            "lower_bound_duration_ns": 5_000_000_000,
        }
    )

    comparison = compare_artifacts(before, after)

    assert comparison["complete"] is True
    assert comparison["blocking"] is False
    assert comparison["chunk_recommendation"]["selected_chunk_size"] == 256 * 1024
    chunk = next(row for row in comparison["rows"] if row["case_id"] == "chunk.exact.nohit.256k")
    assert chunk["status"] == "candidate_only"
    batch = next(row for row in comparison["rows"] if row["case_id"] == "batch.count4.nohit")
    assert batch["status"] == "censored"
    assert batch["censored_speedup_lower_bound"] == 5000.0


def test_declared_historical_capability_gap_is_visible_but_not_blocking():
    before, after = _paired_artifacts()
    case_id = "e2e.boundary.split_protection.exact"
    historical = next(item for item in before["observations"] if item["case_id"] == case_id)
    historical["correct"] = False
    historical["expected_historical_failure"] = True
    historical["actual_count"] = 0
    historical["expected_count"] = 1

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


def test_separate_environment_paths_are_recorded_but_not_compatibility_keys():
    before, after = _paired_artifacts()
    after["metadata"]["python"]["executable"] = "D:/candidate-venv/python.exe"
    after["metadata"]["runner"]["python"] = "D:/candidate-venv/python.exe"

    comparison = compare_artifacts(before, after)

    assert comparison["compatible"] is True


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

    comparison = compare_artifacts(before, after)
    row = next(item for item in comparison["rows"] if item["case_id"] == case_id)

    assert row["status"] == "invalid"
    assert row["blocking"] is True
    assert row["notes"] == ["corpus or target fixture identity mismatch"]


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

    with pytest.raises(ValueError, match="before observation has an invalid pair order"):
        compare_artifacts(before, after)


def test_pair_order_must_be_consistent_across_artifacts():
    before, after = _paired_artifacts()
    after["observations"][0]["pair_order"] = "BA"

    with pytest.raises(ValueError, match="paired observation order mismatch"):
        compare_artifacts(before, after)


def test_incompatible_runner_identity_is_rejected():
    before, after = _paired_artifacts()
    after["metadata"]["runner"]["manifest_version"] = "scanning-manifest-future"

    with pytest.raises(ValueError, match="runner manifest_version differs"):
        compare_artifacts(before, after)


def test_report_bundle_keeps_every_declared_case_visible(tmp_path: Path):
    before, after = _paired_artifacts()
    comparison = compare_artifacts(before, after)

    generate_bundle(comparison, tmp_path)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert all(case.case_id in report for case in CASES)
    assert "Diagnostic selection: `256.00 KiB`" in report
    assert "production reader remains 256.00 KiB" in report
    assert "Candidate correctness" in report
    assert "checksum" in report
    assert (tmp_path / "post.md").is_file()
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
    assert candidate["timeout_seconds"] == 30.0
    assert "candidate benchmark subprocess exceeded" in candidate["error"]
    assert historical["status"] == "censored"
    assert historical["correct"] is None
    assert historical["timeout_seconds"] == case.process_timeout_s
    assert historical["lower_bound_duration_ns"] == int(case.process_timeout_s * 1_000_000_000)


def test_driver_protocol_rejects_mismatched_identity():
    payload = {
        "case_id": "different.case",
        "implementation": "after",
        "profile": "smoke",
        "block": 0,
        "pair_order": "AB",
        "status": "ok",
        "correct": True,
    }

    result = _parse_driver_output(
        json.dumps(payload),
        expected_case_id="compile.exact16",
        expected_implementation="after",
        expected_profile="smoke",
        expected_block=0,
        expected_pair_order="AB",
    )

    assert result["status"] == "driver_error"
    assert result["correct"] is False
    assert "identity mismatch" in result["error"]


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


def _paired_artifacts() -> tuple[dict, dict]:
    before_metadata = _metadata("before")
    after_metadata = _metadata("after")
    before_observations = []
    after_observations = []
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
    for case in CASES:
        fingerprint = case.semantic_fingerprint("smoke")
        if case.kind in {"chunk_sweep", "chunk_salvage", "chunk_timeout"}:
            before_observations.append(
                {
                    "case_id": case.case_id,
                    "implementation": "before",
                    "profile": "smoke",
                    "block": 0,
                    "pair_order": "AB",
                    "semantic_fingerprint": fingerprint,
                    "status": "not_applicable",
                    "correct": None,
                }
            )
        else:
            before_observations.append(
                _observation(
                    case.case_id,
                    fingerprint,
                    implementation="before",
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
                case.case_id,
                fingerprint,
                implementation="after",
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


def _metadata(implementation: str) -> dict:
    return {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "implementation": implementation,
        "profile": "smoke",
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
        "git": {"commit": "a" * 40, "tree": "b" * 40, "dirty": False},
        "runner": {
            "blocks": 1,
            "case_ids": [case.case_id for case in CASES],
            "pairing": "deterministic randomized AB/BA blocks",
            "python": "C:/Python313/python.exe",
            "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
            "manifest_version": MANIFEST_VERSION,
            "corpus_version": CORPUS_VERSION,
        },
    }


def _observation(
    case_id: str,
    fingerprint: str,
    *,
    implementation: str,
    duration_ns: int,
    throughput_mib_s: float,
    physical_bytes_read: int,
    timeout_overshoot_ns: int = 0,
    timed_out: bool = False,
) -> dict:
    return {
        "case_id": case_id,
        "implementation": implementation,
        "profile": "smoke",
        "block": 0,
        "pair_order": "AB",
        "semantic_fingerprint": fingerprint,
        "status": "ok",
        "duration_ns": duration_ns,
        "throughput_mib_s": throughput_mib_s,
        "peak_python_bytes": 4096,
        "actual_checksum": "f" * 64,
        "expected_checksum": "f" * 64,
        "correct": True,
        "metrics": {
            "physical_bytes_read": physical_bytes_read,
            "physical_read_calls": 4,
            "timeout_overshoot_ns": timeout_overshoot_ns,
            "timed_out": timed_out,
        },
    }
