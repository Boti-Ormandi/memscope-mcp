"""Contract and adversarial validation tests for netcap buffer-search evidence."""

from __future__ import annotations

import hashlib
import math
import statistics
from copy import deepcopy
from pathlib import Path

import pytest
from lupa import LuaRuntime

import benchmarks.netcap.buffer_search as benchmark
import memscope_mcp._contrib.plugins.netcap as netcap_module
from benchmarks.netcap import BENCHMARK_NAME, BENCHMARK_SCHEMA_VERSION
from benchmarks.netcap.buffer_search import (
    _ALLOCATION_SAMPLE_COUNTS,
    _LUA_HEAP_SAMPLE_COUNTS,
    _MAX_PERF_COUNTER_RESOLUTION_SECONDS,
    _RETAINED_GROWTH_CALLS,
    ArtifactValidationError,
    _counts,
    _parity_commitment,
    _runtime_bindings,
    build_payload,
    canonical_sampling,
    legacy_lua_table_to_list,
    main,
    minimum_sampling,
    recompute_gates,
    release_cases,
    run_correctness_suite,
    run_suite,
    selected_cases,
    validate_artifact,
    write_artifact,
)

_EXPECTED_CASE_IDS = {
    *(f"find.{shape}.{size}" for size in (64, 4096, 262000, 1048576) for shape in ("start", "tail", "absent")),
    *(f"contains.{shape}.{size}" for size in (64, 4096, 262000, 1048576) for shape in ("start", "tail", "absent")),
    *(f"findall.{shape}.{size}" for size in (64, 4096, 262000, 1048576) for shape in ("sparse", "absent")),
    "findall.overlap.64",
    "findall.dense.4096",
}


@pytest.fixture(scope="module")
def diagnostic_artifact() -> dict:
    repo_root = Path(__file__).resolve().parents[1]
    return run_suite(
        repo_root=repo_root,
        profile="smoke",
        case_ids=("find.absent.4096", "findall.sparse.4096"),
        warmups=0,
        repetitions=1,
    )


def _refresh_correctness_aggregates(correctness: dict) -> None:
    failures = [
        {"scenario": scenario["scenario"], **operation}
        for scenario in correctness["scenarios"]
        for operation in scenario["operations"]
        if not operation["passed"]
    ]
    correctness["scenario_count"] = len(correctness["scenarios"])
    correctness["check_count"] = sum(len(scenario["operations"]) for scenario in correctness["scenarios"])
    correctness["failure_count"] = len(failures)
    correctness["failures"] = failures
    correctness["passed"] = not failures
    correctness["commitment_sha256"] = _parity_commitment(correctness["scenarios"])


def test_schema_and_release_manifest_are_stable():
    assert BENCHMARK_SCHEMA_VERSION == 2
    assert BENCHMARK_NAME == "netcap-buffer-search"
    assert _MAX_PERF_COUNTER_RESOLUTION_SECONDS == 1e-7
    cases = release_cases()
    assert len(cases) == 34
    assert len({case.case_id for case in cases}) == len(cases)
    assert {case.case_id for case in cases} == _EXPECTED_CASE_IDS


def test_canonical_release_sampling_minima_and_overrides():
    assert canonical_sampling() == [
        {"size": 64, "warmups": 3, "repetitions": 101},
        {"size": 4096, "warmups": 3, "repetitions": 25},
        {"size": 262000, "warmups": 3, "repetitions": 9},
        {"size": 1048576, "warmups": 3, "repetitions": 9},
    ]
    for row in canonical_sampling():
        assert minimum_sampling(row["size"]) == (row["warmups"], row["repetitions"])
        assert _counts("release", row["size"], None, None) == (
            row["warmups"],
            row["repetitions"],
        )
        assert _counts("release", row["size"], row["warmups"] + 1, row["repetitions"] + 1) == (
            row["warmups"] + 1,
            row["repetitions"] + 1,
        )
        assert _counts("release", row["size"], 0, 1) == (0, 1)


def test_smoke_profile_is_bounded_and_stable():
    assert {case.case_id for case in selected_cases("smoke")} == {
        "find.start.64",
        "find.absent.4096",
        "contains.tail.4096",
        "findall.sparse.4096",
        "findall.overlap.64",
        "findall.dense.4096",
    }


def test_frozen_converter_is_independent_and_candidate_corruption_breaks_parity(monkeypatch):
    lua = LuaRuntime(unpack_returned_tuples=True)
    table = lua.table_from([1, 2, 3])
    assert legacy_lua_table_to_list(table) == [1, 2, 3]

    lua, _legacy, _candidate, calls = _runtime_bindings()
    monkeypatch.setattr(netcap_module, "_lua_table_to_list", lambda _table: [999])

    assert legacy_lua_table_to_list(lua.table_from([1, 2, 3])) == [1, 2, 3]
    parity = run_correctness_suite(lua, calls)
    assert parity["passed"] is False
    assert parity["failure_count"] > 0


def test_diagnostic_artifact_validates_but_is_insufficient(diagnostic_artifact):
    validate_artifact(diagnostic_artifact)
    assert diagnostic_artifact["schema_version"] == 2
    assert diagnostic_artifact["correctness"]["passed"] is True
    assert diagnostic_artifact["correctness"]["check_count"] == 633
    assert diagnostic_artifact["gates"]["status"] == "insufficient"
    assert "profile-not-release" in diagnostic_artifact["gates"]["insufficiency_reasons"]
    assert "candidate-tree-dirty" in diagnostic_artifact["gates"]["insufficiency_reasons"]
    assert diagnostic_artifact["metadata"]["identity_unchanged"] is True
    assert diagnostic_artifact["metadata"]["identity_before"]["git"]["dirty"] is True
    assert all("search_only" not in case for case in diagnostic_artifact["cases"])
    assert diagnostic_artifact["contract"]["performance_surface"].endswith("production NetcapPlugin calls only")


def test_source_manifest_is_exact_and_has_module_origins(diagnostic_artifact):
    for identity_name in ("identity_before", "identity_after"):
        identity = diagnostic_artifact["metadata"][identity_name]
        assert [entry["label"] for entry in identity["sources"]] == [
            "benchmark_init",
            "benchmark_module",
            "candidate_plugin",
        ]
        assert all(entry["origin"] == entry["path"] for entry in identity["sources"])
        assert all(len(entry["sha256"]) == 64 for entry in identity["sources"])


def test_exact_evidence_matrices_for_selected_cases(diagnostic_artifact):
    assert [row["case_id"] for row in diagnostic_artifact["allocation"]] == [
        "find.absent.4096",
        "findall.sparse.4096",
    ]
    assert [(row["case_id"], row["variant"]) for row in diagnostic_artifact["lua_heap"]] == [
        ("findall.sparse.4096", "baseline"),
        ("findall.sparse.4096", "candidate"),
    ]
    assert [(row["case_id"], row["variant"]) for row in diagnostic_artifact["retained_growth"]] == [
        ("findall.sparse.4096", "baseline"),
        ("findall.sparse.4096", "candidate"),
    ]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unexpected"])
@pytest.mark.parametrize("matrix", ["allocation", "lua_heap", "retained_growth"])
def test_validation_rejects_noncanonical_evidence_matrices(diagnostic_artifact, matrix, mutation):
    invalid = deepcopy(diagnostic_artifact)
    rows = invalid[matrix]
    if mutation == "missing":
        rows.pop()
    elif mutation == "duplicate":
        rows.append(deepcopy(rows[-1]))
    else:
        extra = deepcopy(rows[-1])
        extra["case_id"] = "find.start.64"
        rows.append(extra)

    with pytest.raises(ArtifactValidationError, match="exact expected row matrix"):
        validate_artifact(invalid)


def test_validation_recomputes_gate_status(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["gates"]["status"] = "pass"
    invalid["gates"]["sufficient"] = True
    invalid["gates"]["insufficiency_reasons"] = []

    with pytest.raises(ArtifactValidationError, match="serialized gates"):
        validate_artifact(invalid)
    assert recompute_gates(diagnostic_artifact) == diagnostic_artifact["gates"]


@pytest.mark.parametrize("field", ["baseline_ns", "candidate_ns"])
def test_validation_rejects_raw_timing_length_changes(diagnostic_artifact, field):
    invalid = deepcopy(diagnostic_artifact)
    invalid["cases"][0]["lua_end_to_end"][field].pop()
    with pytest.raises(ArtifactValidationError, match="raw observation lengths"):
        validate_artifact(invalid)


@pytest.mark.parametrize("field", ["baseline_median_ns", "candidate_median_ns", "ratio"])
def test_validation_rejects_serialized_summary_changes(diagnostic_artifact, field):
    invalid = deepcopy(diagnostic_artifact)
    invalid["cases"][0]["lua_end_to_end"][field] *= 2
    with pytest.raises(ArtifactValidationError, match="recomputed value"):
        validate_artifact(invalid)


def test_validation_rejects_source_manifest_and_identity_tampering(diagnostic_artifact):
    missing = deepcopy(diagnostic_artifact)
    missing["metadata"]["identity_before"]["sources"].pop()
    with pytest.raises(ArtifactValidationError, match="exact source manifest"):
        validate_artifact(missing)

    changed = deepcopy(diagnostic_artifact)
    changed["metadata"]["identity_after"]["git"]["branch"] = "different-branch"
    changed["metadata"]["identity_unchanged"] = True
    with pytest.raises(ArtifactValidationError, match="identity_unchanged"):
        validate_artifact(changed)


def test_validation_rejects_unsupported_schema(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["schema_version"] = 1
    with pytest.raises(ArtifactValidationError, match="unsupported schema_version"):
        validate_artifact(invalid)


def test_lower_release_sampling_is_recorded_as_diagnostic():
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_suite(
        repo_root=repo_root,
        profile="release",
        case_ids=("find.start.64",),
        warmups=0,
        repetitions=1,
    )
    validate_artifact(artifact)
    assert artifact["gates"]["status"] == "insufficient"
    assert "sampling-below-minimum:find.start.64" in artifact["gates"]["insufficiency_reasons"]


def test_enforce_gates_fails_insufficient_evidence(tmp_path: Path):
    output = tmp_path / "enforced-smoke.json"
    result = main(
        [
            "--profile",
            "smoke",
            "--case-id",
            "find.start.64",
            "--output",
            str(output),
            "--enforce-gates",
        ]
    )
    assert result == 2
    artifact = __import__("json").loads(output.read_text(encoding="utf-8"))
    validate_artifact(artifact)
    assert artifact["gates"]["status"] == "insufficient"


def test_round_trip_preserves_schema_2_evidence(diagnostic_artifact, tmp_path: Path):
    output = tmp_path / "artifact.json"
    write_artifact(output, diagnostic_artifact)
    artifact = __import__("json").loads(output.read_text(encoding="utf-8"))
    validate_artifact(artifact)
    assert artifact["schema_version"] == 2


def test_canonical_allocation_heap_and_retained_sample_counts():
    assert _ALLOCATION_SAMPLE_COUNTS == {
        "find.absent.4096": 3,
        "contains.absent.4096": 3,
        "findall.sparse.4096": 3,
        "findall.absent.4096": 3,
        "findall.dense.4096": 3,
        "find.absent.262000": 1,
        "findall.sparse.262000": 1,
    }
    assert _LUA_HEAP_SAMPLE_COUNTS == {
        "findall.sparse.4096": 3,
        "findall.sparse.262000": 3,
        "findall.dense.4096": 3,
    }
    assert _RETAINED_GROWTH_CALLS == 100


def test_allocation_allowance_is_payload_derived_and_rejects_inflation(diagnostic_artifact):
    original = recompute_gates(diagnostic_artifact)
    inflated = deepcopy(diagnostic_artifact)
    allocation = inflated["allocation"][0]
    allocation["pattern_size"] += 10_000_000
    allocation["size"] += 10_000_000

    recomputed = recompute_gates(inflated)
    assert recomputed["allocation"] == original["allocation"]
    with pytest.raises(ArtifactValidationError, match=r"allocation\[0\].size is inconsistent"):
        validate_artifact(inflated)


def test_case_pattern_size_inflation_is_rejected(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["cases"][0]["pattern_size"] += 10_000_000
    with pytest.raises(ArtifactValidationError, match=r"cases\[0\].pattern_size is inconsistent"):
        validate_artifact(invalid)


def test_allocation_pattern_size_inflation_is_rejected_independently(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["allocation"][0]["pattern_size"] += 10_000_000
    with pytest.raises(ArtifactValidationError, match=r"allocation\[0\].pattern_size is inconsistent"):
        validate_artifact(invalid)


def test_payload_defines_canonical_pattern_length():
    for case in release_cases():
        data, pattern = build_payload(case)
        assert len(data) == case.size
        assert len(pattern) in {1, 3, 4}


def _mutate_sample_count(measurement, samples_field, median_field, delta):
    samples = measurement[samples_field]
    if delta < 0:
        samples.pop()
    else:
        samples.append(samples[-1])
    measurement["repetitions"] += delta
    measurement[median_field] = statistics.median(samples)


@pytest.mark.parametrize("variant", ["baseline", "candidate"])
@pytest.mark.parametrize("delta", [-1, 1])
def test_allocation_sample_count_mutations_are_rejected(
    diagnostic_artifact,
    variant,
    delta,
):
    invalid = deepcopy(diagnostic_artifact)
    measurement = invalid["allocation"][0][variant]
    _mutate_sample_count(measurement, "samples", "median_peak_bytes", delta)
    with pytest.raises(ArtifactValidationError, match="canonical sample count"):
        validate_artifact(invalid)


@pytest.mark.parametrize("variant", ["baseline", "candidate"])
@pytest.mark.parametrize("delta", [-1, 1])
def test_lua_heap_sample_count_mutations_are_rejected(
    diagnostic_artifact,
    variant,
    delta,
):
    invalid = deepcopy(diagnostic_artifact)
    row = next(item for item in invalid["lua_heap"] if item["variant"] == variant)
    _mutate_sample_count(row, "delta_kib_samples", "median_delta_kib", delta)
    with pytest.raises(ArtifactValidationError, match="canonical sample count"):
        validate_artifact(invalid)


@pytest.mark.parametrize("calls", [99, 101])
def test_retained_growth_call_count_mutations_are_rejected(diagnostic_artifact, calls):
    invalid = deepcopy(diagnostic_artifact)
    invalid["retained_growth"][0]["calls"] = calls
    with pytest.raises(ArtifactValidationError, match="calls must equal 100"):
        validate_artifact(invalid)


def test_gate_recomputation_uses_recorded_clock_resolution(diagnostic_artifact):
    modified = deepcopy(diagnostic_artifact)
    recorded_resolution = _MAX_PERF_COUNTER_RESOLUTION_SECONDS / 2
    modified["metadata"]["clock"]["perf_counter_resolution_seconds"] = recorded_resolution
    modified["gates"] = recompute_gates(modified)

    validate_artifact(modified)
    expected_tolerance_ns = recorded_resolution * 1_000_000_000
    assert all(
        row["clock_tolerance_ns"] == expected_tolerance_ns for row in modified["gates"]["lua_end_to_end_individual"]
    )


@pytest.mark.parametrize(
    "resolution",
    [
        0.0,
        -1.0,
        float("inf"),
        float("nan"),
        True,
        1,
        math.nextafter(_MAX_PERF_COUNTER_RESOLUTION_SECONDS, math.inf),
        1e-6,
    ],
)
def test_invalid_recorded_clock_resolution_is_rejected(diagnostic_artifact, resolution):
    invalid = deepcopy(diagnostic_artifact)
    invalid["metadata"]["clock"]["perf_counter_resolution_seconds"] = resolution
    with pytest.raises(ArtifactValidationError, match="perf_counter_resolution_seconds is invalid"):
        validate_artifact(invalid)


def test_maximum_recorded_clock_resolution_is_accepted(diagnostic_artifact):
    modified = deepcopy(diagnostic_artifact)
    modified["metadata"]["clock"]["perf_counter_resolution_seconds"] = _MAX_PERF_COUNTER_RESOLUTION_SECONDS
    modified["gates"] = recompute_gates(modified)

    validate_artifact(modified)
    assert all(row["clock_tolerance_ns"] == 100.0 for row in modified["gates"]["lua_end_to_end_individual"])


def test_selected_repository_and_git_roots_are_anchored(diagnostic_artifact, tmp_path):
    unrelated = str((tmp_path / "unrelated").resolve())

    selected_root = deepcopy(diagnostic_artifact)
    selected_root["metadata"]["selected_repo_root"] = unrelated
    with pytest.raises(ArtifactValidationError, match="path is outside the selected repository"):
        validate_artifact(selected_root)

    git_root = deepcopy(diagnostic_artifact)
    for identity_name in ("identity_before", "identity_after"):
        git_root["metadata"][identity_name]["git"]["root"] = unrelated
    with pytest.raises(ArtifactValidationError, match="git.root does not match"):
        validate_artifact(git_root)


@pytest.mark.parametrize("field", ["path", "origin"])
@pytest.mark.parametrize("source_index", [0, 1, 2])
def test_every_source_path_and_origin_is_anchored(
    diagnostic_artifact,
    tmp_path,
    field,
    source_index,
):
    invalid = deepcopy(diagnostic_artifact)
    unrelated = str((tmp_path / f"outside-{source_index}.py").resolve())
    for identity_name in ("identity_before", "identity_after"):
        invalid["metadata"][identity_name]["sources"][source_index][field] = unrelated
    with pytest.raises(ArtifactValidationError, match=f"{field} is outside the selected repository"):
        validate_artifact(invalid)


def test_source_hash_is_structural_offline_but_verified_locally(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    for identity_name in ("identity_before", "identity_after"):
        invalid["metadata"][identity_name]["sources"][0]["sha256"] = "0" * 64

    offline = validate_artifact(invalid)
    assert offline["structurally_valid"] is True
    assert offline["repository_verified"] is False
    assert offline["release_eligible"] is False

    repo_root = Path(__file__).resolve().parents[1]
    local = validate_artifact(invalid, repo_root=repo_root)
    assert local["repository_verified"] is False
    assert "current-source-identity-mismatch" in local["repository_verification_reasons"]
    assert local["release_eligible"] is False


def test_local_and_offline_repository_verification_are_distinct(diagnostic_artifact):
    offline = validate_artifact(diagnostic_artifact)
    assert offline == {
        "structurally_valid": True,
        "repository_verified": False,
        "repository_verification_reasons": ["repository-not-provided"],
        "release_eligible": False,
    }

    repo_root = Path(__file__).resolve().parents[1]
    local = validate_artifact(diagnostic_artifact, repo_root=repo_root)
    assert local["structurally_valid"] is True
    assert local["repository_verified"] is True
    assert local["repository_verification_reasons"] == []
    assert local["release_eligible"] is False


def test_full_git_status_records_every_untracked_path(diagnostic_artifact):
    status_lines = diagnostic_artifact["metadata"]["identity_before"]["git"]["status_lines"]
    assert "?? benchmarks/netcap/README.md" in status_lines
    assert "?? benchmarks/netcap/buffer_search.py" in status_lines
    assert "?? tests/test_netcap_benchmarks.py" in status_lines
    assert "?? benchmarks/netcap/" not in status_lines


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("commit", "0" * 40),
        ("tree", "1" * 40),
        ("branch", "forged/release"),
    ],
)
def test_forged_git_snapshot_identity_cannot_verify_locally(
    diagnostic_artifact,
    field,
    forged_value,
):
    forged = deepcopy(diagnostic_artifact)
    for identity_name in ("identity_before", "identity_after"):
        forged["metadata"][identity_name]["git"][field] = forged_value
    forged["metadata"]["identity_unchanged"] = True

    assert validate_artifact(forged)["structurally_valid"] is True
    repo_root = Path(__file__).resolve().parents[1]
    local = validate_artifact(forged, repo_root=repo_root)
    assert local["repository_verified"] is False
    assert "current-git-identity-mismatch" in local["repository_verification_reasons"]
    assert local["release_eligible"] is False


def test_forged_clean_git_identity_cannot_verify_locally(diagnostic_artifact):
    forged = deepcopy(diagnostic_artifact)
    empty_status_hash = hashlib.sha256(b"").hexdigest()
    for identity_name in ("identity_before", "identity_after"):
        git = forged["metadata"][identity_name]["git"]
        git["dirty"] = False
        git["status_lines"] = []
        git["status_sha256"] = empty_status_hash
    forged["metadata"]["identity_unchanged"] = True
    forged["gates"] = recompute_gates(forged)
    assert "candidate-tree-dirty" not in forged["gates"]["insufficiency_reasons"]

    offline = validate_artifact(forged)
    assert offline["structurally_valid"] is True
    assert offline["repository_verified"] is False
    assert offline["release_eligible"] is False

    repo_root = Path(__file__).resolve().parents[1]
    local = validate_artifact(forged, repo_root=repo_root)
    assert local["repository_verified"] is False
    assert "current-git-identity-mismatch" in local["repository_verification_reasons"]
    assert "candidate-tree-dirty" in local["repository_verification_reasons"]
    assert local["release_eligible"] is False


def test_moved_artifact_is_structural_only_without_exact_repository(
    diagnostic_artifact,
    tmp_path,
):
    moved = deepcopy(diagnostic_artifact)
    moved_root = (tmp_path / "moved-repository").resolve()
    relative_paths = {
        "benchmark_init": Path("benchmarks/netcap/__init__.py"),
        "benchmark_module": Path("benchmarks/netcap/buffer_search.py"),
        "candidate_plugin": Path("memscope_mcp/_contrib/plugins/netcap.py"),
    }
    moved["metadata"]["selected_repo_root"] = str(moved_root)
    for identity_name in ("identity_before", "identity_after"):
        identity = moved["metadata"][identity_name]
        identity["git"]["root"] = str(moved_root)
        for source in identity["sources"]:
            expected_path = (moved_root / relative_paths[source["label"]]).resolve()
            source["path"] = str(expected_path)
            source["origin"] = str(expected_path)
    moved["metadata"]["identity_unchanged"] = True

    offline = validate_artifact(moved)
    assert offline["structurally_valid"] is True
    assert offline["repository_verified"] is False
    assert offline["repository_verification_reasons"] == ["repository-not-provided"]
    assert offline["release_eligible"] is False

    local = validate_artifact(moved, repo_root=Path(__file__).resolve().parents[1])
    assert local["repository_verified"] is False
    assert local["repository_verification_reasons"] == ["repository-root-mismatch"]
    assert local["release_eligible"] is False


def test_parity_commitment_covers_exact_bounded_matrix(diagnostic_artifact):
    correctness = diagnostic_artifact["correctness"]
    assert len(correctness["scenarios"]) == 211
    assert sum(len(row["operations"]) for row in correctness["scenarios"]) == 633
    assert correctness["commitment_sha256"] == _parity_commitment(correctness["scenarios"])
    assert all(set(row) == {"scenario", "inputs", "operations"} for row in correctness["scenarios"])


def test_forged_aggregate_parity_is_rejected(diagnostic_artifact):
    forged = deepcopy(diagnostic_artifact)
    correctness = forged["correctness"]
    operation = correctness["scenarios"][0]["operations"][0]
    operation["candidate"] = {"kind": "return", "result": {"value": 999}}
    operation["passed"] = False
    correctness["commitment_sha256"] = _parity_commitment(correctness["scenarios"])
    correctness["passed"] = True
    correctness["failure_count"] = 0
    correctness["failures"] = []

    with pytest.raises(ArtifactValidationError, match="failure_count is inconsistent"):
        validate_artifact(forged)


def test_forged_parity_commitment_is_rejected(diagnostic_artifact):
    forged = deepcopy(diagnostic_artifact)
    forged["correctness"]["commitment_sha256"] = "0" * 64
    with pytest.raises(ArtifactValidationError, match="commitment_sha256 is inconsistent"):
        validate_artifact(forged)


def test_self_consistent_forged_candidate_parity_is_rejected(diagnostic_artifact):
    forged = deepcopy(diagnostic_artifact)
    operation = forged["correctness"]["scenarios"][0]["operations"][0]
    operation["candidate"] = {"kind": "return", "result": {"value": 999}}
    operation["passed"] = False
    _refresh_correctness_aggregates(forged["correctness"])
    forged["gates"] = recompute_gates(forged)

    with pytest.raises(ArtifactValidationError, match="recomputed parity"):
        validate_artifact(forged)


def test_parity_scope_expansion_is_rejected_even_with_new_commitment(diagnostic_artifact):
    forged = deepcopy(diagnostic_artifact)
    forged["correctness"]["scenarios"][0]["undeclared_probe"] = "expanded"
    forged["correctness"]["commitment_sha256"] = _parity_commitment(forged["correctness"]["scenarios"])

    with pytest.raises(ArtifactValidationError, match="unexpected fields"):
        validate_artifact(forged)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True, -1.0])
def test_nonfinite_or_invalid_lua_heap_evidence_is_rejected(
    diagnostic_artifact,
    value,
):
    invalid = deepcopy(diagnostic_artifact)
    row = invalid["lua_heap"][0]
    row["delta_kib_samples"][0] = value
    row["median_delta_kib"] = value
    with pytest.raises(ArtifactValidationError, match="finite number|valid domain"):
        validate_artifact(invalid)


@pytest.mark.parametrize("field", ["before_kib", "after_kib", "growth_kib"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True])
def test_nonfinite_retained_growth_evidence_is_rejected(
    diagnostic_artifact,
    field,
    value,
):
    invalid = deepcopy(diagnostic_artifact)
    invalid["retained_growth"][0][field] = value
    with pytest.raises(ArtifactValidationError, match="finite number"):
        validate_artifact(invalid)


@pytest.mark.parametrize("field", ["before_kib", "after_kib", "growth_kib"])
def test_negative_retained_growth_values_are_rejected(diagnostic_artifact, field):
    invalid = deepcopy(diagnostic_artifact)
    invalid["retained_growth"][0][field] = -1.0
    with pytest.raises(ArtifactValidationError, match="valid domain"):
        validate_artifact(invalid)


def test_tiny_heap_median_forgery_is_rejected(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["lua_heap"][0]["median_delta_kib"] += 1e-10
    with pytest.raises(ArtifactValidationError, match="recomputed value"):
        validate_artifact(invalid)


def test_tiny_retained_growth_arithmetic_forgery_is_rejected(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["retained_growth"][0]["growth_kib"] += 1e-10
    with pytest.raises(ArtifactValidationError, match="recomputed value"):
        validate_artifact(invalid)


@pytest.mark.parametrize(
    ("matrix", "field"),
    [
        ("lua_end_to_end_groups", "ratio"),
        ("lua_end_to_end_groups", "threshold"),
        ("lua_end_to_end_individual", "ratio"),
        ("lua_end_to_end_individual", "threshold"),
        ("lua_end_to_end_individual", "clock_tolerance_ns"),
        ("lua_end_to_end_individual", "limit_ns"),
        ("allocation", "baseline_peak_bytes"),
        ("allocation", "candidate_peak_bytes"),
        ("allocation", "allowance_bytes"),
        ("allocation", "limit_bytes"),
        ("lua_heap", "baseline_delta_bytes"),
        ("lua_heap", "candidate_delta_bytes"),
        ("lua_heap", "allowance_bytes"),
        ("retained_growth", "growth_kib"),
        ("retained_growth", "threshold_kib"),
    ],
)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True])
def test_nonfinite_or_boolean_gate_values_are_rejected(
    diagnostic_artifact,
    matrix,
    field,
    value,
):
    invalid = deepcopy(diagnostic_artifact)
    invalid["gates"][matrix][0][field] = value
    with pytest.raises(ArtifactValidationError, match="finite number"):
        validate_artifact(invalid)


@pytest.mark.parametrize(
    "matrix",
    [
        "lua_end_to_end_groups",
        "lua_end_to_end_individual",
        "allocation",
        "lua_heap",
        "retained_growth",
    ],
)
def test_nonboolean_gate_pass_flags_are_rejected(diagnostic_artifact, matrix):
    invalid = deepcopy(diagnostic_artifact)
    invalid["gates"][matrix][0]["passed"] = 1
    with pytest.raises(ArtifactValidationError, match="must be boolean"):
        validate_artifact(invalid)


def test_nonfinite_allocation_median_is_rejected(diagnostic_artifact):
    invalid = deepcopy(diagnostic_artifact)
    invalid["allocation"][0]["baseline"]["median_peak_bytes"] = float("inf")
    with pytest.raises(ArtifactValidationError, match="finite number"):
        validate_artifact(invalid)


def test_lua_reference_encoding_and_em_dashes():
    path = Path(__file__).resolve().parents[1] / "docs" / "lua-reference.md"
    raw = path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8")
    assert text.count("\N{EM DASH}") == 2
    assert "\u00e2\u20ac\u201d" not in text
    assert "Arbitrary converted integers retain exact legacy comparison semantics." in text


def test_no_benchmark_local_optimized_kernel_is_exposed():
    assert not any(name.startswith("_optimized") for name in vars(benchmark))
