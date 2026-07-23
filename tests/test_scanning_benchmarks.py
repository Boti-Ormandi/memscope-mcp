"""Determinism and schema tests for the scanning benchmark foundation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.scanning import MANIFEST_VERSION
from benchmarks.scanning.common import (
    ArtifactValidationError,
    read_raw_artifact,
    semantic_fingerprint,
    semantic_fingerprint_payload,
    validate_raw_artifact,
    write_raw_artifact,
)
from benchmarks.scanning.corpus import build_corpus
from benchmarks.scanning.engine import run_engine_suite
from benchmarks.scanning.manifest import CASES
from benchmarks.scanning.matcher import BASE_ADDRESS, run_matcher_suite
from benchmarks.scanning.public_api import run_public_api_suite

_MATCHER_CASES = tuple(case for case in CASES if case.layer == "matcher")
_EXPECTED_MATCHER_CASE_IDS = {
    "matcher.exact16.uniform",
    "matcher.selective16.uniform",
    "matcher.alternating16.skew",
    "matcher.sparse_rare16.skew",
    "matcher.sparse_common16.skew",
    "matcher.pointer8.uniform",
    "matcher.ascii16.uniform",
    "matcher.utf16le16.uniform",
}


def test_matcher_manifest_has_stable_unique_coverage():
    assert len({case.case_id for case in CASES}) == len(CASES)
    assert {case.case_id for case in _MATCHER_CASES} == _EXPECTED_MATCHER_CASE_IDS
    assert all(case.expected_strategy is not None for case in _MATCHER_CASES)


def test_selective_process_pattern_is_literal_first_balanced_v5_case():
    process_case = next(case for case in CASES if case.case_id == "e2e.selective16.late.contiguous64m")
    matcher_case = next(case for case in CASES if case.case_id == "matcher.selective16.uniform")
    tokens = process_case.pattern.split()

    assert MANIFEST_VERSION == "scanning-manifest-v5"
    assert process_case.pattern == "8B 45 F8 48 85 C0 75 05 ?? ?? ?? ?? ?? ?? ?? ??"
    assert len(tokens) == 16
    assert tokens[0] != "??"
    assert sum(token == "??" for token in tokens) == 8
    assert sum(token != "??" for token in tokens) == 8
    assert process_case.parameters == {"injections": ["late"]}
    assert process_case.semantic_fingerprint("release") == (
        "f0a3140d6fb949028640c955c757d7e3d41f50c34361d62fc39ec7969aaa10a7"
    )
    assert matcher_case.pattern == "?? ?? ?? ?? 8B 45 F8 48 85 C0 75 05 ?? ?? ?? ??"


def test_manifest_declares_only_strict_unknown_as_non_timing_capability():
    strict = next(case for case in CASES if case.case_id == "public.strict_unknown_field")
    boundary = next(case for case in CASES if case.case_id == "e2e.boundary.split_protection.exact")
    matcher = next(case for case in CASES if case.case_id == "matcher.exact16.uniform")

    assert strict.comparison_class == "new_capability"
    assert strict.primary_metric == "invariant"
    assert strict.size_bytes == 0
    assert strict.observation_metric_contract == "non_timing_capability"
    assert boundary.primary_metric == "invariant"
    assert boundary.observation_metric_contract == "timed"
    assert matcher.observation_metric_contract == "timed"


def test_corpus_and_semantic_fingerprint_are_deterministic():
    case = next(case for case in _MATCHER_CASES if case.case_id == "matcher.sparse_rare16.skew")

    first = build_corpus(case, "smoke", base_address=BASE_ADDRESS)
    second = build_corpus(case, "smoke", base_address=BASE_ADDRESS)

    assert first.data == second.data
    assert first.data_sha256 == second.data_sha256
    assert first.expected_addresses == second.expected_addresses
    assert first.expected_checksum == second.expected_checksum
    assert case.semantic_fingerprint("smoke") == case.semantic_fingerprint("smoke")
    assert replace(case, expected_strategy="regex").semantic_fingerprint("smoke") == case.semantic_fingerprint("smoke")


def test_process_timeout_and_candidate_watchdog_are_part_of_semantic_identity():
    case = next(case for case in CASES if case.case_id == "control.timeout100.common_masked")
    descriptor = case.semantic_descriptor("smoke")
    changed = replace(case, process_timeout_s=31.0)

    assert descriptor["process_timeout_s"] == 5.0
    assert descriptor["candidate_watchdog_timeout_s"] == 30.0
    assert changed.semantic_descriptor("smoke")["candidate_watchdog_timeout_s"] == 31.0
    assert changed.semantic_fingerprint("smoke") != case.semantic_fingerprint("smoke")


def test_warm_section_setup_protocol_is_part_of_semantic_identity():
    case = next(case for case in CASES if case.case_id == "scope.section.text.current_exe.warm")
    changed = replace(case, setup_protocol={**case.setup_protocol, "untimed_operations": 2})

    assert case.semantic_descriptor("smoke")["preflight_protocol"] == {
        "operation": "exact_addresses",
        "ordered": True,
        "checksum": "sha256-u64le",
        "attachment": "same",
        "cache_state": "isolated",
        "excluded_from_timing": True,
        "independent_read_counters": True,
    }
    assert case.setup_protocol == {
        "untimed_operations": 1,
        "operation": "identical",
        "attachment": "same",
        "setup_excluded_from_timing": True,
        "historical_state": "shared_session",
        "candidate_state": "shared_section_cache_hot",
    }
    assert changed.semantic_fingerprint("smoke") != case.semantic_fingerprint("smoke")


def test_smoke_matcher_runner_emits_round_trippable_raw_artifact(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
    )

    validate_raw_artifact(artifact)
    assert {case["case_id"] for case in artifact["cases"]} == _EXPECTED_MATCHER_CASE_IDS
    assert all(case["status"] == "complete" for case in artifact["cases"])
    assert all(case["observations"][0]["duration_ns"] > 0 for case in artifact["cases"])
    assert all(case["expected"]["address_checksum"] for case in artifact["cases"])

    output = tmp_path / "raw.json"
    write_raw_artifact(output, artifact)
    assert read_raw_artifact(output) == artifact


@pytest.mark.parametrize("record", ("manifest", "corpus", "expected"))
def test_raw_artifact_rejects_semantic_record_mutation(record: str):
    repo_root = Path(__file__).resolve().parents[1]
    case_id = _MATCHER_CASES[0].case_id
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(case_id,),
    )
    invalid = deepcopy(artifact)
    if record == "manifest":
        invalid["cases"][0][record]["timeout_ms"] += 1
    elif record == "corpus":
        invalid["cases"][0][record]["size"] += 1
    else:
        invalid["cases"][0][record]["returned_count"] += 1

    with pytest.raises(ArtifactValidationError, match="differs from the canonical"):
        validate_raw_artifact(invalid)


def test_raw_artifact_rejects_fingerprint_payload_and_digest_mutation():
    repo_root = Path(__file__).resolve().parents[1]
    case_id = _MATCHER_CASES[0].case_id
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(case_id,),
    )
    invalid_payload = deepcopy(artifact)
    invalid_payload["cases"][0]["semantic_fingerprint_payload"]["expected"]["returned_count"] += 1
    with pytest.raises(ArtifactValidationError, match="semantic_fingerprint_payload differs"):
        validate_raw_artifact(invalid_payload)

    invalid_digest = deepcopy(artifact)
    invalid_digest["cases"][0]["semantic_fingerprint"] = "0" * 64
    with pytest.raises(ArtifactValidationError, match="semantic_fingerprint does not match"):
        validate_raw_artifact(invalid_digest)


@pytest.mark.parametrize("record", ("manifest", "corpus", "expected"))
def test_raw_artifact_rejects_rehashed_canonical_record_mutation(record: str):
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(_MATCHER_CASES[0].case_id,),
    )
    invalid = deepcopy(artifact)
    case = invalid["cases"][0]
    if record == "manifest":
        case[record]["timeout_ms"] += 1
    elif record == "corpus":
        case[record]["size"] += 1
    else:
        case[record]["returned_count"] += 1
    payload = semantic_fingerprint_payload(case["manifest"], case["corpus"], case["expected"])
    case["semantic_fingerprint_payload"] = payload
    case["semantic_fingerprint"] = semantic_fingerprint(payload)

    with pytest.raises(ArtifactValidationError, match="differs from the canonical"):
        validate_raw_artifact(invalid)


def test_raw_artifact_rejects_unknown_case_id_even_when_records_are_rehashed():
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(_MATCHER_CASES[0].case_id,),
    )
    invalid = deepcopy(artifact)
    invalid["runner"]["selected_case_ids"] = ["matcher.future.unknown"]
    invalid["cases"][0]["case_id"] = "matcher.future.unknown"

    with pytest.raises(ArtifactValidationError, match="unknown case_id"):
        validate_raw_artifact(invalid)


def test_raw_artifact_rejects_noncanonical_case_order():
    repo_root = Path(__file__).resolve().parents[1]
    selected = (_MATCHER_CASES[0].case_id, _MATCHER_CASES[1].case_id)
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=selected,
    )
    invalid = deepcopy(artifact)
    invalid["runner"]["selected_case_ids"].reverse()
    invalid["cases"].reverse()

    with pytest.raises(ArtifactValidationError, match="canonical manifest order"):
        validate_raw_artifact(invalid)


def test_raw_artifact_rejects_forged_summary_and_observation_correctness():
    repo_root = Path(__file__).resolve().parents[1]
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(_MATCHER_CASES[0].case_id,),
    )
    forged_summary = deepcopy(artifact)
    forged_summary["cases"][0]["summary"]["duration_ns"]["median"] += 1
    with pytest.raises(ArtifactValidationError, match="summary differs from observations"):
        validate_raw_artifact(forged_summary)

    forged_observation = deepcopy(artifact)
    forged_observation["cases"][0]["observations"][0]["work"]["observed_count"] += 1
    with pytest.raises(ArtifactValidationError, match="observed count differs"):
        validate_raw_artifact(forged_observation)


@pytest.mark.parametrize(
    ("runner", "case_id"),
    (
        (run_engine_suite, "control.in_band_cancellation"),
        (run_public_api_suite, "public.fastmcp.strict_flat_contract"),
    ),
)
def test_deterministic_raw_suites_reject_rehashed_expected_mutation(runner, case_id: str):
    repo_root = Path(__file__).resolve().parents[1]
    artifact = runner(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(case_id,),
    )
    invalid = deepcopy(artifact)
    case = invalid["cases"][0]
    case["expected"]["forged"] = True
    payload = semantic_fingerprint_payload(case["manifest"], case["corpus"], case["expected"])
    case["semantic_fingerprint_payload"] = payload
    case["semantic_fingerprint"] = semantic_fingerprint(payload)

    with pytest.raises(ArtifactValidationError, match="expected differs from canonical"):
        validate_raw_artifact(invalid)


def test_raw_artifact_rejects_duplicate_case_ids():
    repo_root = Path(__file__).resolve().parents[1]
    case_id = _MATCHER_CASES[0].case_id
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
        case_ids=(case_id,),
    )
    invalid = deepcopy(artifact)
    invalid["cases"].append(deepcopy(invalid["cases"][0]))
    invalid["runner"]["selected_case_ids"].append(case_id)

    with pytest.raises(ArtifactValidationError, match="duplicates"):
        validate_raw_artifact(invalid)
