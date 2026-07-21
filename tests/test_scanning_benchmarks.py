"""Determinism and schema tests for the scanning benchmark foundation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.scanning.common import (
    ArtifactValidationError,
    read_raw_artifact,
    validate_raw_artifact,
    write_raw_artifact,
)
from benchmarks.scanning.corpus import build_corpus
from benchmarks.scanning.manifest import CASES
from benchmarks.scanning.matcher import BASE_ADDRESS, run_matcher_suite

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

    with pytest.raises(ArtifactValidationError, match="duplicate case_id"):
        validate_raw_artifact(invalid)
