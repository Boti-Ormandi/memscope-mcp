"""Validate paired raw artifacts and produce complete per-case comparisons."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from benchmarks.scanning import (
    BENCHMARK_SCHEMA_VERSION,
    CANDIDATE_WATCHDOG_FLOOR_S,
    COMPARISON_SCHEMA_VERSION,
    CORPUS_VERSION,
    DRIVER_PROTOCOL,
    MANIFEST_VERSION,
    PAIRING_PROTOCOL,
)
from benchmarks.scanning.common import (
    address_checksum,
    bootstrap_median_interval,
    candidate_watchdog_error,
    controlled_identity_error,
    is_exact_int,
    is_finite_number,
    operation_continuity_key,
    operation_identity_error,
    pair_order_label,
    pair_seed,
    paired_semantic_fingerprint_payload,
    read_evidence_error,
    read_json,
    semantic_fingerprint,
    sha256_json,
    summarize,
    timeout_control_error,
    timeout_duration_ns,
    write_csv,
    write_json,
)
from benchmarks.scanning.manifest import (
    CASE_BY_ID,
    CASES,
    BenchmarkCase,
    is_candidate_only,
    preflight_protocol,
    requires_exact_preflight,
    uses_controlled_target,
)

_CHUNK_POLICY = (
    "smallest chunk within 10 percent of best throughput while preserving "
    "128 KiB salvage and timeout p95 within 10 percent"
)

CSV_FIELDS = (
    "case_id",
    "group",
    "comparison_class",
    "status",
    "before_median_ns",
    "after_median_ns",
    "paired_speedup_median",
    "paired_speedup_ci_low",
    "paired_speedup_ci_high",
    "censored_speedup_lower_bound",
    "before_throughput_mib_s",
    "after_throughput_mib_s",
    "reader_utilization",
    "before_peak_python_bytes",
    "after_peak_python_bytes",
    "before_physical_bytes_read",
    "after_physical_bytes_read",
    "after_correct_count",
    "after_observation_count",
    "after_expected_checksum",
    "read_reduction_fraction",
    "performance_regression",
    "blocking",
    "notes",
)


def compare_artifacts(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    _validate_artifact_pair(before, after)
    selected_case_ids = before["metadata"]["runner"]["case_ids"]
    selected_cases = tuple(CASE_BY_ID[case_id] for case_id in selected_case_ids)
    before_by_case = _group_observations(before["observations"])
    after_by_case = _group_observations(after["observations"])
    rows = [
        _compare_case(case, before_by_case.get(case.case_id, []), after_by_case.get(case.case_id, []))
        for case in selected_cases
    ]

    reader_after = next(
        (
            row["after"]["throughput_mib_s"]["median"]
            for row in rows
            if row["case_id"] == "reader.ceiling.contiguous64m"
        ),
        None,
    )
    if reader_after:
        for row in rows:
            if row["group"] == "Contiguous end-to-end":
                throughput = row["after"]["throughput_mib_s"]["median"]
                if throughput is not None:
                    row["reader_utilization"] = throughput / reader_after

    blocking_rows = [row["case_id"] for row in rows if row["blocking"]]
    incomplete_statuses = {"missing", "invalid", "partial"}
    complete = all(row["status"] not in incomplete_statuses for row in rows)
    release_eligibility = _release_eligibility(
        before,
        after,
        rows,
        complete=complete,
        blocking=bool(blocking_rows),
    )
    comparison = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "profile": before["metadata"]["profile"],
        "before_environment": before["metadata"],
        "after_environment": after["metadata"],
        "compatible": True,
        "complete": complete,
        "blocking": bool(blocking_rows),
        "blocking_cases": blocking_rows,
        "release_eligibility": release_eligibility,
        "chunk_recommendation": _chunk_recommendation(rows),
        "rows": rows,
    }
    comparison["content_digest"] = comparison_content_digest(comparison)
    return comparison


def comparison_content_payload(comparison: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": comparison.get("schema_version"),
        "profile": comparison.get("profile"),
        "before_environment": comparison.get("before_environment"),
        "after_environment": comparison.get("after_environment"),
        "compatible": comparison.get("compatible"),
        "rows": comparison.get("rows"),
    }


def comparison_content_digest(comparison: dict[str, Any]) -> str:
    return sha256_json(comparison_content_payload(comparison))


def _validate_reporting_environment(label: str, metadata: Any, implementation: str) -> None:
    if not isinstance(metadata, dict):
        raise ValueError(f"{label} comparison environment is missing")
    expected = {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "implementation": implementation,
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise ValueError(f"{label} comparison environment uses unsupported {field}")
    if metadata.get("profile") not in {"smoke", "release"}:
        raise ValueError(f"{label} comparison environment profile is invalid")
    runner = metadata.get("runner")
    if not isinstance(runner, dict):
        raise ValueError(f"{label} comparison runner is missing")
    if runner.get("pairing") != PAIRING_PROTOCOL or runner.get("driver") != DRIVER_PROTOCOL:
        raise ValueError(f"{label} comparison runner protocol is unsupported")
    for field, value in (
        ("benchmark_schema_version", BENCHMARK_SCHEMA_VERSION),
        ("manifest_version", MANIFEST_VERSION),
        ("corpus_version", CORPUS_VERSION),
    ):
        if runner.get(field) != value:
            raise ValueError(f"{label} comparison runner uses unsupported {field}")
    if runner.get("candidate_watchdog_floor_s") != CANDIDATE_WATCHDOG_FLOOR_S:
        raise ValueError(f"{label} comparison runner candidate watchdog policy is unsupported")
    blocks = runner.get("blocks")
    if not is_exact_int(blocks, minimum=1):
        raise ValueError(f"{label} comparison runner block count is invalid")
    selected = runner.get("case_ids")
    if (
        not isinstance(selected, list)
        or not selected
        or len(selected) != len(set(selected))
        or any(case_id not in CASE_BY_ID for case_id in selected)
    ):
        raise ValueError(f"{label} comparison runner selected cases are invalid")
    expected_candidate_only = [case_id for case_id in selected if is_candidate_only(CASE_BY_ID[case_id])]
    if runner.get("candidate_only_case_ids") != expected_candidate_only:
        raise ValueError(f"{label} comparison runner candidate-only declaration is invalid")


_REPORTING_ROW_FIELDS = {
    "case_id",
    "group",
    "layer",
    "tier",
    "headline",
    "comparison_class",
    "primary_metric",
    "status",
    "before",
    "after",
    "paired_speedup",
    "censored_speedup_lower_bound",
    "read_reduction_fraction",
    "allocation_reduction_fraction",
    "reader_utilization",
    "performance_regression",
    "blocking",
    "notes",
    "before_status_counts",
    "after_status_counts",
}
_IMPLEMENTATION_SUMMARY_FIELDS = {
    "duration_ns",
    "throughput_mib_s",
    "peak_python_bytes",
    "physical_bytes_read",
    "physical_read_calls",
    "timeout_overshoot_ns",
    "timed_out_count",
    "correct_count",
    "observation_count",
    "actual_checksum",
    "expected_checksum",
}
_SUMMARY_FIELDS = {"count", "median", "p95", "minimum", "maximum", "mad"}
_OBSERVATION_STATUSES = {"ok", "censored", "not_applicable", "error", "driver_error"}


def _validate_reporting_stats(case_id: str, side: str, field: str, value: Any, observation_count: int) -> None:
    if not isinstance(value, dict) or set(value) != _SUMMARY_FIELDS:
        raise ValueError(f"comparison row {case_id} {side} {field} summary fields are invalid")
    count = value["count"]
    if not is_exact_int(count) or count > observation_count:
        raise ValueError(f"comparison row {case_id} {side} {field} summary count is inconsistent")
    numeric_fields = ("median", "p95", "minimum", "maximum", "mad")
    if count == 0:
        if any(value[name] is not None for name in numeric_fields):
            raise ValueError(f"comparison row {case_id} {side} {field} empty summary is inconsistent")
        return
    if any(not is_finite_number(value[name]) for name in numeric_fields):
        raise ValueError(f"comparison row {case_id} {side} {field} summary values are invalid")
    minimum = float(value["minimum"])
    median = float(value["median"])
    p95 = float(value["p95"])
    maximum = float(value["maximum"])
    if not minimum <= median <= p95 <= maximum:
        raise ValueError(f"comparison row {case_id} {side} {field} summary ordering is invalid")


def _validate_reporting_status_counts(
    case_id: str,
    side: str,
    value: Any,
    *,
    blocks: int,
    allow_empty: bool,
) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError(f"comparison row {case_id} {side} status counts are invalid")
    if allow_empty and not value:
        return {}
    if (
        any(status not in _OBSERVATION_STATUSES for status in value)
        or any(not is_exact_int(count, minimum=1) for count in value.values())
        or sum(value.values()) != blocks
    ):
        raise ValueError(f"comparison row {case_id} {side} status counts are inconsistent")
    return value


def _canonical_reporting_row(row: Any, case: BenchmarkCase, *, blocks: int) -> dict[str, Any]:
    if not isinstance(row, dict) or set(row) != _REPORTING_ROW_FIELDS or row.get("case_id") != case.case_id:
        raise ValueError(f"comparison row identity or fields are invalid for {case.case_id}")
    manifest_fields = {
        "group": case.group,
        "layer": case.layer,
        "tier": case.tier,
        "headline": case.headline,
        "comparison_class": case.comparison_class,
        "primary_metric": case.primary_metric,
    }
    if any(row.get(field) != expected for field, expected in manifest_fields.items()):
        raise ValueError(f"comparison row manifest fields differ for {case.case_id}")
    status = row.get("status")
    if status not in {"ok", "censored", "candidate_only", "not_applicable", "missing", "invalid", "partial"}:
        raise ValueError(f"comparison row status is invalid for {case.case_id}")
    if not isinstance(row.get("blocking"), bool) or not isinstance(row.get("performance_regression"), bool):
        raise ValueError(f"comparison row boolean fields are invalid for {case.case_id}")
    if not isinstance(row.get("notes"), list) or any(not isinstance(note, str) for note in row["notes"]):
        raise ValueError(f"comparison row notes are invalid for {case.case_id}")
    for field in ("censored_speedup_lower_bound", "reader_utilization"):
        value = row[field]
        if value is not None and not is_finite_number(value):
            raise ValueError(f"comparison row {case.case_id} {field} is invalid")
    for field in ("read_reduction_fraction", "allocation_reduction_fraction"):
        value = row[field]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value))
        ):
            raise ValueError(f"comparison row {case.case_id} {field} is invalid")

    allow_empty_status = status in {"missing", "invalid"}
    status_counts = {
        side: _validate_reporting_status_counts(
            case.case_id,
            side,
            row[f"{side}_status_counts"],
            blocks=blocks,
            allow_empty=allow_empty_status,
        )
        for side in ("before", "after")
    }
    for side in ("before", "after"):
        summary = row.get(side)
        if not isinstance(summary, dict) or set(summary) != _IMPLEMENTATION_SUMMARY_FIELDS:
            raise ValueError(f"comparison row {case.case_id} {side} summary fields are invalid")
        observation_count = summary["observation_count"]
        correct_count = summary["correct_count"]
        timed_out_count = summary["timed_out_count"]
        if (
            not is_exact_int(observation_count)
            or not is_exact_int(correct_count)
            or not is_exact_int(timed_out_count)
            or correct_count > observation_count
            or timed_out_count > observation_count
        ):
            raise ValueError(f"comparison row {case.case_id} {side} counts are inconsistent")
        if status_counts[side] and observation_count != status_counts[side].get("ok", 0):
            raise ValueError(f"comparison row {case.case_id} {side} observation count differs from status counts")
        if not _optional_sha256(summary["actual_checksum"]) or not _optional_sha256(summary["expected_checksum"]):
            raise ValueError(f"comparison row {case.case_id} {side} checksums are invalid")
        for field in (
            "duration_ns",
            "throughput_mib_s",
            "peak_python_bytes",
            "physical_bytes_read",
            "physical_read_calls",
            "timeout_overshoot_ns",
        ):
            _validate_reporting_stats(case.case_id, side, field, summary[field], observation_count)
        if (
            summary["duration_ns"]["count"] != observation_count
            or summary["throughput_mib_s"]["count"] != observation_count
        ):
            raise ValueError(f"comparison row {case.case_id} {side} primary summary counts are inconsistent")

    paired = row["paired_speedup"]
    if not isinstance(paired, dict) or set(paired) != {"count", "median", "ci_low", "ci_high"}:
        raise ValueError(f"comparison row {case.case_id} paired speedup fields are invalid")
    if not is_exact_int(paired["count"]) or paired["count"] > min(
        row["before"]["observation_count"], row["after"]["observation_count"]
    ):
        raise ValueError(f"comparison row {case.case_id} paired speedup count is inconsistent")
    if paired["count"] == 0:
        if any(paired[field] is not None for field in ("median", "ci_low", "ci_high")):
            raise ValueError(f"comparison row {case.case_id} empty paired speedup is inconsistent")
    elif any(not is_finite_number(paired[field], minimum=0) for field in ("median", "ci_low", "ci_high")):
        raise ValueError(f"comparison row {case.case_id} paired speedup values are invalid")
    elif not float(paired["ci_low"]) <= float(paired["median"]) <= float(paired["ci_high"]):
        raise ValueError(f"comparison row {case.case_id} paired speedup interval is inconsistent")

    canonical = dict(row)
    before_failures = sum(status_counts["before"].get(name, 0) for name in ("error", "driver_error"))
    after_failures = sum(
        status_counts["after"].get(name, 0) for name in ("error", "driver_error", "censored", "not_applicable")
    )
    after = row["after"]
    blocking = bool(
        row["blocking"]
        or status in {"missing", "invalid", "partial", "not_applicable"}
        or before_failures
        or after_failures
        or after["observation_count"] == 0
        or after["correct_count"] != after["observation_count"]
    )
    if is_candidate_only(case):
        if (
            status != "candidate_only"
            or status_counts["before"].get("not_applicable", 0) != blocks
            or status_counts["after"].get("ok", 0) != blocks
        ):
            blocking = True
    else:
        if status in {"candidate_only", "not_applicable"}:
            blocking = True
        if status == "censored" and status_counts["before"].get("censored", 0) == 0:
            raise ValueError(f"comparison row {case.case_id} censorship status lacks censored observations")
        if status == "ok" and status_counts["before"].get("ok", 0) == 0:
            raise ValueError(f"comparison row {case.case_id} ok status lacks historical observations")
    if row["censored_speedup_lower_bound"] is not None and status_counts["before"].get("censored", 0) == 0:
        raise ValueError(f"comparison row {case.case_id} censored lower bound lacks censorship evidence")
    canonical["blocking"] = blocking
    return canonical


def validate_comparison_content(comparison: dict[str, Any]) -> list[dict[str, Any]]:
    expected_fields = {
        "schema_version",
        "profile",
        "before_environment",
        "after_environment",
        "compatible",
        "complete",
        "blocking",
        "blocking_cases",
        "release_eligibility",
        "chunk_recommendation",
        "rows",
        "content_digest",
    }
    if not isinstance(comparison, dict) or set(comparison) != expected_fields:
        raise ValueError("comparison fields are invalid")
    if comparison.get("schema_version") != COMPARISON_SCHEMA_VERSION:
        raise ValueError("comparison schema version is unsupported")
    if comparison.get("content_digest") != comparison_content_digest(comparison):
        raise ValueError("comparison content digest does not match canonical content")
    before_environment = comparison.get("before_environment")
    after_environment = comparison.get("after_environment")
    _validate_reporting_environment("historical", before_environment, "before")
    _validate_reporting_environment("candidate", after_environment, "after")
    if comparison.get("profile") != before_environment.get("profile") or comparison.get(
        "profile"
    ) != after_environment.get("profile"):
        raise ValueError("comparison profile differs from environment metadata")
    if comparison.get("compatible") is not True:
        raise ValueError("comparison is not environment-compatible")
    selected = before_environment["runner"].get("case_ids")
    if selected != after_environment["runner"].get("case_ids") or not isinstance(selected, list):
        raise ValueError("comparison selected case identities differ")
    rows = comparison.get("rows")
    if not isinstance(rows, list) or [row.get("case_id") for row in rows if isinstance(row, dict)] != selected:
        raise ValueError("comparison rows do not match selected case order")
    blocks = before_environment["runner"]["blocks"]
    return [
        _canonical_reporting_row(row, CASE_BY_ID[case_id], blocks=blocks)
        for case_id, row in zip(selected, rows, strict=True)
    ]


def recompute_comparison_summary(
    comparison: dict[str, Any], rows: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    canonical_rows = validate_comparison_content(comparison) if rows is None else rows
    before_environment = comparison["before_environment"]
    after_environment = comparison["after_environment"]
    blocking_cases = [row["case_id"] for row in canonical_rows if row["blocking"]]
    incomplete_statuses = {"missing", "invalid", "partial"}
    complete = all(row["status"] not in incomplete_statuses for row in canonical_rows)
    release_eligibility = _release_eligibility(
        {"metadata": before_environment},
        {"metadata": after_environment},
        canonical_rows,
        complete=complete,
        blocking=bool(blocking_cases),
    )
    return {
        "complete": complete,
        "blocking": bool(blocking_cases),
        "blocking_cases": blocking_cases,
        "release_eligibility": release_eligibility,
    }


def comparison_for_reporting(comparison: dict[str, Any]) -> dict[str, Any]:
    rows = validate_comparison_content(comparison)
    recomputed = recompute_comparison_summary(comparison, rows)
    return {
        **comparison,
        **recomputed,
        "rows": rows,
        "chunk_recommendation": _chunk_recommendation(rows),
    }


def comparison_csv_rows(comparison: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in comparison["rows"]:
        rows.append(
            {
                "case_id": item["case_id"],
                "group": item["group"],
                "comparison_class": item["comparison_class"],
                "status": item["status"],
                "before_median_ns": item["before"]["duration_ns"]["median"],
                "after_median_ns": item["after"]["duration_ns"]["median"],
                "paired_speedup_median": item["paired_speedup"]["median"],
                "paired_speedup_ci_low": item["paired_speedup"]["ci_low"],
                "paired_speedup_ci_high": item["paired_speedup"]["ci_high"],
                "censored_speedup_lower_bound": item["censored_speedup_lower_bound"],
                "before_throughput_mib_s": item["before"]["throughput_mib_s"]["median"],
                "after_throughput_mib_s": item["after"]["throughput_mib_s"]["median"],
                "reader_utilization": item.get("reader_utilization"),
                "before_peak_python_bytes": item["before"]["peak_python_bytes"]["median"],
                "after_peak_python_bytes": item["after"]["peak_python_bytes"]["median"],
                "before_physical_bytes_read": item["before"]["physical_bytes_read"]["median"],
                "after_physical_bytes_read": item["after"]["physical_bytes_read"]["median"],
                "after_correct_count": item["after"]["correct_count"],
                "after_observation_count": item["after"]["observation_count"],
                "after_expected_checksum": item["after"]["expected_checksum"],
                "read_reduction_fraction": item["read_reduction_fraction"],
                "performance_regression": item["performance_regression"],
                "blocking": item["blocking"],
                "notes": "; ".join(item["notes"]),
            }
        )
    return rows


_TERMINATIONS = {
    "complete",
    "scope_exhausted",
    "first_hit",
    "page_limit",
    "match_limit",
    "timeout",
    "cancelled",
}
_BASE_OBSERVATION_FIELDS = {
    "case_id",
    "implementation",
    "profile",
    "block",
    "pair_seed",
    "pair_order",
    "semantic_fingerprint_payload",
    "semantic_fingerprint",
    "semantic_descriptor",
    "status",
    "correct",
}
_OK_OBSERVATION_FIELDS = _BASE_OBSERVATION_FIELDS | {
    "duration_ns",
    "logical_bytes",
    "throughput_mib_s",
    "peak_python_bytes",
    "actual_count",
    "expected_count",
    "actual_checksum",
    "expected_checksum",
    "termination",
    "comparison_identity",
    "expected_historical_failure",
    "metrics",
    "wall_duration_ns",
    "driver_returncode",
}
_OK_OPTIONAL_FIELDS = {"driver_stderr", "timed_wall_duration_ns"}
_CENSORED_OBSERVATION_FIELDS = _BASE_OBSERVATION_FIELDS | {
    "comparison_identity",
    "logical_bytes",
    "expected_count",
    "expected_checksum",
    "expected_historical_failure",
    "preparation",
    "metrics",
    "censorship",
    "wall_duration_ns",
    "timed_wall_duration_ns",
    "stdout",
    "stderr",
}
_NOT_APPLICABLE_FIELDS = _BASE_OBSERVATION_FIELDS | {"reason"}
_ERROR_REQUIRED_FIELDS = _BASE_OBSERVATION_FIELDS | {"error"}
_ERROR_OPTIONAL_FIELDS = {
    "error_type",
    "traceback",
    "comparison_identity",
    "logical_bytes",
    "expected_count",
    "expected_checksum",
    "expected_historical_failure",
    "preparation",
    "metrics",
    "wall_duration_ns",
    "timed_wall_duration_ns",
    "driver_returncode",
    "driver_stderr",
    "stdout",
    "stderr",
}


def _sha256_value(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _optional_sha256(value: Any) -> bool:
    return value is None or _sha256_value(value)


def _validate_semantic_identity(case: BenchmarkCase, observation: dict[str, Any], profile: str) -> None:
    descriptor = case.semantic_descriptor(profile)
    if observation.get("semantic_descriptor") != descriptor:
        raise ValueError(f"{case.case_id}: semantic descriptor differs from the supported manifest")
    comparison_identity = observation.get("comparison_identity")
    payload = paired_semantic_fingerprint_payload(descriptor, comparison_identity)
    if observation.get("semantic_fingerprint_payload") != payload:
        raise ValueError(f"{case.case_id}: semantic fingerprint payload differs from canonical fields")
    if observation.get("semantic_fingerprint") != semantic_fingerprint(payload):
        raise ValueError(f"{case.case_id}: semantic fingerprint does not match its payload")


def _validate_common_observation_fields(
    case: BenchmarkCase,
    observation: dict[str, Any],
    *,
    implementation: str,
    profile: str,
    block: int,
    pair_order: str,
) -> None:
    if observation.get("case_id") != case.case_id:
        raise ValueError("observation case identity is invalid")
    if observation.get("implementation") != implementation:
        raise ValueError("observation implementation identity is invalid")
    if observation.get("profile") != profile:
        raise ValueError("observation profile differs from artifact metadata")
    if observation.get("block") != block or not is_exact_int(observation.get("block")):
        raise ValueError("observation block is invalid")
    expected_seed = pair_seed(case.case_id, block)
    if observation.get("pair_seed") != expected_seed or not is_exact_int(observation.get("pair_seed")):
        raise ValueError("observation pair seed differs from the deterministic protocol")
    expected_order = pair_order_label(case.case_id, block)
    if pair_order != expected_order or observation.get("pair_order") != expected_order:
        raise ValueError("observation pair order differs from the deterministic protocol")
    status = observation.get("status")
    if status not in {"ok", "censored", "not_applicable", "error", "driver_error", "ready"}:
        raise ValueError("observation status is invalid")
    _validate_semantic_identity(case, observation, profile)


def validate_paired_observation(
    case: BenchmarkCase,
    observation: dict[str, Any],
    *,
    implementation: str,
    profile: str,
    block: int,
    pair_order: str,
) -> None:
    _validate_common_observation_fields(
        case,
        observation,
        implementation=implementation,
        profile=profile,
        block=block,
        pair_order=pair_order,
    )
    status = observation["status"]
    fields = set(observation)
    if status == "ok":
        if not _OK_OBSERVATION_FIELDS <= fields or fields - _OK_OBSERVATION_FIELDS - _OK_OPTIONAL_FIELDS:
            raise ValueError("ok observation fields are invalid")
        if observation.get("correct") not in {True, False} or not isinstance(observation.get("correct"), bool):
            raise ValueError("ok observation correctness must be boolean")
        for name in ("duration_ns", "logical_bytes", "actual_count", "expected_count", "wall_duration_ns"):
            if not is_exact_int(observation.get(name)):
                raise ValueError(f"ok observation {name} must be a non-negative integer")
        if not is_finite_number(observation.get("throughput_mib_s")):
            raise ValueError("ok observation throughput must be finite and non-negative")
        peak = observation.get("peak_python_bytes")
        if peak is not None and not is_exact_int(peak):
            raise ValueError("ok observation peak allocation is invalid")
        if not _optional_sha256(observation.get("actual_checksum")) or not _optional_sha256(
            observation.get("expected_checksum")
        ):
            raise ValueError("ok observation checksum fields are invalid")
        if observation.get("termination") not in _TERMINATIONS:
            raise ValueError("ok observation termination is invalid")
        if not isinstance(observation.get("expected_historical_failure"), bool):
            raise ValueError("ok observation historical-failure flag is invalid")
        if not isinstance(observation.get("metrics"), dict):
            raise ValueError("ok observation metrics are invalid")
        if not isinstance(observation.get("driver_returncode"), int) or isinstance(
            observation.get("driver_returncode"), bool
        ):
            raise ValueError("ok observation driver return code is invalid")
        timed_wall = observation.get("timed_wall_duration_ns")
        if timed_wall is not None and not is_exact_int(timed_wall, minimum=1):
            raise ValueError("ok observation timed wall duration is invalid")
    elif status == "censored":
        if fields != _CENSORED_OBSERVATION_FIELDS:
            raise ValueError("censored observation fields are invalid")
        _validate_censorship(case, observation)
    elif status == "not_applicable":
        if fields != _NOT_APPLICABLE_FIELDS:
            raise ValueError("not-applicable observation fields are invalid")
        if implementation != "before" or not is_candidate_only(case):
            raise ValueError("not-applicable observation is not a declared candidate-only case")
        if observation.get("correct") is not None or not isinstance(observation.get("reason"), str):
            raise ValueError("not-applicable observation payload is invalid")
    else:
        if not _ERROR_REQUIRED_FIELDS <= fields or fields - _ERROR_REQUIRED_FIELDS - _ERROR_OPTIONAL_FIELDS:
            raise ValueError("error observation fields are invalid")
        if observation.get("correct") is not False or not isinstance(observation.get("error"), str):
            raise ValueError("error observation payload is invalid")

    identity = observation.get("comparison_identity")
    if uses_controlled_target(case) and status != "not_applicable":
        error = controlled_identity_error(f"{implementation} block {block}", identity)
        if error is not None:
            raise ValueError(error)
        if status == "ok":
            if implementation == "after":
                watchdog_error = candidate_watchdog_error(
                    f"candidate block {block}",
                    observation["metrics"],
                    candidate_watchdog_timeout_s=case.semantic_descriptor(profile)["candidate_watchdog_timeout_s"],
                    require_enforced=True,
                )
                if watchdog_error is not None:
                    raise ValueError(watchdog_error)
            timed_identity = observation["metrics"].get("operation_identity")
            error = operation_identity_error(
                f"{implementation} block {block} timed",
                timed_identity,
                expected_phase="timed",
            )
            if error is not None:
                raise ValueError(error)
            if timed_identity["target_identity_sha256"] != sha256_json(identity):
                raise ValueError(f"{implementation} block {block} timed target identity fingerprint differs")


_PREPARATION_FIELDS = {
    "imports_complete",
    "setup_complete",
    "warmups_complete",
    "validation_complete",
    "timed_statement_pending",
}


def _validate_preparation(preparation: Any) -> None:
    if not isinstance(preparation, dict) or set(preparation) != _PREPARATION_FIELDS:
        raise ValueError("historical preparation evidence fields are invalid")
    if any(preparation[field] is not True for field in _PREPARATION_FIELDS):
        raise ValueError("historical preparation evidence is incomplete")


def _validate_censorship(case: BenchmarkCase, observation: dict[str, Any]) -> None:
    if observation.get("implementation") != "before" or observation.get("correct") is not None:
        raise ValueError("censored observation identity is invalid")
    censorship = observation.get("censorship")
    if not isinstance(censorship, dict) or set(censorship) != {
        "phase",
        "reason",
        "timeout_seconds",
        "lower_bound_duration_ns",
    }:
        raise ValueError("censorship metadata fields are invalid")
    timeout_seconds = censorship["timeout_seconds"]
    if type(timeout_seconds) is not float or timeout_seconds != case.process_timeout_s:
        raise ValueError("censorship timeout does not match manifest process_timeout_s")
    if censorship["phase"] != "timed" or censorship["reason"] != "process_timeout":
        raise ValueError("censorship reason or phase is invalid")
    if censorship["lower_bound_duration_ns"] != timeout_duration_ns(case.process_timeout_s):
        raise ValueError("censorship lower bound is not exactly derived from the manifest timeout")
    if not is_exact_int(observation.get("wall_duration_ns"), minimum=1) or not is_exact_int(
        observation.get("timed_wall_duration_ns"), minimum=1
    ):
        raise ValueError("censored observation wall duration is invalid")
    if observation["timed_wall_duration_ns"] < censorship["lower_bound_duration_ns"]:
        raise ValueError("censored timed wall duration is below its lower bound")
    _validate_preparation(observation.get("preparation"))
    metrics = observation.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("censored observation metrics are invalid")
    if metrics.get("timed_phase_started") is not True:
        raise ValueError("censored observation does not prove timed phase start")
    for name in ("logical_bytes", "expected_count"):
        if not is_exact_int(observation.get(name)):
            raise ValueError(f"censored observation {name} is invalid")
    if uses_controlled_target(case):
        timed_operation = metrics.get("operation_identity")
        error = operation_identity_error("censored timed", timed_operation, expected_phase="timed")
        if error is not None:
            raise ValueError(error)
        if timed_operation["target_identity_sha256"] != sha256_json(observation.get("comparison_identity")):
            raise ValueError("censored timed target identity fingerprint differs")
        if requires_exact_preflight(case):
            preflight = metrics.get("preflight")
            if not isinstance(preflight, dict) or operation_continuity_key(timed_operation) != operation_continuity_key(
                preflight.get("operation_identity", {})
            ):
                raise ValueError("censored timed continuity differs from preflight")
    if not _optional_sha256(observation.get("expected_checksum")):
        raise ValueError("censored observation expected checksum is invalid")
    if not isinstance(observation.get("expected_historical_failure"), bool):
        raise ValueError("censored observation historical-failure flag is invalid")
    if not isinstance(observation.get("stdout"), str) or not isinstance(observation.get("stderr"), str):
        raise ValueError("censored observation captured streams are invalid")


def validate_historical_ready(
    case: BenchmarkCase,
    ready: dict[str, Any],
    *,
    profile: str,
    block: int,
    pair_order: str,
) -> None:
    expected_fields = _BASE_OBSERVATION_FIELDS | {
        "event",
        "comparison_identity",
        "logical_bytes",
        "expected_count",
        "expected_checksum",
        "expected_historical_failure",
        "preparation",
        "metrics",
    }
    if set(ready) != expected_fields or ready.get("event") != "historical_ready" or ready.get("status") != "ready":
        raise ValueError("historical ready record fields are invalid")
    _validate_common_observation_fields(
        case,
        ready,
        implementation="before",
        profile=profile,
        block=block,
        pair_order=pair_order,
    )
    _validate_preparation(ready.get("preparation"))
    if uses_controlled_target(case):
        error = controlled_identity_error("historical ready", ready.get("comparison_identity"))
        if error is not None:
            raise ValueError(error)
        timed_identity = ready.get("metrics", {}).get("operation_identity")
        error = operation_identity_error("historical ready timed", timed_identity, expected_phase="timed")
        if error is not None:
            raise ValueError(error)
        if timed_identity["target_identity_sha256"] != sha256_json(ready.get("comparison_identity")):
            raise ValueError("historical ready timed target identity fingerprint differs")
    if not is_exact_int(ready.get("logical_bytes")) or not is_exact_int(ready.get("expected_count")):
        raise ValueError("historical ready expected counts are invalid")
    if not _optional_sha256(ready.get("expected_checksum")):
        raise ValueError("historical ready expected checksum is invalid")
    if not isinstance(ready.get("expected_historical_failure"), bool) or not isinstance(ready.get("metrics"), dict):
        raise ValueError("historical ready provenance fields are invalid")
    pseudo = {
        "block": block,
        "status": "censored",
        "comparison_identity": ready["comparison_identity"],
        "metrics": ready["metrics"],
    }
    if requires_exact_preflight(case):
        error = _single_preflight_error(case, "historical", pseudo)
        if error is not None:
            raise ValueError(error)
    if case.kind == "section_filter_warm":
        error = _single_setup_error(case, "historical", pseudo)
        if error is not None:
            raise ValueError(error)


def validate_historical_timed_start(
    case: BenchmarkCase,
    timed_start: dict[str, Any],
    ready: dict[str, Any],
    *,
    profile: str,
    block: int,
    pair_order: str,
) -> None:
    expected = {
        **ready,
        "event": "historical_timed_start",
        "metrics": {**ready["metrics"], "timed_phase_started": True},
    }
    if timed_start != expected:
        raise ValueError("historical timed-start proof differs from validated readiness")
    _validate_common_observation_fields(
        case,
        timed_start,
        implementation="before",
        profile=profile,
        block=block,
        pair_order=pair_order,
    )


def _validate_artifact_pair(before: dict[str, Any], after: dict[str, Any]) -> None:
    observation_matrices: dict[str, dict[tuple[str, int], str]] = {}
    expected_versions = {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
    }
    for name, artifact, expected_implementation in (("before", before, "before"), ("after", after, "after")):
        if not isinstance(artifact, dict) or not isinstance(artifact.get("metadata"), dict):
            raise ValueError(f"{name} artifact is missing metadata")
        metadata = artifact["metadata"]
        if metadata.get("implementation") != expected_implementation:
            raise ValueError(f"{name} artifact implementation identity is invalid")
        for field, supported in expected_versions.items():
            if metadata.get(field) != supported:
                raise ValueError(f"{name} artifact uses unsupported {field}")

        profile = metadata.get("profile")
        if profile not in {"smoke", "release"}:
            raise ValueError(f"{name} artifact profile is invalid")
        observations = artifact.get("observations")
        if not isinstance(observations, list):
            raise ValueError(f"{name} artifact is missing observations")
        runner = metadata.get("runner")
        if not isinstance(runner, dict):
            raise ValueError(f"{name} artifact is missing runner metadata")
        for field, supported in expected_versions.items():
            if runner.get(field) != supported:
                raise ValueError(f"{name} runner uses unsupported {field}")
        watchdog_floor = runner.get("candidate_watchdog_floor_s")
        if type(watchdog_floor) is not float or watchdog_floor != CANDIDATE_WATCHDOG_FLOOR_S:
            raise ValueError(f"{name} runner candidate watchdog policy is unsupported")
        if runner.get("pairing") != PAIRING_PROTOCOL:
            raise ValueError(f"{name} runner pairing protocol is unsupported")
        if runner.get("driver") != DRIVER_PROTOCOL:
            raise ValueError(f"{name} runner driver protocol is unsupported")
        if not isinstance(runner.get("tooling_git"), dict):
            raise ValueError(f"{name} runner is missing tooling Git identity")

        blocks = runner.get("blocks")
        if isinstance(blocks, bool) or not isinstance(blocks, int) or blocks < 1:
            raise ValueError(f"{name} artifact declares an invalid block count")
        selected = runner.get("case_ids")
        if (
            not isinstance(selected, list)
            or not selected
            or any(not isinstance(case_id, str) or not case_id for case_id in selected)
        ):
            raise ValueError(f"{name} artifact declares an invalid selected case set")
        if len(selected) != len(set(selected)):
            raise ValueError(f"{name} artifact declares duplicate selected cases")
        unknown = [case_id for case_id in selected if case_id not in CASE_BY_ID]
        if unknown:
            raise ValueError(f"{name} artifact declares an unknown selected case")
        candidate_only = runner.get("candidate_only_case_ids")
        expected_candidate_only = [case_id for case_id in selected if is_candidate_only(CASE_BY_ID[case_id])]
        if candidate_only != expected_candidate_only:
            raise ValueError(f"{name} artifact candidate-only declaration is invalid")

        matrix: dict[tuple[str, int], str] = {}
        for observation in observations:
            if not isinstance(observation, dict):
                raise ValueError(f"{name} artifact contains a non-object observation")
            if observation.get("implementation") != expected_implementation:
                raise ValueError(f"{name} observation implementation identity is invalid")
            case_id = observation.get("case_id")
            if case_id not in selected:
                raise ValueError(f"{name} observation is outside the selected case set")
            if observation.get("profile") != profile:
                raise ValueError(f"{name} observation profile differs from artifact metadata")
            block = observation.get("block")
            if isinstance(block, bool) or not isinstance(block, int) or not 0 <= block < blocks:
                raise ValueError(f"{name} observation block is outside the declared matrix")
            pair_order = observation.get("pair_order")
            expected_order = pair_order_label(case_id, block)
            if pair_order != expected_order:
                raise ValueError(f"{name} observation pair order differs from deterministic protocol")
            validate_paired_observation(
                CASE_BY_ID[case_id],
                observation,
                implementation=expected_implementation,
                profile=profile,
                block=block,
                pair_order=expected_order,
            )
            key = (case_id, block)
            if key in matrix:
                raise ValueError(f"{name} artifact contains a duplicate case/block observation")
            matrix[key] = pair_order

        expected_matrix = {(case_id, block) for case_id in selected for block in range(blocks)}
        if set(matrix) != expected_matrix:
            raise ValueError(f"{name} artifact observation matrix is incomplete")
        observation_matrices[name] = matrix

    if before["metadata"].get("profile") != after["metadata"].get("profile"):
        raise ValueError("benchmark profiles differ")

    before_python = before["metadata"].get("python", {})
    after_python = after["metadata"].get("python", {})
    for field in ("implementation", "version", "bitness"):
        if before_python.get(field) != after_python.get(field):
            raise ValueError(f"Python {field} differs between paired artifacts")
    before_os = before["metadata"].get("os", {})
    after_os = after["metadata"].get("os", {})
    for field in ("system", "release", "version", "machine"):
        if before_os.get(field) != after_os.get(field):
            raise ValueError(f"OS {field} differs between paired artifacts")
    for field in ("packages", "cpu", "execution_policy"):
        if before["metadata"].get(field) != after["metadata"].get(field):
            raise ValueError(f"environment {field} differs between paired artifacts")
    before_runner = before["metadata"]["runner"]
    after_runner = after["metadata"]["runner"]
    for field in (
        "blocks",
        "case_ids",
        "candidate_only_case_ids",
        "pairing",
        "driver",
        "candidate_watchdog_floor_s",
        "benchmark_schema_version",
        "manifest_version",
        "corpus_version",
        "tooling_git",
    ):
        if before_runner.get(field) != after_runner.get(field):
            raise ValueError(f"runner {field} differs between paired artifacts")
    if observation_matrices["before"] != observation_matrices["after"]:
        raise ValueError("paired observation order mismatch")


def _group_observations(observations: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        case_id = observation.get("case_id")
        if isinstance(case_id, str):
            grouped[case_id].append(observation)
    return grouped


def _compare_case(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> dict[str, Any]:
    notes: list[str] = []
    if not before or not after:
        return _empty_row(case, "missing", ["one or both implementation artifacts are missing"])

    before_blocks = [item.get("block") for item in before]
    after_blocks = [item.get("block") for item in after]
    if len(before_blocks) != len(set(before_blocks)) or len(after_blocks) != len(set(after_blocks)):
        return _empty_row(case, "invalid", ["duplicate observation block"], blocking=True)
    before_orders = {item.get("block"): item.get("pair_order") for item in before}
    after_orders = {item.get("block"): item.get("pair_order") for item in after}
    for block in before_orders.keys() & after_orders.keys():
        if before_orders[block] != after_orders[block]:
            return _empty_row(case, "invalid", ["paired observation order mismatch"], blocking=True)

    fingerprint_payloads = {
        json.dumps(item.get("semantic_fingerprint_payload"), sort_keys=True, separators=(",", ":"))
        for item in [*before, *after]
        if item.get("status") != "not_applicable"
    }
    if len(fingerprint_payloads) != 1:
        return _empty_row(case, "invalid", ["semantic comparison fingerprint payload mismatch"], blocking=True)

    identity_error = _comparison_identity_error(case, before, after)
    if identity_error is not None:
        return _empty_row(case, "invalid", [identity_error], blocking=True)

    preflight_error = _preflight_validation_error(case, before, after)
    if preflight_error is not None:
        return _empty_row(case, "invalid", [preflight_error], blocking=True)

    timed_read_error = _timed_read_validation_error(case, before, after)
    if timed_read_error is not None:
        return _empty_row(case, "invalid", [timed_read_error], blocking=True)

    timeout_control_error = _timeout_control_validation_error(case, before, after)
    if timeout_control_error is not None:
        return _empty_row(case, "invalid", [timeout_control_error], blocking=True)

    expected_strategy_error = _expected_strategy_validation_error(case, after)
    if expected_strategy_error is not None:
        return _empty_row(case, "invalid", [expected_strategy_error], blocking=True)

    warm_setup_error = _warm_setup_validation_error(case, before, after)
    if warm_setup_error is not None:
        return _empty_row(case, "invalid", [warm_setup_error], blocking=True)

    correctness_error = _timed_correctness_validation_error(case, before, after)
    if correctness_error is not None:
        return _empty_row(case, "invalid", [correctness_error], blocking=True)

    before_ok = [item for item in before if item.get("status") == "ok"]
    after_ok = [item for item in after if item.get("status") == "ok"]
    before_censored = [item for item in before if item.get("status") == "censored"]
    before_not_applicable = [item for item in before if item.get("status") == "not_applicable"]
    before_failures = [item for item in before if item.get("status") not in {"ok", "censored", "not_applicable"}]
    after_failures = [item for item in after if item.get("status") != "ok"]

    expected_historical_failures = [
        item
        for item in before_ok
        if item.get("correct") is not True
        and item.get("expected_historical_failure") is True
        and case.comparison_class == "new_capability"
    ]
    historical_incorrect = [
        item for item in before_ok if item.get("correct") is not True and item not in expected_historical_failures
    ]
    candidate_incorrect = [item for item in after_ok if item.get("correct") is not True]
    blocking = bool(before_failures or after_failures or historical_incorrect or candidate_incorrect)
    if before_failures:
        notes.append(f"{len(before_failures)} historical observations failed")
    if historical_incorrect:
        notes.append(f"{len(historical_incorrect)} historical observations failed correctness")
    if expected_historical_failures:
        notes.append(
            f"{len(expected_historical_failures)} historical observations demonstrate the declared capability gap"
        )
    if before_censored:
        notes.append(f"{len(before_censored)} historical observations were censored")
    if before_not_applicable:
        notes.append(f"{len(before_not_applicable)} historical observations were not applicable")
    if after_failures:
        notes.append(f"{len(after_failures)} candidate observations failed or were censored")
    if candidate_incorrect:
        notes.append("candidate correctness check failed")

    paired_ratios: list[float] = []
    before_by_block = {int(item["block"]): item for item in before_ok if item.get("duration_ns", 0) > 0}
    after_by_block = {int(item["block"]): item for item in after_ok if item.get("duration_ns", 0) > 0}
    if case.comparison_class != "new_capability":
        for block in sorted(before_by_block.keys() & after_by_block.keys()):
            paired_ratios.append(before_by_block[block]["duration_ns"] / after_by_block[block]["duration_ns"])

    censored_bounds: list[float] = []
    censored_by_block = {int(item["block"]): item for item in before_censored}
    for block in sorted(censored_by_block.keys() & after_by_block.keys()):
        lower_bound = censored_by_block[block]["censorship"]["lower_bound_duration_ns"]
        if lower_bound and after_by_block[block]["duration_ns"] > 0:
            censored_bounds.append(lower_bound / after_by_block[block]["duration_ns"])

    ci_low, ci_high = bootstrap_median_interval(
        paired_ratios,
        seed=int.from_bytes(hashlib.sha256(case.case_id.encode()).digest()[:8], "little"),
    )
    before_summary = _implementation_summary(before_ok)
    after_summary = _implementation_summary(after_ok)
    read_reduction = _reduction(
        before_summary["physical_bytes_read"]["median"],
        after_summary["physical_bytes_read"]["median"],
    )

    performance_regression = False
    if case.comparison_class == "apples_to_apples" and paired_ratios:
        median_speedup = statistics.median(paired_ratios)
        if median_speedup < 1 / 1.15:
            performance_regression = True
            notes.append("candidate median latency regressed by more than 15 percent")
    status = "censored" if before_censored and not before_ok else "ok"
    if before_not_applicable and not before_ok and not before_censored:
        status = "candidate_only" if after_ok else "not_applicable"
    if before_failures or after_failures or historical_incorrect or candidate_incorrect:
        status = "partial"
    if not before_ok and not before_censored and not before_not_applicable:
        status = "invalid"

    return {
        "case_id": case.case_id,
        "group": case.group,
        "layer": case.layer,
        "tier": case.tier,
        "headline": case.headline,
        "comparison_class": case.comparison_class,
        "primary_metric": case.primary_metric,
        "status": status,
        "before": before_summary,
        "after": after_summary,
        "paired_speedup": {
            "count": len(paired_ratios),
            "median": statistics.median(paired_ratios) if paired_ratios else None,
            "ci_low": ci_low,
            "ci_high": ci_high,
        },
        "censored_speedup_lower_bound": min(censored_bounds) if censored_bounds else None,
        "read_reduction_fraction": read_reduction,
        "allocation_reduction_fraction": _reduction(
            before_summary["peak_python_bytes"]["median"],
            after_summary["peak_python_bytes"]["median"],
        ),
        "reader_utilization": None,
        "performance_regression": performance_regression,
        "blocking": blocking,
        "notes": notes,
        "before_status_counts": _status_counts(before),
        "after_status_counts": _status_counts(after),
    }


def _comparison_identity_error(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str | None:
    identities: dict[str, set[str]] = {}
    strict = requires_exact_preflight(case) or case.kind == "section_filter_warm"
    for implementation, observations in (("historical", before), ("candidate", after)):
        values: set[str] = set()
        for observation in observations:
            if observation.get("status") == "not_applicable":
                continue
            identity = observation.get("comparison_identity")
            if identity is None:
                if strict:
                    return f"{implementation} block {observation.get('block')} is missing comparison identity"
                continue
            if not isinstance(identity, dict) or not identity:
                return f"{implementation} block {observation.get('block')} has invalid comparison identity"
            if strict:
                expected_count = identity.get("expected_count")
                expected_relative_checksum = identity.get("expected_relative_checksum")
                if (
                    not is_exact_int(expected_count)
                    or not isinstance(expected_relative_checksum, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", expected_relative_checksum)
                ):
                    return f"{implementation} block {observation.get('block')} comparison expectation is invalid"
            values.add(json.dumps(identity, sort_keys=True, separators=(",", ":")))
        if len(values) > 1:
            return f"{implementation} comparison identity changed between blocks"
        identities[implementation] = values
    if identities["historical"] and identities["candidate"] and identities["historical"] != identities["candidate"]:
        return "corpus or target fixture identity mismatch"
    if strict and not is_candidate_only(case) and not identities["historical"]:
        return "historical comparison identity is missing"
    if strict and not identities["candidate"]:
        return "candidate comparison identity is missing"
    return None


def _single_preflight_error(
    case: BenchmarkCase,
    implementation: str,
    observation: dict[str, Any],
) -> str | None:
    block = observation.get("block")
    metrics = observation.get("metrics")
    if not isinstance(metrics, dict):
        return f"{implementation} block {block} is missing preflight metrics"
    preflight = metrics.get("preflight")
    if not isinstance(preflight, dict):
        return f"{implementation} block {block} is missing exact-address preflight evidence"
    for field, expected in preflight_protocol(case.kind).items():
        if preflight.get(field) != expected:
            return f"{implementation} block {block} preflight protocol field {field} differs"
    identity = observation.get("comparison_identity")
    if preflight.get("comparison_identity") != identity:
        return f"{implementation} block {block} preflight comparison identity differs"
    operation = preflight.get("operation_identity")
    error = operation_identity_error(f"{implementation} block {block} preflight", operation, expected_phase="preflight")
    if error is not None:
        return error
    if operation["target_identity_sha256"] != sha256_json(identity):
        return f"{implementation} block {block} preflight target identity fingerprint differs"
    addresses = preflight.get("addresses")
    if not isinstance(addresses, list) or any(not is_exact_int(address) for address in addresses):
        return f"{implementation} block {block} preflight addresses are invalid"
    checksum = address_checksum(addresses)
    if preflight.get("address_checksum") != checksum:
        return f"{implementation} block {block} preflight address checksum is invalid"
    address_base = preflight.get("address_base")
    relative = preflight.get("relative_addresses")
    if (
        not is_exact_int(address_base)
        or not isinstance(relative, list)
        or any(not is_exact_int(address) for address in relative)
    ):
        return f"{implementation} block {block} preflight relative addresses are invalid"
    if relative != [address - address_base for address in addresses]:
        return f"{implementation} block {block} preflight absolute and relative addresses differ"
    relative_checksum = address_checksum(relative)
    if preflight.get("relative_address_checksum") != relative_checksum:
        return f"{implementation} block {block} preflight relative address checksum is invalid"
    expected_addresses = preflight.get("expected_addresses")
    expected_count = preflight.get("expected_count")
    expected_checksum = preflight.get("expected_checksum")
    expected_relative_checksum = preflight.get("expected_relative_checksum")
    if (
        not isinstance(expected_addresses, list)
        or any(not is_exact_int(address) for address in expected_addresses)
        or not is_exact_int(expected_count)
        or expected_count != len(expected_addresses)
        or not _sha256_value(expected_checksum)
        or expected_checksum != address_checksum(expected_addresses)
        or not _sha256_value(expected_relative_checksum)
    ):
        return f"{implementation} block {block} preflight expectation is invalid"
    correct = preflight.get("correct")
    if not isinstance(correct, bool):
        return f"{implementation} block {block} preflight correctness is not boolean"
    if (
        expected_count != identity["expected_count"]
        or expected_relative_checksum != identity["expected_relative_checksum"]
    ):
        return f"{implementation} block {block} preflight comparison expectation differs"
    if correct:
        if (
            len(addresses) != expected_count
            or checksum != expected_checksum
            or relative_checksum != expected_relative_checksum
        ):
            return f"{implementation} block {block} preflight result differs from expectation"
    elif not (
        implementation == "historical"
        and preflight.get("expected_historical_failure") is True
        and case.comparison_class == "new_capability"
        and bool(case.parameters.get("historical_expected_failure"))
    ):
        return f"{implementation} block {block} preflight result is incorrect"
    read_error = read_evidence_error(f"{implementation} block {block} preflight", preflight.get("read"))
    if read_error is not None:
        return read_error
    if not is_exact_int(preflight.get("logical_scanned_region_count")):
        return f"{implementation} block {block} preflight logical region count is invalid"
    return None


def _preflight_validation_error(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str | None:
    if not requires_exact_preflight(case):
        return None
    sides = (("historical", before, is_candidate_only(case)), ("candidate", after, False))
    for implementation, observations, not_applicable in sides:
        if not_applicable:
            continue
        for observation in observations:
            error = _single_preflight_error(case, implementation, observation)
            if error is not None:
                return error
    return None


def _timed_read_validation_error(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str | None:
    if not requires_exact_preflight(case) and case.kind not in {"cursor", "batch"}:
        return None
    sides = (("historical", before, is_candidate_only(case)), ("candidate", after, False))
    for implementation, observations, not_applicable in sides:
        if not_applicable:
            continue
        for observation in observations:
            if observation.get("status") != "ok":
                continue
            block = observation.get("block")
            metrics = observation.get("metrics")
            timed_operation = metrics.get("operation_identity") if isinstance(metrics, dict) else None
            error = operation_identity_error(
                f"{implementation} block {block} timed",
                timed_operation,
                expected_phase="timed",
            )
            if error is not None:
                return error
            if timed_operation["target_identity_sha256"] != sha256_json(observation.get("comparison_identity")):
                return f"{implementation} block {block} timed target identity fingerprint differs"
            if requires_exact_preflight(case):
                preflight = metrics.get("preflight")
                if not isinstance(preflight, dict) or operation_continuity_key(
                    timed_operation
                ) != operation_continuity_key(preflight.get("operation_identity", {})):
                    return f"{implementation} block {block} timed continuity differs from preflight"
            error = read_evidence_error(f"{implementation} block {block} timed", metrics)
            if error is not None:
                return error
            if not is_exact_int(metrics.get("logical_scanned_region_count")):
                return f"{implementation} block {block} timed logical region count is invalid"
    return None


def _timeout_control_validation_error(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str | None:
    if case.kind not in {"timeout", "chunk_timeout"}:
        return None
    sides = (("historical", before, is_candidate_only(case)), ("candidate", after, False))
    for implementation, observations, not_applicable in sides:
        if not_applicable:
            continue
        for observation in observations:
            block = observation.get("block")
            if observation.get("status") != "ok":
                return f"{implementation} block {block} timeout control did not complete"
            error = timeout_control_error(
                f"{implementation} block {block}",
                duration_ns=observation.get("duration_ns"),
                termination=observation.get("termination"),
                metrics=observation.get("metrics"),
                timeout_ms=case.timeout_ms,
                process_timeout_s=case.process_timeout_s,
                require_control_polls=implementation == "candidate",
                require_timeout_hit=implementation == "historical",
                candidate_watchdog_timeout_s=(
                    case.semantic_descriptor(observation["profile"])["candidate_watchdog_timeout_s"]
                    if implementation == "candidate"
                    else None
                ),
                require_candidate_watchdog_enforced=implementation == "candidate",
            )
            if error is not None:
                return error
    return None


def _expected_strategy_validation_error(case: BenchmarkCase, after: list[dict[str, Any]]) -> str | None:
    if case.expected_strategy is None:
        return None
    for observation in after:
        if observation.get("status") != "ok":
            continue
        metrics = observation.get("metrics")
        strategies = metrics.get("strategy_counts") if isinstance(metrics, dict) else None
        units = metrics.get("span_count", metrics.get("matcher_invocations", 1)) if isinstance(metrics, dict) else None
        if not is_exact_int(units, minimum=1):
            return f"candidate block {observation.get('block')} has invalid strategy observation units"
        expected_map = {case.expected_strategy: units}
        if strategies != expected_map:
            return f"candidate block {observation.get('block')} strategy map differs from {expected_map}"
    return None


def _retained_values(case: BenchmarkCase, values: list[int]) -> list[int]:
    if case.mode == "first":
        return values[:1]
    if case.mode == "addresses":
        return values[: case.limit or case.max_matches or 50]
    return values[: case.max_matches or len(values)]


def _expected_termination(case: BenchmarkCase, full_count: int, retained_count: int) -> str:
    if case.mode == "first" and retained_count:
        return "first_hit"
    if case.max_matches is not None and full_count >= case.max_matches:
        return "match_limit"
    if case.mode == "addresses" and retained_count >= (case.limit or 50):
        return "page_limit"
    return "scope_exhausted"


def _timed_correctness_validation_error(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str | None:
    for implementation, observations in (("historical", before), ("candidate", after)):
        if implementation == "historical" and is_candidate_only(case):
            continue
        for observation in observations:
            if observation.get("status") != "ok":
                continue
            block = observation.get("block")
            actual_count = observation.get("actual_count")
            expected_count = observation.get("expected_count")
            actual_checksum = observation.get("actual_checksum")
            expected_checksum = observation.get("expected_checksum")
            metrics = observation.get("metrics")
            if isinstance(metrics, dict):
                for field, value in (("actual_count", actual_count), ("expected_count", expected_count)):
                    metric_value = metrics.get(field)
                    if metric_value is not None and metric_value != value:
                        return f"{implementation} block {block} timed {field} differs between fields"
            derived_correct = actual_count == expected_count
            expected_historical_failure = observation.get("expected_historical_failure") is True
            if requires_exact_preflight(case):
                preflight = metrics["preflight"]
                full_addresses = preflight["expected_addresses"]
                retained_addresses = _retained_values(case, full_addresses)
                derived_expected_count = len(retained_addresses)
                derived_expected_checksum = None if case.mode == "count" else address_checksum(retained_addresses)
                if expected_count != derived_expected_count:
                    return f"{implementation} block {block} timed expected count differs from preflight"
                if expected_checksum != derived_expected_checksum:
                    return f"{implementation} block {block} timed expected checksum differs from preflight"
                if case.mode == "count":
                    if actual_checksum is not None:
                        return f"{implementation} block {block} count mode must not report an actual checksum"
                else:
                    derived_correct = derived_correct and actual_checksum == derived_expected_checksum
                expected_termination = _expected_termination(case, len(full_addresses), len(retained_addresses))
                if observation.get("termination") != expected_termination:
                    derived_correct = False
            elif expected_checksum is not None or actual_checksum is not None:
                derived_correct = derived_correct and actual_checksum == expected_checksum

            allowed_gap = (
                implementation == "historical"
                and expected_historical_failure
                and case.comparison_class == "new_capability"
                and bool(case.parameters.get("historical_expected_failure"))
            )
            if observation.get("correct") != derived_correct:
                return f"{implementation} block {block} timed correctness flag differs from exact fields"
            if not derived_correct and not allowed_gap:
                return f"{implementation} block {block} timed result differs from expectation"
    return None


def _single_setup_error(
    case: BenchmarkCase,
    implementation: str,
    observation: dict[str, Any],
) -> str | None:
    block = observation.get("block")
    metrics = observation.get("metrics")
    setup = metrics.get("setup") if isinstance(metrics, dict) else None
    if not isinstance(setup, dict):
        return f"{implementation} block {block} is missing warm setup evidence"
    for field, expected in case.setup_protocol.items():
        if setup.get(field) != expected:
            return f"{implementation} block {block} warm setup protocol field {field} differs"
    state_key = "historical_state" if implementation == "historical" else "candidate_state"
    if setup.get("implementation_state") != case.setup_protocol[state_key]:
        return f"{implementation} block {block} warm setup implementation state differs"
    if setup.get("correct") is not True:
        return f"{implementation} block {block} warm setup did not produce the expected result"
    identity = observation.get("comparison_identity")
    if setup.get("comparison_identity") != identity:
        return f"{implementation} block {block} warm setup comparison identity differs"
    setup_operation = setup.get("operation_identity")
    error = operation_identity_error(
        f"{implementation} block {block} warm setup",
        setup_operation,
        expected_phase="setup",
    )
    if error is not None:
        return error
    if setup_operation["target_identity_sha256"] != sha256_json(identity):
        return f"{implementation} block {block} warm setup target identity fingerprint differs"
    if not is_exact_int(setup.get("actual_count")) or not is_exact_int(setup.get("expected_count")):
        return f"{implementation} block {block} warm setup count evidence is invalid"
    if setup["actual_count"] != setup["expected_count"]:
        return f"{implementation} block {block} warm setup count differs from expectation"
    preflight = metrics.get("preflight")
    if not isinstance(preflight, dict) or setup["expected_count"] != preflight.get("expected_count"):
        return f"{implementation} block {block} warm setup expectation differs from preflight"
    if operation_continuity_key(setup_operation) != operation_continuity_key(preflight["operation_identity"]):
        return f"{implementation} block {block} warm setup continuity differs from preflight"
    if setup_operation.get("cache_token") is None:
        return f"{implementation} block {block} warm setup cache token is missing"
    read_error = read_evidence_error(f"{implementation} block {block} warm setup", setup.get("read"))
    if read_error is not None:
        return read_error
    if not is_exact_int(setup.get("logical_scanned_region_count")):
        return f"{implementation} block {block} warm setup logical region count is invalid"
    return None


def _warm_setup_validation_error(
    case: BenchmarkCase,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str | None:
    if case.kind != "section_filter_warm":
        return None

    for implementation, observations in (("historical", before), ("candidate", after)):
        for observation in observations:
            error = _single_setup_error(case, implementation, observation)
            if error is not None:
                return error

    section_name = case.parameters.get("section")
    for implementation, observations in (("historical", before), ("candidate", after)):
        for observation in observations:
            metrics = observation["metrics"]
            setup = metrics["setup"]
            timed_operation = metrics.get("operation_identity")
            error = operation_identity_error(
                f"{implementation} block {observation.get('block')} warm timed",
                timed_operation,
                expected_phase="timed",
            )
            if error is not None:
                return error
            if operation_continuity_key(timed_operation) != operation_continuity_key(setup["operation_identity"]):
                return f"{implementation} block {observation.get('block')} warm timed continuity differs from setup"
            if timed_operation.get("cache_token") != setup["operation_identity"].get("cache_token"):
                return (
                    f"{implementation} block {observation.get('block')} warm cache token differs "
                    "between setup and timed"
                )
            if observation.get("status") != "ok":
                continue
            setup_ranges = setup["read"]["physical_read_ranges"]
            timed_ranges = metrics["physical_read_ranges"]
            if not setup_ranges or not timed_ranges or setup_ranges[-1] != timed_ranges[-1]:
                return (
                    f"{implementation} block {observation.get('block')} warm setup final corpus range "
                    "differs from timed"
                )

    for observation in after:
        if observation.get("status") != "ok":
            continue
        block = observation.get("block")
        metrics = observation["metrics"]
        setup = metrics["setup"]
        unique_bytes = metrics.get("unique_bytes_examined")
        if not is_exact_int(unique_bytes, minimum=1):
            return f"candidate block {block} warm timed scan has invalid examined-byte evidence"
        if metrics["physical_read_calls"] != 1:
            return f"candidate block {block} warm timed scan did not use exactly one physical read"
        if (
            metrics["physical_bytes_requested"] != unique_bytes
            or metrics["physical_bytes_read"] != unique_bytes
            or metrics["unique_logical_bytes"] != unique_bytes
            or metrics["physical_request_sizes"] != [unique_bytes]
            or metrics["physical_read_sizes"] != [unique_bytes]
        ):
            return f"candidate block {block} warm timed scan includes non-corpus reads"
        if metrics.get("sections") != [section_name]:
            return f"candidate block {block} warm timed scan selected unexpected sections"

        setup_read = setup["read"]
        if setup_read["physical_read_calls"] <= 1:
            return f"candidate block {block} warm setup did not perform cold metadata reads"
        if (
            setup_read["physical_bytes_requested"] <= unique_bytes
            or setup_read["physical_bytes_read"] <= unique_bytes
            or setup_read["physical_read_sizes"][-1] != unique_bytes
            or setup.get("unique_bytes_examined") != unique_bytes
            or setup.get("sections") != [section_name]
        ):
            return f"candidate block {block} warm setup did not prove cold metadata work"
    return None


_GIT_OID = re.compile(r"[0-9a-f]{40}")


def _git_release_reason(label: str, identity: Any) -> str | None:
    if not isinstance(identity, dict):
        return f"{label} Git identity is missing"
    if not isinstance(identity.get("commit"), str) or not _GIT_OID.fullmatch(identity["commit"]):
        return f"{label} Git commit identity is not exact"
    if not isinstance(identity.get("tree"), str) or not _GIT_OID.fullmatch(identity["tree"]):
        return f"{label} Git tree identity is not exact"
    if identity.get("dirty") is not False:
        return f"{label} Git tree is not clean"
    return None


def _release_eligibility(
    before: dict[str, Any],
    after: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    complete: bool,
    blocking: bool,
) -> dict[str, Any]:
    reasons: list[str] = []
    before_metadata = before["metadata"]
    after_metadata = after["metadata"]
    runner = before_metadata["runner"]
    full_case_ids = [case.case_id for case in CASES]
    if before_metadata["profile"] != "release":
        reasons.append("profile is not release")
    if runner["case_ids"] != full_case_ids:
        reasons.append("selected cases are not the exact full manifest order")
    if runner["blocks"] < 7:
        reasons.append("fewer than seven paired blocks were declared")
    git_identities = {
        "historical source": before_metadata.get("git"),
        "candidate source": after_metadata.get("git"),
        "tooling": runner.get("tooling_git"),
    }
    git_reasons = {label: _git_release_reason(label, identity) for label, identity in git_identities.items()}
    reasons.extend(reason for reason in git_reasons.values() if reason is not None)
    tooling = git_identities["tooling"]
    candidate_git = git_identities["candidate source"]
    if (
        git_reasons["tooling"] is None
        and git_reasons["candidate source"] is None
        and (tooling["commit"] != candidate_git["commit"] or tooling["tree"] != candidate_git["tree"])
    ):
        reasons.append("tooling Git identity does not match candidate source")
    if not complete:
        reasons.append("comparison rows are incomplete")
    if blocking:
        reasons.append("comparison contains blocking rows")

    expected_candidate_only = [case.case_id for case in CASES if is_candidate_only(case)]
    if runner["candidate_only_case_ids"] != expected_candidate_only:
        reasons.append("candidate-only declaration does not match the full manifest")
    rows_by_id = {row["case_id"]: row for row in rows}
    for case in CASES:
        row = rows_by_id.get(case.case_id)
        if row is None:
            continue
        if is_candidate_only(case):
            if row["status"] != "candidate_only":
                reasons.append(f"candidate-only case {case.case_id} has status {row['status']}")
        elif row["status"] in {"candidate_only", "not_applicable"}:
            reasons.append(f"paired case {case.case_id} is incorrectly candidate-only")
    return {"eligible": not reasons, "reasons": reasons}


def _implementation_summary(observations: list[dict[str, Any]]) -> dict[str, Any]:
    actual_checksums = {item.get("actual_checksum") for item in observations if item.get("actual_checksum") is not None}
    expected_checksums = {
        item.get("expected_checksum") for item in observations if item.get("expected_checksum") is not None
    }
    return {
        "duration_ns": summarize([item["duration_ns"] for item in observations if item.get("duration_ns") is not None]),
        "throughput_mib_s": summarize(
            [item["throughput_mib_s"] for item in observations if item.get("throughput_mib_s") is not None]
        ),
        "peak_python_bytes": summarize(
            [item["peak_python_bytes"] for item in observations if item.get("peak_python_bytes") is not None]
        ),
        "physical_bytes_read": summarize(
            [
                item.get("metrics", {}).get("physical_bytes_read")
                for item in observations
                if item.get("metrics", {}).get("physical_bytes_read") is not None
            ]
        ),
        "physical_read_calls": summarize(
            [
                item.get("metrics", {}).get("physical_read_calls")
                for item in observations
                if item.get("metrics", {}).get("physical_read_calls") is not None
            ]
        ),
        "timeout_overshoot_ns": summarize(
            [
                item.get("metrics", {}).get("timeout_overshoot_ns")
                for item in observations
                if item.get("metrics", {}).get("timeout_overshoot_ns") is not None
            ]
        ),
        "timed_out_count": sum(item.get("metrics", {}).get("timed_out") is True for item in observations),
        "correct_count": sum(item.get("correct") is True for item in observations),
        "observation_count": len(observations),
        "actual_checksum": next(iter(actual_checksums)) if len(actual_checksums) == 1 else None,
        "expected_checksum": next(iter(expected_checksums)) if len(expected_checksums) == 1 else None,
    }


def _empty_row(
    case: BenchmarkCase,
    status: str,
    notes: list[str],
    *,
    blocking: bool = False,
) -> dict[str, Any]:
    empty = _implementation_summary([])
    return {
        "case_id": case.case_id,
        "group": case.group,
        "layer": case.layer,
        "tier": case.tier,
        "headline": case.headline,
        "comparison_class": case.comparison_class,
        "primary_metric": case.primary_metric,
        "status": status,
        "before": empty,
        "after": empty,
        "paired_speedup": {"count": 0, "median": None, "ci_low": None, "ci_high": None},
        "censored_speedup_lower_bound": None,
        "read_reduction_fraction": None,
        "allocation_reduction_fraction": None,
        "reader_utilization": None,
        "performance_regression": False,
        "blocking": blocking,
        "notes": notes,
        "before_status_counts": {},
        "after_status_counts": {},
    }


def _status_counts(observations: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for observation in observations:
        status = str(observation.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return counts


def _reduction(before: float | int | None, after: float | int | None) -> float | None:
    if before is None or after is None or before == 0:
        return None
    return 1 - float(after) / float(before)


def _chunk_recommendation(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    baseline_size = 128 * 1024
    by_kind_and_size: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        case = CASE_BY_ID[row["case_id"]]
        if case.kind not in {"chunk_sweep", "chunk_salvage", "chunk_timeout"}:
            continue
        by_kind_and_size[(case.kind, int(case.parameters["chunk_size"]))] = row

    sizes = sorted(chunk_size for kind, chunk_size in by_kind_and_size if kind == "chunk_sweep")
    if not sizes:
        return None

    measurements: list[dict[str, Any]] = []
    for chunk_size in sizes:
        throughput_row = by_kind_and_size.get(("chunk_sweep", chunk_size))
        salvage_row = by_kind_and_size.get(("chunk_salvage", chunk_size))
        timeout_row = by_kind_and_size.get(("chunk_timeout", chunk_size))
        throughput = None if throughput_row is None else throughput_row["after"]["throughput_mib_s"]["median"]
        salvage_p95 = None if salvage_row is None else salvage_row["after"]["duration_ns"]["p95"]
        timeout_p95 = None if timeout_row is None else timeout_row["after"]["timeout_overshoot_ns"]["p95"]
        rows_present = throughput_row is not None and salvage_row is not None and timeout_row is not None
        correct = rows_present and all(
            not row["blocking"]
            and row["status"] in {"ok", "candidate_only"}
            and row["after"]["observation_count"] > 0
            and row["after"]["correct_count"] == row["after"]["observation_count"]
            for row in (throughput_row, salvage_row, timeout_row)
        )
        timeout_observed = bool(
            timeout_row is not None
            and timeout_row["after"]["timed_out_count"] == timeout_row["after"]["observation_count"]
        )
        measurements.append(
            {
                "case_id": None if throughput_row is None else throughput_row["case_id"],
                "chunk_size": chunk_size,
                "throughput_mib_s": throughput,
                "salvage_p95_ns": salvage_p95,
                "timeout_overshoot_p95_ns": timeout_p95,
                "correct": correct,
                "timeout_observed": timeout_observed,
            }
        )

    baseline = next((item for item in measurements if item["chunk_size"] == baseline_size), None)
    valid_throughputs = [
        float(item["throughput_mib_s"])
        for item in measurements
        if item["correct"] and item["throughput_mib_s"] is not None
    ]
    if baseline is None or not baseline["correct"] or not valid_throughputs:
        return {
            "policy": _CHUNK_POLICY,
            "status": "inconclusive",
            "selected_chunk_size": None,
            "selected_case_id": None,
            "measurements": measurements,
            "reason": "the complete correct 128 KiB control matrix is unavailable",
        }

    best = max(valid_throughputs)
    throughput_floor = best * 0.9
    baseline_salvage = baseline["salvage_p95_ns"]
    baseline_timeout = baseline["timeout_overshoot_p95_ns"]
    if baseline_salvage is None or baseline_timeout is None or not baseline["timeout_observed"]:
        return {
            "policy": _CHUNK_POLICY,
            "status": "inconclusive",
            "selected_chunk_size": None,
            "selected_case_id": None,
            "measurements": measurements,
            "reason": "the 128 KiB latency controls are incomplete",
        }
    salvage_ceiling = float(baseline_salvage) * 1.10
    timeout_ceiling = max(25_000_000.0, float(baseline_timeout) * 1.10)
    for item in measurements:
        item["controls_valid"] = bool(
            item["correct"]
            and item["timeout_observed"]
            and item["throughput_mib_s"] is not None
            and item["salvage_p95_ns"] is not None
            and item["timeout_overshoot_p95_ns"] is not None
            and float(item["throughput_mib_s"]) >= throughput_floor
            and float(item["salvage_p95_ns"]) <= salvage_ceiling
            and float(item["timeout_overshoot_p95_ns"]) <= timeout_ceiling
        )
    eligible = [item for item in measurements if item["controls_valid"]]
    selected = min(eligible, key=lambda item: int(item["chunk_size"])) if eligible else None
    return {
        "policy": _CHUNK_POLICY,
        "status": "selected" if selected is not None else "inconclusive",
        "best_throughput_mib_s": best,
        "threshold_throughput_mib_s": throughput_floor,
        "salvage_ceiling_ns": salvage_ceiling,
        "timeout_overshoot_ceiling_ns": timeout_ceiling,
        "selected_chunk_size": None if selected is None else selected["chunk_size"],
        "selected_case_id": None if selected is None else selected["case_id"],
        "measurements": measurements,
        "reason": None if selected is not None else "no chunk satisfied every throughput, salvage, and timeout control",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    arguments = parser.parse_args(argv)

    comparison = compare_artifacts(read_json(arguments.before), read_json(arguments.after))
    write_json(arguments.output_json, comparison)
    write_csv(arguments.output_csv, comparison_csv_rows(comparison), CSV_FIELDS)
    return 1 if comparison["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
