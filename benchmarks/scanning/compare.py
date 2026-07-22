"""Validate paired raw artifacts and produce complete per-case comparisons."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from benchmarks.scanning.common import (
    bootstrap_median_interval,
    read_json,
    summarize,
    write_csv,
    write_json,
)
from benchmarks.scanning.manifest import CASE_BY_ID, BenchmarkCase

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
    return {
        "schema_version": 1,
        "profile": before["metadata"]["profile"],
        "before_environment": before["metadata"],
        "after_environment": after["metadata"],
        "compatible": True,
        "complete": all(row["status"] not in incomplete_statuses for row in rows),
        "blocking": bool(blocking_rows),
        "blocking_cases": blocking_rows,
        "chunk_recommendation": _chunk_recommendation(rows),
        "rows": rows,
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


def _validate_artifact_pair(before: dict[str, Any], after: dict[str, Any]) -> None:
    observation_matrices: dict[str, dict[tuple[str, int], str]] = {}
    for name, artifact, expected in (("before", before, "before"), ("after", after, "after")):
        if not isinstance(artifact, dict) or not isinstance(artifact.get("metadata"), dict):
            raise ValueError(f"{name} artifact is missing metadata")
        metadata = artifact["metadata"]
        if metadata.get("implementation") != expected:
            raise ValueError(f"{name} artifact implementation identity is invalid")
        observations = artifact.get("observations")
        if not isinstance(observations, list):
            raise ValueError(f"{name} artifact is missing observations")
        runner = metadata.get("runner")
        if not isinstance(runner, dict):
            raise ValueError(f"{name} artifact is missing runner metadata")
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

        profile = metadata.get("profile")
        matrix: dict[tuple[str, int], str] = {}
        for observation in observations:
            if not isinstance(observation, dict):
                raise ValueError(f"{name} artifact contains a non-object observation")
            if observation.get("implementation") != expected:
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
            if pair_order not in {"AB", "BA"}:
                raise ValueError(f"{name} observation has an invalid pair order")
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

    for field in ("benchmark_schema_version", "manifest_version", "corpus_version"):
        if before["metadata"].get(field) != after["metadata"].get(field):
            raise ValueError(f"benchmark metadata {field} differs between paired artifacts")

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
        "pairing",
        "benchmark_schema_version",
        "manifest_version",
        "corpus_version",
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

    fingerprints = {item.get("semantic_fingerprint") for item in [*before, *after]}
    if fingerprints != {case.semantic_fingerprint(str(before[0].get("profile")))}:
        return _empty_row(case, "invalid", ["semantic comparison fingerprint mismatch"], blocking=True)

    before_identities = {
        json.dumps(item["comparison_identity"], sort_keys=True, separators=(",", ":"))
        for item in before
        if item.get("comparison_identity") is not None
    }
    after_identities = {
        json.dumps(item["comparison_identity"], sort_keys=True, separators=(",", ":"))
        for item in after
        if item.get("comparison_identity") is not None
    }
    if len(before_identities) > 1 or len(after_identities) > 1:
        return _empty_row(case, "invalid", ["comparison identity changed between blocks"], blocking=True)
    if before_identities and after_identities and before_identities != after_identities:
        return _empty_row(case, "invalid", ["corpus or target fixture identity mismatch"], blocking=True)

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
        lower_bound = censored_by_block[block].get("lower_bound_duration_ns")
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
            row["after"]["observation_count"] > 0 and row["after"]["correct_count"] == row["after"]["observation_count"]
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
