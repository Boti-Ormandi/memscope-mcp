"""Run the current hybrid matcher against the version-neutral corpus."""

from __future__ import annotations

import argparse
import gc
import time
from pathlib import Path
from typing import Any

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.common import (
    address_checksum,
    environment_metadata,
    semantic_fingerprint,
    semantic_fingerprint_payload,
    summarize,
    validate_raw_artifact,
    write_raw_artifact,
)
from benchmarks.scanning.corpus import build_corpus
from benchmarks.scanning.manifest import CASES, BenchmarkCase
from memscope_mcp.scanning.collectors import BoundedAddressCollector, CountCollector
from memscope_mcp.scanning.matcher import search_window
from memscope_mcp.scanning.model import ScanControl, ScanStats, SearchWindow, TerminationReason
from memscope_mcp.scanning.pattern import make_aob_query

BASE_ADDRESS = 0x10000000


class BenchmarkFailure(RuntimeError):
    """Raised when correctness or fixed strategy expectations fail before evidence is accepted."""


def run_matcher_suite(
    *,
    repo_root: Path,
    profile: str,
    warmups: int,
    repetitions: int,
    implementation_label: str = "candidate",
    case_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Run selected matcher cases and return one validated raw artifact."""

    if profile not in {"smoke", "release"}:
        raise ValueError("profile must be 'smoke' or 'release'")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
        raise ValueError("warmups must be a non-negative integer")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if not isinstance(implementation_label, str) or not implementation_label:
        raise ValueError("implementation_label must be a non-empty string")

    selected = _select_cases(case_ids)
    environment = environment_metadata(
        target_root=repo_root,
        implementation=implementation_label,
        profile=profile,
    )
    git = environment["git"]
    if not isinstance(git, dict) or not isinstance(git.get("commit"), str) or not isinstance(git.get("dirty"), bool):
        raise BenchmarkFailure("Git identity is required for raw benchmark evidence")

    artifact = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "suite": "scanning.matcher",
        "implementation": {
            "label": implementation_label,
            "git_commit": git["commit"],
            "git_dirty": git["dirty"],
        },
        "generated_at": environment["timestamp_utc"],
        "environment": environment,
        "runner": {
            "profile": profile,
            "warmups": warmups,
            "repetitions": repetitions,
            "selected_case_ids": [case.case_id for case in selected],
        },
        "cases": [_run_case(case, profile=profile, warmups=warmups, repetitions=repetitions) for case in selected],
    }
    validate_raw_artifact(artifact)
    return artifact


def _run_case(
    case: BenchmarkCase,
    *,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    corpus = build_corpus(case, profile, base_address=BASE_ADDRESS)
    alignment = int(case.parameters.get("alignment", 1))
    query = make_aob_query(case.pattern, alignment=alignment)
    window = SearchWindow(
        base_address=BASE_ADDRESS,
        data=corpus.data,
        eligible_start=BASE_ADDRESS,
        eligible_end=BASE_ADDRESS + len(corpus.data) - query.pattern.length + 1,
    )
    match_cap = case.max_matches or 100_000
    expected_count = len(corpus.expected_addresses)
    expected_termination = (
        TerminationReason.MATCH_LIMIT.value if expected_count == match_cap else TerminationReason.SCOPE_EXHAUSTED.value
    )

    _validate_correctness(
        case,
        query=query,
        window=window,
        match_cap=match_cap,
        expected_addresses=corpus.expected_addresses,
        expected_termination=expected_termination,
    )
    for _ in range(warmups):
        _measure_once(
            case,
            query=query,
            window=window,
            match_cap=match_cap,
            expected_count=expected_count,
            expected_termination=expected_termination,
        )

    observations = [
        _measure_once(
            case,
            query=query,
            window=window,
            match_cap=match_cap,
            expected_count=expected_count,
            expected_termination=expected_termination,
        )
        for _ in range(repetitions)
    ]
    strategy_names = sorted(
        {strategy for observation in observations for strategy in observation["work"]["strategy_counts"]}
    )
    manifest = case.semantic_descriptor(profile)
    corpus_record = {
        "corpus_version": CORPUS_VERSION,
        "profile": profile,
        "base_address": BASE_ADDRESS,
        "size": len(corpus.data),
        "sha256": corpus.data_sha256,
    }
    expected_record = {
        "returned_count": expected_count,
        "address_checksum": corpus.expected_checksum,
        "termination": expected_termination,
    }
    fingerprint_payload = semantic_fingerprint_payload(manifest, corpus_record, expected_record)

    return {
        "case_id": case.case_id,
        "tier": case.tier,
        "layer": case.layer,
        "comparison_class": case.comparison_class,
        "semantic_fingerprint_payload": fingerprint_payload,
        "semantic_fingerprint": semantic_fingerprint(fingerprint_payload),
        "manifest": manifest,
        "corpus": corpus_record,
        "expected": expected_record,
        "observations": observations,
        "summary": {
            "duration_ns": summarize([observation["duration_ns"] for observation in observations]),
            "throughput_mib_s": summarize([observation["throughput_mib_s"] for observation in observations]),
            "strategies": strategy_names,
        },
        "status": "complete",
    }


def _validate_correctness(
    case: BenchmarkCase,
    *,
    query,
    window: SearchWindow,
    match_cap: int,
    expected_addresses: tuple[int, ...],
    expected_termination: str,
) -> None:
    collector = BoundedAddressCollector(match_cap)
    result = search_window(query, window, collector, ScanControl(), ScanStats())
    termination = result.termination_reason or TerminationReason.SCOPE_EXHAUSTED
    collected = collector.finish(termination)
    observed_addresses = tuple(hit.address for hit in collected.hits)
    if observed_addresses != expected_addresses:
        raise BenchmarkFailure(
            f"{case.case_id}: current matcher address checksum differs from the independent reference"
        )
    if address_checksum(observed_addresses) != address_checksum(expected_addresses):
        raise BenchmarkFailure(f"{case.case_id}: current matcher address checksum is unstable")
    if collected.termination_reason.value != expected_termination:
        raise BenchmarkFailure(
            f"{case.case_id}: expected {expected_termination}, observed {collected.termination_reason.value}"
        )


def _measure_once(
    case: BenchmarkCase,
    *,
    query,
    window: SearchWindow,
    match_cap: int,
    expected_count: int,
    expected_termination: str,
) -> dict[str, Any]:
    collector = CountCollector(match_cap)
    stats = ScanStats()
    control = ScanControl()

    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()
    try:
        started = time.perf_counter_ns()
        matcher_result = search_window(query, window, collector, control, stats)
        duration_ns = time.perf_counter_ns() - started
    finally:
        if gc_was_enabled:
            gc.enable()

    termination = matcher_result.termination_reason or TerminationReason.SCOPE_EXHAUSTED
    result = collector.finish(termination)
    if result.observed_count != expected_count:
        raise BenchmarkFailure(f"{case.case_id}: expected {expected_count} matches, observed {result.observed_count}")
    if result.termination_reason.value != expected_termination:
        raise BenchmarkFailure(
            f"{case.case_id}: expected {expected_termination}, observed {result.termination_reason.value}"
        )

    strategy_counts = {
        strategy.value: count
        for strategy, count in sorted(stats.strategy_counts.items(), key=lambda item: item[0].value)
    }
    if case.expected_strategy is None:
        raise BenchmarkFailure(f"{case.case_id}: matcher cases must declare an expected strategy")
    if strategy_counts != {case.expected_strategy: 1}:
        raise BenchmarkFailure(
            f"{case.case_id}: expected strategy {case.expected_strategy}, observed {strategy_counts}"
        )

    throughput = stats.unique_bytes_examined / (1024 * 1024) / (duration_ns / 1_000_000_000) if duration_ns > 0 else 0.0
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": throughput,
        "work": {
            "strategy_counts": strategy_counts,
            "unique_bytes_examined": stats.unique_bytes_examined,
            "candidate_count": stats.candidate_count,
            "verification_count": stats.verification_count,
            "anchor_candidates": stats.anchor_candidates,
            "segment_verifications": stats.segment_verifications,
            "regex_candidates": stats.regex_candidates,
            "verified_matches": stats.verified_matches,
            "committed_matches": stats.committed_matches,
            "selector_invocations": stats.selector_invocations,
            "selector_sampled_bytes": stats.selector_sampled_bytes,
            "selector_estimated_candidates": stats.selector_estimated_candidates,
            "control_polls": stats.control_polls,
            "matcher_invocations": stats.matcher_invocations,
            "find_calls": stats.find_calls,
            "observed_count": result.observed_count,
            "termination": result.termination_reason.value,
        },
    }


def _select_cases(case_ids: tuple[str, ...] | None) -> tuple[BenchmarkCase, ...]:
    available = tuple(case for case in CASES if case.layer == "matcher")
    if case_ids is None:
        return available
    requested = set(case_ids)
    if len(requested) != len(case_ids):
        raise ValueError("case_ids must not contain duplicates")
    selected = tuple(case for case in available if case.case_id in requested)
    missing = requested - {case.case_id for case in selected}
    if missing:
        raise ValueError(f"unknown matcher case_ids: {', '.join(sorted(missing))}")
    return selected


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run deterministic in-buffer scanning matcher benchmarks")
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--implementation-label", default="candidate")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    output = args.output or repo_root / "benchmark-results" / f"matcher-{args.profile}.json"
    artifact = run_matcher_suite(
        repo_root=repo_root,
        profile=args.profile,
        warmups=args.warmups,
        repetitions=args.repetitions,
        implementation_label=args.implementation_label,
        case_ids=None if args.case_ids is None else tuple(args.case_ids),
    )
    write_raw_artifact(output, artifact)
    for case in artifact["cases"]:
        median = case["summary"]["throughput_mib_s"]["median"]
        print(f"{case['case_id']}: {median:.2f} MiB/s")
    print(f"wrote {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
