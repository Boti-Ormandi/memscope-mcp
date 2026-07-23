"""Run one scanning benchmark observation against one selected source tree."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from pathlib import Path
from typing import Any

from benchmarks.scanning.common import (
    pair_order_label,
    pair_seed,
    paired_semantic_fingerprint_payload,
    semantic_fingerprint,
)
from benchmarks.scanning.manifest import CASE_BY_ID


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False), flush=True)


def _base_observation(arguments: argparse.Namespace) -> dict[str, Any]:
    case = CASE_BY_ID[arguments.case_id]
    return {
        "case_id": case.case_id,
        "implementation": arguments.implementation,
        "profile": arguments.profile,
        "block": arguments.block,
        "pair_seed": arguments.pair_seed,
        "pair_order": arguments.pair_order,
        "semantic_descriptor": case.semantic_descriptor(arguments.profile),
    }


def _bind_semantic_identity(observation: dict[str, Any]) -> None:
    payload = paired_semantic_fingerprint_payload(
        observation["semantic_descriptor"],
        observation.get("comparison_identity"),
    )
    observation["semantic_fingerprint_payload"] = payload
    observation["semantic_fingerprint"] = semantic_fingerprint(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementation", choices=("before", "after"), required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--case-id", choices=tuple(CASE_BY_ID), required=True)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--block", type=int, default=0)
    parser.add_argument("--pair-seed", type=int, required=True)
    parser.add_argument("--pair-order", choices=("AB", "BA"), required=True)
    parser.add_argument("--historical-phase-handshake", action="store_true")
    parser.add_argument("--candidate-outer-watchdog-s", type=float)
    arguments = parser.parse_args(argv)

    expected_seed = pair_seed(arguments.case_id, arguments.block)
    expected_order = pair_order_label(arguments.case_id, arguments.block)
    if arguments.pair_seed != expected_seed:
        parser.error("pair seed does not match the deterministic case/block protocol")
    if arguments.pair_order != expected_order:
        parser.error("pair order does not match the deterministic case/block protocol")
    if arguments.implementation == "before" and arguments.candidate_outer_watchdog_s is not None:
        parser.error("candidate outer watchdog is only valid for candidate observations")

    target_root = arguments.target_root.resolve()
    if not (target_root / "memscope_mcp").is_dir():
        parser.error(f"target root does not contain memscope_mcp: {target_root}")
    sys.path.insert(0, str(target_root))
    logging.disable(logging.CRITICAL)

    from benchmarks.scanning.adapters import run_case

    case = CASE_BY_ID[arguments.case_id]
    observation = _base_observation(arguments)
    ready_evidence: dict[str, Any] | None = None
    try:
        if arguments.historical_phase_handshake:
            if arguments.implementation != "before":
                raise RuntimeError("historical phase handshake is only valid for historical observations")

            def authorize_timed(evidence: dict[str, Any]) -> None:
                nonlocal ready_evidence
                ready_evidence = evidence
                ready = {
                    **observation,
                    **evidence,
                    "event": "historical_ready",
                    "status": "ready",
                    "correct": True,
                }
                _bind_semantic_identity(ready)
                _emit(ready)
                command = sys.stdin.readline().strip()
                if command != "run-timed":
                    raise RuntimeError("historical timed phase was not authorized")
                timed_start = {
                    **ready,
                    "event": "historical_timed_start",
                    "metrics": {**evidence["metrics"], "timed_phase_started": True},
                }
                _bind_semantic_identity(timed_start)
                _emit(timed_start)

            observation.update(
                run_case(
                    case,
                    implementation=arguments.implementation,
                    profile=arguments.profile,
                    target_root=target_root,
                    before_timed=authorize_timed,
                    candidate_outer_watchdog_s=None,
                )
            )
            if ready_evidence is None:
                raise RuntimeError("historical runner did not publish timed-phase readiness")
        else:
            observation.update(
                run_case(
                    case,
                    implementation=arguments.implementation,
                    profile=arguments.profile,
                    target_root=target_root,
                    candidate_outer_watchdog_s=arguments.candidate_outer_watchdog_s,
                )
            )
        _bind_semantic_identity(observation)
    except Exception as error:
        if ready_evidence is not None:
            observation.update(ready_evidence)
        observation.update(
            {
                "status": "error",
                "error_type": type(error).__name__,
                "error": str(error)[-4096:],
                "traceback": traceback.format_exc()[-16_384:],
                "correct": False,
            }
        )
        _bind_semantic_identity(observation)
    _emit(observation)
    return 0 if observation["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
