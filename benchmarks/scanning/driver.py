"""Run one scanning benchmark observation against one selected source tree."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from pathlib import Path
from typing import Any

from benchmarks.scanning.manifest import CASE_BY_ID


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementation", choices=("before", "after"), required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--case-id", choices=tuple(CASE_BY_ID), required=True)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--block", type=int, default=0)
    parser.add_argument("--pair-order", choices=("AB", "BA"), default="AB")
    arguments = parser.parse_args(argv)

    target_root = arguments.target_root.resolve()
    if not (target_root / "memscope_mcp").is_dir():
        parser.error(f"target root does not contain memscope_mcp: {target_root}")
    sys.path.insert(0, str(target_root))
    logging.disable(logging.CRITICAL)

    from benchmarks.scanning.adapters import run_case

    case = CASE_BY_ID[arguments.case_id]
    observation: dict[str, Any] = {
        "case_id": case.case_id,
        "implementation": arguments.implementation,
        "profile": arguments.profile,
        "block": arguments.block,
        "pair_order": arguments.pair_order,
        "semantic_fingerprint": case.semantic_fingerprint(arguments.profile),
        "semantic_descriptor": case.semantic_descriptor(arguments.profile),
    }
    try:
        observation.update(
            run_case(
                case,
                implementation=arguments.implementation,
                profile=arguments.profile,
                target_root=target_root,
            )
        )
    except Exception as error:
        observation.update(
            {
                "status": "error",
                "error_type": type(error).__name__,
                "error": str(error)[-4096:],
                "traceback": traceback.format_exc()[-16_384:],
                "correct": False,
            }
        )
    print(json.dumps(observation, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0 if observation["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
