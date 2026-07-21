"""Run randomized paired scanning benchmarks and generate the evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.common import git_identity, normalize_path, write_csv, write_json
from benchmarks.scanning.compare import CSV_FIELDS, compare_artifacts, comparison_csv_rows
from benchmarks.scanning.manifest import BenchmarkCase, select_cases
from benchmarks.scanning.report import generate_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-ref", default="c534fbd")
    parser.add_argument("--before-root", type=Path)
    parser.add_argument("--after-root", type=Path, default=Path.cwd())
    parser.add_argument("--before-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--after-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--blocks", type=int)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--group", action="append", dest="groups")
    parser.add_argument("--allow-dirty-release", action="store_true")
    arguments = parser.parse_args(argv)

    repo_root = normalize_path(Path.cwd())
    after_root = normalize_path(arguments.after_root)
    output_dir = normalize_path(arguments.output)
    blocks = arguments.blocks if arguments.blocks is not None else (1 if arguments.profile == "smoke" else 7)
    if blocks < 1:
        parser.error("--blocks must be positive")
    cases = select_cases(arguments.case_ids, arguments.groups)
    if not cases:
        parser.error("case selection is empty")
    if arguments.profile == "release" and not arguments.allow_dirty_release:
        if git_identity(after_root).get("dirty"):
            parser.error(
                "release evidence requires a clean candidate tree; use --allow-dirty-release only for diagnostics"
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    with _baseline_root(repo_root, arguments.before_ref, arguments.before_root) as before_root:
        before_metadata = _environment_metadata_for_python(
            python=normalize_path(arguments.before_python),
            tooling_root=repo_root,
            target_root=before_root,
            implementation="before",
            profile=arguments.profile,
        )
        after_metadata = _environment_metadata_for_python(
            python=normalize_path(arguments.after_python),
            tooling_root=repo_root,
            target_root=after_root,
            implementation="after",
            profile=arguments.profile,
        )
        before_metadata["runner"] = _runner_metadata(
            python=normalize_path(arguments.before_python),
            source_root=before_root,
            blocks=blocks,
            cases=cases,
        )
        after_metadata["runner"] = _runner_metadata(
            python=normalize_path(arguments.after_python),
            source_root=after_root,
            blocks=blocks,
            cases=cases,
        )

        before_observations: list[dict[str, Any]] = []
        after_observations: list[dict[str, Any]] = []
        for case in cases:
            for block in range(blocks):
                pair_order = _pair_order(case.case_id, block)
                pair_label = "AB" if pair_order == ("before", "after") else "BA"
                candidate_only = case.kind in {"chunk_sweep", "chunk_salvage", "chunk_timeout"}
                implementations = ("after",) if candidate_only else pair_order
                if candidate_only:
                    observation = _not_applicable_observation(
                        case=case,
                        profile=arguments.profile,
                        block=block,
                        pair_order=pair_label,
                        reason="the historical scanner exposes no configurable reader chunk",
                    )
                    before_observations.append(observation)
                    _write_progress(output_dir, case, block, "before", observation)

                for implementation in implementations:
                    root = before_root if implementation == "before" else after_root
                    python = arguments.before_python if implementation == "before" else arguments.after_python
                    observation = _run_observation(
                        repo_root=repo_root,
                        python=normalize_path(python),
                        target_root=root,
                        case=case,
                        implementation=implementation,
                        profile=arguments.profile,
                        block=block,
                        pair_order=pair_label,
                    )
                    if implementation == "before":
                        before_observations.append(observation)
                    else:
                        after_observations.append(observation)
                    _write_progress(output_dir, case, block, implementation, observation)

    raw_before = {"metadata": before_metadata, "observations": before_observations}
    raw_after = {"metadata": after_metadata, "observations": after_observations}
    write_json(output_dir / "raw-before.json", raw_before)
    write_json(output_dir / "raw-after.json", raw_after)
    comparison = compare_artifacts(raw_before, raw_after)
    write_json(output_dir / "comparison.json", comparison)
    write_csv(output_dir / "comparison.csv", comparison_csv_rows(comparison), CSV_FIELDS)
    generate_bundle(comparison, output_dir)
    (output_dir / "progress.jsonl").unlink(missing_ok=True)

    candidate_failures = [
        item for item in after_observations if item.get("status") != "ok" or item.get("correct") is not True
    ]
    return 1 if candidate_failures or comparison["blocking"] else 0


def _environment_metadata_for_python(
    *,
    python: Path,
    tooling_root: Path,
    target_root: Path,
    implementation: str,
    profile: str,
) -> dict[str, Any]:
    script = (
        "import json,sys; "
        "from pathlib import Path; "
        "sys.path.insert(0, sys.argv[1]); "
        "from benchmarks.scanning.common import environment_metadata; "
        "print(json.dumps(environment_metadata(target_root=Path(sys.argv[2]), "
        "implementation=sys.argv[3], profile=sys.argv[4]), sort_keys=True))"
    )
    completed = subprocess.run(
        [str(python), "-c", script, str(tooling_root), str(target_root), implementation, profile],
        cwd=tooling_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    for line in reversed(completed.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise RuntimeError(
        "metadata subprocess produced no JSON object; stdout="
        f"{_bounded_text(completed.stdout)!r}, stderr={_bounded_text(completed.stderr)!r}"
    )


def _not_applicable_observation(
    *,
    case: BenchmarkCase,
    profile: str,
    block: int,
    pair_order: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "implementation": "before",
        "profile": profile,
        "block": block,
        "pair_order": pair_order,
        "semantic_fingerprint": case.semantic_fingerprint(profile),
        "semantic_descriptor": case.semantic_descriptor(profile),
        "status": "not_applicable",
        "correct": None,
        "reason": reason,
    }


def _run_observation(
    *,
    repo_root: Path,
    python: Path,
    target_root: Path,
    case: BenchmarkCase,
    implementation: str,
    profile: str,
    block: int,
    pair_order: str,
) -> dict[str, Any]:
    command = [
        str(python),
        "-m",
        "benchmarks.scanning.driver",
        "--implementation",
        implementation,
        "--target-root",
        str(target_root),
        "--case-id",
        case.case_id,
        "--profile",
        profile,
        "--block",
        str(block),
        "--pair-order",
        pair_order,
    ]
    environment = os.environ.copy()
    environment.update({"PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"})
    timeout_seconds = case.process_timeout_s
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "case_id": case.case_id,
            "implementation": implementation,
            "profile": profile,
            "block": block,
            "pair_order": pair_order,
            "semantic_fingerprint": case.semantic_fingerprint(profile),
            "semantic_descriptor": case.semantic_descriptor(profile),
            "status": "censored",
            "correct": None,
            "lower_bound_duration_ns": int(timeout_seconds * 1_000_000_000),
            "wall_duration_ns": time.perf_counter_ns() - started,
            "timeout_seconds": timeout_seconds,
            "stdout": _bounded_text(error.stdout),
            "stderr": _bounded_text(error.stderr),
        }

    observation = _parse_driver_output(
        completed.stdout,
        expected_case_id=case.case_id,
        expected_implementation=implementation,
        expected_profile=profile,
        expected_block=block,
        expected_pair_order=pair_order,
    )
    observation["wall_duration_ns"] = time.perf_counter_ns() - started
    observation["driver_returncode"] = completed.returncode
    if completed.stderr:
        observation["driver_stderr"] = completed.stderr[-16_384:]
    if completed.returncode != 0 and observation.get("status") == "ok":
        observation.update(
            {
                "status": "driver_error",
                "correct": False,
                "error": f"driver exited with status {completed.returncode}",
            }
        )
    return observation


def _parse_driver_output(
    stdout: str,
    *,
    expected_case_id: str,
    expected_implementation: str,
    expected_profile: str,
    expected_block: int,
    expected_pair_order: str,
) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        text = line.strip()
        if not text:
            continue
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        identity = (
            value.get("case_id"),
            value.get("implementation"),
            value.get("profile"),
            value.get("block"),
            value.get("pair_order"),
        )
        expected = (
            expected_case_id,
            expected_implementation,
            expected_profile,
            expected_block,
            expected_pair_order,
        )
        if identity != expected:
            return {
                "case_id": expected_case_id,
                "implementation": expected_implementation,
                "profile": expected_profile,
                "block": expected_block,
                "pair_order": expected_pair_order,
                "status": "driver_error",
                "correct": False,
                "error": f"driver observation identity mismatch: {identity!r} != {expected!r}",
            }
        return value
    return {
        "case_id": expected_case_id,
        "implementation": expected_implementation,
        "profile": expected_profile,
        "block": expected_block,
        "pair_order": expected_pair_order,
        "status": "driver_error",
        "correct": False,
        "error": "driver produced no parseable observation",
        "stdout": _bounded_text(stdout),
    }


def _pair_order(case_id: str, block: int) -> tuple[str, str]:
    seed = int.from_bytes(hashlib.sha256(f"{case_id}:{block}".encode()).digest()[:8], "little")
    return ("before", "after") if random.Random(seed).randrange(2) == 0 else ("after", "before")


def _runner_metadata(
    *,
    python: Path,
    source_root: Path,
    blocks: int,
    cases: tuple[BenchmarkCase, ...],
) -> dict[str, Any]:
    return {
        "python": str(python),
        "source_root": str(source_root),
        "blocks": blocks,
        "case_ids": [case.case_id for case in cases],
        "pairing": "deterministic randomized AB/BA blocks",
        "driver": "python -m benchmarks.scanning.driver",
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
    }


def _write_progress(
    output_dir: Path,
    case: BenchmarkCase,
    block: int,
    implementation: str,
    observation: dict[str, Any],
) -> None:
    progress = {
        "case_id": case.case_id,
        "block": block,
        "implementation": implementation,
        "status": observation.get("status"),
        "correct": observation.get("correct"),
    }
    with (output_dir / "progress.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(progress, sort_keys=True) + "\n")


@contextmanager
def _baseline_root(repo_root: Path, before_ref: str, supplied_root: Path | None) -> Iterator[Path]:
    if supplied_root is not None:
        root = normalize_path(supplied_root)
        if not (root / "memscope_mcp").is_dir():
            raise ValueError(f"historical root does not contain memscope_mcp: {root}")
        yield root
        return

    owned_root = Path(tempfile.gettempdir()) / "memscope-benchmark-owned-worktrees"
    owned_root.mkdir(parents=True, exist_ok=True)
    _cleanup_stale_owned_worktrees(repo_root, owned_root)
    resolved_ref = _git(repo_root, "rev-parse", f"{before_ref}^{{commit}}").strip()
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=owned_root))
    worktree = run_root / "before"
    owner_path = run_root / "owner.json"
    owner = {
        "schema_version": 1,
        "repo_root": str(repo_root),
        "worktree": str(worktree),
        "expected_commit": resolved_ref,
        "owner_pid": os.getpid(),
        "run_id": uuid.uuid4().hex,
        "state": "prepared",
    }
    write_json(owner_path, owner)
    subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "add", "--detach", str(worktree), resolved_ref],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    owner["state"] = "active"
    write_json(owner_path, owner)
    active_exception = False
    try:
        yield worktree.resolve()
    except BaseException:
        active_exception = True
        raise
    finally:
        try:
            _cleanup_owned_worktree(repo_root, owned_root, run_root, owner)
        except Exception:
            if not active_exception:
                raise


def _cleanup_stale_owned_worktrees(repo_root: Path, owned_root: Path) -> None:
    for run_root in sorted(owned_root.glob("run-*")):
        owner_path = run_root / "owner.json"
        try:
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(owner, dict) or owner.get("schema_version") != 1:
            continue
        if normalize_path(owner.get("repo_root", ".")) != repo_root:
            continue
        owner_pid = owner.get("owner_pid")
        if isinstance(owner_pid, int) and _pid_is_running(owner_pid):
            continue
        _cleanup_owned_worktree(repo_root, owned_root, run_root, owner)


def _cleanup_owned_worktree(
    repo_root: Path,
    owned_root: Path,
    run_root: Path,
    owner: dict[str, Any],
) -> None:
    resolved_run = normalize_path(run_root)
    if resolved_run.parent != normalize_path(owned_root):
        raise RuntimeError(f"refusing cleanup outside owned benchmark root: {resolved_run}")
    worktree_value = owner.get("worktree")
    expected_commit = owner.get("expected_commit")
    if not isinstance(worktree_value, str) or not isinstance(expected_commit, str):
        raise RuntimeError(f"invalid benchmark ownership record: {run_root}")
    worktree = normalize_path(worktree_value)
    if worktree.parent != resolved_run:
        raise RuntimeError(f"owned worktree path escaped its run directory: {worktree}")
    if worktree.exists():
        actual_commit = _git(worktree, "rev-parse", "HEAD").strip()
        status = _git(worktree, "status", "--porcelain=v2", "--untracked-files=all")
        if actual_commit != expected_commit or status.strip():
            owner["state"] = "retained-unexpected-state"
            write_json(run_root / "owner.json", owner)
            raise RuntimeError(f"refusing to remove benchmark worktree with unexpected state: {worktree}")
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "remove", str(worktree)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "prune"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    shutil.rmtree(resolved_run)
    try:
        owned_root.rmdir()
    except OSError:
        pass


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout


def _pid_is_running(pid: int) -> bool:
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _bounded_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-16_384:]


if __name__ == "__main__":
    raise SystemExit(main())
