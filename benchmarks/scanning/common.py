"""Shared benchmark metadata, statistics, hashing, and JSON helpers."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for fingerprints and artifacts."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def address_checksum(addresses: Iterable[int]) -> str:
    digest = hashlib.sha256()
    for address in addresses:
        if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address < 1 << 64:
            raise ValueError("addresses must be unsigned 64-bit integers")
        digest.update(address.to_bytes(8, "little"))
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: Sequence[dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def percentile(values: Sequence[float], percentile_value: float) -> float | None:
    if not values:
        return None
    if not 0 <= percentile_value <= 100:
        raise ValueError("percentile must be between 0 and 100")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile_value / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def summarize(values: Sequence[float]) -> dict[str, float | int | None]:
    numeric = [float(value) for value in values]
    if not numeric:
        return {"count": 0, "median": None, "p95": None, "minimum": None, "maximum": None, "mad": None}
    median = statistics.median(numeric)
    deviations = [abs(value - median) for value in numeric]
    return {
        "count": len(numeric),
        "median": median,
        "p95": percentile(numeric, 95),
        "minimum": min(numeric),
        "maximum": max(numeric),
        "mad": statistics.median(deviations),
    }


def bootstrap_median_interval(
    values: Sequence[float],
    *,
    seed: int,
    samples: int = 4000,
    confidence: float = 0.95,
) -> tuple[float | None, float | None]:
    """Return a deterministic percentile bootstrap interval for a median."""

    if not values:
        return None, None
    if len(values) == 1:
        value = float(values[0])
        return value, value
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between zero and one")

    import random

    rng = random.Random(seed)
    source = [float(value) for value in values]
    medians = [statistics.median(rng.choices(source, k=len(source))) for _ in range(samples)]
    tail = (1 - confidence) / 2
    return percentile(medians, tail * 100), percentile(medians, (1 - tail) * 100)


def git_identity(root: Path) -> dict[str, Any]:
    root = root.resolve()

    def command(*args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return completed.stdout.strip()

    try:
        commit = command("rev-parse", "HEAD")
        tree = command("rev-parse", "HEAD^{tree}")
        status = command("status", "--porcelain=v1", "--untracked-files=normal")
    except (OSError, subprocess.CalledProcessError):
        return {"root": str(root), "commit": None, "tree": None, "dirty": None}
    return {"root": str(root), "commit": commit, "tree": tree, "dirty": bool(status)}


def _execution_policy_metadata() -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "process_affinity_mask": None,
        "process_priority_class": None,
        "power_plan": None,
    }
    if sys.platform != "win32":
        return metadata

    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetProcessAffinityMask.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.GetProcessAffinityMask.restype = ctypes.c_int
        kernel32.GetPriorityClass.argtypes = [ctypes.c_void_p]
        kernel32.GetPriorityClass.restype = ctypes.c_uint32
        process = kernel32.GetCurrentProcess()
        process_mask = ctypes.c_size_t()
        system_mask = ctypes.c_size_t()
        if kernel32.GetProcessAffinityMask(process, ctypes.byref(process_mask), ctypes.byref(system_mask)):
            metadata["process_affinity_mask"] = f"0x{int(process_mask.value):X}"
        priority = int(kernel32.GetPriorityClass(process))
        if priority:
            metadata["process_priority_class"] = priority
    except (AttributeError, OSError):
        pass

    try:
        completed = subprocess.run(
            ["powercfg", "/getactivescheme"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        metadata["power_plan"] = " ".join(completed.stdout.split()) or None
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return metadata


def environment_metadata(*, target_root: Path, implementation: str, profile: str) -> dict[str, Any]:
    uname = platform.uname()
    packages: dict[str, str | None] = {}
    for package in ("mcp", "pydantic", "pymem", "lupa"):
        try:
            packages[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            packages[package] = None
    return {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "implementation": implementation,
        "profile": profile,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": {
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "bitness": 64 if sys.maxsize > 2**32 else 32,
        },
        "packages": packages,
        "os": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        },
        "cpu": {
            "processor": platform.processor(),
            "logical_count": os.cpu_count(),
        },
        "execution_policy": _execution_policy_metadata(),
        "git": git_identity(target_root),
    }


def format_duration_ns(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    milliseconds = float(value) / 1_000_000
    if milliseconds < 1:
        return f"{milliseconds:.3f} ms"
    if milliseconds < 1000:
        return f"{milliseconds:.2f} ms"
    return f"{milliseconds / 1000:.2f} s"


def format_bytes(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB"):
        if abs(amount) < 1024 or suffix == "GiB":
            return f"{amount:.2f} {suffix}"
        amount /= 1024
    raise AssertionError("unreachable")


def format_ratio(value: float | int | None, *, suffix: str = "x") -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.2f}{suffix}"


def normalize_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def utc_timestamp() -> str:
    """Return one second-resolution UTC timestamp in the raw artifact format."""

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def summarize_numbers(values: Iterable[float | int]) -> dict[str, float | int | None]:
    """Summarize an iterable without making callers materialize it first."""

    return summarize([float(value) for value in values])


def collect_environment(repo_root: Path) -> dict[str, Any]:
    """Collect the stable environment fields used by standalone benchmark artifacts."""

    identity = git_identity(repo_root)
    uname = platform.uname()
    return {
        "git_commit": identity.get("commit"),
        "git_tree": identity.get("tree"),
        "git_dirty": bool(identity.get("dirty")),
        "python_executable": sys.executable,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_bitness": 64 if sys.maxsize > 2**32 else 32,
        "os_system": uname.system,
        "os_release": uname.release,
        "os_version": uname.version,
        "machine": uname.machine,
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
    }


class ArtifactValidationError(ValueError):
    """Raised when a raw benchmark artifact violates its versioned contract."""


_REQUIRED_TOP_LEVEL = {
    "schema_version",
    "manifest_version",
    "corpus_version",
    "suite",
    "implementation",
    "generated_at",
    "environment",
    "runner",
    "cases",
}
_REQUIRED_CASE_FIELDS = {
    "case_id",
    "tier",
    "layer",
    "comparison_class",
    "semantic_fingerprint",
    "manifest",
    "corpus",
    "expected",
    "observations",
    "summary",
    "status",
}
_REQUIRED_OBSERVATION_FIELDS = {"duration_ns", "throughput_mib_s", "work"}


def write_raw_artifact(path: Path, artifact: Mapping[str, Any]) -> None:
    """Validate and atomically persist one canonical raw benchmark artifact."""

    validate_raw_artifact(artifact)
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_bytes(canonical_json_bytes(artifact) + b"\n")
    temporary.replace(destination)


def read_raw_artifact(path: Path) -> dict[str, Any]:
    """Load and validate one raw benchmark artifact."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError(f"cannot read benchmark artifact: {exc}") from exc
    validate_raw_artifact(value)
    return value


def validate_raw_artifact(value: Mapping[str, Any]) -> None:
    """Validate the raw evidence envelope consumed by later comparison tooling."""

    if not isinstance(value, Mapping):
        raise ArtifactValidationError("artifact must be a JSON object")
    if set(value) != _REQUIRED_TOP_LEVEL:
        raise ArtifactValidationError("artifact has unexpected top-level fields")
    if value["schema_version"] != BENCHMARK_SCHEMA_VERSION:
        raise ArtifactValidationError("unsupported benchmark schema version")
    if value["manifest_version"] != MANIFEST_VERSION:
        raise ArtifactValidationError("unsupported manifest version")
    if value["corpus_version"] != CORPUS_VERSION:
        raise ArtifactValidationError("unsupported corpus version")
    _require_non_empty_string("suite", value["suite"])
    _require_non_empty_string("generated_at", value["generated_at"])

    implementation = value["implementation"]
    if not isinstance(implementation, Mapping) or set(implementation) != {"label", "git_commit", "git_dirty"}:
        raise ArtifactValidationError("implementation metadata is invalid")
    _require_non_empty_string("implementation.label", implementation["label"])
    _require_git_oid("implementation.git_commit", implementation["git_commit"])
    if not isinstance(implementation["git_dirty"], bool):
        raise ArtifactValidationError("implementation.git_dirty must be a boolean")

    if not isinstance(value["environment"], Mapping):
        raise ArtifactValidationError("environment must be an object")
    runner = value["runner"]
    if not isinstance(runner, Mapping):
        raise ArtifactValidationError("runner must be an object")
    for field in ("profile", "warmups", "repetitions", "selected_case_ids"):
        if field not in runner:
            raise ArtifactValidationError(f"runner.{field} is required")
    _require_non_empty_string("runner.profile", runner["profile"])
    _require_non_negative_int("runner.warmups", runner["warmups"])
    _require_positive_int("runner.repetitions", runner["repetitions"])
    selected_case_ids = runner["selected_case_ids"]
    if not isinstance(selected_case_ids, list) or any(
        not isinstance(case_id, str) or not case_id for case_id in selected_case_ids
    ):
        raise ArtifactValidationError("runner.selected_case_ids must be a list of non-empty strings")

    cases = value["cases"]
    if not isinstance(cases, list) or not cases:
        raise ArtifactValidationError("cases must be a non-empty list")
    seen_case_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping) or set(case) != _REQUIRED_CASE_FIELDS:
            raise ArtifactValidationError(f"cases[{index}] has invalid fields")
        case_id = case["case_id"]
        _require_non_empty_string(f"cases[{index}].case_id", case_id)
        if case_id in seen_case_ids:
            raise ArtifactValidationError(f"duplicate case_id: {case_id}")
        seen_case_ids.add(case_id)
        for field in ("tier", "layer", "comparison_class", "status"):
            _require_non_empty_string(f"cases[{index}].{field}", case[field])
        _require_sha256(f"cases[{index}].semantic_fingerprint", case["semantic_fingerprint"])
        for field in ("manifest", "corpus", "expected", "summary"):
            if not isinstance(case[field], Mapping):
                raise ArtifactValidationError(f"cases[{index}].{field} must be an object")
        observations = case["observations"]
        if not isinstance(observations, list) or not observations:
            raise ArtifactValidationError(f"cases[{index}].observations must be non-empty")
        for observation_index, observation in enumerate(observations):
            if not isinstance(observation, Mapping) or set(observation) != _REQUIRED_OBSERVATION_FIELDS:
                raise ArtifactValidationError(f"cases[{index}].observations[{observation_index}] has invalid fields")
            _require_positive_int(
                f"cases[{index}].observations[{observation_index}].duration_ns",
                observation["duration_ns"],
            )
            throughput = observation["throughput_mib_s"]
            if isinstance(throughput, bool) or not isinstance(throughput, (int, float)) or throughput < 0:
                raise ArtifactValidationError("throughput_mib_s must be a non-negative number")
            if not isinstance(observation["work"], Mapping):
                raise ArtifactValidationError("observation work must be an object")

    if selected_case_ids != [case["case_id"] for case in cases]:
        raise ArtifactValidationError("runner.selected_case_ids must match artifact case order")


def _require_non_empty_string(name: str, value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ArtifactValidationError(f"{name} must be a non-empty string")


def _require_sha256(name: str, value: Any) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ArtifactValidationError(f"{name} must be a SHA-256 hex digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ArtifactValidationError(f"{name} must be a SHA-256 hex digest") from exc


def _require_git_oid(name: str, value: Any) -> None:
    if not isinstance(value, str) or len(value) not in {40, 64}:
        raise ArtifactValidationError(f"{name} must be a full Git object ID")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ArtifactValidationError(f"{name} must be a full Git object ID") from exc


def _require_non_negative_int(name: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArtifactValidationError(f"{name} must be a non-negative integer")


def _require_positive_int(name: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ArtifactValidationError(f"{name} must be a positive integer")
