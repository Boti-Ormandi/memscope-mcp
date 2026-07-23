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
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from benchmarks.scanning import (
    BENCHMARK_SCHEMA_VERSION,
    CANDIDATE_WATCHDOG_FLOOR_S,
    CORPUS_VERSION,
    MANIFEST_VERSION,
    PAIRING_PROTOCOL,
)


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for fingerprints and artifacts."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def semantic_fingerprint_payload(
    manifest: Mapping[str, Any],
    corpus: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "manifest": dict(manifest),
        "corpus": dict(corpus),
        "expected": dict(expected),
    }


def semantic_fingerprint(payload: Mapping[str, Any]) -> str:
    return sha256_json(payload)


def paired_semantic_fingerprint_payload(
    manifest: Mapping[str, Any],
    comparison_identity: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "manifest": dict(manifest),
        "comparison_identity": None if comparison_identity is None else dict(comparison_identity),
    }


def pair_seed(case_id: str, block: int) -> int:
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    if isinstance(block, bool) or not isinstance(block, int) or block < 0:
        raise ValueError("block must be a non-negative integer")
    payload = PAIRING_PROTOCOL["seed_payload"].format(case_id=case_id, block=block)
    return int.from_bytes(hashlib.sha256(payload.encode("utf-8")).digest()[:8], "little")


def pair_order_label(case_id: str, block: int) -> str:
    import random

    return PAIRING_PROTOCOL["labels"][random.Random(pair_seed(case_id, block)).randrange(2)]


def timeout_duration_ns(seconds: float | int) -> int:
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(float(seconds)):
        raise ValueError("timeout seconds must be a finite number")
    if float(seconds) <= 0:
        raise ValueError("timeout seconds must be positive")
    try:
        nanoseconds = Decimal(str(seconds)) * Decimal(1_000_000_000)
    except InvalidOperation as exc:
        raise ValueError("timeout seconds are invalid") from exc
    if nanoseconds != nanoseconds.to_integral_value():
        raise ValueError("timeout seconds must resolve to whole nanoseconds")
    return int(nanoseconds)


CANDIDATE_WATCHDOG_ENFORCED_CONTEXT = "paired_parent_outer_watchdog"
CANDIDATE_WATCHDOG_DIAGNOSTIC_CONTEXT = "standalone_diagnostic_no_outer_watchdog"


def candidate_watchdog_metrics(
    process_timeout_s: float,
    enforced_outer_watchdog_s: float | None,
) -> dict[str, Any]:
    declared_s = max(process_timeout_s, CANDIDATE_WATCHDOG_FLOOR_S)
    declared_ns = timeout_duration_ns(declared_s)
    if enforced_outer_watchdog_s is None:
        return {
            "candidate_watchdog_timeout_ns": declared_ns,
            "candidate_watchdog_enforced": False,
            "candidate_watchdog_context": CANDIDATE_WATCHDOG_DIAGNOSTIC_CONTEXT,
            "process_watchdog_ns": None,
        }
    if type(enforced_outer_watchdog_s) is not float or enforced_outer_watchdog_s != declared_s:
        raise ValueError("enforced candidate watchdog does not match the manifest-bound effective timeout")
    return {
        "candidate_watchdog_timeout_ns": declared_ns,
        "candidate_watchdog_enforced": True,
        "candidate_watchdog_context": CANDIDATE_WATCHDOG_ENFORCED_CONTEXT,
        "process_watchdog_ns": declared_ns,
    }


def candidate_watchdog_error(
    label: str,
    metrics: Any,
    *,
    candidate_watchdog_timeout_s: Any,
    require_enforced: bool,
) -> str | None:
    if not isinstance(metrics, Mapping):
        return f"{label} candidate watchdog evidence is missing"
    try:
        expected_ns = timeout_duration_ns(candidate_watchdog_timeout_s)
    except ValueError:
        return f"{label} candidate watchdog timeout is invalid"
    if metrics.get("candidate_watchdog_timeout_ns") != expected_ns:
        return f"{label} candidate watchdog deadline differs from the manifest"
    enforced = metrics.get("candidate_watchdog_enforced")
    context = metrics.get("candidate_watchdog_context")
    actual_ns = metrics.get("process_watchdog_ns")
    if enforced is True:
        if context != CANDIDATE_WATCHDOG_ENFORCED_CONTEXT or actual_ns != expected_ns:
            return f"{label} enforced candidate watchdog provenance is inconsistent"
    elif enforced is False:
        if context != CANDIDATE_WATCHDOG_DIAGNOSTIC_CONTEXT or actual_ns is not None:
            return f"{label} diagnostic candidate watchdog provenance is inconsistent"
        if require_enforced:
            return f"{label} candidate outer watchdog was not enforced"
    else:
        return f"{label} candidate watchdog enforcement flag is invalid"
    return None


def timeout_control_error(
    label: str,
    *,
    duration_ns: Any,
    termination: Any,
    metrics: Any,
    timeout_ms: Any,
    process_timeout_s: Any,
    require_control_polls: bool,
    require_timeout_hit: bool,
    candidate_watchdog_timeout_s: Any | None = None,
    require_candidate_watchdog_enforced: bool = False,
) -> str | None:
    if not is_exact_int(timeout_ms, minimum=1):
        return f"{label} timeout budget is invalid"
    try:
        historical_watchdog_ns = timeout_duration_ns(process_timeout_s)
    except ValueError:
        return f"{label} process watchdog is invalid"
    budget_ns = timeout_ms * 1_000_000
    if not isinstance(metrics, Mapping):
        return f"{label} timeout control metrics are missing"
    if termination != "timeout" or metrics.get("termination") != "timeout":
        return f"{label} timeout control termination is not timeout"
    if metrics.get("timed_out") is not True:
        return f"{label} timeout control timed_out flag is not true"
    if metrics.get("timeout_budget_ns") != budget_ns:
        return f"{label} timeout budget differs from the manifest"
    if candidate_watchdog_timeout_s is None:
        if metrics.get("process_watchdog_ns") != historical_watchdog_ns:
            return f"{label} process watchdog differs from the manifest"
        effective_watchdog_ns: int | None = historical_watchdog_ns
    else:
        watchdog_error = candidate_watchdog_error(
            label,
            metrics,
            candidate_watchdog_timeout_s=candidate_watchdog_timeout_s,
            require_enforced=require_candidate_watchdog_enforced,
        )
        if watchdog_error is not None:
            return watchdog_error
        effective_watchdog_ns = metrics.get("process_watchdog_ns")
    if not is_exact_int(duration_ns, minimum=budget_ns):
        return f"{label} timeout duration is below the declared budget"
    if effective_watchdog_ns is not None and duration_ns >= effective_watchdog_ns:
        return f"{label} timeout duration is not bounded by the process watchdog"
    overshoot_ns = metrics.get("timeout_overshoot_ns")
    if not is_exact_int(overshoot_ns) or overshoot_ns != duration_ns - budget_ns:
        return f"{label} timeout overshoot is inconsistent"
    if require_control_polls and not is_exact_int(metrics.get("control_polls"), minimum=1):
        return f"{label} timeout control has no control-poll evidence"
    if require_timeout_hit and metrics.get("timeout_hit") is not True:
        return f"{label} timeout control has no timeout-hit evidence"
    return None


def address_checksum(addresses: Iterable[int]) -> str:
    digest = hashlib.sha256()
    for address in addresses:
        if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address < 1 << 64:
            raise ValueError("addresses must be unsigned 64-bit integers")
        digest.update(address.to_bytes(8, "little"))
    return digest.hexdigest()


def range_union_size(ranges: Iterable[tuple[int, int]]) -> int:
    ordered = sorted(ranges)
    total = 0
    current_start = None
    current_end = None
    for start, end in ordered:
        if (
            isinstance(start, bool)
            or not isinstance(start, int)
            or isinstance(end, bool)
            or not isinstance(end, int)
            or start < 0
            or end < start
        ):
            raise ValueError("ranges must contain ordered non-negative integer bounds")
        if current_start is None:
            current_start, current_end = start, end
        elif start > current_end:
            total += current_end - current_start
            current_start, current_end = start, end
        else:
            current_end = max(current_end, end)
    if current_start is not None:
        total += current_end - current_start
    return total


def is_exact_int(value: Any, *, minimum: int = 0) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def is_finite_number(value: Any, *, minimum: float = 0) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= minimum
    )


def read_evidence_error(label: str, read: Any) -> str | None:
    if not isinstance(read, Mapping):
        return f"{label} read evidence is missing"
    integer_fields = (
        "physical_read_calls",
        "physical_bytes_requested",
        "physical_bytes_read",
        "unique_logical_bytes",
        "failed_read_calls",
    )
    for field in integer_fields:
        if not is_exact_int(read.get(field)):
            return f"{label} read field {field} is not a non-negative integer"
    calls = read["physical_read_calls"]
    failed = read["failed_read_calls"]
    if failed > calls:
        return f"{label} failed read count exceeds total calls"
    successful = calls - failed
    operations = read.get("physical_read_operations")
    if not isinstance(operations, list) or len(operations) != calls:
        return f"{label} per-call read evidence is invalid"
    derived_request_sizes: list[int] = []
    derived_read_sizes: list[int] = []
    derived_ranges: list[list[int]] = []
    derived_failed = 0
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping) or set(operation) != {
            "address",
            "requested_size",
            "returned_size",
            "success",
        }:
            return f"{label} read operation {index} has invalid fields"
        address = operation["address"]
        requested_size = operation["requested_size"]
        returned_size = operation["returned_size"]
        success = operation["success"]
        if not is_exact_int(address) or not is_exact_int(requested_size, minimum=1):
            return f"{label} read operation {index} request is invalid"
        if not is_exact_int(returned_size) or returned_size > requested_size:
            return f"{label} read operation {index} returned size exceeds its request"
        if not isinstance(success, bool):
            return f"{label} read operation {index} success flag is invalid"
        if success and returned_size < 1:
            return f"{label} read operation {index} succeeded without returned bytes"
        if not success and returned_size != 0:
            return f"{label} read operation {index} failed with returned bytes"
        derived_request_sizes.append(requested_size)
        if success:
            derived_read_sizes.append(returned_size)
            derived_ranges.append([address, address + returned_size])
        else:
            derived_failed += 1
    if derived_failed != failed:
        return f"{label} failed read count differs from per-call evidence"
    if read.get("physical_read_operations_sha256") != sha256_json(operations):
        return f"{label} per-call read checksum is invalid"
    request_sizes = read.get("physical_request_sizes")
    read_sizes = read.get("physical_read_sizes")
    ranges = read.get("physical_read_ranges")
    if (
        not isinstance(request_sizes, list)
        or len(request_sizes) != calls
        or any(not is_exact_int(size, minimum=1) for size in request_sizes)
    ):
        return f"{label} request-size evidence is invalid"
    if (
        not isinstance(read_sizes, list)
        or len(read_sizes) != successful
        or any(not is_exact_int(size, minimum=1) for size in read_sizes)
    ):
        return f"{label} read-size evidence is invalid"
    if not isinstance(ranges, list) or len(ranges) != successful:
        return f"{label} read-range evidence is invalid"
    if request_sizes != derived_request_sizes:
        return f"{label} request sizes differ from per-call evidence"
    if read_sizes != derived_read_sizes:
        return f"{label} read sizes differ from per-call evidence"
    if ranges != derived_ranges:
        return f"{label} read ranges differ from per-call evidence"
    normalized_ranges: list[tuple[int, int]] = []
    for index, item in enumerate(ranges):
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not is_exact_int(item[0])
            or not is_exact_int(item[1])
            or item[1] <= item[0]
            or item[1] - item[0] != read_sizes[index]
        ):
            return f"{label} read range {index} is invalid"
        normalized_ranges.append((item[0], item[1]))
    if sum(request_sizes) != read["physical_bytes_requested"]:
        return f"{label} requested-byte total differs from request sizes"
    if sum(read_sizes) != read["physical_bytes_read"]:
        return f"{label} returned-byte total differs from read sizes"
    if range_union_size(normalized_ranges) != read["unique_logical_bytes"]:
        return f"{label} unique logical byte union is invalid"
    if read.get("read_ranges_sha256") != sha256_json(normalized_ranges):
        return f"{label} read-range checksum is invalid"
    for field in ("read_call_p95_ns", "read_call_max_ns"):
        if not is_finite_number(read.get(field)):
            return f"{label} read timing field {field} is invalid"
    return None


_CONTROLLED_IDENTITY_FIELDS = {
    "corpus_version",
    "profile",
    "size",
    "sha256",
    "fixture_version",
    "fixture_source_sha256",
    "topology_fingerprint",
    "expected_count",
    "expected_relative_checksum",
}
_OPERATION_IDENTITY_FIELDS = {
    "run_id",
    "pid",
    "attachment_generation",
    "module_fingerprint",
    "target_identity_sha256",
    "phase",
    "cache_token",
}


def controlled_identity_error(label: str, identity: Any) -> str | None:
    if not isinstance(identity, Mapping) or set(identity) != _CONTROLLED_IDENTITY_FIELDS:
        return f"{label} controlled-target identity has invalid fields"
    if identity.get("corpus_version") != CORPUS_VERSION:
        return f"{label} controlled-target corpus version is unsupported"
    if identity.get("profile") not in {"smoke", "release"}:
        return f"{label} controlled-target profile is invalid"
    if not is_exact_int(identity.get("size"), minimum=1):
        return f"{label} controlled-target size is invalid"
    for field in ("sha256", "fixture_source_sha256", "topology_fingerprint", "expected_relative_checksum"):
        value = identity.get(field)
        if not isinstance(value, str) or not _is_sha256(value):
            return f"{label} controlled-target {field} is invalid"
    if not isinstance(identity.get("fixture_version"), str) or not identity["fixture_version"]:
        return f"{label} controlled-target fixture version is invalid"
    if not is_exact_int(identity.get("expected_count")):
        return f"{label} controlled-target expected count is invalid"
    return None


def operation_identity_error(label: str, identity: Any, *, expected_phase: str) -> str | None:
    if not isinstance(identity, Mapping) or set(identity) != _OPERATION_IDENTITY_FIELDS:
        return f"{label} operation identity has invalid fields"
    run_id = identity.get("run_id")
    if not isinstance(run_id, str) or not _is_hex(run_id, length=32):
        return f"{label} run identity is invalid"
    if not is_exact_int(identity.get("pid"), minimum=1):
        return f"{label} process identity is invalid"
    if not is_exact_int(identity.get("attachment_generation"), minimum=1):
        return f"{label} attachment generation is invalid"
    for field in ("module_fingerprint", "target_identity_sha256"):
        value = identity.get(field)
        if not isinstance(value, str) or not _is_sha256(value):
            return f"{label} {field} is invalid"
    if identity.get("phase") != expected_phase:
        return f"{label} phase identity differs"
    cache_token = identity.get("cache_token")
    if cache_token is not None and (not isinstance(cache_token, str) or not _is_sha256(cache_token)):
        return f"{label} cache token is invalid"
    return None


def operation_continuity_key(identity: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        identity.get("run_id"),
        identity.get("pid"),
        identity.get("attachment_generation"),
        identity.get("module_fingerprint"),
        identity.get("target_identity_sha256"),
    )


def _is_hex(value: str, *, length: int) -> bool:
    if len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _is_sha256(value: str) -> bool:
    return _is_hex(value, length=64)


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
        top_level = Path(command("rev-parse", "--show-toplevel")).resolve()
        if top_level != root:
            return {"root": str(root), "commit": None, "tree": None, "dirty": None}
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
    "semantic_fingerprint_payload",
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


def _raw_suite_cases(suite: str) -> tuple[Any, ...]:
    if suite == "scanning.matcher":
        from benchmarks.scanning.manifest import CASES

        return tuple(case for case in CASES if case.layer == "matcher")
    if suite == "scanning.process":
        from benchmarks.scanning.manifest import CASES
        from benchmarks.scanning.process_scan import PROCESS_CASE_KINDS

        return tuple(case for case in CASES if case.kind in PROCESS_CASE_KINDS)
    if suite == "scanning.engine-control":
        from benchmarks.scanning.engine import CASES

        return CASES
    if suite == "scanning.public-api":
        from benchmarks.scanning.public_api import CASES

        return CASES
    raise ArtifactValidationError(f"unsupported benchmark suite: {suite}")


def _canonical_case_manifest(case: Any, profile: str) -> dict[str, Any]:
    semantic_descriptor = getattr(case, "semantic_descriptor", None)
    if callable(semantic_descriptor):
        return semantic_descriptor(profile)
    manifest = getattr(case, "manifest", None)
    if callable(manifest):
        return manifest(profile)
    raise ArtifactValidationError(f"case {case.case_id} has no canonical manifest")


def _canonical_matcher_records(case: Any, profile: str) -> tuple[dict[str, Any], dict[str, Any]]:
    from benchmarks.scanning.corpus import build_corpus
    from benchmarks.scanning.matcher import BASE_ADDRESS

    corpus = build_corpus(case, profile, base_address=BASE_ADDRESS)
    expected_count = len(corpus.expected_addresses)
    expected_termination = "match_limit" if expected_count == (case.max_matches or 100_000) else "scope_exhausted"
    return (
        {
            "corpus_version": CORPUS_VERSION,
            "profile": profile,
            "base_address": BASE_ADDRESS,
            "size": len(corpus.data),
            "sha256": corpus.data_sha256,
        },
        {
            "returned_count": expected_count,
            "address_checksum": corpus.expected_checksum,
            "termination": expected_termination,
        },
    )


def _canonical_evidence_records(
    suite: str,
    case: Any,
    environment: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if suite == "scanning.engine-control":
        from benchmarks.scanning.engine import _EXERCISES

        validation = _EXERCISES[case.case_id]()
    elif suite == "scanning.public-api":
        from benchmarks.scanning.public_api import _EXERCISES

        git = environment.get("git")
        root = git.get("root") if isinstance(git, Mapping) else None
        if not isinstance(root, str) or not root:
            raise ArtifactValidationError("public API environment Git root is missing")
        validation = _EXERCISES[case.case_id](Path(root))
    else:
        raise ArtifactValidationError(f"unsupported deterministic evidence suite: {suite}")
    if not isinstance(validation, Mapping) or validation.get("work", {}).get("correct") is not True:
        raise ArtifactValidationError(f"case {case.case_id} canonical validation failed")
    corpus = validation.get("corpus")
    expected = validation.get("expected")
    if not isinstance(corpus, Mapping) or not isinstance(expected, Mapping):
        raise ArtifactValidationError(f"case {case.case_id} canonical records are invalid")
    return dict(corpus), dict(expected)


def _validate_process_records(
    label: str,
    case: Any,
    profile: str,
    corpus: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> None:
    from benchmarks.scanning.process_target import canonical_process_records

    canonical_corpus, canonical_expected = canonical_process_records(case, profile)
    if dict(corpus) != canonical_corpus:
        raise ArtifactValidationError(f"{label}.corpus differs from the canonical controlled target")
    expected_fields = {
        "returned_count",
        "address_checksum",
        "relative_address_checksum",
        "inaccessible_ranges",
        "readonly_ranges",
    }
    if set(expected) != expected_fields:
        raise ArtifactValidationError(f"{label}.expected fields are invalid")
    if expected.get("returned_count") != canonical_expected["returned_count"]:
        raise ArtifactValidationError(f"{label}.expected returned_count differs from the canonical target")
    if expected.get("relative_address_checksum") != canonical_expected["relative_address_checksum"]:
        raise ArtifactValidationError(f"{label}.expected relative checksum differs from the canonical target")
    if canonical_expected["returned_count"] == 0 and expected.get("address_checksum") != address_checksum(()):
        raise ArtifactValidationError(f"{label}.expected empty address checksum is invalid")
    for field, canonical_field in (
        ("inaccessible_ranges", "inaccessible_offsets"),
        ("readonly_ranges", "readonly_offsets"),
    ):
        ranges = expected.get(field)
        offsets = canonical_expected[canonical_field]
        if not isinstance(ranges, list) or len(ranges) != len(offsets):
            raise ArtifactValidationError(f"{label}.expected {field} differs from the canonical topology")
        lengths = []
        for item in ranges:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not is_exact_int(item[0])
                or not is_exact_int(item[1])
                or item[1] <= item[0]
            ):
                raise ArtifactValidationError(f"{label}.expected {field} contains an invalid range")
            lengths.append(item[1] - item[0])
        if lengths != [end - start for start, end in offsets]:
            raise ArtifactValidationError(f"{label}.expected {field} lengths differ from the canonical topology")


def _retained_process_addresses(case: Any, addresses: list[int]) -> list[int]:
    if case.mode == "first":
        return addresses[:1]
    if case.mode == "addresses":
        return addresses[: min(case.limit or len(addresses), case.max_matches or len(addresses))]
    return addresses[: case.max_matches or len(addresses)]


def _expected_process_termination(case: Any, expected_count: int) -> str:
    if case.kind in {"timeout", "chunk_timeout"}:
        return "timeout"
    if case.mode == "first" and expected_count:
        return "first_hit"
    if case.max_matches is not None and expected_count >= case.max_matches:
        return "match_limit"
    if case.mode == "addresses" and expected_count >= (case.limit or 50):
        return "page_limit"
    return "scope_exhausted"


def _validate_observation_correctness(
    suite: str,
    case: Any,
    profile: str,
    observation: Mapping[str, Any],
    corpus: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    label: str,
    process_watchdog: Mapping[str, Any] | None,
) -> None:
    work = observation["work"]
    if suite == "scanning.matcher":
        expected_count = expected["returned_count"]
        if work.get("observed_count") != expected_count:
            raise ArtifactValidationError(f"{label} observed count differs from the canonical expectation")
        if work.get("termination") != expected["termination"]:
            raise ArtifactValidationError(f"{label} termination differs from the canonical expectation")
        if work.get("strategy_counts") != {case.expected_strategy: 1}:
            raise ArtifactValidationError(f"{label} strategy evidence differs from the manifest")
        unique_bytes = work.get("unique_bytes_examined")
        if not is_exact_int(unique_bytes):
            raise ArtifactValidationError(f"{label} unique_bytes_examined is invalid")
        recomputed = unique_bytes / (1024 * 1024) / (observation["duration_ns"] / 1_000_000_000)
        if observation["throughput_mib_s"] != recomputed:
            raise ArtifactValidationError(f"{label} throughput differs from observation work")
        return
    if suite == "scanning.process":
        manifest = case.semantic_descriptor(profile)
        watchdog_error = candidate_watchdog_error(
            label,
            work,
            candidate_watchdog_timeout_s=manifest["candidate_watchdog_timeout_s"],
            require_enforced=bool(process_watchdog and process_watchdog.get("enforced")),
        )
        if watchdog_error is not None:
            raise ArtifactValidationError(watchdog_error)
        if process_watchdog is None:
            raise ArtifactValidationError("process runner candidate_outer_watchdog is missing")
        expected_context = (
            CANDIDATE_WATCHDOG_ENFORCED_CONTEXT
            if process_watchdog.get("enforced") is True
            else CANDIDATE_WATCHDOG_DIAGNOSTIC_CONTEXT
        )
        if work.get("candidate_watchdog_context") != expected_context:
            raise ArtifactValidationError(f"{label} watchdog context differs from runner metadata")
        if process_watchdog.get("timeout_s") is not None:
            if process_watchdog["timeout_s"] != manifest["candidate_watchdog_timeout_s"]:
                raise ArtifactValidationError(f"{label} runner watchdog timeout differs from the manifest")
        canonical_timed_count = expected.get("returned_count")
        canonical_timed_checksum: str | None = None
        if manifest.get("preflight_protocol"):
            preflight = work.get("preflight")
            if not isinstance(preflight, Mapping):
                raise ArtifactValidationError(f"{label} exact-address preflight evidence is missing")
            expected_addresses = preflight.get("expected_addresses")
            address_base = preflight.get("address_base")
            relative_addresses = preflight.get("relative_addresses")
            if (
                not isinstance(expected_addresses, list)
                or any(not is_exact_int(address) for address in expected_addresses)
                or not is_exact_int(address_base)
                or not isinstance(relative_addresses, list)
                or any(not is_exact_int(address) for address in relative_addresses)
            ):
                raise ArtifactValidationError(f"{label} preflight expected-address evidence is invalid")
            if relative_addresses != [address - address_base for address in expected_addresses]:
                raise ArtifactValidationError(f"{label} preflight absolute and relative expectations differ")
            canonical_absolute = address_checksum(expected_addresses)
            canonical_relative = address_checksum(relative_addresses)
            retained_addresses = _retained_process_addresses(case, expected_addresses)
            canonical_timed_count = len(retained_addresses)
            canonical_timed_checksum = None if case.mode == "count" else address_checksum(retained_addresses)
            if (
                expected.get("returned_count") != len(expected_addresses)
                or expected.get("address_checksum") != canonical_absolute
                or expected.get("relative_address_checksum") != canonical_relative
                or preflight.get("expected_count") != len(expected_addresses)
                or preflight.get("expected_checksum") != canonical_absolute
                or preflight.get("expected_relative_checksum") != canonical_relative
            ):
                raise ArtifactValidationError(f"{label} expected record differs from canonical preflight addresses")
        if case.kind in {"timeout", "chunk_timeout"}:
            error = timeout_control_error(
                label,
                duration_ns=observation["duration_ns"],
                termination=work.get("termination"),
                metrics=work,
                timeout_ms=case.timeout_ms,
                process_timeout_s=case.process_timeout_s,
                require_control_polls=True,
                require_timeout_hit=False,
                candidate_watchdog_timeout_s=manifest["candidate_watchdog_timeout_s"],
                require_candidate_watchdog_enforced=bool(process_watchdog.get("enforced")),
            )
            if error is not None:
                raise ArtifactValidationError(error)
            derived_correct = True
        elif case.kind == "reader_ceiling":
            derived_correct = work.get("correct") is True and work.get("physical_bytes_read") == corpus.get("size")
        else:
            actual_count = work.get("actual_count")
            expected_count = work.get("expected_count")
            canonical_count = canonical_timed_count
            if not is_exact_int(actual_count) or not is_exact_int(expected_count) or not is_exact_int(canonical_count):
                raise ArtifactValidationError(f"{label} count evidence is invalid")
            if expected_count != canonical_count:
                raise ArtifactValidationError(f"{label} expected count differs from the canonical target")
            derived_correct = actual_count == expected_count
            if case.mode == "count":
                if work.get("actual_checksum") is not None or work.get("expected_checksum") is not None:
                    raise ArtifactValidationError(f"{label} count mode checksum fields must be null")
            else:
                if canonical_timed_checksum is None:
                    raise ArtifactValidationError(f"{label} canonical timed checksum is unavailable")
                if work.get("expected_checksum") != canonical_timed_checksum:
                    raise ArtifactValidationError(f"{label} timed expected checksum differs from canonical preflight")
                if work.get("actual_checksum") != canonical_timed_checksum:
                    raise ArtifactValidationError(f"{label} timed actual checksum differs from canonical preflight")
            derived_correct = derived_correct and work.get("termination") == _expected_process_termination(
                case, expected_count
            )
        if work.get("correct") is not derived_correct:
            raise ArtifactValidationError(f"{label} correctness flag differs from canonical observation fields")
        unique_bytes = work.get("unique_bytes_examined")
        if case.kind == "reader_ceiling":
            unique_bytes = corpus.get("size")
        if is_exact_int(unique_bytes):
            recomputed = unique_bytes / (1024 * 1024) / (observation["duration_ns"] / 1_000_000_000)
            if observation["throughput_mib_s"] != recomputed:
                raise ArtifactValidationError(f"{label} throughput differs from observation work")
        return
    if work.get("correct") is not True:
        raise ArtifactValidationError(f"{label} deterministic correctness evidence is false")


def _canonical_raw_summary(suite: str, observations: list[Mapping[str, Any]]) -> dict[str, Any]:
    durations = [float(observation["duration_ns"]) for observation in observations]
    throughputs = [float(observation["throughput_mib_s"]) for observation in observations]
    if suite == "scanning.matcher":
        strategies = sorted(
            {strategy for observation in observations for strategy in observation["work"].get("strategy_counts", {})}
        )
        return {
            "duration_ns": summarize(durations),
            "throughput_mib_s": summarize(throughputs),
            "strategies": strategies,
        }
    if suite == "scanning.process":
        work = [observation["work"] for observation in observations]
        fields = (
            "physical_read_calls",
            "physical_bytes_requested",
            "physical_bytes_read",
            "failed_read_calls",
            "unique_bytes_examined",
            "candidate_count",
            "verification_count",
            "control_polls",
            "timeout_overshoot_ns",
            "peak_python_bytes",
        )
        return {
            "duration_ns": summarize(durations),
            "throughput_mib_s": summarize(throughputs),
            "work": {
                field: summarize([float(item[field]) for item in work if isinstance(item.get(field), (int, float))])
                for field in fields
            },
            "all_correct": all(item.get("correct") is True for item in work),
        }
    return {
        "duration_ns": summarize(durations),
        "throughput_mib_s": summarize(throughputs),
        "all_correct": all(observation["work"].get("correct") is True for observation in observations),
    }


def validate_raw_artifact(value: Mapping[str, Any]) -> None:
    """Validate one raw evidence artifact against the current canonical suite contract."""

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
    suite = value["suite"]
    _require_non_empty_string("suite", suite)
    canonical_cases = _raw_suite_cases(suite)
    canonical_by_id = {case.case_id: case for case in canonical_cases}
    canonical_order = [case.case_id for case in canonical_cases]
    _require_non_empty_string("generated_at", value["generated_at"])

    implementation = value["implementation"]
    if not isinstance(implementation, Mapping) or set(implementation) != {"label", "git_commit", "git_dirty"}:
        raise ArtifactValidationError("implementation metadata is invalid")
    _require_non_empty_string("implementation.label", implementation["label"])
    _require_git_oid("implementation.git_commit", implementation["git_commit"])
    if not isinstance(implementation["git_dirty"], bool):
        raise ArtifactValidationError("implementation.git_dirty must be a boolean")

    environment = value["environment"]
    if not isinstance(environment, Mapping):
        raise ArtifactValidationError("environment must be an object")
    for field, supported in (
        ("benchmark_schema_version", BENCHMARK_SCHEMA_VERSION),
        ("manifest_version", MANIFEST_VERSION),
        ("corpus_version", CORPUS_VERSION),
    ):
        if environment.get(field) != supported:
            raise ArtifactValidationError(f"environment uses unsupported {field}")
    if environment.get("implementation") != implementation["label"]:
        raise ArtifactValidationError("environment implementation differs from artifact metadata")

    runner = value["runner"]
    if not isinstance(runner, Mapping):
        raise ArtifactValidationError("runner must be an object")
    for field in ("profile", "warmups", "repetitions", "selected_case_ids"):
        if field not in runner:
            raise ArtifactValidationError(f"runner.{field} is required")
    profile = runner["profile"]
    if profile not in {"smoke", "release"}:
        raise ArtifactValidationError("runner.profile is invalid")
    if environment.get("profile") != profile:
        raise ArtifactValidationError("environment profile differs from runner profile")
    _require_non_negative_int("runner.warmups", runner["warmups"])
    _require_positive_int("runner.repetitions", runner["repetitions"])
    selected_case_ids = runner["selected_case_ids"]
    if (
        not isinstance(selected_case_ids, list)
        or not selected_case_ids
        or any(not isinstance(case_id, str) or not case_id for case_id in selected_case_ids)
    ):
        raise ArtifactValidationError("runner.selected_case_ids must be a non-empty list of case IDs")
    if len(selected_case_ids) != len(set(selected_case_ids)):
        raise ArtifactValidationError("runner.selected_case_ids must not contain duplicates")
    unknown = [case_id for case_id in selected_case_ids if case_id not in canonical_by_id]
    if unknown:
        raise ArtifactValidationError(f"unknown case_id for {suite}: {unknown[0]}")
    canonical_selected_order = [case_id for case_id in canonical_order if case_id in set(selected_case_ids)]
    if selected_case_ids != canonical_selected_order:
        raise ArtifactValidationError("runner.selected_case_ids differs from canonical manifest order")

    process_watchdog: Mapping[str, Any] | None = None
    if suite == "scanning.process":
        process_watchdog = runner.get("candidate_outer_watchdog")
        if not isinstance(process_watchdog, Mapping) or set(process_watchdog) != {
            "enforced",
            "context",
            "timeout_s",
        }:
            raise ArtifactValidationError("runner.candidate_outer_watchdog is invalid")
        enforced = process_watchdog["enforced"]
        context = process_watchdog["context"]
        timeout_s = process_watchdog["timeout_s"]
        if enforced is True:
            if context != CANDIDATE_WATCHDOG_ENFORCED_CONTEXT or type(timeout_s) is not float:
                raise ArtifactValidationError("runner enforced candidate watchdog provenance is invalid")
        elif enforced is False:
            if context != CANDIDATE_WATCHDOG_DIAGNOSTIC_CONTEXT or timeout_s is not None:
                raise ArtifactValidationError("runner diagnostic candidate watchdog provenance is invalid")
        else:
            raise ArtifactValidationError("runner candidate watchdog enforcement flag is invalid")

    cases = value["cases"]
    if not isinstance(cases, list) or not cases:
        raise ArtifactValidationError("cases must be a non-empty list")
    if [case.get("case_id") for case in cases if isinstance(case, Mapping)] != selected_case_ids:
        raise ArtifactValidationError("runner.selected_case_ids must match artifact case order")

    for index, case_record in enumerate(cases):
        label = f"cases[{index}]"
        if not isinstance(case_record, Mapping) or set(case_record) != _REQUIRED_CASE_FIELDS:
            raise ArtifactValidationError(f"{label} has invalid fields")
        case_id = case_record["case_id"]
        canonical_case = canonical_by_id[case_id]
        expected_metadata = {
            "tier": canonical_case.tier,
            "layer": canonical_case.layer,
            "comparison_class": canonical_case.comparison_class,
        }
        for field, expected_value in expected_metadata.items():
            if case_record[field] != expected_value:
                raise ArtifactValidationError(f"{label}.{field} differs from the canonical manifest")
        if case_record["status"] != "complete":
            raise ArtifactValidationError(f"{label}.status must be complete")
        manifest = case_record["manifest"]
        corpus = case_record["corpus"]
        expected = case_record["expected"]
        summary = case_record["summary"]
        for field, record in (("manifest", manifest), ("corpus", corpus), ("expected", expected), ("summary", summary)):
            if not isinstance(record, Mapping):
                raise ArtifactValidationError(f"{label}.{field} must be an object")
        canonical_manifest = _canonical_case_manifest(canonical_case, profile)
        if dict(manifest) != canonical_manifest:
            raise ArtifactValidationError(f"{label}.manifest differs from the canonical manifest")
        if suite == "scanning.matcher":
            canonical_corpus, canonical_expected = _canonical_matcher_records(canonical_case, profile)
            if dict(corpus) != canonical_corpus:
                raise ArtifactValidationError(f"{label}.corpus differs from the canonical matcher corpus")
            if dict(expected) != canonical_expected:
                raise ArtifactValidationError(f"{label}.expected differs from the canonical matcher expectation")
        elif suite == "scanning.process":
            _validate_process_records(label, canonical_case, profile, corpus, expected)
        else:
            manifest_profile = manifest.get("profile")
            if manifest_profile != profile:
                raise ArtifactValidationError(f"{label}.manifest profile differs from the runner")
            canonical_corpus, canonical_expected = _canonical_evidence_records(
                suite,
                canonical_case,
                environment,
            )
            if dict(corpus) != canonical_corpus:
                raise ArtifactValidationError(f"{label}.corpus differs from canonical deterministic validation")
            if dict(expected) != canonical_expected:
                raise ArtifactValidationError(f"{label}.expected differs from canonical deterministic validation")

        expected_payload = semantic_fingerprint_payload(manifest, corpus, expected)
        if case_record["semantic_fingerprint_payload"] != expected_payload:
            raise ArtifactValidationError(f"{label}.semantic_fingerprint_payload differs from canonical fields")
        if case_record["semantic_fingerprint"] != semantic_fingerprint(expected_payload):
            raise ArtifactValidationError(f"{label}.semantic_fingerprint does not match its payload")

        observations = case_record["observations"]
        if not isinstance(observations, list) or len(observations) != runner["repetitions"]:
            raise ArtifactValidationError(f"{label}.observations count differs from runner.repetitions")
        for observation_index, observation in enumerate(observations):
            observation_label = f"{label}.observations[{observation_index}]"
            if not isinstance(observation, Mapping) or set(observation) != _REQUIRED_OBSERVATION_FIELDS:
                raise ArtifactValidationError(f"{observation_label} has invalid fields")
            _require_positive_int(f"{observation_label}.duration_ns", observation["duration_ns"])
            if not is_finite_number(observation["throughput_mib_s"]):
                raise ArtifactValidationError(f"{observation_label}.throughput_mib_s must be finite")
            work = observation["work"]
            if not isinstance(work, Mapping):
                raise ArtifactValidationError(f"{observation_label}.work must be an object")
            _validate_observation_correctness(
                suite,
                canonical_case,
                profile,
                observation,
                corpus,
                expected,
                label=observation_label,
                process_watchdog=process_watchdog,
            )
            preflight = manifest.get("preflight_protocol", {})
            if preflight:
                error = read_evidence_error(f"{observation_label} timed", work)
                if error is not None:
                    raise ArtifactValidationError(error)
                evidence = work.get("preflight")
                if not isinstance(evidence, Mapping):
                    raise ArtifactValidationError("exact-address preflight evidence is required")
                for field, expected_value in preflight.items():
                    if evidence.get(field) != expected_value:
                        raise ArtifactValidationError(f"preflight protocol field {field} differs")
                error = read_evidence_error(f"{observation_label} preflight", evidence.get("read"))
                if error is not None:
                    raise ArtifactValidationError(error)
            setup_protocol = manifest.get("setup_protocol", {})
            if setup_protocol:
                setup = work.get("setup")
                if not isinstance(setup, Mapping):
                    raise ArtifactValidationError("declared setup evidence is required")
                for field, expected_value in setup_protocol.items():
                    if setup.get(field) != expected_value:
                        raise ArtifactValidationError(f"setup protocol field {field} differs")
                error = read_evidence_error(f"{observation_label} setup", setup.get("read"))
                if error is not None:
                    raise ArtifactValidationError(error)

        canonical_summary = _canonical_raw_summary(suite, observations)
        if dict(summary) != canonical_summary:
            raise ArtifactValidationError(f"{label}.summary differs from observations")

    if suite == "scanning.process":
        from benchmarks.scanning.process_scan import _chunk_selection_for_run

        recomputed_selection = _chunk_selection_for_run(
            cases,
            profile=profile,
            warmups=runner["warmups"],
            repetitions=runner["repetitions"],
        )
        if runner.get("chunk_selection") != recomputed_selection:
            raise ArtifactValidationError("runner.chunk_selection differs from canonical observations")


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
