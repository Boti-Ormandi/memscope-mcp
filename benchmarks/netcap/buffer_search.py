"""Deterministic evidence for the netcap Lua buffer-search helpers."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any

from lupa import LuaRuntime

import benchmarks.netcap as benchmark_package
from benchmarks.netcap import BENCHMARK_NAME, BENCHMARK_SCHEMA_VERSION
from memscope_mcp._contrib.plugins.netcap import NetcapPlugin

_PATTERN = bytes((0xDE, 0xAD, 0xBE, 0xEF))
_RELEASE_SIZES = (64, 4096, 262000, 1048576)
_CANONICAL_SAMPLING = (
    {"size": 64, "warmups": 3, "repetitions": 101},
    {"size": 4096, "warmups": 3, "repetitions": 25},
    {"size": 262000, "warmups": 3, "repetitions": 9},
    {"size": 1048576, "warmups": 3, "repetitions": 9},
)
_PARITY_SAMPLE_SPACE = {
    "version": 1,
    "fixed_scenarios": [
        "ordinary",
        "overlap",
        "empty-pattern-nonempty",
        "empty-pattern-empty",
        "pattern-longer",
        "coercion",
        "out-of-range-exact",
        "out-of-range-no-mask",
        "invalid-conversion",
        "first-hole",
        "index-zero",
    ],
    "random_seed": 0xB00F,
    "random_scenarios": 200,
    "random_data_length": {"minimum": 0, "maximum": 128},
    "random_pattern_length": {"minimum": 0, "maximum": 16},
    "random_values": "integers in the inclusive range 0..255",
}
_SOURCE_LABELS = ("benchmark_init", "benchmark_module", "candidate_plugin")
_SOURCE_RELATIVE_PATHS = {
    "benchmark_init": Path("benchmarks/netcap/__init__.py"),
    "benchmark_module": Path("benchmarks/netcap/buffer_search.py"),
    "candidate_plugin": Path("memscope_mcp/_contrib/plugins/netcap.py"),
}
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PERF_COUNTER_RESOLUTION_SECONDS = 1e-7


class ArtifactValidationError(ValueError):
    """Raised when a raw benchmark artifact violates the schema-2 contract."""


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    operation: str
    size: int
    shape: str


@dataclass(frozen=True)
class ParityScenario:
    scenario_id: str
    data_entries: tuple[tuple[int, Any], ...]
    pattern_entries: tuple[tuple[int, Any], ...]


_RELEASE_CASES = tuple(
    BenchmarkCase(f"{operation}.{shape}.{size}", operation, size, shape)
    for size in _RELEASE_SIZES
    for operation, shapes in (
        ("find", ("start", "tail", "absent")),
        ("contains", ("start", "tail", "absent")),
        ("findall", ("sparse", "absent")),
    )
    for shape in shapes
) + (
    BenchmarkCase("findall.overlap.64", "findall", 64, "overlap"),
    BenchmarkCase("findall.dense.4096", "findall", 4096, "dense"),
)
_CASE_BY_ID = {case.case_id: case for case in _RELEASE_CASES}
_RELEASE_CASE_IDS = tuple(case.case_id for case in _RELEASE_CASES)
_SMOKE_CASE_IDS = (
    "find.start.64",
    "find.absent.4096",
    "contains.tail.4096",
    "findall.sparse.4096",
    "findall.overlap.64",
    "findall.dense.4096",
)
_ALLOCATION_CASE_IDS = {
    "find.absent.4096",
    "contains.absent.4096",
    "findall.sparse.4096",
    "findall.absent.4096",
    "findall.dense.4096",
    "find.absent.262000",
    "findall.sparse.262000",
}
_LUA_HEAP_CASE_IDS = {
    "findall.sparse.4096",
    "findall.sparse.262000",
    "findall.dense.4096",
}
_RETAINED_CASE_IDS = {
    "findall.sparse.4096",
    "findall.dense.4096",
}
_ALLOCATION_SAMPLE_COUNTS = {case_id: 3 if _CASE_BY_ID[case_id].size <= 4096 else 1 for case_id in _ALLOCATION_CASE_IDS}
_LUA_HEAP_SAMPLE_COUNTS = {case_id: 3 for case_id in _LUA_HEAP_CASE_IDS}
_RETAINED_GROWTH_CALLS = 100


def legacy_lua_table_to_list(table) -> list[int]:
    """Frozen copy of the legacy sequential Lua-table conversion contract."""
    result: list[int] = []
    index = 1
    while True:
        try:
            value = table[index]
            if value is None:
                break
            result.append(int(value))
            index += 1
        except (KeyError, IndexError):
            break
    return result


class LegacyBufferSearch:
    """Frozen legacy converter plus list-slice search oracle."""

    def __init__(self, table_factory: Callable[..., Any]) -> None:
        self._table = table_factory

    def find(self, data, pattern):
        data_list = legacy_lua_table_to_list(data)
        pattern_list = legacy_lua_table_to_list(pattern)
        pattern_length = len(pattern_list)
        for index in range(len(data_list) - pattern_length + 1):
            if data_list[index : index + pattern_length] == pattern_list:
                return index + 1
        return None

    def contains(self, data, pattern):
        return self.find(data, pattern) is not None

    def find_all(self, data, pattern):
        data_list = legacy_lua_table_to_list(data)
        pattern_list = legacy_lua_table_to_list(pattern)
        pattern_length = len(pattern_list)
        offsets = [
            index + 1
            for index in range(len(data_list) - pattern_length + 1)
            if data_list[index : index + pattern_length] == pattern_list
        ]
        return self._table(*offsets) if offsets else self._table()


def release_cases() -> tuple[BenchmarkCase, ...]:
    """Return the stable release case matrix."""
    return _RELEASE_CASES


def canonical_sampling() -> list[dict[str, int]]:
    """Return copies of the canonical release sampling minima."""
    return [dict(row) for row in _CANONICAL_SAMPLING]


def minimum_sampling(size: int) -> tuple[int, int]:
    """Return canonical warmup and observation minima for one input size."""
    for row in _CANONICAL_SAMPLING:
        if row["size"] == size:
            return row["warmups"], row["repetitions"]
    raise ValueError(f"unsupported benchmark size: {size}")


def selected_cases(profile: str, case_ids: Sequence[str] = ()) -> tuple[BenchmarkCase, ...]:
    """Select stable cases for a profile and optional explicit IDs."""
    if profile not in {"smoke", "release"}:
        raise ValueError("profile must be 'smoke' or 'release'")
    if case_ids:
        unknown = sorted(set(case_ids) - _CASE_BY_ID.keys())
        if unknown:
            raise ValueError(f"unknown case IDs: {', '.join(unknown)}")
        requested = set(case_ids)
        return tuple(case for case in _RELEASE_CASES if case.case_id in requested)
    if profile == "smoke":
        requested = set(_SMOKE_CASE_IDS)
        return tuple(case for case in _RELEASE_CASES if case.case_id in requested)
    return _RELEASE_CASES


def build_payload(case: BenchmarkCase) -> tuple[bytes, bytes]:
    """Build deterministic valid-byte timing input for one case."""
    if case.shape == "overlap":
        return b"A" * case.size, b"AAA"
    if case.shape == "dense":
        return bytes(0xAA if index % 2 == 0 else 0xBB for index in range(case.size)), b"\xaa"

    data = bytearray(b"\x11" * case.size)
    if case.shape == "start":
        data[: len(_PATTERN)] = _PATTERN
    elif case.shape == "tail":
        data[-len(_PATTERN) :] = _PATTERN
    elif case.shape == "sparse":
        positions = sorted(
            {
                0,
                max(0, case.size // 3),
                max(0, (2 * case.size) // 3),
                max(0, case.size - len(_PATTERN)),
            }
        )
        for position in positions:
            data[position : position + len(_PATTERN)] = _PATTERN
    elif case.shape != "absent":
        raise ValueError(f"unsupported case shape: {case.shape}")
    return bytes(data), _PATTERN


def _indexed_entries(values: Sequence[Any]) -> tuple[tuple[int, Any], ...]:
    return tuple((index, value) for index, value in enumerate(values, 1))


def _parity_scenarios() -> tuple[ParityScenario, ...]:
    fixed = (
        ParityScenario("ordinary", _indexed_entries([1, 2, 3, 2, 3]), _indexed_entries([2, 3])),
        ParityScenario("overlap", _indexed_entries([65, 65, 65, 65]), _indexed_entries([65, 65])),
        ParityScenario("empty-pattern-nonempty", _indexed_entries([1, 2, 3]), ()),
        ParityScenario("empty-pattern-empty", (), ()),
        ParityScenario("pattern-longer", _indexed_entries([1]), _indexed_entries([1, 2])),
        ParityScenario("coercion", _indexed_entries(["65", 66.9, True]), _indexed_entries([65, 66, 1])),
        ParityScenario(
            "out-of-range-exact",
            _indexed_entries([300, -1, 65536]),
            _indexed_entries([300, -1, 65536]),
        ),
        ParityScenario("out-of-range-no-mask", _indexed_entries([300]), _indexed_entries([44])),
        ParityScenario(
            "invalid-conversion",
            _indexed_entries([1, "not-an-integer"]),
            _indexed_entries([1]),
        ),
        ParityScenario("first-hole", ((1, 1), (3, 3)), _indexed_entries([3])),
        ParityScenario("index-zero", ((0, 9), (1, 1), (2, 2)), _indexed_entries([9])),
    )
    rng = random.Random(_PARITY_SAMPLE_SPACE["random_seed"])
    randomized = []
    for index in range(_PARITY_SAMPLE_SPACE["random_scenarios"]):
        data_values = [rng.randrange(256) for _ in range(rng.randrange(0, 129))]
        pattern_values = [rng.randrange(256) for _ in range(rng.randrange(0, 17))]
        randomized.append(
            ParityScenario(
                f"random-{index:03d}",
                _indexed_entries(data_values),
                _indexed_entries(pattern_values),
            )
        )
    return fixed + tuple(randomized)


def _table_from_entries(lua: LuaRuntime, entries: Sequence[tuple[int, Any]]):
    table = lua.table()
    for index, value in entries:
        table[index] = value
    return table


def _mapping_from_entries(entries: Sequence[tuple[int, Any]]) -> dict[int, Any]:
    return dict(entries)


def _fingerprint_scalar(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("parity inputs must contain finite floats")
        return {"type": "float", "value": repr(value)}
    if isinstance(value, str):
        return {"type": "string", "value": value}
    raise TypeError(f"unsupported parity input value: {type(value).__name__}")


def _input_fingerprint(entries: Sequence[tuple[int, Any]]) -> dict[str, Any]:
    descriptor = [{"index": index, "value": _fingerprint_scalar(value)} for index, value in entries]
    return {
        "entry_count": len(descriptor),
        "sha256": _sha256_bytes(_canonical_json(descriptor).encode("utf-8")),
    }


def _oracle_observation(scenario: ParityScenario, operation: str) -> dict[str, Any]:
    def table_factory(*values):
        return {index: value for index, value in enumerate(values, 1)}

    oracle = LegacyBufferSearch(table_factory)
    method = {
        "find": oracle.find,
        "contains": oracle.contains,
        "findall": oracle.find_all,
    }[operation]
    return _observe(
        partial(
            method,
            _mapping_from_entries(scenario.data_entries),
            _mapping_from_entries(scenario.pattern_entries),
        ),
        operation,
    )


def _parity_commitment(rows: Sequence[Mapping[str, Any]]) -> str:
    return _sha256_bytes(_canonical_json(rows).encode("utf-8"))


def _legacy_sequence_result(data: bytes, pattern: bytes, operation: str) -> Any:
    data_list = list(data)
    pattern_list = list(pattern)
    pattern_length = len(pattern_list)
    offsets = [
        index + 1
        for index in range(len(data_list) - pattern_length + 1)
        if data_list[index : index + pattern_length] == pattern_list
    ]
    if operation == "find":
        return offsets[0] if offsets else None
    if operation == "contains":
        return bool(offsets)
    return tuple(offsets)


def _sequence_fingerprint(values: Sequence[int]) -> dict[str, Any]:
    normalized = [int(value) for value in values]
    encoded = json.dumps(normalized, separators=(",", ":")).encode("utf-8")
    return {
        "count": len(normalized),
        "first": normalized[:4],
        "last": normalized[-4:] if normalized else [],
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def result_fingerprint(value: Any, operation: str) -> dict[str, Any]:
    """Return a stable scalar or sequential-table result fingerprint."""
    if operation == "find":
        return {"value": value}
    if operation == "contains":
        return {"value": bool(value)}
    if isinstance(value, (list, tuple)):
        return _sequence_fingerprint(value)
    return _sequence_fingerprint(legacy_lua_table_to_list(value))


def _observe(call: Callable[[], Any], operation: str) -> dict[str, Any]:
    try:
        return {"kind": "return", "result": result_fingerprint(call(), operation)}
    except Exception as exc:  # parity includes exception type and message
        return {"kind": "exception", "type": type(exc).__name__, "message": str(exc)}


def _candidate_module() -> ModuleType:
    return sys.modules[NetcapPlugin.__module__]


def _runtime_bindings() -> tuple[
    LuaRuntime,
    LegacyBufferSearch,
    NetcapPlugin,
    dict[tuple[str, str], Callable],
]:
    lua = LuaRuntime(unpack_returned_tuples=True)
    legacy = LegacyBufferSearch(lua.table)
    candidate = NetcapPlugin()
    candidate._table = lua.table
    globals_table = lua.globals()
    globals_table["legacy_find"] = legacy.find
    globals_table["legacy_contains"] = legacy.contains
    globals_table["legacy_find_all"] = legacy.find_all
    globals_table["candidate_find"] = candidate._buffer_find
    globals_table["candidate_contains"] = candidate._buffer_contains
    globals_table["candidate_find_all"] = candidate._buffer_find_all
    calls = {
        ("baseline", "find"): lua.eval("function(d, p) return legacy_find(d, p) end"),
        ("baseline", "contains"): lua.eval("function(d, p) return legacy_contains(d, p) end"),
        ("baseline", "findall"): lua.eval("function(d, p) return legacy_find_all(d, p) end"),
        ("candidate", "find"): lua.eval("function(d, p) return candidate_find(d, p) end"),
        ("candidate", "contains"): lua.eval("function(d, p) return candidate_contains(d, p) end"),
        ("candidate", "findall"): lua.eval("function(d, p) return candidate_find_all(d, p) end"),
    }
    return lua, legacy, candidate, calls


def run_correctness_suite(
    lua: LuaRuntime,
    calls: Mapping[tuple[str, str], Callable],
) -> dict[str, Any]:
    """Check parity only across the declared fixed and randomized sample space."""
    scenario_rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for scenario in _parity_scenarios():
        data = _table_from_entries(lua, scenario.data_entries)
        pattern = _table_from_entries(lua, scenario.pattern_entries)
        operation_rows = []
        for operation in ("find", "contains", "findall"):
            baseline = _observe(
                partial(calls[("baseline", operation)], data, pattern),
                operation,
            )
            independent_baseline = _oracle_observation(scenario, operation)
            if baseline != independent_baseline:
                raise AssertionError(f"independent parity oracle mismatch for {scenario.scenario_id}.{operation}")
            candidate = _observe(
                partial(calls[("candidate", operation)], data, pattern),
                operation,
            )
            passed = baseline == candidate
            operation_row = {
                "operation": operation,
                "baseline": baseline,
                "candidate": candidate,
                "passed": passed,
            }
            operation_rows.append(operation_row)
            if not passed:
                failures.append({"scenario": scenario.scenario_id, **operation_row})
        scenario_rows.append(
            {
                "scenario": scenario.scenario_id,
                "inputs": {
                    "data": _input_fingerprint(scenario.data_entries),
                    "pattern": _input_fingerprint(scenario.pattern_entries),
                },
                "operations": operation_rows,
            }
        )

    scenario_count = len(scenario_rows)
    check_count = sum(len(row["operations"]) for row in scenario_rows)
    return {
        "sample_space": dict(_PARITY_SAMPLE_SPACE),
        "scenarios": scenario_rows,
        "commitment_sha256": _parity_commitment(scenario_rows),
        "passed": not failures,
        "scenario_count": scenario_count,
        "check_count": check_count,
        "failure_count": len(failures),
        "failures": failures,
    }


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _run_git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.rstrip("\r\n")


def _git_identity(repo_root: Path) -> dict[str, Any]:
    try:
        status = _run_git(repo_root, "status", "--porcelain=v1", "--untracked-files=all")
        return {
            "root": _run_git(repo_root, "rev-parse", "--show-toplevel"),
            "commit": _run_git(repo_root, "rev-parse", "HEAD"),
            "tree": _run_git(repo_root, "rev-parse", "HEAD^{tree}"),
            "branch": _run_git(repo_root, "branch", "--show-current"),
            "dirty": bool(status),
            "status_sha256": _sha256_bytes(status.encode("utf-8")),
            "status_lines": status.splitlines(),
        }
    except (OSError, subprocess.CalledProcessError):
        return {
            "root": str(repo_root.resolve()),
            "commit": None,
            "tree": None,
            "branch": None,
            "dirty": None,
            "status_sha256": None,
            "status_lines": None,
        }


def _selected_repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _normalized_path(path: str | Path) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _source_entry(label: str, module: ModuleType, repo_root: Path) -> dict[str, Any]:
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise RuntimeError(f"module {module.__name__!r} has no source file")
    path = Path(module_file).resolve()
    expected_path = (repo_root / _SOURCE_RELATIVE_PATHS[label]).resolve()
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None) if spec is not None else None
    module_name = getattr(spec, "name", None) if spec is not None else None
    if not origin or _normalized_path(origin) != _normalized_path(expected_path):
        raise RuntimeError(f"module origin for {label} is outside the selected repository")
    if _normalized_path(path) != _normalized_path(expected_path):
        raise RuntimeError(f"module path for {label} is outside the selected repository")
    return {
        "label": label,
        "module": module_name or module.__name__,
        "path": str(path),
        "origin": str(Path(origin).resolve()),
        "sha256": _sha256_bytes(path.read_bytes()),
    }


def capture_identity(repo_root: Path) -> dict[str, Any]:
    """Capture source, module-origin, and Git identity without runtime binding."""
    repo_root = repo_root.resolve()
    if _normalized_path(repo_root) != _normalized_path(_selected_repository_root()):
        raise RuntimeError("selected repository root does not contain the benchmark module")
    modules = (
        ("benchmark_init", benchmark_package),
        ("benchmark_module", sys.modules[__name__]),
        ("candidate_plugin", _candidate_module()),
    )
    git = _git_identity(repo_root)
    if _normalized_path(git["root"]) != _normalized_path(repo_root):
        raise RuntimeError("Git root does not match the selected repository root")
    return {
        "sources": [_source_entry(label, module, repo_root) for label, module in modules],
        "git": git,
    }


def identity_unchanged(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    """Return whether all captured immutable identity fields remained equal."""
    return _canonical_json(before) == _canonical_json(after)


def _verify_local_repository(
    metadata: Mapping[str, Any],
    repo_root: Path | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if repo_root is None:
        reasons.append("repository-not-provided")
        return {"verified": False, "reasons": reasons}

    recorded_root = Path(metadata["selected_repo_root"]).resolve()
    repo_root = repo_root.resolve()
    if _normalized_path(repo_root) != _normalized_path(recorded_root):
        reasons.append("repository-root-mismatch")
        return {"verified": False, "reasons": reasons}

    try:
        current = capture_identity(repo_root)
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        reasons.append("repository-unavailable")
        return {"verified": False, "reasons": reasons}

    before = metadata["identity_before"]
    after = metadata["identity_after"]
    if _canonical_json(current["sources"]) != _canonical_json(before["sources"]):
        reasons.append("current-source-identity-mismatch")
    if _canonical_json(current["sources"]) != _canonical_json(after["sources"]):
        if "current-source-identity-mismatch" not in reasons:
            reasons.append("current-source-identity-mismatch")
    current_git = current["git"]
    before_git = before["git"]
    after_git = after["git"]
    if _canonical_json(current_git) != _canonical_json(before_git):
        reasons.append("current-git-identity-mismatch")
    if _canonical_json(current_git) != _canonical_json(after_git):
        if "current-git-identity-mismatch" not in reasons:
            reasons.append("current-git-identity-mismatch")
    if current_git["dirty"] and not before_git["dirty"] and not after_git["dirty"]:
        reasons.append("candidate-tree-dirty")
    return {"verified": not reasons, "reasons": reasons}


def _environment_metadata(profile: str) -> dict[str, Any]:
    try:
        lupa_version = importlib.metadata.version("lupa")
    except importlib.metadata.PackageNotFoundError:
        lupa_version = None
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profile": profile,
        "python": {
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "bitness": 64 if sys.maxsize > 2**32 else 32,
        },
        "lupa": lupa_version,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "cpu": {"processor": platform.processor(), "logical_count": os.cpu_count()},
        "clock": {"perf_counter_resolution_seconds": float(time.get_clock_info("perf_counter").resolution)},
    }


def _counts(
    profile: str,
    size: int,
    warmups: int | None,
    repetitions: int | None,
) -> tuple[int, int]:
    if warmups is not None and warmups < 0:
        raise ValueError("warmups must be non-negative")
    if repetitions is not None and repetitions < 1:
        raise ValueError("repetitions must be positive")
    if profile == "smoke":
        return warmups if warmups is not None else 0, repetitions if repetitions is not None else 1
    minimum_warmups, minimum_repetitions = minimum_sampling(size)
    return (
        warmups if warmups is not None else minimum_warmups,
        repetitions if repetitions is not None else minimum_repetitions,
    )


def _balanced_orders(repetitions: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    orders = ["AB"] * (repetitions // 2) + ["BA"] * (repetitions // 2)
    if repetitions % 2:
        orders.append("AB" if rng.randrange(2) == 0 else "BA")
    rng.shuffle(orders)
    return orders


def _paired_measure(
    baseline: Callable[[], Any],
    candidate: Callable[[], Any],
    operation: str,
    *,
    expected: dict[str, Any],
    warmups: int,
    repetitions: int,
    seed: int,
    lua: LuaRuntime | None = None,
) -> dict[str, Any]:
    for call in (baseline, candidate):
        for _ in range(warmups):
            if result_fingerprint(call(), operation) != expected:
                raise AssertionError("warmup result mismatch")

    orders = _balanced_orders(repetitions, seed)
    baseline_ns: list[int] = []
    candidate_ns: list[int] = []
    for order_name in orders:
        gc.collect()
        if lua is not None:
            lua.execute("collectgarbage('collect')")
        order = [("baseline", baseline), ("candidate", candidate)]
        if order_name == "BA":
            order.reverse()
        for name, call in order:
            started = time.perf_counter_ns()
            value = call()
            duration = time.perf_counter_ns() - started
            if result_fingerprint(value, operation) != expected:
                raise AssertionError(f"timed result mismatch for {name}")
            del value
            (baseline_ns if name == "baseline" else candidate_ns).append(duration)

    baseline_median = statistics.median(baseline_ns)
    candidate_median = statistics.median(candidate_ns)
    return {
        "warmups": warmups,
        "repetitions": repetitions,
        "seed": seed,
        "orders": orders,
        "baseline_ns": baseline_ns,
        "candidate_ns": candidate_ns,
        "baseline_median_ns": baseline_median,
        "candidate_median_ns": candidate_median,
        "ratio": candidate_median / baseline_median,
    }


def _paired_conversion_measure(
    baseline: Callable[[], Any],
    candidate: Callable[[], Any],
    *,
    warmups: int,
    repetitions: int,
    seed: int,
) -> dict[str, Any]:
    for call in (baseline, candidate):
        for _ in range(warmups):
            call()

    orders = _balanced_orders(repetitions, seed)
    baseline_ns: list[int] = []
    candidate_ns: list[int] = []
    for order_name in orders:
        gc.collect()
        order = [("baseline", baseline), ("candidate", candidate)]
        if order_name == "BA":
            order.reverse()
        for name, call in order:
            started = time.perf_counter_ns()
            value = call()
            duration = time.perf_counter_ns() - started
            del value
            (baseline_ns if name == "baseline" else candidate_ns).append(duration)

    baseline_median = statistics.median(baseline_ns)
    candidate_median = statistics.median(candidate_ns)
    return {
        "warmups": warmups,
        "repetitions": repetitions,
        "seed": seed,
        "orders": orders,
        "baseline_ns": baseline_ns,
        "candidate_ns": candidate_ns,
        "baseline_median_ns": baseline_median,
        "candidate_median_ns": candidate_median,
        "ratio": candidate_median / baseline_median,
    }


def _measure_peak(
    call: Callable[[], Any],
    operation: str,
    expected: dict[str, Any],
    repetitions: int,
) -> dict[str, Any]:
    peaks: list[int] = []
    for _ in range(repetitions):
        gc.collect()
        tracemalloc.start()
        try:
            value = call()
            if result_fingerprint(value, operation) != expected:
                raise AssertionError("allocation result mismatch")
            peaks.append(tracemalloc.get_traced_memory()[1])
            del value
        finally:
            tracemalloc.stop()
    return {
        "repetitions": repetitions,
        "samples": peaks,
        "median_peak_bytes": statistics.median(peaks),
    }


def _measure_lua_heap(
    lua: LuaRuntime,
    call: Callable[[], Any],
    operation: str,
    expected: dict[str, Any],
    repetitions: int = 3,
) -> dict[str, Any]:
    deltas: list[float] = []
    for _ in range(repetitions):
        lua.execute("collectgarbage('collect')")
        before = float(lua.eval("collectgarbage('count')"))
        value = call()
        after = float(lua.eval("collectgarbage('count')"))
        if result_fingerprint(value, operation) != expected:
            raise AssertionError("Lua heap result mismatch")
        delta = after - before
        if not math.isfinite(delta):
            raise RuntimeError("Lua heap measurement was not finite")
        deltas.append(max(0.0, delta))
        del value
        lua.execute("collectgarbage('collect')")
    return {
        "repetitions": repetitions,
        "delta_kib_samples": deltas,
        "median_delta_kib": statistics.median(deltas),
    }


def _measure_retained_growth(
    lua: LuaRuntime,
    call: Callable[[], Any],
    repetitions: int = 100,
) -> dict[str, Any]:
    lua.execute("collectgarbage('collect')")
    before = float(lua.eval("collectgarbage('count')"))
    for _ in range(repetitions):
        value = call()
        del value
    gc.collect()
    lua.execute("collectgarbage('collect')")
    after = float(lua.eval("collectgarbage('count')"))
    if not math.isfinite(before) or not math.isfinite(after) or before < 0 or after < 0:
        raise RuntimeError("retained Lua heap measurement was outside its valid domain")
    return {
        "calls": repetitions,
        "before_kib": before,
        "after_kib": after,
        "growth_kib": max(0.0, after - before),
    }


def _expected_allocation_ids(selected_case_ids: Sequence[str]) -> list[str]:
    return [case_id for case_id in selected_case_ids if case_id in _ALLOCATION_CASE_IDS]


def _expected_variant_keys(
    selected_case_ids: Sequence[str],
    eligible_case_ids: set[str],
) -> list[tuple[str, str]]:
    return [
        (case_id, variant)
        for case_id in selected_case_ids
        if case_id in eligible_case_ids
        for variant in ("baseline", "candidate")
    ]


def _timing_gate(
    measurement: Mapping[str, Any],
    threshold: float,
    perf_counter_resolution_seconds: float,
) -> dict[str, Any]:
    tolerance_ns = perf_counter_resolution_seconds * 1_000_000_000
    baseline_ns = measurement["baseline_median_ns"]
    candidate_ns = measurement["candidate_median_ns"]
    limit_ns = baseline_ns * threshold + tolerance_ns
    return {
        "ratio": measurement["ratio"],
        "threshold": threshold,
        "clock_tolerance_ns": tolerance_ns,
        "limit_ns": limit_ns,
        "passed": candidate_ns <= limit_ns,
    }


def _matrix_keys(rows: Sequence[Mapping[str, Any]], *, variants: bool) -> list[Any]:
    if variants:
        return [(row.get("case_id"), row.get("variant")) for row in rows]
    return [row.get("case_id") for row in rows]


def _sufficiency_reasons(artifact: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    runner = artifact["runner"]
    metadata = artifact["metadata"]
    selected_case_ids = runner["selected_case_ids"]

    if runner["profile"] != "release":
        reasons.append("profile-not-release")
    if selected_case_ids != list(_RELEASE_CASE_IDS):
        reasons.append("incomplete-release-case-matrix")
    if not artifact["correctness"]["passed"]:
        reasons.append("correctness-failed")
    if not metadata["identity_unchanged"]:
        reasons.append("identity-changed-during-run")
    if metadata["identity_before"]["git"]["dirty"] or metadata["identity_after"]["git"]["dirty"]:
        reasons.append("candidate-tree-dirty")

    for case in artifact["cases"]:
        minimum_warmups, minimum_repetitions = minimum_sampling(case["size"])
        measurement = case["lua_end_to_end"]
        if measurement["warmups"] < minimum_warmups or measurement["repetitions"] < minimum_repetitions:
            reasons.append(f"sampling-below-minimum:{case['case_id']}")

    if _matrix_keys(artifact["allocation"], variants=False) != _expected_allocation_ids(selected_case_ids):
        reasons.append("allocation-matrix-incomplete")
    if _matrix_keys(artifact["lua_heap"], variants=True) != _expected_variant_keys(
        selected_case_ids, _LUA_HEAP_CASE_IDS
    ):
        reasons.append("lua-heap-matrix-incomplete")
    if _matrix_keys(artifact["retained_growth"], variants=True) != _expected_variant_keys(
        selected_case_ids, _RETAINED_CASE_IDS
    ):
        reasons.append("retained-growth-matrix-incomplete")
    return reasons


def recompute_gates(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute sufficiency and all production-call performance gates."""
    cases = artifact["cases"]
    perf_counter_resolution_seconds = artifact["metadata"]["clock"]["perf_counter_resolution_seconds"]
    four_kib = [case["lua_end_to_end"]["ratio"] for case in cases if case["size"] == 4096]
    large = [case["lua_end_to_end"]["ratio"] for case in cases if case["size"] in {262000, 1048576}]

    group_rows: list[dict[str, Any]] = []
    if four_kib:
        ratio = math.exp(sum(math.log(value) for value in four_kib) / len(four_kib))
        group_rows.append(
            {
                "name": "4KiB geometric mean",
                "ratio": ratio,
                "threshold": 0.90,
                "passed": ratio <= 0.90,
            }
        )
    if large:
        ratio = math.exp(sum(math.log(value) for value in large) / len(large))
        group_rows.append(
            {
                "name": "262000B+1MiB geometric mean",
                "ratio": ratio,
                "threshold": 0.85,
                "passed": ratio <= 0.85,
            }
        )

    individual_rows = [
        {
            "case_id": case["case_id"],
            **_timing_gate(
                case["lua_end_to_end"],
                1.15 if case["size"] == 64 else 1.10,
                perf_counter_resolution_seconds,
            ),
        }
        for case in cases
    ]

    allocation_rows = []
    for row in artifact["allocation"]:
        if row["shape"] not in {"absent", "sparse"}:
            continue
        case = _CASE_BY_ID[row["case_id"]]
        data, pattern = build_payload(case)
        baseline_peak = row["baseline"]["median_peak_bytes"]
        candidate_peak = row["candidate"]["median_peak_bytes"]
        allowance = len(data) + len(pattern) + 8192
        limit = baseline_peak + allowance
        allocation_rows.append(
            {
                "case_id": row["case_id"],
                "baseline_peak_bytes": baseline_peak,
                "candidate_peak_bytes": candidate_peak,
                "allowance_bytes": allowance,
                "limit_bytes": limit,
                "passed": candidate_peak <= limit,
            }
        )

    heap_by_case: dict[str, dict[str, Mapping[str, Any]]] = {}
    for row in artifact["lua_heap"]:
        heap_by_case.setdefault(row["case_id"], {})[row["variant"]] = row
    heap_rows = []
    for case_id in artifact["runner"]["selected_case_ids"]:
        if case_id not in _LUA_HEAP_CASE_IDS:
            continue
        variants = heap_by_case[case_id]
        baseline_bytes = variants["baseline"]["median_delta_kib"] * 1024
        candidate_bytes = variants["candidate"]["median_delta_kib"] * 1024
        allowance = max(4096.0, baseline_bytes * 0.05)
        heap_rows.append(
            {
                "case_id": case_id,
                "baseline_delta_bytes": baseline_bytes,
                "candidate_delta_bytes": candidate_bytes,
                "allowance_bytes": allowance,
                "passed": candidate_bytes <= baseline_bytes + allowance,
            }
        )

    retained_rows = [
        {
            "case_id": row["case_id"],
            "variant": row["variant"],
            "growth_kib": row["growth_kib"],
            "threshold_kib": 64.0,
            "passed": row["growth_kib"] <= 64.0,
        }
        for row in artifact["retained_growth"]
    ]

    reasons = _sufficiency_reasons(artifact)
    all_gate_rows = group_rows + individual_rows + allocation_rows + heap_rows + retained_rows
    if reasons:
        status = "insufficient"
    elif all(row["passed"] for row in all_gate_rows):
        status = "pass"
    else:
        status = "fail"
    return {
        "status": status,
        "sufficient": not reasons,
        "insufficiency_reasons": reasons,
        "lua_end_to_end_groups": group_rows,
        "lua_end_to_end_individual": individual_rows,
        "allocation": allocation_rows,
        "lua_heap": heap_rows,
        "retained_growth": retained_rows,
    }


def run_suite(
    *,
    repo_root: Path,
    profile: str,
    case_ids: Sequence[str] = (),
    warmups: int | None = None,
    repetitions: int | None = None,
) -> dict[str, Any]:
    """Run the selected profile and return a validated schema-2 raw artifact."""
    repo_root = repo_root.resolve()
    if _normalized_path(repo_root) != _normalized_path(_selected_repository_root()):
        raise ValueError("repo_root must be the repository containing this benchmark")
    cases = selected_cases(profile, case_ids)
    identity_before = capture_identity(repo_root)
    lua, _legacy, _candidate, calls = _runtime_bindings()
    correctness = run_correctness_suite(lua, calls)
    if not correctness["passed"]:
        raise AssertionError("declared semantic parity sample failed before timing")

    candidate_converter = getattr(_candidate_module(), "_lua_table_to_list")
    conversion_rows: list[dict[str, Any]] = []
    for size in sorted({case.size for case in cases}):
        data_table = lua.table_from(b"\x11" * size)
        case_warmups, case_repetitions = _counts(profile, size, warmups, repetitions)
        measurement = _paired_conversion_measure(
            partial(legacy_lua_table_to_list, data_table),
            partial(candidate_converter, data_table),
            warmups=case_warmups,
            repetitions=case_repetitions,
            seed=0xC0DE ^ size,
        )
        conversion_rows.append({"case_id": f"conversion.{size}", "size": size, **measurement})
        del data_table
        lua.execute("collectgarbage('collect')")

    case_rows: list[dict[str, Any]] = []
    allocation_rows: list[dict[str, Any]] = []
    lua_heap_rows: list[dict[str, Any]] = []
    retained_rows: list[dict[str, Any]] = []

    for index, case in enumerate(cases):
        data_bytes, pattern_bytes = build_payload(case)
        data_table = lua.table_from(data_bytes)
        pattern_table = lua.table_from(pattern_bytes)
        baseline_lua = partial(calls[("baseline", case.operation)], data_table, pattern_table)
        candidate_lua = partial(calls[("candidate", case.operation)], data_table, pattern_table)
        expected = result_fingerprint(baseline_lua(), case.operation)
        independent_expected = result_fingerprint(
            _legacy_sequence_result(data_bytes, pattern_bytes, case.operation),
            case.operation,
        )
        if expected != independent_expected:
            raise AssertionError(f"legacy timing oracle mismatch for {case.case_id}")

        case_warmups, case_repetitions = _counts(profile, case.size, warmups, repetitions)
        measurement = _paired_measure(
            baseline_lua,
            candidate_lua,
            case.operation,
            expected=expected,
            warmups=case_warmups,
            repetitions=case_repetitions,
            seed=0xA110 + index,
            lua=lua,
        )
        case_rows.append(
            {
                "case_id": case.case_id,
                "operation": case.operation,
                "shape": case.shape,
                "size": case.size,
                "pattern_size": len(pattern_bytes),
                "input": {
                    "data_sha256": _sha256_bytes(data_bytes),
                    "pattern_sha256": _sha256_bytes(pattern_bytes),
                },
                "expected": expected,
                "lua_end_to_end": measurement,
            }
        )

        if case.case_id in _ALLOCATION_CASE_IDS:
            allocation_repetitions = _ALLOCATION_SAMPLE_COUNTS[case.case_id]
            allocation_rows.append(
                {
                    "case_id": case.case_id,
                    "operation": case.operation,
                    "shape": case.shape,
                    "size": case.size,
                    "pattern_size": len(pattern_bytes),
                    "baseline": _measure_peak(
                        baseline_lua,
                        case.operation,
                        expected,
                        allocation_repetitions,
                    ),
                    "candidate": _measure_peak(
                        candidate_lua,
                        case.operation,
                        expected,
                        allocation_repetitions,
                    ),
                }
            )

        if case.case_id in _LUA_HEAP_CASE_IDS:
            for variant, call in (("baseline", baseline_lua), ("candidate", candidate_lua)):
                lua_heap_rows.append(
                    {
                        "case_id": case.case_id,
                        "variant": variant,
                        **_measure_lua_heap(
                            lua,
                            call,
                            case.operation,
                            expected,
                            _LUA_HEAP_SAMPLE_COUNTS[case.case_id],
                        ),
                    }
                )

        if case.case_id in _RETAINED_CASE_IDS:
            for variant, call in (("baseline", baseline_lua), ("candidate", candidate_lua)):
                retained_rows.append(
                    {
                        "case_id": case.case_id,
                        "variant": variant,
                        **_measure_retained_growth(lua, call, _RETAINED_GROWTH_CALLS),
                    }
                )

        del data_table, pattern_table, data_bytes, pattern_bytes
        lua.execute("collectgarbage('collect')")
        gc.collect()

    identity_after = capture_identity(repo_root)
    artifact: dict[str, Any] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "benchmark": BENCHMARK_NAME,
        "metadata": {
            **_environment_metadata(profile),
            "selected_repo_root": str(repo_root),
            "lua": str(lua.eval("_VERSION")),
            "identity_before": identity_before,
            "identity_after": identity_after,
            "identity_unchanged": identity_unchanged(identity_before, identity_after),
        },
        "runner": {
            "profile": profile,
            "selected_case_ids": [case.case_id for case in cases],
            "warmups_override": warmups,
            "repetitions_override": repetitions,
            "canonical_release_sampling": canonical_sampling(),
        },
        "contract": {
            "baseline": "independent frozen sequential-table converter and list-slice oracle",
            "candidate": "checked-out NetcapPlugin methods",
            "performance_surface": "real Lua tables and production NetcapPlugin calls only",
            "conversion_rows": "diagnostic and excluded from release performance gates",
            "pairing": (
                "deterministically shuffled, position-balanced AB/BA blocks with collection outside timed regions"
            ),
            "parity_scope": dict(_PARITY_SAMPLE_SPACE),
        },
        "correctness": correctness,
        "conversion": conversion_rows,
        "cases": case_rows,
        "allocation": allocation_rows,
        "lua_heap": lua_heap_rows,
        "retained_growth": retained_rows,
    }
    artifact["gates"] = recompute_gates(artifact)
    validate_artifact(artifact, repo_root=repo_root)
    return artifact


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ArtifactValidationError(f"{label} must be an object")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ArtifactValidationError(f"{label} must be a list")
    return value


def _require_integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise ArtifactValidationError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise ArtifactValidationError(f"{label} is outside its valid domain")
    return value


def _require_boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ArtifactValidationError(f"{label} must be boolean")
    return value


def _require_finite_number(
    value: Any,
    label: str,
    *,
    minimum: float | None = None,
    strict_minimum: bool = False,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArtifactValidationError(f"{label} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ArtifactValidationError(f"{label} must be a finite number")
    if minimum is not None:
        if strict_minimum and numeric <= minimum:
            raise ArtifactValidationError(f"{label} is outside its valid domain")
        if not strict_minimum and numeric < minimum:
            raise ArtifactValidationError(f"{label} is outside its valid domain")
    if maximum is not None and numeric > maximum:
        raise ArtifactValidationError(f"{label} is outside its valid domain")
    return numeric


def _assert_close(actual: Any, expected: float, label: str) -> None:
    numeric = _require_finite_number(actual, label)
    if numeric != float(expected):
        raise ArtifactValidationError(f"{label} does not match recomputed value")


def _validate_source_manifest(
    identity: Mapping[str, Any],
    label: str,
    repo_root: Path,
) -> None:
    sources = _require_list(identity.get("sources"), f"{label}.sources")
    source_labels = [entry.get("label") for entry in sources if isinstance(entry, Mapping)]
    if source_labels != list(_SOURCE_LABELS):
        raise ArtifactValidationError(f"{label}.sources must contain the exact source manifest")
    expected_modules = {
        "benchmark_init": "benchmarks.netcap",
        "benchmark_module": "benchmarks.netcap.buffer_search",
        "candidate_plugin": "memscope_mcp._contrib.plugins.netcap",
    }
    for index, entry_value in enumerate(sources):
        entry = _require_mapping(entry_value, f"{label}.sources[{index}]")
        for field in ("module", "path", "origin", "sha256"):
            if not entry.get(field):
                raise ArtifactValidationError(f"{label}.sources[{index}].{field} is required")
        source_label = entry["label"]
        expected_path = (repo_root / _SOURCE_RELATIVE_PATHS[source_label]).resolve()
        if entry["module"] != expected_modules[source_label]:
            raise ArtifactValidationError(f"{label}.sources[{index}].module is inconsistent")
        if _normalized_path(entry["path"]) != _normalized_path(expected_path):
            raise ArtifactValidationError(f"{label}.sources[{index}].path is outside the selected repository")
        if _normalized_path(entry["origin"]) != _normalized_path(expected_path):
            raise ArtifactValidationError(f"{label}.sources[{index}].origin is outside the selected repository")
        if not _HASH_RE.fullmatch(str(entry["sha256"])):
            raise ArtifactValidationError(f"{label}.sources[{index}].sha256 is invalid")

    git = _require_mapping(identity.get("git"), f"{label}.git")
    for field in ("root", "commit", "tree", "branch", "status_sha256"):
        if not git.get(field):
            raise ArtifactValidationError(f"{label}.git.{field} is required")
    if _normalized_path(git["root"]) != _normalized_path(repo_root):
        raise ArtifactValidationError(f"{label}.git.root does not match the selected repository")
    if not isinstance(git.get("dirty"), bool):
        raise ArtifactValidationError(f"{label}.git.dirty must be boolean")
    if not _HASH_RE.fullmatch(str(git["status_sha256"])):
        raise ArtifactValidationError(f"{label}.git.status_sha256 is invalid")
    status_lines = git.get("status_lines")
    if not isinstance(status_lines, list) or any(not isinstance(line, str) for line in status_lines):
        raise ArtifactValidationError(f"{label}.git.status_lines must be a string list")
    expected_status_hash = _sha256_bytes("\n".join(status_lines).encode("utf-8"))
    if git["status_sha256"] != expected_status_hash:
        raise ArtifactValidationError(f"{label}.git.status_sha256 is inconsistent")
    if git["dirty"] is not bool(status_lines):
        raise ArtifactValidationError(f"{label}.git.dirty is inconsistent")


def _validate_timing_measurement(measurement_value: Any, label: str) -> None:
    measurement = _require_mapping(measurement_value, label)
    warmups = measurement.get("warmups")
    repetitions = measurement.get("repetitions")
    seed = measurement.get("seed")
    _require_integer(warmups, f"{label}.warmups", minimum=0)
    _require_integer(repetitions, f"{label}.repetitions", minimum=1)
    _require_integer(seed, f"{label}.seed")

    orders = _require_list(measurement.get("orders"), f"{label}.orders")
    if orders != _balanced_orders(repetitions, seed):
        raise ArtifactValidationError(f"{label}.orders does not match the balanced schedule")
    baseline_ns = _require_list(measurement.get("baseline_ns"), f"{label}.baseline_ns")
    candidate_ns = _require_list(measurement.get("candidate_ns"), f"{label}.candidate_ns")
    if len(baseline_ns) != repetitions or len(candidate_ns) != repetitions:
        raise ArtifactValidationError(f"{label} raw observation lengths do not match repetitions")
    if any(type(value) is not int or value <= 0 for value in baseline_ns + candidate_ns):
        raise ArtifactValidationError(f"{label} raw observations must be positive integers")

    _require_finite_number(
        measurement.get("baseline_median_ns"),
        f"{label}.baseline_median_ns",
        minimum=0,
        strict_minimum=True,
    )
    _require_finite_number(
        measurement.get("candidate_median_ns"),
        f"{label}.candidate_median_ns",
        minimum=0,
        strict_minimum=True,
    )
    _require_finite_number(
        measurement.get("ratio"),
        f"{label}.ratio",
        minimum=0,
        strict_minimum=True,
    )
    baseline_median = statistics.median(baseline_ns)
    candidate_median = statistics.median(candidate_ns)
    _assert_close(measurement.get("baseline_median_ns"), baseline_median, f"{label}.baseline_median_ns")
    _assert_close(measurement.get("candidate_median_ns"), candidate_median, f"{label}.candidate_median_ns")
    _assert_close(measurement.get("ratio"), candidate_median / baseline_median, f"{label}.ratio")


def _validate_peak_measurement(
    measurement_value: Any,
    label: str,
    expected_repetitions: int,
) -> None:
    measurement = _require_mapping(measurement_value, label)
    repetitions = measurement.get("repetitions")
    samples = _require_list(measurement.get("samples"), f"{label}.samples")
    if repetitions != expected_repetitions or len(samples) != expected_repetitions:
        raise ArtifactValidationError(f"{label} does not use the canonical sample count")
    if any(type(value) is not int or value < 0 for value in samples):
        raise ArtifactValidationError(f"{label} samples must be non-negative integers")
    _require_finite_number(
        measurement.get("median_peak_bytes"),
        f"{label}.median_peak_bytes",
        minimum=0,
    )
    _assert_close(
        measurement.get("median_peak_bytes"),
        statistics.median(samples),
        f"{label}.median_peak_bytes",
    )


def _validate_heap_row(
    row_value: Any,
    label: str,
    expected_repetitions: int,
) -> None:
    row = _require_mapping(row_value, label)
    repetitions = row.get("repetitions")
    samples = _require_list(row.get("delta_kib_samples"), f"{label}.delta_kib_samples")
    if repetitions != expected_repetitions or len(samples) != expected_repetitions:
        raise ArtifactValidationError(f"{label} does not use the canonical sample count")
    for index, value in enumerate(samples):
        _require_finite_number(
            value,
            f"{label}.delta_kib_samples[{index}]",
            minimum=0,
        )
    _require_finite_number(
        row.get("median_delta_kib"),
        f"{label}.median_delta_kib",
        minimum=0,
    )
    _assert_close(
        row.get("median_delta_kib"),
        statistics.median(samples),
        f"{label}.median_delta_kib",
    )


def _validate_exact_matrix(
    rows: Sequence[Mapping[str, Any]],
    expected: Sequence[Any],
    label: str,
    *,
    variants: bool,
) -> None:
    actual = _matrix_keys(rows, variants=variants)
    if actual != list(expected):
        raise ArtifactValidationError(f"{label} must contain the exact expected row matrix")
    if len(actual) != len(set(actual)):
        raise ArtifactValidationError(f"{label} contains duplicate rows")


def _validate_observation(
    observation_value: Any,
    operation: str,
    label: str,
) -> Mapping[str, Any]:
    observation = _require_mapping(observation_value, label)
    kind = observation.get("kind")
    if kind == "exception":
        if not isinstance(observation.get("type"), str) or not observation["type"]:
            raise ArtifactValidationError(f"{label}.type is invalid")
        if not isinstance(observation.get("message"), str):
            raise ArtifactValidationError(f"{label}.message is invalid")
        if set(observation) != {"kind", "type", "message"}:
            raise ArtifactValidationError(f"{label} has unexpected exception fields")
        return observation
    if kind != "return":
        raise ArtifactValidationError(f"{label}.kind is invalid")
    if set(observation) != {"kind", "result"}:
        raise ArtifactValidationError(f"{label} has unexpected return fields")
    result = _require_mapping(observation.get("result"), f"{label}.result")
    if operation == "find":
        if set(result) != {"value"}:
            raise ArtifactValidationError(f"{label}.result is invalid")
        value = result.get("value")
        if value is not None and (type(value) is not int or value < 1):
            raise ArtifactValidationError(f"{label}.result.value is invalid")
    elif operation == "contains":
        if set(result) != {"value"} or type(result.get("value")) is not bool:
            raise ArtifactValidationError(f"{label}.result is invalid")
    elif operation == "findall":
        if set(result) != {"count", "first", "last", "sha256"}:
            raise ArtifactValidationError(f"{label}.result is invalid")
        count = _require_integer(result.get("count"), f"{label}.result.count", minimum=0)
        first = _require_list(result.get("first"), f"{label}.result.first")
        last = _require_list(result.get("last"), f"{label}.result.last")
        if any(type(value) is not int or value < 1 for value in first + last):
            raise ArtifactValidationError(f"{label}.result offsets are invalid")
        if len(first) > min(4, count) or len(last) > min(4, count):
            raise ArtifactValidationError(f"{label}.result boundary samples are invalid")
        if not _HASH_RE.fullmatch(str(result.get("sha256"))):
            raise ArtifactValidationError(f"{label}.result.sha256 is invalid")
    else:
        raise ArtifactValidationError(f"{label} has unknown operation")
    return observation


def _validate_correctness_commitment(correctness: Mapping[str, Any]) -> None:
    expected_fields = {
        "sample_space",
        "scenarios",
        "commitment_sha256",
        "passed",
        "scenario_count",
        "check_count",
        "failure_count",
        "failures",
    }
    if set(correctness) != expected_fields:
        raise ArtifactValidationError("correctness has unexpected fields")
    if correctness.get("sample_space") != _PARITY_SAMPLE_SPACE:
        raise ArtifactValidationError("correctness sample space does not match the declared contract")
    scenarios = _require_list(correctness.get("scenarios"), "correctness.scenarios")
    expected_scenarios = _parity_scenarios()
    parity_lua, _legacy, _candidate, parity_calls = _runtime_bindings()
    if len(scenarios) != len(expected_scenarios):
        raise ArtifactValidationError("correctness scenarios do not match the declared matrix")

    failures: list[dict[str, Any]] = []
    recomputed_scenarios: list[dict[str, Any]] = []
    for scenario_index, (row_value, scenario) in enumerate(zip(scenarios, expected_scenarios, strict=True)):
        row = _require_mapping(row_value, f"correctness.scenarios[{scenario_index}]")
        if set(row) != {"scenario", "inputs", "operations"}:
            raise ArtifactValidationError(f"correctness.scenarios[{scenario_index}] has unexpected fields")
        if row.get("scenario") != scenario.scenario_id:
            raise ArtifactValidationError(f"correctness.scenarios[{scenario_index}].scenario is inconsistent")
        expected_inputs = {
            "data": _input_fingerprint(scenario.data_entries),
            "pattern": _input_fingerprint(scenario.pattern_entries),
        }
        if row.get("inputs") != expected_inputs:
            raise ArtifactValidationError(f"correctness.scenarios[{scenario_index}].inputs are inconsistent")
        operations = _require_list(
            row.get("operations"),
            f"correctness.scenarios[{scenario_index}].operations",
        )
        if len(operations) != 3:
            raise ArtifactValidationError(f"correctness.scenarios[{scenario_index}].operations is incomplete")
        data = _table_from_entries(parity_lua, scenario.data_entries)
        pattern = _table_from_entries(parity_lua, scenario.pattern_entries)
        recomputed_operations: list[dict[str, Any]] = []
        for operation_index, operation in enumerate(("find", "contains", "findall")):
            operation_row = _require_mapping(
                operations[operation_index],
                f"correctness.scenarios[{scenario_index}].operations[{operation_index}]",
            )
            if operation_row.get("operation") != operation:
                raise ArtifactValidationError(
                    f"correctness.scenarios[{scenario_index}].operations[{operation_index}].operation is inconsistent"
                )
            baseline = _validate_observation(
                operation_row.get("baseline"),
                operation,
                f"correctness.scenarios[{scenario_index}].operations[{operation_index}].baseline",
            )
            candidate = _validate_observation(
                operation_row.get("candidate"),
                operation,
                f"correctness.scenarios[{scenario_index}].operations[{operation_index}].candidate",
            )
            expected_baseline = _oracle_observation(scenario, operation)
            if baseline != expected_baseline:
                raise ArtifactValidationError(
                    f"correctness.scenarios[{scenario_index}].operations[{operation_index}].baseline is inconsistent"
                )
            passed = baseline == candidate
            if operation_row.get("passed") is not passed:
                raise ArtifactValidationError(
                    f"correctness.scenarios[{scenario_index}].operations[{operation_index}].passed is inconsistent"
                )
            if set(operation_row) != {"operation", "baseline", "candidate", "passed"}:
                raise ArtifactValidationError(
                    f"correctness.scenarios[{scenario_index}].operations[{operation_index}] has unexpected fields"
                )
            if not passed:
                failures.append({"scenario": scenario.scenario_id, **operation_row})
            recomputed_candidate = _observe(
                partial(parity_calls[("candidate", operation)], data, pattern),
                operation,
            )
            recomputed_operations.append(
                {
                    "operation": operation,
                    "baseline": expected_baseline,
                    "candidate": recomputed_candidate,
                    "passed": expected_baseline == recomputed_candidate,
                }
            )
        recomputed_scenarios.append(
            {
                "scenario": scenario.scenario_id,
                "inputs": expected_inputs,
                "operations": recomputed_operations,
            }
        )

    scenario_count = len(scenarios)
    check_count = scenario_count * 3
    if correctness.get("scenario_count") != scenario_count:
        raise ArtifactValidationError("correctness scenario_count is invalid")
    if correctness.get("check_count") != check_count:
        raise ArtifactValidationError("correctness check_count is invalid")
    if correctness.get("failure_count") != len(failures):
        raise ArtifactValidationError("correctness failure_count is inconsistent")
    if correctness.get("failures") != failures:
        raise ArtifactValidationError("correctness failures are inconsistent")
    if correctness.get("passed") is not (not failures):
        raise ArtifactValidationError("correctness passed flag is inconsistent")
    commitment = correctness.get("commitment_sha256")
    if not _HASH_RE.fullmatch(str(commitment)):
        raise ArtifactValidationError("correctness commitment_sha256 is invalid")
    if commitment != _parity_commitment(scenarios):
        raise ArtifactValidationError("correctness commitment_sha256 is inconsistent")
    if scenarios != recomputed_scenarios:
        raise ArtifactValidationError("correctness scenarios do not match recomputed parity")
    if commitment != _parity_commitment(recomputed_scenarios):
        raise ArtifactValidationError("correctness commitment_sha256 does not match recomputed parity")


def _validate_gate_rows(gates_value: Any) -> None:
    gates = _require_mapping(gates_value, "gates")
    if gates.get("status") not in {"pass", "fail", "insufficient"}:
        raise ArtifactValidationError("gates.status is invalid")
    _require_boolean(gates.get("sufficient"), "gates.sufficient")
    reasons = _require_list(gates.get("insufficiency_reasons"), "gates.insufficiency_reasons")
    if any(not isinstance(reason, str) or not reason for reason in reasons):
        raise ArtifactValidationError("gates.insufficiency_reasons is invalid")

    groups = _require_list(gates.get("lua_end_to_end_groups"), "gates.lua_end_to_end_groups")
    for index, row_value in enumerate(groups):
        row = _require_mapping(row_value, f"gates.lua_end_to_end_groups[{index}]")
        if not isinstance(row.get("name"), str) or not row["name"]:
            raise ArtifactValidationError(f"gates.lua_end_to_end_groups[{index}].name is invalid")
        _require_finite_number(
            row.get("ratio"), f"gates.lua_end_to_end_groups[{index}].ratio", minimum=0, strict_minimum=True
        )
        _require_finite_number(
            row.get("threshold"), f"gates.lua_end_to_end_groups[{index}].threshold", minimum=0, strict_minimum=True
        )
        _require_boolean(row.get("passed"), f"gates.lua_end_to_end_groups[{index}].passed")

    individuals = _require_list(
        gates.get("lua_end_to_end_individual"),
        "gates.lua_end_to_end_individual",
    )
    for index, row_value in enumerate(individuals):
        row = _require_mapping(row_value, f"gates.lua_end_to_end_individual[{index}]")
        if not isinstance(row.get("case_id"), str) or not row["case_id"]:
            raise ArtifactValidationError(f"gates.lua_end_to_end_individual[{index}].case_id is invalid")
        for field in ("ratio", "threshold", "clock_tolerance_ns", "limit_ns"):
            _require_finite_number(
                row.get(field),
                f"gates.lua_end_to_end_individual[{index}].{field}",
                minimum=0,
                strict_minimum=True,
            )
        _require_boolean(row.get("passed"), f"gates.lua_end_to_end_individual[{index}].passed")

    for matrix_name in ("allocation", "lua_heap"):
        rows = _require_list(gates.get(matrix_name), f"gates.{matrix_name}")
        for index, row_value in enumerate(rows):
            row = _require_mapping(row_value, f"gates.{matrix_name}[{index}]")
            if not isinstance(row.get("case_id"), str) or not row["case_id"]:
                raise ArtifactValidationError(f"gates.{matrix_name}[{index}].case_id is invalid")
            numeric_fields = (
                ("baseline_peak_bytes", "candidate_peak_bytes", "allowance_bytes", "limit_bytes")
                if matrix_name == "allocation"
                else ("baseline_delta_bytes", "candidate_delta_bytes", "allowance_bytes")
            )
            for field in numeric_fields:
                _require_finite_number(
                    row.get(field),
                    f"gates.{matrix_name}[{index}].{field}",
                    minimum=0,
                )
            _require_boolean(row.get("passed"), f"gates.{matrix_name}[{index}].passed")

    retained = _require_list(gates.get("retained_growth"), "gates.retained_growth")
    for index, row_value in enumerate(retained):
        row = _require_mapping(row_value, f"gates.retained_growth[{index}]")
        if not isinstance(row.get("case_id"), str) or not row["case_id"]:
            raise ArtifactValidationError(f"gates.retained_growth[{index}].case_id is invalid")
        if row.get("variant") not in {"baseline", "candidate"}:
            raise ArtifactValidationError(f"gates.retained_growth[{index}].variant is invalid")
        _require_finite_number(
            row.get("growth_kib"),
            f"gates.retained_growth[{index}].growth_kib",
            minimum=0,
        )
        _require_finite_number(
            row.get("threshold_kib"),
            f"gates.retained_growth[{index}].threshold_kib",
            minimum=0,
            strict_minimum=True,
        )
        _require_boolean(row.get("passed"), f"gates.retained_growth[{index}].passed")


def validate_artifact(
    artifact_value: Any,
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Validate schema, raw evidence, identity, matrices, and recomputed status."""
    artifact = _require_mapping(artifact_value, "artifact")
    if artifact.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
        raise ArtifactValidationError("unsupported schema_version")
    if artifact.get("benchmark") != BENCHMARK_NAME:
        raise ArtifactValidationError("unexpected benchmark name")

    verification_repo_root = repo_root
    metadata = _require_mapping(artifact.get("metadata"), "metadata")
    repo_root_value = metadata.get("selected_repo_root")
    if not isinstance(repo_root_value, str) or not repo_root_value:
        raise ArtifactValidationError("metadata.selected_repo_root is required")
    recorded_repo_root = Path(repo_root_value)
    if not recorded_repo_root.is_absolute():
        raise ArtifactValidationError("metadata.selected_repo_root must be absolute")
    recorded_repo_root = recorded_repo_root.resolve()
    clock = _require_mapping(metadata.get("clock"), "metadata.clock")
    resolution = clock.get("perf_counter_resolution_seconds")
    if (
        type(resolution) is not float
        or not math.isfinite(resolution)
        or resolution <= 0
        or resolution > _MAX_PERF_COUNTER_RESOLUTION_SECONDS
    ):
        raise ArtifactValidationError("metadata.clock.perf_counter_resolution_seconds is invalid")
    before = _require_mapping(metadata.get("identity_before"), "metadata.identity_before")
    after = _require_mapping(metadata.get("identity_after"), "metadata.identity_after")
    _validate_source_manifest(before, "metadata.identity_before", recorded_repo_root)
    _validate_source_manifest(after, "metadata.identity_after", recorded_repo_root)
    recomputed_identity = identity_unchanged(before, after)
    if metadata.get("identity_unchanged") is not recomputed_identity:
        raise ArtifactValidationError("metadata.identity_unchanged is inconsistent")

    runner = _require_mapping(artifact.get("runner"), "runner")
    if runner.get("profile") not in {"smoke", "release"}:
        raise ArtifactValidationError("runner.profile is invalid")
    if runner.get("canonical_release_sampling") != canonical_sampling():
        raise ArtifactValidationError("runner canonical sampling does not match schema 2")
    selected_case_ids = _require_list(runner.get("selected_case_ids"), "runner.selected_case_ids")
    if len(selected_case_ids) != len(set(selected_case_ids)):
        raise ArtifactValidationError("runner.selected_case_ids contains duplicates")
    if any(case_id not in _CASE_BY_ID for case_id in selected_case_ids):
        raise ArtifactValidationError("runner.selected_case_ids contains unknown cases")

    correctness = _require_mapping(artifact.get("correctness"), "correctness")
    _validate_correctness_commitment(correctness)

    cases = _require_list(artifact.get("cases"), "cases")
    case_ids = [case.get("case_id") for case in cases if isinstance(case, Mapping)]
    if case_ids != selected_case_ids:
        raise ArtifactValidationError("cases must exactly match runner.selected_case_ids")
    for index, case_value in enumerate(cases):
        case = _require_mapping(case_value, f"cases[{index}]")
        expected_case = _CASE_BY_ID[case["case_id"]]
        for field in ("operation", "size", "shape"):
            if case.get(field) != getattr(expected_case, field):
                raise ArtifactValidationError(f"cases[{index}].{field} is inconsistent")
        data, pattern = build_payload(expected_case)
        if case.get("pattern_size") != len(pattern):
            raise ArtifactValidationError(f"cases[{index}].pattern_size is inconsistent")
        expected_input = {
            "data_sha256": _sha256_bytes(data),
            "pattern_sha256": _sha256_bytes(pattern),
        }
        if case.get("input") != expected_input:
            raise ArtifactValidationError(f"cases[{index}].input is inconsistent")
        expected_result = result_fingerprint(
            _legacy_sequence_result(data, pattern, expected_case.operation),
            expected_case.operation,
        )
        if case.get("expected") != expected_result:
            raise ArtifactValidationError(f"cases[{index}].expected is inconsistent")
        _validate_timing_measurement(case.get("lua_end_to_end"), f"cases[{index}].lua_end_to_end")

    conversion = _require_list(artifact.get("conversion"), "conversion")
    selected_sizes = sorted({_CASE_BY_ID[case_id].size for case_id in selected_case_ids})
    if [row.get("size") for row in conversion if isinstance(row, Mapping)] != selected_sizes:
        raise ArtifactValidationError("conversion rows must exactly cover selected sizes")
    if len({row.get("case_id") for row in conversion if isinstance(row, Mapping)}) != len(conversion):
        raise ArtifactValidationError("conversion contains duplicate rows")
    for index, row_value in enumerate(conversion):
        row = _require_mapping(row_value, f"conversion[{index}]")
        if row.get("case_id") != f"conversion.{row.get('size')}":
            raise ArtifactValidationError(f"conversion[{index}].case_id is inconsistent")
        _validate_timing_measurement(row, f"conversion[{index}]")

    allocation = _require_list(artifact.get("allocation"), "allocation")
    _validate_exact_matrix(
        allocation,
        _expected_allocation_ids(selected_case_ids),
        "allocation",
        variants=False,
    )
    for index, row_value in enumerate(allocation):
        row = _require_mapping(row_value, f"allocation[{index}]")
        case = _CASE_BY_ID[row["case_id"]]
        data, pattern = build_payload(case)
        for field in ("operation", "size", "shape"):
            if row.get(field) != getattr(case, field):
                raise ArtifactValidationError(f"allocation[{index}].{field} is inconsistent")
        if row.get("size") != len(data):
            raise ArtifactValidationError(f"allocation[{index}].size is inconsistent")
        if row.get("pattern_size") != len(pattern):
            raise ArtifactValidationError(f"allocation[{index}].pattern_size is inconsistent")
        expected_repetitions = _ALLOCATION_SAMPLE_COUNTS[case.case_id]
        _validate_peak_measurement(
            row.get("baseline"),
            f"allocation[{index}].baseline",
            expected_repetitions,
        )
        _validate_peak_measurement(
            row.get("candidate"),
            f"allocation[{index}].candidate",
            expected_repetitions,
        )

    lua_heap = _require_list(artifact.get("lua_heap"), "lua_heap")
    _validate_exact_matrix(
        lua_heap,
        _expected_variant_keys(selected_case_ids, _LUA_HEAP_CASE_IDS),
        "lua_heap",
        variants=True,
    )
    for index, row_value in enumerate(lua_heap):
        row = _require_mapping(row_value, f"lua_heap[{index}]")
        _validate_heap_row(
            row,
            f"lua_heap[{index}]",
            _LUA_HEAP_SAMPLE_COUNTS[row["case_id"]],
        )

    retained = _require_list(artifact.get("retained_growth"), "retained_growth")
    _validate_exact_matrix(
        retained,
        _expected_variant_keys(selected_case_ids, _RETAINED_CASE_IDS),
        "retained_growth",
        variants=True,
    )
    for index, row_value in enumerate(retained):
        row = _require_mapping(row_value, f"retained_growth[{index}]")
        if row.get("calls") != _RETAINED_GROWTH_CALLS:
            raise ArtifactValidationError(f"retained_growth[{index}].calls must equal {_RETAINED_GROWTH_CALLS}")
        before_kib = _require_finite_number(
            row.get("before_kib"),
            f"retained_growth[{index}].before_kib",
            minimum=0,
        )
        after_kib = _require_finite_number(
            row.get("after_kib"),
            f"retained_growth[{index}].after_kib",
            minimum=0,
        )
        _require_finite_number(
            row.get("growth_kib"),
            f"retained_growth[{index}].growth_kib",
            minimum=0,
        )
        _assert_close(
            row.get("growth_kib"),
            max(0.0, after_kib - before_kib),
            f"retained_growth[{index}].growth_kib",
        )

    _validate_gate_rows(artifact.get("gates"))
    recomputed = recompute_gates(artifact)
    if _canonical_json(artifact.get("gates")) != _canonical_json(recomputed):
        raise ArtifactValidationError("serialized gates do not match recomputed evidence")

    repository = _verify_local_repository(metadata, verification_repo_root)
    return {
        "structurally_valid": True,
        "repository_verified": repository["verified"],
        "repository_verification_reasons": repository["reasons"],
        "release_eligible": recomputed["status"] == "pass" and repository["verified"],
    }


def write_artifact(path: Path, artifact: Mapping[str, Any]) -> None:
    """Write deterministic-key-order JSON evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _summary(artifact: Mapping[str, Any]) -> str:
    lines = [
        f"benchmark={artifact['benchmark']}",
        f"schema={artifact['schema_version']}",
        f"profile={artifact['runner']['profile']}",
        f"correctness={artifact['correctness']['passed']}",
        f"checks={artifact['correctness']['check_count']}",
        f"gate_status={artifact['gates']['status']}",
    ]
    if artifact["gates"]["insufficiency_reasons"]:
        lines.append("insufficient=" + ",".join(artifact["gates"]["insufficiency_reasons"]))
    for row in artifact["gates"]["lua_end_to_end_groups"]:
        lines.append(f"{row['name']}: ratio={row['ratio']:.6f} threshold={row['threshold']:.2f} passed={row['passed']}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--enforce-gates", action="store_true")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    artifact = run_suite(
        repo_root=repo_root,
        profile=args.profile,
        case_ids=tuple(args.case_id),
        warmups=args.warmups,
        repetitions=args.repetitions,
    )
    validation = validate_artifact(artifact, repo_root=repo_root)
    write_artifact(args.output, artifact)
    print(_summary(artifact))
    print(f"output={args.output.resolve()}")
    if args.enforce_gates and not validation["release_eligible"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
