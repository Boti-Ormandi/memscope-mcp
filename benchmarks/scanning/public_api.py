"""Deterministic FastMCP, Lua, formatting, and clean-break scanning evidence."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from benchmarks.scanning import BENCHMARK_SCHEMA_VERSION, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.common import (
    environment_metadata,
    semantic_fingerprint,
    semantic_fingerprint_payload,
    sha256_bytes,
    sha256_json,
    summarize,
    validate_raw_artifact,
    write_raw_artifact,
)
from memscope_mcp.extensions.core.module_scan import ModuleScanExtension
from memscope_mcp.scanning.boundary import register_strict_model_tool
from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanSuccess,
    FirstScanSuccess,
    RangeScopeInput,
    ScanHit,
    ScanInput,
    ScanResponse,
    ScanStatus,
    scan_input_validation_failure,
)
from memscope_mcp.scanning.cursor import CursorCodec
from memscope_mcp.scanning.execution import ScanExecutor
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease
from memscope_mcp.scanning.lua import LuaScanAdapter
from memscope_mcp.scanning.planner import MEM_COMMIT, MEM_PRIVATE, PAGE_READWRITE
from memscope_mcp.tools.lua.engine import MemscopeLuaEngine

_BASE_ADDRESS = 0x1000
_REMOVED_RUNTIME_TERMS = frozenset(
    {
        "AOBScanModule",
        "scan_aob_addresses",
        "scan_references",
        "summary_only",
        "return_offset",
        "error_detail",
        "source_error",
        "scanning_helpers",
        "utils.pattern",
    }
)
_SCAN_HELPERS = ("AOBScan", "AOBScanMany", "scanString", "scanPointer")


class EvidenceFailure(RuntimeError):
    """Raised when public-adapter evidence violates a fixed invariant."""


@dataclass(frozen=True, slots=True)
class EvidenceCase:
    case_id: str
    group: str
    comparison_class: str
    description: str
    tier: str = "headline"
    layer: str = "public"

    def manifest(self, profile: str) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "group": self.group,
            "comparison_class": self.comparison_class,
            "description": self.description,
            "profile": profile,
            "layer": self.layer,
        }


CASES: tuple[EvidenceCase, ...] = (
    EvidenceCase(
        "public.fastmcp.strict_flat_contract",
        "FastMCP",
        "new_capability",
        "The real FastMCP boundary rejects unknown fields before the handler and returns flat structured unions.",
    ),
    EvidenceCase(
        "public.output.formatting_sizes",
        "Formatting",
        "new_capability",
        "Validated address and count outputs record serialization work at supported retained-result sizes.",
    ),
    EvidenceCase(
        "public.lua.normalization_and_formatting",
        "Lua",
        "new_capability",
        "Lua adapters normalize named tables, preserve result metadata, and return stable error tuples.",
    ),
    EvidenceCase(
        "public.lua.serialized_runtime",
        "Lua",
        "new_capability",
        "Concurrent callers receive exclusive ownership of the mutable Lua runtime.",
    ),
    EvidenceCase(
        "public.clean_break.audit",
        "Clean break",
        "new_capability",
        "Production modules, registrations, and shipped instructions expose only the replacement scanning surface.",
    ),
)
CASE_BY_ID = {case.case_id: case for case in CASES}


class TrackingSession:
    def __init__(self, lease: ScanLease) -> None:
        self.lease = lease
        self.active = 0
        self.released = threading.Event()
        self._lock = threading.Lock()

    @contextmanager
    def acquire_scan_lease(self):
        with self._lock:
            self.active += 1
            self.released.clear()
        try:
            yield self.lease
        finally:
            with self._lock:
                self.active -= 1
                if self.active == 0:
                    self.released.set()


def run_public_api_suite(
    *,
    repo_root: Path,
    profile: str,
    warmups: int,
    repetitions: int,
    implementation_label: str = "candidate",
    case_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Run selected public-adapter cases and return a validated raw artifact."""

    if profile not in {"smoke", "release"}:
        raise ValueError("profile must be 'smoke' or 'release'")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
        raise ValueError("warmups must be a non-negative integer")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if not implementation_label:
        raise ValueError("implementation_label must be non-empty")

    selected = _select_cases(case_ids)
    environment = environment_metadata(
        target_root=repo_root,
        implementation=implementation_label,
        profile=profile,
    )
    git = environment["git"]
    if not isinstance(git, dict) or not isinstance(git.get("commit"), str) or not isinstance(git.get("dirty"), bool):
        raise EvidenceFailure("Git identity is required for raw benchmark evidence")

    artifact = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": CORPUS_VERSION,
        "suite": "scanning.public-api",
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
        "cases": [
            _run_case(case, repo_root=repo_root, profile=profile, warmups=warmups, repetitions=repetitions)
            for case in selected
        ],
    }
    validate_raw_artifact(artifact)
    return artifact


def _run_case(
    case: EvidenceCase,
    *,
    repo_root: Path,
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    exercise = _EXERCISES[case.case_id]
    validation = exercise(repo_root)
    if not validation["work"].get("correct"):
        raise EvidenceFailure(f"{case.case_id}: deterministic validation failed")
    for _ in range(warmups):
        exercise(repo_root)
    observations = [exercise(repo_root) for _ in range(repetitions)]
    if not all(observation["work"].get("correct") for observation in observations):
        raise EvidenceFailure(f"{case.case_id}: an observation failed correctness")

    manifest = case.manifest(profile)
    expected = validation["expected"]
    corpus = validation["corpus"]
    fingerprint_payload = semantic_fingerprint_payload(manifest, corpus, expected)
    return {
        "case_id": case.case_id,
        "tier": case.tier,
        "layer": case.layer,
        "comparison_class": case.comparison_class,
        "semantic_fingerprint_payload": fingerprint_payload,
        "semantic_fingerprint": semantic_fingerprint(fingerprint_payload),
        "manifest": manifest,
        "corpus": corpus,
        "expected": expected,
        "observations": [
            {
                "duration_ns": max(1, int(observation["duration_ns"])),
                "throughput_mib_s": float(observation.get("throughput_mib_s", 0.0)),
                "work": observation["work"],
            }
            for observation in observations
        ],
        "summary": {
            "duration_ns": summarize([float(observation["duration_ns"]) for observation in observations]),
            "throughput_mib_s": summarize(
                [float(observation.get("throughput_mib_s", 0.0)) for observation in observations]
            ),
            "all_correct": True,
        },
        "status": "complete",
    }


def _fastmcp_contract(_repo_root: Path) -> dict[str, Any]:
    calls: list[ScanInput] = []
    server = FastMCP("scanning-public-evidence")

    async def handler(request: ScanInput, _context):
        calls.append(request)
        if request.mode == "first":
            return FirstScanSuccess(
                success=True,
                mode="first",
                match=ScanHit(address="0x1000", module="target.dll", module_offset="0x10"),
                status=ScanStatus(termination="first_hit", read_gaps_detected=False),
            )
        if request.mode == "count":
            return CountScanSuccess(
                success=True,
                mode="count",
                count=5000,
                observation="complete_traversal",
                status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
            )
        return AddressScanSuccess(
            success=True,
            mode="addresses",
            matches=[],
            returned_count=0,
            sequence_returned_count=0,
            next_cursor=None,
            status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
        )

    register_strict_model_tool(
        server,
        name="scan",
        description="Strict scanning evidence tool",
        input_model=ScanInput,
        output_model=ScanResponse,
        handler=handler,
        validation_failure_mapper=scan_input_validation_failure,
    )

    async def scenario() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        tools = await server.list_tools()
        if len(tools) != 1:
            raise EvidenceFailure("FastMCP evidence server registered an unexpected tool set")
        tool = tools[0]
        invalid_result = await server.call_tool("scan", {"pattern": "AA", "legacy": True})
        if len(calls) != 0:
            raise EvidenceFailure("unknown FastMCP input reached the handler")
        outputs: list[dict[str, Any]] = []
        for arguments in (
            {"pattern": "AA"},
            {"pattern": "AA", "mode": "first"},
            {"pattern": "AA", "mode": "count"},
        ):
            result = await server.call_tool("scan", arguments)
            if not isinstance(result, tuple):
                raise EvidenceFailure("FastMCP call did not return structured content")
            _content, structured = result
            outputs.append(structured)
        if not isinstance(invalid_result, tuple):
            raise EvidenceFailure("FastMCP invalid call did not return structured content")
        _invalid_content, invalid_structured = invalid_result
        return invalid_structured, outputs, tool.inputSchema, tool.outputSchema

    started = time.perf_counter_ns()
    invalid, outputs, input_schema, output_schema = asyncio.run(scenario())
    duration_ns = time.perf_counter_ns() - started
    expected_properties = {
        "pattern",
        "scope",
        "mode",
        "limit",
        "max_matches",
        "timeout_ms",
        "diagnostics",
        "cursor",
    }
    flat_outputs = all("result" not in output for output in outputs)
    correct = (
        invalid
        == {
            "success": False,
            "error": "INVALID_ARGUMENT",
            "detail": "Unknown scan argument 'legacy'",
            "field": "legacy",
        }
        and len(calls) == 3
        and set(input_schema.get("properties", {})) == expected_properties
        and "anyOf" in output_schema
        and flat_outputs
        and [output.get("mode") for output in outputs] == ["addresses", "first", "count"]
    )
    if not correct:
        raise EvidenceFailure("FastMCP strict flat-contract evidence differs from the expected boundary")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {
            "kind": "fastmcp-in-memory",
            "input_schema_sha256": sha256_json(input_schema),
            "output_schema_sha256": sha256_json(output_schema),
        },
        "expected": {
            "unknown_rejected_before_handler": True,
            "handler_calls": 3,
            "flat_structured_union": True,
            "modes": ["addresses", "first", "count"],
        },
        "work": {
            "correct": correct,
            "unknown_rejected_before_handler": True,
            "invalid_response": invalid,
            "handler_calls": len(calls),
            "flat_structured_union": flat_outputs,
            "modes": [output.get("mode") for output in outputs],
            "input_schema_bytes": len(json.dumps(input_schema, sort_keys=True, separators=(",", ":")).encode()),
            "output_schema_bytes": len(json.dumps(output_schema, sort_keys=True, separators=(",", ":")).encode()),
        },
    }


def _formatting_sizes(_repo_root: Path) -> dict[str, Any]:
    status = ScanStatus(termination="scope_exhausted", read_gaps_detected=False)
    sizes: dict[str, int] = {}
    durations: dict[str, int] = {}
    started_total = time.perf_counter_ns()
    for count in (1, 100, 500):
        response = AddressScanSuccess(
            success=True,
            mode="addresses",
            matches=[
                ScanHit(address=f"0x{_BASE_ADDRESS + index:X}", module=None, module_offset=None)
                for index in range(count)
            ],
            returned_count=count,
            sequence_returned_count=count,
            next_cursor=None,
            status=status,
        )
        started = time.perf_counter_ns()
        payload = response.model_dump_json(exclude_none=False).encode("utf-8")
        durations[f"addresses_{count}"] = max(1, time.perf_counter_ns() - started)
        sizes[f"addresses_{count}"] = len(payload)
    count_response = CountScanSuccess(
        success=True,
        mode="count",
        count=5000,
        observation="complete_traversal",
        status=status,
    )
    started = time.perf_counter_ns()
    count_payload = count_response.model_dump_json(exclude_none=False).encode("utf-8")
    durations["count_5000"] = max(1, time.perf_counter_ns() - started)
    sizes["count_5000"] = len(count_payload)
    duration_ns = time.perf_counter_ns() - started_total
    correct = sizes["addresses_1"] < sizes["addresses_100"] < sizes["addresses_500"]
    if not correct:
        raise EvidenceFailure("serialized address output size is not monotonic")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "validated-response-models", "retained_counts": [1, 100, 500, 5000]},
        "expected": {
            "address_counts": [1, 100, 500],
            "count_value": 5000,
            "monotonic_address_size": True,
        },
        "work": {
            "correct": correct,
            "serialized_bytes": sizes,
            "serialization_duration_ns": durations,
            "count_5000_is_summary_only": True,
        },
    }


def _lua_normalization(_repo_root: Path) -> dict[str, Any]:
    pointer_value = 0x12345678
    memory = bytearray(512)
    memory[8:10] = bytes.fromhex("DE AD")
    memory[32:40] = b"memscope"
    memory[64:80] = "memscope".encode("utf-16le")
    memory[96:104] = pointer_value.to_bytes(8, "little")
    executor, session, reads, scope = _make_executor(bytes(memory))
    engine = MemscopeLuaEngine()
    logged_errors: list[str] = []
    adapter = LuaScanAdapter(
        executor,
        engine=engine,
        table_factory=engine.lua.table,
        log_error=lambda name, error: logged_errors.append(f"{name}:{type(error).__name__}"),
    )
    options = {
        "scope": scope.model_dump(mode="python"),
        "mode": "addresses",
        "max_matches": 10,
        "diagnostics": True,
    }

    started = time.perf_counter_ns()
    aob = engine._lua_to_python(adapter.aob_scan("DE AD", options))
    ascii_result = engine._lua_to_python(adapter.string_scan("memscope", {**options, "encoding": "ascii"}))
    utf16_result = engine._lua_to_python(adapter.string_scan("memscope", {**options, "encoding": "utf-16le"}))
    pointer_result = engine._lua_to_python(adapter.pointer_scan(pointer_value, {**options, "alignment": 1}))
    batch_result = engine._lua_to_python(
        adapter.aob_scan_many(
            [
                {"key": "aob", "pattern": "DE AD"},
                {"key": "ascii", "pattern": "6D 65 6D 73 63 6F 70 65"},
            ],
            {
                "scope": scope.model_dump(mode="python"),
                "mode": "first",
                "diagnostics": True,
            },
        )
    )
    invalid_value, invalid_error = adapter.aob_scan("DE AD", {**options, "legacy": True})
    invalid = engine._lua_to_python(invalid_error)
    duration_ns = time.perf_counter_ns() - started

    correct = (
        aob[1] == _BASE_ADDRESS + 8
        and ascii_result[1] == _BASE_ADDRESS + 32
        and utf16_result[1] == _BASE_ADDRESS + 64
        and pointer_result[1] == _BASE_ADDRESS + 96
        and aob["metadata"]["mode"] == "addresses"
        and batch_result[1]["key"] == "aob"
        and batch_result[2]["key"] == "ascii"
        and batch_result["metadata"]["mode"] == "first"
        and invalid_value is None
        and invalid["error"] == "INVALID_ARGUMENT"
        and invalid["field"] == "options.legacy"
        and not logged_errors
    )
    if not correct:
        raise EvidenceFailure("Lua normalization or result formatting differs from the strict adapter contract")
    if session.active != 0 or not session.released.is_set():
        raise EvidenceFailure("Lua adapter retained its scan lease")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "fake-range", "size": len(memory), "sha256": sha256_bytes(bytes(memory))},
        "expected": {
            "aob": _BASE_ADDRESS + 8,
            "ascii": _BASE_ADDRESS + 32,
            "utf16le": _BASE_ADDRESS + 64,
            "pointer": _BASE_ADDRESS + 96,
            "unknown_field": "options.legacy",
        },
        "work": {
            "correct": correct,
            "aob_address": aob[1],
            "ascii_address": ascii_result[1],
            "utf16le_address": utf16_result[1],
            "pointer_address": pointer_result[1],
            "batch_keys": [batch_result[1]["key"], batch_result[2]["key"]],
            "unknown_error": invalid,
            "physical_read_calls": len(reads),
            "lease_released": session.active == 0 and session.released.is_set(),
        },
    }


def _lua_serialization(_repo_root: Path) -> dict[str, Any]:
    engine = MemscopeLuaEngine()
    first_entered = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_entered = threading.Event()
    entry_order: list[str] = []
    results: list[dict[str, Any]] = []
    active = 0
    maximum_active = 0
    active_lock = threading.Lock()

    def block() -> int:
        nonlocal active, maximum_active
        with active_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        entry_order.append("block")
        first_entered.set()
        if not release_first.wait(2):
            raise EvidenceFailure("serialized Lua call was not released")
        with active_lock:
            active -= 1
        return 1

    def mark() -> int:
        nonlocal active, maximum_active
        with active_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        entry_order.append("mark")
        second_entered.set()
        with active_lock:
            active -= 1
        return 7

    engine.register_functions("scanning-evidence", {"block": block, "mark": mark})

    def run_first() -> None:
        results.append(engine.execute("return block()"))

    def run_second() -> None:
        second_started.set()
        results.append(engine.execute("return mark()"))

    first = threading.Thread(target=run_first)
    second = threading.Thread(target=run_second)
    started = time.perf_counter_ns()
    first.start()
    if not first_entered.wait(2):
        raise EvidenceFailure("first Lua execution did not enter")
    second.start()
    if not second_started.wait(2):
        raise EvidenceFailure("second Lua execution did not start")
    observed_locked_runtime = engine._execution_lock.locked() and not second_entered.is_set()
    release_first.set()
    first.join(2)
    second.join(2)
    duration_ns = time.perf_counter_ns() - started

    correct = (
        observed_locked_runtime
        and not first.is_alive()
        and not second.is_alive()
        and maximum_active == 1
        and entry_order == ["block", "mark"]
        and len(results) == 2
        and all(result.get("success") for result in results)
    )
    if not correct:
        raise EvidenceFailure("mutable Lua runtime was not serialized across callers")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {"kind": "concurrent-lua-callers", "threads": 2},
        "expected": {"maximum_active_callbacks": 1, "entry_order": ["block", "mark"]},
        "work": {
            "correct": correct,
            "execution_lock_observed": observed_locked_runtime,
            "maximum_active_callbacks": maximum_active,
            "entry_order": entry_order,
            "threads_completed": not first.is_alive() and not second.is_alive(),
        },
    }


def _clean_break(repo_root: Path) -> dict[str, Any]:
    production = repo_root / "memscope_mcp"
    started = time.perf_counter_ns()
    source_paths = sorted(path for path in production.rglob("*.py") if "__pycache__" not in path.parts)
    production_text = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)
    surviving_terms = sorted(term for term in _REMOVED_RUNTIME_TERMS if term in production_text)
    removed_paths = {
        "memscope_mcp/tools/scanning.py": not (production / "tools" / "scanning.py").exists(),
        "memscope_mcp/tools/lua/scanning_helpers.py": not (
            production / "tools" / "lua" / "scanning_helpers.py"
        ).exists(),
        "memscope_mcp/utils/pattern.py": not (production / "utils" / "pattern.py").exists(),
    }
    instructions = ModuleScanExtension.instructions
    register_source = inspect.getsource(ModuleScanExtension.register)
    helper_presence = {name: f'"{name}"' in register_source for name in _SCAN_HELPERS}
    instructions_named_only = (
        "AOBScan(pattern, options?)" in instructions
        and "AOBScanMany(patterns, options?)" in instructions
        and "scanString(text, options?)" in instructions
        and "scanPointer(target, options?)" in instructions
        and "Expected failures return `nil, error_table`" in instructions
        and "start?, end?, limit?" not in instructions
        and "AOBScanModule" not in instructions
    )
    duration_ns = time.perf_counter_ns() - started
    correct = (
        not surviving_terms
        and all(removed_paths.values())
        and all(helper_presence.values())
        and instructions_named_only
    )
    if not correct:
        raise EvidenceFailure("clean-break audit found a removed surface or incomplete replacement registration")
    return {
        "duration_ns": duration_ns,
        "throughput_mib_s": 0.0,
        "corpus": {
            "kind": "production-source-audit",
            "python_files": len(source_paths),
            "production_sha256": sha256_bytes(production_text.encode("utf-8")),
        },
        "expected": {
            "surviving_removed_terms": [],
            "removed_paths_absent": True,
            "registered_scan_helpers": list(_SCAN_HELPERS),
            "instructions_named_only": True,
        },
        "work": {
            "correct": correct,
            "surviving_removed_terms": surviving_terms,
            "removed_paths": removed_paths,
            "registered_scan_helpers": helper_presence,
            "instructions_named_only": instructions_named_only,
        },
    }


def _make_lease() -> ScanLease:
    return ScanLease(
        generation=1,
        pid=123,
        process_handle=1,
        target_process="Target.exe",
        modules=ModuleSnapshot.create((), generation=1),
        lifecycle_cancel=threading.Event(),
    )


def _make_executor(
    memory: bytes,
    *,
    base: int = _BASE_ADDRESS,
) -> tuple[ScanExecutor, TrackingSession, list[tuple[int, int]], RangeScopeInput]:
    session = TrackingSession(_make_lease())
    reads: list[tuple[int, int]] = []

    def query(_handle: int, address: int):
        if not base <= address < base + len(memory):
            raise OSError(f"unmapped address 0x{address:X}")
        return SimpleNamespace(
            BaseAddress=base,
            RegionSize=len(memory),
            State=MEM_COMMIT,
            Protect=PAGE_READWRITE,
            Type=MEM_PRIVATE,
        )

    def read(_handle: int, address: int, size: int) -> bytes:
        reads.append((address, size))
        offset = address - base
        return memory[offset : offset + size]

    executor = ScanExecutor(
        session,
        cursor_codec=CursorCodec(secret=b"p" * 32, instance_id=b"a" * 16),
        query_memory=query,
        read_memory=read,
        target_alive=lambda _handle: True,
        chunk_size=128,
        page_size=1,
    )
    return executor, session, reads, RangeScopeInput(kind="range", start=base, end_exclusive=base + len(memory))


_EXERCISES: dict[str, Callable[[Path], dict[str, Any]]] = {
    "public.fastmcp.strict_flat_contract": _fastmcp_contract,
    "public.output.formatting_sizes": _formatting_sizes,
    "public.lua.normalization_and_formatting": _lua_normalization,
    "public.lua.serialized_runtime": _lua_serialization,
    "public.clean_break.audit": _clean_break,
}


def _select_cases(case_ids: tuple[str, ...] | None) -> tuple[EvidenceCase, ...]:
    if case_ids is None:
        return CASES
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("case_ids must not contain duplicates")
    unknown = sorted(set(case_ids) - CASE_BY_ID.keys())
    if unknown:
        raise ValueError(f"unknown public evidence case_ids: {', '.join(unknown)}")
    wanted = set(case_ids)
    return tuple(case for case in CASES if case.case_id in wanted)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    parser.add_argument("--warmups", type=int, default=0)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--implementation-label", default="candidate")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    artifact = run_public_api_suite(
        repo_root=repo_root,
        profile=arguments.profile,
        warmups=arguments.warmups,
        repetitions=arguments.repetitions,
        implementation_label=arguments.implementation_label,
        case_ids=None if arguments.case_ids is None else tuple(arguments.case_ids),
    )
    if arguments.output is not None:
        write_raw_artifact(arguments.output, artifact)
    else:
        print(json.dumps(artifact, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
