"""Strict scan contract and FastMCP boundary tests."""

import asyncio
import json
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from memscope_mcp.scanning.boundary import register_strict_model_tool
from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanSuccess,
    FirstScanSuccess,
    LuaScanFailure,
    ScanFailure,
    ScanHit,
    ScanInput,
    ScanResponse,
    ScanStatus,
    scan_input_validation_failure,
)

SNAPSHOT_DIR = Path(__file__).with_name("snapshots")


def _call(server: FastMCP, arguments: dict) -> dict:
    result = asyncio.run(server.call_tool("scan", arguments))
    assert isinstance(result, tuple)
    _content, structured = result
    return structured


def _make_server(calls: list[ScanInput]) -> FastMCP:
    server = FastMCP("scan-contract-test")

    async def handler(request: ScanInput, _context):
        calls.append(request)
        if request.pattern == "FAIL":
            return ScanFailure(error="INVALID_PATTERN", detail="The compiled pattern is invalid", field="pattern")
        if request.cursor is not None or request.mode == "addresses":
            return AddressScanSuccess(
                success=True,
                mode="addresses",
                matches=[],
                returned_count=0,
                sequence_returned_count=0,
                next_cursor=None,
                status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
            )
        if request.mode == "first":
            return FirstScanSuccess(
                success=True,
                mode="first",
                match=ScanHit(address="0x1000", module="target.dll", module_offset="0x10"),
                status=ScanStatus(termination="first_hit", read_gaps_detected=False),
            )
        return CountScanSuccess(
            success=True,
            mode="count",
            count=3,
            observation="complete_traversal",
            status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
        )

    register_strict_model_tool(
        server,
        name="scan",
        description="Strict scan contract test tool",
        input_model=ScanInput,
        output_model=ScanResponse,
        handler=handler,
        validation_failure_mapper=scan_input_validation_failure,
    )
    return server


def _load_snapshot(name: str) -> dict:
    return json.loads((SNAPSHOT_DIR / name).read_text(encoding="utf-8"))


def test_supported_boundary_dependency_range_is_explicit():
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")

    assert '"mcp[cli]>=1.27,<1.28"' in pyproject
    assert '"pydantic>=2.12,<3"' in pyproject


def test_strict_boundary_requires_async_handlers():
    server = FastMCP("sync-handler-test")

    def handler(_request, _context):
        return ScanFailure(error="INTERNAL_SCAN_ERROR", detail="not called")

    with pytest.raises(TypeError, match="must be async"):
        register_strict_model_tool(
            server,
            name="scan",
            description="test",
            input_model=ScanInput,
            output_model=ScanResponse,
            handler=handler,
            validation_failure_mapper=scan_input_validation_failure,
        )


def test_strict_boundary_rejects_duplicate_tool_names():
    server = _make_server([])

    async def handler(_request, _context):
        return ScanFailure(error="INTERNAL_SCAN_ERROR", detail="not called")

    with pytest.raises(ValueError, match="Tool already exists"):
        register_strict_model_tool(
            server,
            name="scan",
            description="test",
            input_model=ScanInput,
            output_model=ScanResponse,
            handler=handler,
            validation_failure_mapper=scan_input_validation_failure,
        )


def test_real_fastmcp_scan_schemas_match_snapshots():
    server = _make_server([])
    tools = asyncio.run(server.list_tools())

    assert len(tools) == 1
    assert tools[0].inputSchema == _load_snapshot("scan-input-schema.json")
    assert tools[0].outputSchema == _load_snapshot("scan-output-schema.json")
    assert set(tools[0].inputSchema["properties"]) == {
        "pattern",
        "scope",
        "mode",
        "limit",
        "max_matches",
        "timeout_ms",
        "diagnostics",
        "cursor",
    }
    assert "result" not in tools[0].outputSchema.get("properties", {})
    assert "anyOf" in tools[0].outputSchema


@pytest.mark.parametrize(
    "removed_field",
    ["offset", "summary_only", "max_results", "return_offset", "module", "address_min", "address_max"],
)
def test_removed_and_unknown_top_level_fields_are_rejected(removed_field):
    calls: list[ScanInput] = []
    server = _make_server(calls)

    structured = _call(server, {"pattern": "48 8B ??", removed_field: 1})

    assert structured == {
        "success": False,
        "error": "INVALID_ARGUMENT",
        "detail": f"Unknown scan argument '{removed_field}'",
        "field": removed_field,
    }
    assert calls == []


@pytest.mark.parametrize(
    ("arguments", "error", "field"),
    [
        ({}, "INVALID_ARGUMENT", None),
        ({"pattern": "AA", "cursor": "token"}, "INVALID_ARGUMENT", None),
        ({"cursor": "token", "mode": "addresses"}, "INVALID_ARGUMENT", "mode"),
        ({"pattern": "AA", "mode": "first", "limit": 1}, "INVALID_ARGUMENT", "limit"),
        ({"pattern": "AA", "mode": "first", "max_matches": 1}, "INVALID_ARGUMENT", "max_matches"),
        ({"pattern": "AA", "mode": "count", "limit": 1}, "INVALID_ARGUMENT", "limit"),
        ({"pattern": "AA", "mode": "invalid"}, "INVALID_MODE", "mode"),
        ({"pattern": "AA", "timeout_ms": True}, "INVALID_ARGUMENT", "timeout_ms"),
        ({"pattern": "   "}, "INVALID_PATTERN", "pattern"),
        ({"cursor": ""}, "INVALID_CURSOR", "cursor"),
        (
            {"pattern": "AA", "scope": {"kind": "modules", "names": ["a.dll", "A.DLL"]}},
            "INVALID_SCOPE",
            "scope.names",
        ),
        (
            {
                "pattern": "AA",
                "scope": {
                    "kind": "range",
                    "start": "0x1000",
                    "end_exclusive": "0x2000",
                    "filters": {"sections": [".text"]},
                },
            },
            "INVALID_SCOPE",
            "scope.filters.sections",
        ),
    ],
)
def test_invalid_forms_map_to_stable_application_errors(arguments, error, field):
    calls: list[ScanInput] = []
    server = _make_server(calls)

    structured = _call(server, arguments)

    assert structured["success"] is False
    assert structured["error"] == error
    assert structured.get("field") == field
    assert "pydantic" not in structured["detail"].lower()
    assert "validation error" not in structured["detail"].lower()
    assert calls == []


@pytest.mark.parametrize(
    ("arguments", "error", "field"),
    [
        ({"pattern": "AA", "limit": 0}, "INVALID_ARGUMENT", "limit"),
        ({"pattern": "AA", "limit": 501}, "INVALID_ARGUMENT", "limit"),
        ({"pattern": "AA", "max_matches": 0}, "INVALID_ARGUMENT", "max_matches"),
        ({"pattern": "AA", "max_matches": 100_001}, "INVALID_ARGUMENT", "max_matches"),
        ({"pattern": "AA", "timeout_ms": 99}, "INVALID_ARGUMENT", "timeout_ms"),
        ({"pattern": "AA", "timeout_ms": 30_001}, "INVALID_ARGUMENT", "timeout_ms"),
        ({"pattern": "A" * 4097}, "INVALID_PATTERN", "pattern"),
        ({"cursor": "x" * 65_537}, "INVALID_CURSOR", "cursor"),
        (
            {"pattern": "AA", "scope": {"kind": "modules", "names": ["target.dll"], "unknown": True}},
            "INVALID_SCOPE",
            "scope.unknown",
        ),
        (
            {"pattern": "AA", "scope": {"kind": "all_modules", "filters": {"unknown": True}}},
            "INVALID_SCOPE",
            "scope.filters.unknown",
        ),
        (
            {
                "pattern": "AA",
                "scope": {"kind": "range", "start": True, "end_exclusive": "0x2000"},
            },
            "INVALID_SCOPE",
            "scope.start",
        ),
        (
            {"pattern": "AA", "scope": {"kind": "modules", "names": ["x" * 261]}},
            "INVALID_SCOPE",
            "scope.names",
        ),
        (
            {
                "pattern": "AA",
                "scope": {"kind": "all_modules", "filters": {"sections": ["é" * 33]}},
            },
            "INVALID_SCOPE",
            "scope.filters.sections",
        ),
    ],
)
def test_public_bounds_and_nested_strictness_fail_before_handler(arguments, error, field):
    calls: list[ScanInput] = []
    server = _make_server(calls)

    structured = _call(server, arguments)

    assert structured["success"] is False
    assert structured["error"] == error
    assert structured.get("field") == field
    assert calls == []


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (
            {"pattern": "ADDRESSES"},
            {
                "success": True,
                "mode": "addresses",
                "matches": [],
                "returned_count": 0,
                "sequence_returned_count": 0,
                "next_cursor": None,
                "status": {"termination": "scope_exhausted", "read_gaps_detected": False},
                "diagnostics": None,
            },
        ),
        (
            {"pattern": "FIRST", "mode": "first"},
            {
                "success": True,
                "mode": "first",
                "match": {"address": "0x1000", "module": "target.dll", "module_offset": "0x10"},
                "status": {"termination": "first_hit", "read_gaps_detected": False},
                "diagnostics": None,
            },
        ),
        (
            {"pattern": "COUNT", "mode": "count"},
            {
                "success": True,
                "mode": "count",
                "count": 3,
                "observation": "complete_traversal",
                "status": {"termination": "scope_exhausted", "read_gaps_detected": False},
                "diagnostics": None,
            },
        ),
        (
            {"pattern": "FAIL"},
            {
                "success": False,
                "error": "INVALID_PATTERN",
                "detail": "The compiled pattern is invalid",
                "field": "pattern",
            },
        ),
    ],
)
def test_real_fastmcp_structured_content_uses_the_top_level_union(arguments, expected):
    server = _make_server([])

    assert _call(server, arguments) == expected


def test_continuation_accepts_only_cursor_page_controls():
    calls: list[ScanInput] = []
    server = _make_server(calls)

    structured = _call(server, {"cursor": "opaque", "limit": 100, "timeout_ms": 1000, "diagnostics": True})

    assert structured["success"] is True
    assert calls[0].cursor == "opaque"
    assert calls[0].limit == 100
    assert calls[0].timeout_ms == 1000
    assert calls[0].diagnostics is True


def test_mode_specific_output_invariants_are_enforced():
    with pytest.raises(ValidationError):
        AddressScanSuccess(
            success=True,
            mode="addresses",
            matches=[],
            returned_count=1,
            sequence_returned_count=1,
            next_cursor=None,
            status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
        )

    with pytest.raises(ValidationError):
        FirstScanSuccess(
            success=True,
            mode="first",
            match=ScanHit(address="0x1000", module=None, module_offset=None),
            status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
        )

    with pytest.raises(ValidationError):
        CountScanSuccess(
            success=True,
            mode="count",
            count=1,
            observation="complete_traversal",
            status=ScanStatus(termination="timeout", read_gaps_detected=False),
        )


def test_lua_expected_failure_contract_has_no_success_flag_or_null_optionals():
    failure = LuaScanFailure(
        error="MODULE_NOT_FOUND",
        detail="Module 'target.dll' is not loaded",
        field="scope.names[0]",
    )

    assert failure.model_dump(mode="json") == {
        "error": "MODULE_NOT_FOUND",
        "detail": "Module 'target.dll' is not loaded",
        "field": "scope.names[0]",
    }
