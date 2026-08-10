"""Strict scan contract and public MCPServer boundary tests."""

import asyncio
import inspect
import json
import threading
from pathlib import Path

import pytest
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

import memscope_mcp.server as public_server
from memscope_mcp.scanning.boundary import MemscopeMCPServer, StrictModelToolSpec
from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanSuccess,
    FirstScanManyItem,
    FirstScanManySuccess,
    FirstScanSuccess,
    LuaScanFailure,
    ScanFailure,
    ScanHit,
    ScanInput,
    ScanManyResponse,
    ScanManyShared,
    ScanResponse,
    ScanStatus,
    scan_input_validation_failure,
)

SNAPSHOT_DIR = Path(__file__).with_name("snapshots")


def _call(server: MemscopeMCPServer, arguments: dict) -> dict:
    result = asyncio.run(server.call_tool("scan", arguments))
    assert isinstance(result, CallToolResult)
    assert isinstance(result.structured_content, dict)
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert json.loads(result.content[0].text) == result.structured_content
    return result.structured_content


def _make_server(calls: list[ScanInput]) -> MemscopeMCPServer:
    server = MemscopeMCPServer("scan-contract-test")

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

    server.add_strict_model_tool(
        StrictModelToolSpec(
            name="scan",
            description="Strict scan contract test tool",
            input_model=ScanInput,
            output_model=ScanResponse,
            handler=handler,
            validation_failure_mapper=scan_input_validation_failure,
        )
    )
    return server


def _load_snapshot(name: str) -> dict:
    return json.loads((SNAPSHOT_DIR / name).read_text(encoding="utf-8"))


def _assert_output_schema_matches_snapshot(schema: dict | None, snapshot_name: str) -> None:
    assert schema == _load_snapshot(snapshot_name)


def test_supported_boundary_dependency_range_is_explicit():
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")

    assert '"mcp>=2,<3"' in pyproject
    assert "mcp[cli]" not in pyproject
    assert '"pydantic>=2.12,<3"' in pyproject


def test_strict_boundary_requires_async_handlers():
    server = MemscopeMCPServer("sync-handler-test")

    def handler(_request, _context):
        return ScanFailure(error="INTERNAL_SCAN_ERROR", detail="not called")

    with pytest.raises(TypeError, match="must be async"):
        server.add_strict_model_tool(
            StrictModelToolSpec(
                name="scan",
                description="test",
                input_model=ScanInput,
                output_model=ScanResponse,
                handler=handler,
                validation_failure_mapper=scan_input_validation_failure,
            )
        )


def test_strict_boundary_rejects_duplicate_tool_names():
    server = _make_server([])

    async def handler(_request, _context):
        return ScanFailure(error="INTERNAL_SCAN_ERROR", detail="not called")

    with pytest.raises(ValueError, match="Tool already exists"):
        server.add_strict_model_tool(
            StrictModelToolSpec(
                name="scan",
                description="test",
                input_model=ScanInput,
                output_model=ScanResponse,
                handler=handler,
                validation_failure_mapper=scan_input_validation_failure,
            )
        )


def test_sync_tool_registration_runs_on_the_request_thread_without_changing_the_function():
    server = MemscopeMCPServer("same-thread-test")
    request_thread = threading.get_ident()

    @server.tool()
    def thread_probe(value: int = 7) -> dict:
        return {"thread": threading.get_ident(), "value": value}

    assert inspect.iscoroutinefunction(thread_probe) is False
    assert thread_probe(3) == {"thread": request_thread, "value": 3}

    result = asyncio.run(server.call_tool("thread_probe", {"value": 9}))

    assert isinstance(result, CallToolResult)
    assert result.structured_content is None
    assert isinstance(result.content[0], TextContent)
    payload = json.loads(result.content[0].text)
    assert payload == {"thread": request_thread, "value": 9}


def test_mcpserver_scan_schemas_match_snapshots():
    server = _make_server([])
    tools = asyncio.run(server.list_tools())

    assert len(tools) == 1
    assert tools[0].input_schema == _load_snapshot("scan-input-schema.json")
    _assert_output_schema_matches_snapshot(tools[0].output_schema, "scan-output-schema.json")
    assert set(tools[0].input_schema["properties"]) == {
        "pattern",
        "scope",
        "mode",
        "limit",
        "max_matches",
        "timeout_ms",
        "diagnostics",
        "cursor",
    }
    assert "result" not in tools[0].output_schema.get("properties", {})
    assert "anyOf" in tools[0].output_schema


def test_registered_public_scan_schemas_match_snapshots():
    tools = asyncio.run(public_server.mcp.list_tools())
    scan_tool = next(tool for tool in tools if tool.name == "scan")

    assert scan_tool.input_schema == _load_snapshot("scan-input-schema.json")
    _assert_output_schema_matches_snapshot(scan_tool.output_schema, "scan-output-schema.json")


def test_registered_public_scan_many_schemas_match_snapshots():
    tools = asyncio.run(public_server.mcp.list_tools())
    scan_many_tool = next(tool for tool in tools if tool.name == "scan_many")

    assert scan_many_tool.input_schema == _load_snapshot("scan-many-input-schema.json")
    _assert_output_schema_matches_snapshot(scan_many_tool.output_schema, "scan-many-output-schema.json")
    assert set(scan_many_tool.input_schema["properties"]) == {
        "patterns",
        "scope",
        "mode",
        "max_matches",
        "timeout_ms",
        "diagnostics",
    }
    assert "cursor" not in scan_many_tool.input_schema["properties"]
    assert "limit" not in scan_many_tool.input_schema["properties"]
    assert "anyOf" in scan_many_tool.output_schema


def test_registered_public_scan_many_rejects_raw_invalid_inputs_before_execution(monkeypatch):
    calls = []

    async def fake_execute(_executor, request):
        calls.append(request)
        return ScanManyResponse.model_validate(
            FirstScanManySuccess(
                success=True,
                mode="first",
                results=[
                    FirstScanManyItem(
                        key=request.patterns[0].key,
                        match=None,
                        status=ScanStatus(termination="scope_exhausted", read_gaps_detected=False),
                    )
                ],
                shared=ScanManyShared(termination="scope_exhausted", read_gaps_detected=False),
            )
        )

    monkeypatch.setattr(public_server, "execute_scan_many_async", fake_execute)
    monkeypatch.setattr(public_server.LOGGER, "log", lambda *_args: None)

    invalid_cases = [
        (
            {"patterns": [{"key": "a", "pattern": "AA"}], "legacy": True},
            {
                "success": False,
                "error": "INVALID_ARGUMENT",
                "detail": "Unknown scan_many argument 'legacy'",
                "field": "legacy",
            },
        ),
        (
            {"patterns": [{"key": "a", "pattern": "AA"}, {"key": "a", "pattern": "BB"}]},
            {
                "success": False,
                "error": "INVALID_ARGUMENT",
                "detail": "Batch pattern keys must be unique",
                "field": "patterns[1].key",
            },
        ),
        (
            {"patterns": [{"key": "a", "pattern": "AA"}], "mode": "addresses"},
            {
                "success": False,
                "error": "INVALID_MODE",
                "detail": "Mode must be one of: first, count",
                "field": "mode",
            },
        ),
        (
            {"patterns": [{"key": "a", "pattern": "AA"}], "mode": "first", "max_matches": 1},
            {
                "success": False,
                "error": "INVALID_ARGUMENT",
                "detail": "Mode 'first' does not accept 'max_matches'",
                "field": "max_matches",
            },
        ),
    ]

    for arguments, expected in invalid_cases:
        result = asyncio.run(public_server.mcp.call_tool("scan_many", arguments))
        assert isinstance(result, CallToolResult)
        assert result.structured_content == expected
        assert len(result.content) == 1
        assert isinstance(result.content[0], TextContent)
        assert json.loads(result.content[0].text) == expected
        assert result.is_error is False

    assert calls == []

    valid = asyncio.run(
        public_server.mcp.call_tool(
            "scan_many",
            {"patterns": [{"key": "a", "pattern": "AA"}], "mode": "first"},
        )
    )
    assert isinstance(valid, CallToolResult)
    assert valid.structured_content == {
        "success": True,
        "mode": "first",
        "results": [
            {
                "key": "a",
                "match": None,
                "status": {"termination": "scope_exhausted", "read_gaps_detected": False},
            }
        ],
        "shared": {
            "termination": "scope_exhausted",
            "read_gaps_detected": False,
            "diagnostics": None,
        },
    }
    assert len(valid.content) == 1
    assert isinstance(valid.content[0], TextContent)
    assert json.loads(valid.content[0].text) == valid.structured_content
    assert valid.is_error is False
    assert len(calls) == 1
    assert calls[0].patterns[0].key == "a"


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
def test_mcpserver_structured_content_uses_the_top_level_union(arguments, expected):
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
