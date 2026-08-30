"""MCP wrapper boundary error normalization tests."""

import asyncio
import time

from mcp.types import CallToolResult

import memscope_mcp.server as server


def _call_public_tool(name: str, arguments: dict) -> CallToolResult:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    assert isinstance(result, CallToolResult)
    return result


def test_expected_strict_domain_failure_remains_a_successful_structured_result():
    result = _call_public_tool("scan", {"pattern": "AA", "offset": 1})

    assert result.is_error is False
    assert result.structured_content == {
        "success": False,
        "error": "INVALID_ARGUMENT",
        "detail": "Unknown scan argument 'offset'",
        "field": "offset",
    }


def test_failure_keeps_one_flat_detail_field():
    result = server._normalize_tool_result({"success": False, "error": "BAD_INPUT", "detail": "bad input"})

    assert result == {"success": False, "error": "BAD_INPUT", "detail": "bad input"}


def test_process_not_attached_keeps_wrapper_code_without_source_duplication():
    result = server._normalize_tool_result(
        {
            "success": False,
            "error": "PROCESS_NOT_ATTACHED",
            "detail": "Call attach first",
            "address": "0x1000",
            "type_name": "int32",
        }
    )

    assert result == {
        "success": False,
        "error": "NOT_ATTACHED",
        "detail": "Call attach first",
        "address": "0x1000",
        "type_name": "int32",
    }


def test_error_key_without_success_is_a_failure_with_synthesized_detail():
    result = server._normalize_tool_result({"error": "VALUE_LENGTH_MISMATCH", "expected": 4, "got": 3})

    assert result == {
        "success": False,
        "error": "VALUE_LENGTH_MISMATCH",
        "detail": "VALUE_LENGTH_MISMATCH",
        "expected": 4,
        "got": 3,
    }


def test_success_false_without_error_gets_generic_error_code():
    result = server._normalize_tool_result({"success": False, "detail": "operation failed", "hint": "retry"})

    assert result == {
        "success": False,
        "error": "ERROR",
        "detail": "operation failed",
        "hint": "retry",
    }


def test_success_shape_without_success_key_is_not_misclassified():
    result = {"scripts": [], "count": 0}

    normalized = server._normalize_tool_result(result)

    assert normalized == {"scripts": [], "count": 0}
    assert "success" not in normalized
    assert "error" not in normalized


def test_log_sends_flat_normalized_result_to_logger(monkeypatch):
    seen = {}

    def fake_log(tool, args, result, duration_ms):
        seen["tool"] = tool
        seen["args"] = args
        seen["result"] = result
        seen["duration_ms"] = duration_ms

    monkeypatch.setattr(server.LOGGER, "log", fake_log)
    lower_result = {
        "success": False,
        "error": "PROCESS_NOT_ATTACHED",
        "detail": "Call attach first",
        "hint": "attach to a process",
    }

    returned = server._log("read", {"address": "0x1000"}, lower_result, time.perf_counter())

    assert returned == {
        "success": False,
        "error": "NOT_ATTACHED",
        "detail": "Call attach first",
        "hint": "attach to a process",
    }
    assert seen["tool"] == "read"
    assert seen["args"] == {"address": "0x1000"}
    assert seen["result"] == returned
    assert seen["duration_ms"] >= 0
    assert lower_result["error"] == "PROCESS_NOT_ATTACHED"
