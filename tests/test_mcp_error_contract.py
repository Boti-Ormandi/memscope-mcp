"""MCP wrapper boundary error normalization tests."""

import time

import memscope_mcp.server as server


def test_failure_mirrors_detail_to_error_detail():
    result = server._normalize_tool_result({"success": False, "error": "BAD_INPUT", "detail": "bad input"})

    assert result == {
        "success": False,
        "error": "BAD_INPUT",
        "detail": "bad input",
        "error_detail": "bad input",
    }


def test_failure_mirrors_error_detail_to_detail():
    result = server._normalize_tool_result({"success": False, "error": "READ_ERROR", "error_detail": "read failed"})

    assert result == {
        "success": False,
        "error": "READ_ERROR",
        "detail": "read failed",
        "error_detail": "read failed",
    }


def test_process_not_attached_is_canonicalized_with_source_error():
    result = server._normalize_tool_result(
        {
            "success": False,
            "error": "PROCESS_NOT_ATTACHED",
            "error_detail": "Call attach first",
            "address": "0x1000",
            "type_name": "int32",
        }
    )

    assert result["success"] is False
    assert result["error"] == "NOT_ATTACHED"
    assert result["source_error"] == "PROCESS_NOT_ATTACHED"
    assert result["detail"] == "Call attach first"
    assert result["error_detail"] == "Call attach first"
    assert result["address"] == "0x1000"
    assert result["type_name"] == "int32"


def test_error_key_without_success_is_a_failure_with_synthesized_detail():
    result = server._normalize_tool_result({"error": "VALUE_LENGTH_MISMATCH", "expected": 4, "got": 3})

    assert result == {
        "success": False,
        "error": "VALUE_LENGTH_MISMATCH",
        "detail": "VALUE_LENGTH_MISMATCH",
        "error_detail": "VALUE_LENGTH_MISMATCH",
        "expected": 4,
        "got": 3,
    }


def test_success_false_without_error_gets_generic_error_code():
    result = server._normalize_tool_result({"success": False, "detail": "operation failed", "hint": "retry"})

    assert result == {
        "success": False,
        "error": "ERROR",
        "detail": "operation failed",
        "error_detail": "operation failed",
        "hint": "retry",
    }


def test_success_shape_without_success_key_is_not_misclassified():
    result = {"scripts": [], "count": 0}

    normalized = server._normalize_tool_result(result)

    assert normalized == {"scripts": [], "count": 0}
    assert "success" not in normalized
    assert "error" not in normalized


def test_log_sends_normalized_result_to_logger(monkeypatch):
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
        "error_detail": "Call attach first",
        "hint": "attach to a process",
    }

    returned = server._log("read", {"address": "0x1000"}, lower_result, time.perf_counter())

    assert returned["error"] == "NOT_ATTACHED"
    assert returned["source_error"] == "PROCESS_NOT_ATTACHED"
    assert returned["detail"] == "Call attach first"
    assert returned["error_detail"] == "Call attach first"
    assert returned["hint"] == "attach to a process"
    assert seen["tool"] == "read"
    assert seen["args"] == {"address": "0x1000"}
    assert seen["result"] == returned
    assert seen["duration_ms"] >= 0
    assert lower_result["error"] == "PROCESS_NOT_ATTACHED"
