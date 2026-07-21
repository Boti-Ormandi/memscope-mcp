"""Session logger hardening tests."""

import hashlib
import json

import memscope_mcp.paths as paths
import memscope_mcp.server as server
from memscope_mcp.session import DebugSession
from memscope_mcp.utils.logger import MAX_CONTAINER_ITEMS, MAX_LUA_PREVIEW_CHARS, MCPLogger


def _entries(logger: MCPLogger) -> list[dict]:
    logger._close_file()
    return [json.loads(line) for line in logger._get_log_file().read_text(encoding="utf-8").splitlines()]


def test_request_ids_are_session_local_and_monotonic(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()

    logger.log("read", {"address": "0x1000"}, {"success": True, "value": 1}, 1.2)
    logger.log("read", {"address": "0x1004"}, {"success": True, "value": 2}, 1.3)

    entries = _entries(logger)

    assert [entry["request_id"] for entry in entries] == [1, 2]


def test_lua_source_is_logged_as_bounded_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()
    source = "\n".join(f"print({i})" for i in range(100))

    logger.log("lua", {"script": source, "timeout": 2.5}, {"success": True, "results": {"ok": True}}, 10.0)

    entry = _entries(logger)[0]
    script = entry["args"]["script"]

    assert script["type"] == "lua_source"
    assert script["length"] == len(source)
    assert script["lines"] == 100
    assert len(script["preview"]) <= MAX_LUA_PREVIEW_CHARS + 3
    assert script["sha256"] == hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert entry["args"]["timeout"] == 2.5
    assert source not in json.dumps(entry, ensure_ascii=False)


def test_large_write_args_and_success_payloads_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()
    payload = "AA" * 500

    logger.log(
        "write",
        {"address": "0x2000", "value": payload, "type_name": "bytes", "verify": True},
        {"success": True, "new_value": payload, "actual_value": payload},
        4.0,
    )

    entry = _entries(logger)[0]

    assert entry["args"]["value"]["type"] == "str"
    assert entry["args"]["value"]["length"] == len(payload)
    assert entry["result"]["new_value"]["type"] == "str"
    assert entry["result"]["actual_value"]["length"] == len(payload)
    assert payload not in json.dumps(entry, ensure_ascii=False)


def test_nested_script_args_are_recursively_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()
    nested_args = {
        "items": [{"payload": "BB" * 300, "index": index} for index in range(MAX_CONTAINER_ITEMS + 3)],
        "empty": {},
    }

    logger.log(
        "scripts",
        {"action": "run", "name": "probe", "args": nested_args, "timeout": None},
        {"success": True, "output": []},
        3.0,
    )

    entry = _entries(logger)[0]
    items = entry["args"]["args"]["items"]

    assert items["type"] == "list"
    assert items["length"] == MAX_CONTAINER_ITEMS + 3
    assert items["truncated_items"] == 3
    assert items["items"][0]["payload"]["type"] == "str"
    assert entry["args"]["args"]["empty"] == {}


def test_success_summary_covers_complete_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()
    result = {"success": True, "modules": [{"name": "target.exe", "base": "0x140000000"}], "total": 1}

    logger.log("modules", {"filter": None, "limit": 30}, result, 2.0)

    entry = _entries(logger)[0]

    assert entry["success"] is True
    assert entry["result"]["modules"] == [{"name": "target.exe", "base": "0x140000000"}]
    assert entry["result"]["total"] == 1


def test_failure_summary_preserves_bounded_extras(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()
    long_output = "trace " * 200
    result = {
        "success": False,
        "error": "BAD_INPUT",
        "detail": "invalid input",
        "hint": "check address syntax",
        "output": [long_output],
        "expected": 4,
        "got": 3,
    }

    logger.log("read", {"address": "bad"}, result, 2.0)

    entry = _entries(logger)[0]

    assert entry["success"] is False
    assert entry["error"] == "BAD_INPUT"
    assert entry["detail"] == "invalid input"
    assert entry["failure"]["hint"] == "check address syntax"
    assert entry["failure"]["expected"] == 4
    assert entry["failure"]["got"] == 3
    assert entry["failure"]["output"][0]["type"] == "str"
    assert long_output not in json.dumps(entry, ensure_ascii=False)


def test_non_json_values_are_summarized_before_jsonl_write(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path)
    logger = MCPLogger()

    logger.log(
        "debug",
        {"nan": float("nan"), "blob": b"\x00\x01" * 40, "path": tmp_path},
        {"success": True, "value": float("inf")},
        1.0,
    )

    entry = _entries(logger)[0]

    assert entry["args"]["nan"] == {"type": "float", "value": "nan"}
    assert entry["args"]["blob"]["type"] == "bytes"
    assert entry["args"]["blob"]["length"] == 80
    assert entry["args"]["path"]["type"] in {"PosixPath", "WindowsPath"}
    assert entry["result"]["value"] == {"type": "float", "value": "inf"}


def test_lua_wrapper_logs_timeout(monkeypatch):
    seen = {}

    def fake_execute_lua(script, timeout=None):
        seen["execute"] = (script, timeout)
        return {"success": True, "results": {}}

    def fake_log(tool, args, result, duration_ms):
        seen["log"] = (tool, args, result, duration_ms)

    monkeypatch.setattr(server, "execute_lua", fake_execute_lua)
    monkeypatch.setattr(server.LOGGER, "log", fake_log)

    result = server.lua("return 1", timeout=2.5)

    assert result == {"success": True, "results": {}}
    assert seen["execute"] == ("return 1", 2.5)
    assert seen["log"][0] == "lua"
    assert seen["log"][1] == {"script": "return 1", "timeout": 2.5}


def test_scripts_wrapper_logs_empty_args_and_timeout(monkeypatch):
    seen = {}

    def fake_run_script(name, process, args, timeout=None):
        seen["run"] = (name, process, args, timeout)
        return {"success": True, "script_name": name}

    def fake_log(tool, args, result, duration_ms):
        seen["log"] = (tool, args, result, duration_ms)

    monkeypatch.setattr(server, "run_script", fake_run_script)
    monkeypatch.setattr(server.LOGGER, "log", fake_log)

    result = server.scripts("run", name="probe", process="Target.exe", args={}, timeout=1.5)

    assert result == {"success": True, "script_name": "probe"}
    assert seen["run"] == ("probe", "Target.exe", {}, 1.5)
    assert seen["log"][0] == "scripts"
    assert seen["log"][1] == {
        "action": "run",
        "name": "probe",
        "process": "Target.exe",
        "args": {},
        "timeout": 1.5,
    }


def test_failed_attach_does_not_keep_stale_log_process(monkeypatch):
    def fake_switch_process(process_name, pid=0):
        return False

    def fake_log(_tool, _args, _result, _duration_ms):
        return None

    monkeypatch.setattr(server.SESSION, "switch_process", fake_switch_process)
    monkeypatch.setattr(server.LOGGER, "_current_process", "Old.exe", raising=False)
    monkeypatch.setattr(server.LOGGER, "log", fake_log)

    result = server.attach("Missing.exe")

    assert result["success"] is False
    assert result["error"] == "PROCESS_NOT_FOUND"
    assert server.LOGGER._current_process is None


def test_session_detach_clears_log_process(monkeypatch):
    class FakeProcess:
        def close_process(self):
            return None

    session = DebugSession(pm=FakeProcess(), target_process="Target.exe", pid=4242)
    monkeypatch.setattr(session, "_is_process_alive", lambda: False)
    monkeypatch.setattr(server.LOGGER, "_current_process", "Target.exe", raising=False)

    session.detach()

    assert server.LOGGER._current_process is None
