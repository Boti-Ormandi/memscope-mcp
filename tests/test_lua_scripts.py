"""Tests for saved Lua script execution routing."""

import pytest

import memscope_mcp.tools.lua_engine as lua_engine_compat
from memscope_mcp.tools import lua_scripts


@pytest.fixture(autouse=True)
def isolated_lua_scripts(tmp_path, monkeypatch):
    monkeypatch.setattr(lua_scripts, "SCRIPTS_DIR", tmp_path)
    monkeypatch.setattr(lua_scripts.SESSION, "pm", None)
    monkeypatch.setattr(lua_scripts.SESSION, "target_process", "")
    monkeypatch.setattr(lua_scripts.SESSION, "pid", 0)


def write_script(scripts_dir, process="Target.exe", name="probe", source="-- test script\nreturn 1\n"):
    script_path = scripts_dir / process / f"{name}.lua"
    script_path.parent.mkdir(parents=True)
    script_path.write_text(source, encoding="utf-8")
    return script_path


def test_run_without_process_ignores_stale_target_when_detached(tmp_path, monkeypatch):
    write_script(tmp_path, process="Stale.exe")
    monkeypatch.setattr(lua_scripts.SESSION, "target_process", "Stale.exe")

    def fail_execute_lua(*_args, **_kwargs):
        raise AssertionError("run_script should not execute without an attached process or explicit namespace")

    monkeypatch.setattr(lua_engine_compat, "execute_lua", fail_execute_lua)

    result = lua_scripts.run_script("probe")

    assert result == {
        "success": False,
        "error": "NOT_ATTACHED",
        "detail": "Must be attached to determine process, or pass process='ProcessName.exe'",
        "requested_process": None,
        "attached_process": None,
        "attached_pid": None,
        "detached_execution": False,
    }


def test_run_with_explicit_process_executes_while_detached(tmp_path, monkeypatch):
    source = "-- detached probe\nreturn args.needle\n"
    script_path = write_script(tmp_path, source=source)
    calls = []

    def fake_execute_lua(script, args=None, timeout=None):
        calls.append((script, args, timeout))
        return {"success": True, "results": {"return": args["needle"]}, "output": []}

    monkeypatch.setattr(lua_engine_compat, "execute_lua", fake_execute_lua)

    result = lua_scripts.run_script("probe", process="Target.exe", args={"needle": 7}, timeout=2.5)

    assert calls == [(source, {"needle": 7}, 2.5)]
    assert result == {
        "success": True,
        "results": {"return": 7},
        "output": [],
        "requested_process": "Target.exe",
        "attached_process": None,
        "attached_pid": None,
        "detached_execution": True,
        "script_name": "probe",
        "script_path": str(script_path),
        "script_description": "detached probe",
    }


def test_run_with_matching_attached_process_executes(tmp_path, monkeypatch):
    source = "-- attached probe\nreturn 1\n"
    script_path = write_script(tmp_path, source=source)
    calls = []
    monkeypatch.setattr(lua_scripts.SESSION, "pm", object())
    monkeypatch.setattr(lua_scripts.SESSION, "target_process", "Target.exe")
    monkeypatch.setattr(lua_scripts.SESSION, "pid", 4242)

    def fake_execute_lua(script, args=None, timeout=None):
        calls.append((script, args, timeout))
        return {"success": True, "results": {"return": 1}, "output": []}

    monkeypatch.setattr(lua_engine_compat, "execute_lua", fake_execute_lua)

    result = lua_scripts.run_script("probe", process="Target.exe")

    assert calls == [(source, None, None)]
    assert result == {
        "success": True,
        "results": {"return": 1},
        "output": [],
        "requested_process": "Target.exe",
        "attached_process": "Target.exe",
        "attached_pid": 4242,
        "detached_execution": False,
        "script_name": "probe",
        "script_path": str(script_path),
        "script_description": "attached probe",
    }


def test_run_with_different_attached_process_fails_without_executing(tmp_path, monkeypatch):
    write_script(tmp_path, process="Other.exe")
    monkeypatch.setattr(lua_scripts.SESSION, "pm", object())
    monkeypatch.setattr(lua_scripts.SESSION, "target_process", "Target.exe")
    monkeypatch.setattr(lua_scripts.SESSION, "pid", 4242)

    def fail_execute_lua(*_args, **_kwargs):
        raise AssertionError("run_script should not execute with a mismatched attached process")

    monkeypatch.setattr(lua_engine_compat, "execute_lua", fail_execute_lua)

    result = lua_scripts.run_script("probe", process="Other.exe")

    assert result["success"] is False
    assert result["error"] == "PROCESS_MISMATCH"
    assert "process namespace 'Other.exe'" in result["detail"]
    assert "attached to 'Target.exe'" in result["detail"]
    assert result["requested_process"] == "Other.exe"
    assert result["attached_process"] == "Target.exe"
    assert result["attached_pid"] == 4242
    assert result["detached_execution"] is False


def test_script_not_found_failure_includes_run_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(lua_scripts.SESSION, "pm", object())
    monkeypatch.setattr(lua_scripts.SESSION, "target_process", "Target.exe")
    monkeypatch.setattr(lua_scripts.SESSION, "pid", 4242)

    result = lua_scripts.run_script("missing")

    assert result["success"] is False
    assert result["error"] == "SCRIPT_NOT_FOUND"
    assert result["requested_process"] == "Target.exe"
    assert result["attached_process"] == "Target.exe"
    assert result["attached_pid"] == 4242
    assert result["detached_execution"] is False
