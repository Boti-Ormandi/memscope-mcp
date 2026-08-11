"""Tests for saved Lua script execution routing."""

import pytest

import memscope_mcp.extensions.bootstrap as bootstrap_mod
import memscope_mcp.tools.lua.engine as lua_engine
import memscope_mcp.tools.lua_engine as lua_engine_compat
from memscope_mcp.extensions.base import LuaExtension
from memscope_mcp.extensions.bootstrap import bootstrap_extensions
from memscope_mcp.session import DebugSession
from memscope_mcp.tools import lua_scripts
from memscope_mcp.tools.lua.engine import MemscopeLuaEngine


@pytest.fixture(autouse=True)
def isolated_lua_scripts(tmp_path, monkeypatch):
    monkeypatch.setattr(lua_scripts, "SCRIPTS_DIR", tmp_path)


def make_composition(monkeypatch, session=None, core_extensions=()):
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", core_extensions)
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
    session = session or DebugSession()
    engine = MemscopeLuaEngine()
    bootstrap_extensions(engine, session)
    return engine, session


def test_lua_engine_compat_reexports_canonical_execute_lua():
    assert lua_engine_compat.execute_lua is lua_engine.execute_lua


def write_script(scripts_dir, process="Target.exe", name="probe", source="-- test script\nreturn 1\n"):
    script_path = scripts_dir / process / f"{name}.lua"
    script_path.parent.mkdir(parents=True)
    script_path.write_text(source, encoding="utf-8")
    return script_path


def test_run_without_process_ignores_stale_target_when_detached(tmp_path, monkeypatch):
    write_script(tmp_path, process="Stale.exe")
    engine, session = make_composition(monkeypatch)
    session.target_process = "Stale.exe"

    def fail_execute(*_args, **_kwargs):
        raise AssertionError("run_script should not execute without an attached process or explicit namespace")

    monkeypatch.setattr(engine, "execute", fail_execute)

    result = lua_scripts.run_script("probe", engine=engine)

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
    engine, _session = make_composition(monkeypatch)

    def fake_execute(script, args=None, timeout=None):
        calls.append((script, args, timeout))
        return {"success": True, "results": {"return": args["needle"]}, "output": []}

    monkeypatch.setattr(engine, "execute", fake_execute)

    result = lua_scripts.run_script("probe", process="Target.exe", args={"needle": 7}, timeout=2.5, engine=engine)

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
    engine, session = make_composition(monkeypatch)
    session.pm = object()
    session.target_process = "Target.exe"
    session.pid = 4242

    def fake_execute(script, args=None, timeout=None):
        calls.append((script, args, timeout))
        return {"success": True, "results": {"return": 1}, "output": []}

    monkeypatch.setattr(engine, "execute", fake_execute)

    result = lua_scripts.run_script("probe", process="Target.exe", engine=engine)

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


def test_run_with_implicit_attached_process_reports_no_requested_process(tmp_path, monkeypatch):
    source = "-- implicit attached probe\nreturn 1\n"
    script_path = write_script(tmp_path, source=source)
    calls = []
    engine, session = make_composition(monkeypatch)
    session.pm = object()
    session.target_process = "Target.exe"
    session.pid = 4242

    def fake_execute(script, args=None, timeout=None):
        calls.append((script, args, timeout))
        return {"success": True, "results": {"return": 1}, "output": []}

    monkeypatch.setattr(engine, "execute", fake_execute)

    result = lua_scripts.run_script("probe", engine=engine)

    assert calls == [(source, None, None)]
    assert result == {
        "success": True,
        "results": {"return": 1},
        "output": [],
        "requested_process": None,
        "attached_process": "Target.exe",
        "attached_pid": 4242,
        "detached_execution": False,
        "script_name": "probe",
        "script_path": str(script_path),
        "script_description": "implicit attached probe",
    }


def test_run_with_different_attached_process_fails_without_executing(tmp_path, monkeypatch):
    write_script(tmp_path, process="Other.exe")
    engine, session = make_composition(monkeypatch)
    session.pm = object()
    session.target_process = "Target.exe"
    session.pid = 4242

    def fail_execute(*_args, **_kwargs):
        raise AssertionError("run_script should not execute with a mismatched attached process")

    monkeypatch.setattr(engine, "execute", fail_execute)

    result = lua_scripts.run_script("probe", process="Other.exe", engine=engine)

    assert result["success"] is False
    assert result["error"] == "PROCESS_MISMATCH"
    assert "process namespace 'Other.exe'" in result["detail"]
    assert "attached to 'Target.exe'" in result["detail"]
    assert result["requested_process"] == "Other.exe"
    assert result["attached_process"] == "Target.exe"
    assert result["attached_pid"] == 4242
    assert result["detached_execution"] is False


def test_script_not_found_failure_includes_run_metadata(tmp_path, monkeypatch):
    engine, session = make_composition(monkeypatch)
    session.pm = object()
    session.target_process = "Target.exe"
    session.pid = 4242

    result = lua_scripts.run_script("missing", engine=engine)

    assert result["success"] is False
    assert result["error"] == "SCRIPT_NOT_FOUND"
    assert result["requested_process"] is None
    assert result["attached_process"] == "Target.exe"
    assert result["attached_pid"] == 4242
    assert result["detached_execution"] is False


def test_script_helpers_require_explicit_composition_inputs():
    with pytest.raises(TypeError, match="session"):
        lua_scripts.list_scripts("*")
    with pytest.raises(TypeError, match="session"):
        lua_scripts.get_script_count()
    with pytest.raises(TypeError, match="engine"):
        lua_scripts.run_script("probe", process="Target.exe")


def test_unbound_run_script_fails_before_script_lookup_or_execution(monkeypatch):
    class LookupTrap:
        def __truediv__(self, _other):
            raise AssertionError("run_script must reject an unbound engine before script lookup")

    engine = MemscopeLuaEngine()
    monkeypatch.setattr(lua_scripts, "SCRIPTS_DIR", LookupTrap())
    monkeypatch.setattr(
        engine,
        "execute",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("run_script must reject an unbound engine before execution")
        ),
    )

    with pytest.raises(
        RuntimeError,
        match=(
            r"^MemscopeLuaEngine composition is not ready; "
            r"bootstrap_extensions\(\) must complete successfully first$"
        ),
    ):
        lua_scripts.run_script("probe", process="Target.exe", engine=engine)


def test_failed_bootstrap_run_script_rejects_before_metadata_lookup_or_execution(monkeypatch):
    class BrokenCore(LuaExtension):
        name = "broken"

        def register(self, ctx):
            raise RuntimeError("hard failure")

    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (BrokenCore,))
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
    engine = MemscopeLuaEngine()
    session = DebugSession()
    with pytest.raises(RuntimeError, match="hard failure"):
        bootstrap_extensions(engine, session)

    def trap(*_args, **_kwargs):
        raise AssertionError("failed engine must reject before metadata lookup")

    class LookupTrap:
        def __truediv__(self, _other):
            raise AssertionError("failed engine must reject before script lookup")

    monkeypatch.setattr(lua_scripts, "_get_attached_process_name", trap)
    monkeypatch.setattr(lua_scripts, "_get_attached_pid", trap)
    monkeypatch.setattr(lua_scripts, "SCRIPTS_DIR", LookupTrap())
    monkeypatch.setattr(
        engine,
        "execute",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("failed engine must reject before execution")),
    )

    with pytest.raises(
        RuntimeError,
        match=(
            r"^MemscopeLuaEngine composition is not ready; "
            r"bootstrap_extensions\(\) must complete successfully first$"
        ),
    ):
        lua_scripts.run_script("probe", process="Target.exe", engine=engine)


def test_two_compositions_run_same_saved_script_with_own_session_identity(tmp_path, monkeypatch):
    class SessionIdentityExtension(LuaExtension):
        name = "session_identity"

        def register(self, ctx):
            return {"sessionPid": lambda: ctx.session.pid}

    source = "-- composition identity\nreturn sessionPid()\n"
    script_path = write_script(tmp_path, process="Shared.exe", source=source)
    session_a = DebugSession(pm=object(), target_process="Shared.exe", pid=101)
    session_b = DebugSession(pm=object(), target_process="Shared.exe", pid=202)
    engine_a, _ = make_composition(monkeypatch, session_a, (SessionIdentityExtension,))
    engine_b, _ = make_composition(monkeypatch, session_b, (SessionIdentityExtension,))

    result_a = lua_scripts.run_script("probe", engine=engine_a)
    result_b = lua_scripts.run_script("probe", engine=engine_b)

    assert result_a["results"]["return"] == 101
    assert result_b["results"]["return"] == 202
    assert result_a["attached_pid"] == 101
    assert result_b["attached_pid"] == 202
    assert result_a["attached_process"] == result_b["attached_process"] == "Shared.exe"
    assert result_a["requested_process"] is result_b["requested_process"] is None
    assert result_a["script_path"] == result_b["script_path"] == str(script_path)
