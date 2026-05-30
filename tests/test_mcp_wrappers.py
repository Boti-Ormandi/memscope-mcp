"""Direct tests for the public MCP wrapper functions."""

import pytest

import memscope_mcp.server as server


@pytest.fixture(autouse=True)
def disable_session_logging(monkeypatch):
    monkeypatch.setattr(server, "_log", lambda _tool, _args, result, _start_time: result)


def test_scan_forwards_default_arguments_by_keyword(monkeypatch):
    calls = []

    def fake_scan_aob(*args, **kwargs):
        calls.append((args, kwargs))
        return {"success": True, "data": [{"address": "0x1000"}]}

    monkeypatch.setattr(server, "scan_aob", fake_scan_aob)

    result = server.scan("48 8B ??")

    assert result == {"success": True, "data": [{"address": "0x1000"}]}
    assert calls == [
        (
            (),
            {
                "pattern": "48 8B ??",
                "module": None,
                "limit": 50,
                "offset": 0,
                "summary_only": False,
                "address_min": None,
                "address_max": None,
                "max_results": 5000,
                "return_offset": False,
                "timeout_ms": 30000,
            },
        )
    ]


def test_scan_forwards_custom_arguments_by_keyword(monkeypatch):
    calls = []

    def fake_scan_aob(*args, **kwargs):
        calls.append((args, kwargs))
        return {"success": True, "data": [{"address": "0x1000", "module_offset": "target.dll+0x10"}]}

    monkeypatch.setattr(server, "scan_aob", fake_scan_aob)

    result = server.scan(
        "48 8B ??",
        module="target.dll",
        limit=7,
        offset=2,
        summary_only=True,
        address_min="target.dll+0x100",
        address_max="target.dll+0x200",
        max_results=123,
        return_offset=True,
        timeout_ms=1500,
    )

    assert result == {"success": True, "data": [{"address": "0x1000", "module_offset": "target.dll+0x10"}]}
    assert calls == [
        (
            (),
            {
                "pattern": "48 8B ??",
                "module": "target.dll",
                "limit": 7,
                "offset": 2,
                "summary_only": True,
                "address_min": "target.dll+0x100",
                "address_max": "target.dll+0x200",
                "max_results": 123,
                "return_offset": True,
                "timeout_ms": 1500,
            },
        )
    ]


def test_dump_forwards_default_arguments_by_keyword(monkeypatch):
    calls = []

    def fake_smart_dump(*args, **kwargs):
        calls.append((args, kwargs))
        return {"success": True, "entries": []}

    monkeypatch.setattr(server, "smart_dump", fake_smart_dump)

    result = server.dump("module.dll+0x20")

    assert result == {"success": True, "entries": []}
    assert calls == [
        (
            (),
            {
                "address": "module.dll+0x20",
                "size": 0x100,
                "start_offset": 0,
                "pointers_only": False,
                "non_null_only": False,
                "max_entries": 100,
                "annotation_level": "normal",
            },
        )
    ]


def test_dump_forwards_custom_arguments_by_keyword(monkeypatch):
    calls = []

    def fake_smart_dump(*args, **kwargs):
        calls.append((args, kwargs))
        return {"success": True, "entries": [{"offset": "+0x10"}]}

    monkeypatch.setattr(server, "smart_dump", fake_smart_dump)

    result = server.dump(
        "module.dll+0x20",
        size=0x80,
        pointers_only=True,
        start_offset=0x10,
        non_null_only=True,
        max_entries=7,
        annotation_level="full",
    )

    assert result == {"success": True, "entries": [{"offset": "+0x10"}]}
    assert calls == [
        (
            (),
            {
                "address": "module.dll+0x20",
                "size": 0x80,
                "start_offset": 0x10,
                "pointers_only": True,
                "non_null_only": True,
                "max_entries": 7,
                "annotation_level": "full",
            },
        )
    ]


def test_modules_response_includes_module_path_and_tolerates_missing_path(monkeypatch):
    monkeypatch.setattr(server.SESSION, "pm", object())
    monkeypatch.setattr(
        server.SESSION,
        "modules",
        {
            "target.exe": {"base": 0x140000000, "size": 0x2000, "path": r"C:\\Games\\target.exe"},
            "helper.dll": {"base": 0x7FFE0000, "size": 0x1000},
        },
    )

    result = server.modules()

    assert result["success"] is True
    assert result["modules"] == [
        {"name": "target.exe", "base": "0x140000000", "size": 0x2000, "path": r"C:\\Games\\target.exe"},
        {"name": "helper.dll", "base": "0x7FFE0000", "size": 0x1000, "path": ""},
    ]


def test_modules_filter_and_limit_apply_before_formatting(monkeypatch):
    monkeypatch.setattr(server.SESSION, "pm", object())
    monkeypatch.setattr(
        server.SESSION,
        "modules",
        {
            "target.exe": {"base": 0x140000000, "size": 0x2000},
            "helper.dll": {"base": 0x7FFE0000, "size": 0x1000},
            "helper_extra.dll": {"base": 0x7FFF0000, "size": 0x3000},
        },
    )

    result = server.modules(filter="helper", limit=1)

    assert result["success"] is True
    assert result["modules"] == [{"name": "helper.dll", "base": "0x7FFE0000", "size": 0x1000, "path": ""}]
    assert result["total"] == 3


def test_read_wrapper_forwards_to_read_typed(monkeypatch):
    calls = []

    def fake_read_typed(address, type_name, count):
        calls.append((address, type_name, count))
        return {"success": True, "value": [1, 2, 3]}

    monkeypatch.setattr(server, "read_typed", fake_read_typed)

    result = server.read("0x1000", "int32", count=3)

    assert result == {"success": True, "value": [1, 2, 3]}
    assert calls == [("0x1000", "int32", 3)]


def test_write_wrapper_forwards_verify_to_write_typed(monkeypatch):
    calls = []

    def fake_write_typed(address, value, type_name, verify):
        calls.append((address, value, type_name, verify))
        return {"success": True, "new_value": value}

    monkeypatch.setattr(server, "write_typed", fake_write_typed)

    result = server.write("0x2000", {"x": 1, "y": 2, "z": 3}, "vector3", verify=True)

    assert result == {"success": True, "new_value": {"x": 1, "y": 2, "z": 3}}
    assert calls == [("0x2000", {"x": 1, "y": 2, "z": 3}, "vector3", True)]


def test_read_write_docstrings_describe_current_basics():
    assert "Use count > 1" in server.read.__doc__
    assert "sbyte" in server.read.__doc__
    assert "char" in server.read.__doc__
    assert "bytes[N]" in server.read.__doc__
    assert "color32" in server.read.__doc__
    assert "ptr/pointer/intptr" in server.read.__doc__
    assert "Set verify=True" in server.write.__doc__
    assert "vector3 as {x,y,z} dict" in server.write.__doc__


def test_scripts_list_forwards_process_filter(monkeypatch):
    calls = []

    def fake_list_scripts(process):
        calls.append(process)
        return {"scripts": [], "count": 0, "scripts_dir": "scripts"}

    monkeypatch.setattr(server, "list_scripts", fake_list_scripts)

    result = server.scripts("list", process="*")

    assert result == {"scripts": [], "count": 0, "scripts_dir": "scripts"}
    assert calls == ["*"]


def test_scripts_run_requires_name_before_delegate(monkeypatch):
    def fail_run_script(*_args, **_kwargs):
        raise AssertionError("run_script should not be called without a script name")

    monkeypatch.setattr(server, "run_script", fail_run_script)

    result = server.scripts("run")

    assert result == {"success": False, "error": "MISSING_PARAM", "detail": "name required"}


def test_scripts_run_forwards_namespace_args_and_timeout(monkeypatch):
    calls = []

    def fake_run_script(name, process, args, timeout=None):
        calls.append((name, process, args, timeout))
        return {"success": True, "script_name": name}

    monkeypatch.setattr(server, "run_script", fake_run_script)

    result = server.scripts(
        "run",
        name="probe",
        process="Target.exe",
        args={"needle": "DE AD BE EF"},
        timeout=2.5,
    )

    assert result == {"success": True, "script_name": "probe"}
    assert calls == [("probe", "Target.exe", {"needle": "DE AD BE EF"}, 2.5)]


def test_scripts_docstring_describes_process_namespace_contract():
    assert "saved-script namespace only" in server.scripts.__doc__
    assert "does not attach or switch" in server.scripts.__doc__
    assert "process must match" in server.scripts.__doc__


def test_scripts_unknown_action_reports_valid_actions(monkeypatch):
    def fail_list_scripts(*_args, **_kwargs):
        raise AssertionError("list_scripts should not be called for an unknown action")

    def fail_run_script(*_args, **_kwargs):
        raise AssertionError("run_script should not be called for an unknown action")

    monkeypatch.setattr(server, "list_scripts", fail_list_scripts)
    monkeypatch.setattr(server, "run_script", fail_run_script)

    result = server.scripts("remove", name="probe")

    assert result["success"] is False
    assert result["error"] == "INVALID_ACTION"
    assert "Valid: list, run" in result["detail"]
