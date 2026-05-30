"""Lua runtime discovery helper tests."""

import memscope_mcp.server as server
from memscope_mcp.tools.lua.engine import LUA_ENGINE


def test_list_lua_functions_reports_names_and_owner_filter():
    result = LUA_ENGINE.execute(
        """
        local all_funcs = listLuaFunctions()
        local general_funcs = listLuaFunctions("general")
        local found_aob_scan = false
        local found_addr = false
        local found_capabilities = false
        local all_general = true

        for _, fn in ipairs(all_funcs) do
            if fn.name == "AOBScan" and fn.owner == "module_scan" then
                found_aob_scan = true
            end
        end

        for _, fn in ipairs(general_funcs) do
            if fn.owner ~= "general" then
                all_general = false
            end
            if fn.name == "addr" then
                found_addr = true
            end
            if fn.name == "getCapabilities" then
                found_capabilities = true
            end
        end

        addResult("all_count", #all_funcs)
        addResult("general_count", #general_funcs)
        addResult("found_aob_scan", found_aob_scan)
        addResult("found_addr", found_addr)
        addResult("found_capabilities", found_capabilities)
        addResult("all_general", all_general)
        """
    )

    assert result["success"] is True
    assert result["results"]["all_count"] > result["results"]["general_count"]
    assert result["results"]["found_aob_scan"] is True
    assert result["results"]["found_addr"] is True
    assert result["results"]["found_capabilities"] is True
    assert result["results"]["all_general"] is True


def test_get_loaded_extensions_preserves_first_seen_owner_order():
    result = LUA_ENGINE.execute(
        """
        local owners = getLoadedExtensions()
        for i = 1, 7 do
            addResult("owner_" .. i, owners[i])
        end
        """
    )

    assert result["success"] is True
    assert [result["results"][f"owner_{index}"] for index in range(1, 8)] == [
        "general",
        "memory",
        "module_scan",
        "execution",
        "hooking",
        "process",
        "network",
    ]


def test_get_capabilities_reports_detached_state_paths_and_wrapper_flags(monkeypatch):
    monkeypatch.setattr(server.SESSION, "pm", None)
    monkeypatch.setattr(server.SESSION, "pid", 0)
    monkeypatch.setattr(server.SESSION, "target_process", "")
    monkeypatch.setattr(server.SESSION, "modules", {})

    result = LUA_ENGINE.execute(
        """
        local caps = getCapabilities()
        addResult("attached", caps.attached)
        addResult("has_process", caps.process ~= nil)
        addResult("has_memscope_home", caps.paths.memscope_home ~= nil)
        addResult("has_scripts_dir", caps.paths.scripts_dir ~= nil)
        addResult("has_session_log", caps.paths.session_log ~= nil)
        addResult("tool_count", caps.wrappers.tool_count)
        addResult("error_normalization", caps.wrappers.error_normalization)
        addResult("script_namespace_selection", caps.wrappers.script_namespace_selection)
        addResult("verified_writes", caps.wrappers.verified_writes)
        addResult("typed_byte_writes", caps.wrappers.typed_byte_writes)
        """
    )

    assert result["success"] is True
    assert result["results"]["attached"] is False
    assert result["results"]["has_process"] is False
    assert result["results"]["has_memscope_home"] is True
    assert result["results"]["has_scripts_dir"] is True
    assert result["results"]["has_session_log"] is True
    assert result["results"]["tool_count"] == 10
    assert result["results"]["error_normalization"] is True
    assert result["results"]["script_namespace_selection"] is True
    assert result["results"]["verified_writes"] is True
    assert result["results"]["typed_byte_writes"] is True


def test_get_capabilities_includes_attached_process_info(monkeypatch):
    monkeypatch.setattr(server.SESSION, "pm", object())
    monkeypatch.setattr(server.SESSION, "pid", 1234)
    monkeypatch.setattr(server.SESSION, "target_process", "Target.exe")
    monkeypatch.setattr(server.SESSION, "modules", {"Target.exe": {}, "helper.dll": {}})

    result = LUA_ENGINE.execute(
        """
        local caps = getCapabilities()
        addResult("attached", caps.attached)
        addResult("pid", caps.process.pid)
        addResult("name", caps.process.name)
        addResult("module_count", caps.process.module_count)
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "attached": True,
        "pid": 1234,
        "name": "Target.exe",
        "module_count": 2,
    }
