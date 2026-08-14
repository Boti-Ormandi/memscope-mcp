"""Lua runtime discovery helper tests."""

import memscope_mcp.server as server
from memscope_mcp.attachment import ModuleRecord, ModuleSnapshot, normalize_module_name
from memscope_mcp.extensions.core.module_scan import ModuleScanExtension
from memscope_mcp.session import DebugSession
from memscope_mcp.tools.lua.engine import LUA_ENGINE
from memscope_mcp.utils.memory_utils import get_module_for_address


def _module_snapshot(*entries: tuple[str, int, int, str]) -> ModuleSnapshot:
    return ModuleSnapshot.create(
        (
            ModuleRecord(
                name=name,
                normalized_name=normalize_module_name(name),
                base=base,
                size=size,
                path=path,
            )
            for name, base, size, path in entries
        ),
        generation=1,
    )


def test_module_scan_instructions_teach_named_scan_options_contract():
    instructions = " ".join(ModuleScanExtension.instructions.split())

    for signature in (
        "AOBScan(pattern, options?)",
        "AOBScanMany(patterns, options?)",
        "scanString(text, options?)",
        "scanPointer(target, options?)",
    ):
        assert signature in instructions

    assert (
        "Scan options use named fields only: `scope`, `mode`, `max_matches`, "
        "`timeout_ms`, and `diagnostics`; `scanString` also accepts `encoding`, "
        "and `scanPointer` accepts `alignment`."
    ) in instructions
    assert "Expected failures return `nil, error_table`;" in instructions


def test_list_lua_functions_reports_names_and_owner_filter():
    result = LUA_ENGINE.execute(
        """
        local all_funcs = listLuaFunctions()
        local general_funcs = listLuaFunctions("general")
        local found_aob_scan = false
        local found_aob_scan_many = false
        local found_addr = false
        local found_capabilities = false
        local all_general = true

        for _, fn in ipairs(all_funcs) do
            if fn.name == "AOBScan" and fn.owner == "module_scan" then
                found_aob_scan = true
            end
            if fn.name == "AOBScanMany" and fn.owner == "module_scan" then
                found_aob_scan_many = true
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
        addResult("found_aob_scan_many", found_aob_scan_many)
        addResult("found_addr", found_addr)
        addResult("found_capabilities", found_capabilities)
        addResult("all_general", all_general)
        """
    )

    assert result["success"] is True
    assert result["results"]["all_count"] > result["results"]["general_count"]
    assert result["results"]["found_aob_scan"] is True
    assert result["results"]["found_aob_scan_many"] is True
    assert result["results"]["found_addr"] is True
    assert result["results"]["found_capabilities"] is True
    assert result["results"]["all_general"] is True


def test_legacy_open_process_remains_registered_without_raw_runtime_access():
    result = LUA_ENGINE.execute("return openProcess ~= nil")

    assert result["success"] is True
    assert result["results"]["return"] is True
    assert LUA_ENGINE._function_registry["openProcess"] == "process"
    assert not hasattr(LUA_ENGINE, "lua")


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
    monkeypatch.setattr(server.SESSION, "_module_snapshot", None)

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
        addResult("strict_scan_contract", caps.wrappers.strict_scan_contract)
        addResult("scan_cursor_continuation", caps.wrappers.scan_cursor_continuation)
        addResult("lua_scan_options", caps.wrappers.lua_scan_options)
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
    assert result["results"]["tool_count"] == 11
    assert result["results"]["error_normalization"] is True
    assert result["results"]["strict_scan_contract"] is True
    assert result["results"]["scan_cursor_continuation"] is True
    assert result["results"]["lua_scan_options"] is True
    assert result["results"]["script_namespace_selection"] is True
    assert result["results"]["verified_writes"] is True
    assert result["results"]["typed_byte_writes"] is True


def test_get_capabilities_includes_attached_process_info(monkeypatch):
    monkeypatch.setattr(server.SESSION, "pm", object())
    monkeypatch.setattr(server.SESSION, "pid", 1234)
    monkeypatch.setattr(server.SESSION, "target_process", "Target.exe")
    monkeypatch.setattr(
        server.SESSION,
        "_module_snapshot",
        _module_snapshot(
            ("Target.exe", 0x140000000, 0x2000, r"C:\\Games\\Target.exe"),
            ("helper.dll", 0x7FFE0000, 0x1000, r"C:\\Games\\helper.dll"),
        ),
    )

    result = LUA_ENGINE.execute(
        """
        local caps = getCapabilities()
        local proc = getAttachedProcess()
        addResult("attached", caps.attached)
        addResult("pid", caps.process.pid)
        addResult("name", caps.process.name)
        addResult("module_count", caps.process.module_count)
        addResult("process_module_count", proc.module_count)
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "attached": True,
        "pid": 1234,
        "name": "Target.exe",
        "module_count": 2,
        "process_module_count": 2,
    }


def test_debug_session_modules_preserves_detached_dictionary_compatibility():
    session = DebugSession()
    snapshot = _module_snapshot(("legacy.dll", 0x1000, 0x200, r"C:\\Target\\legacy.dll"))
    session._module_snapshot = snapshot

    modules = session.modules

    assert isinstance(modules, dict)
    assert modules == {
        "legacy.dll": {
            "base": 0x1000,
            "size": 0x200,
            "path": r"C:\\Target\\legacy.dll",
        }
    }
    modules["legacy.dll"]["base"] = 0xDEADBEEF
    assert session.modules["legacy.dll"]["base"] == 0x1000


def test_legacy_module_readers_preserve_duplicate_address_semantics(monkeypatch):
    snapshot = _module_snapshot(
        ("dup.dll", 0x100000, 0x100, r"C:\\First\\dup.dll"),
        ("DUP.dll", 0x200000, 0x200, r"C:\\Case\\DUP.dll"),
        ("dup.dll", 0x300000, 0x300, r"C:\\Last\\dup.dll"),
    )
    monkeypatch.setattr(server.SESSION, "_module_snapshot", snapshot)

    result = LUA_ENGINE.execute(
        """
        local mods = getModules()
        local collapsed = getModuleFromAddress(0x100010)
        local case_variant = getModuleFromAddress(0x200010)
        addResult("count", #mods)
        addResult("first_name", mods[1].name)
        addResult("first_base", mods[1].base)
        addResult("second_name", mods[2].name)
        addResult("second_base", mods[2].base)
        addResult("collapsed_found", collapsed ~= nil)
        addResult("case_name", case_variant.name)
        addResult("case_offset", case_variant.offset)
        addResult("formatted", formatAddress(0x200010))
        """
    )

    assert result["success"] is True
    assert result["results"] == {
        "count": 2,
        "first_name": "dup.dll",
        "first_base": 0x300000,
        "second_name": "DUP.dll",
        "second_base": 0x200000,
        "collapsed_found": False,
        "case_name": "DUP.dll",
        "case_offset": 0x10,
        "formatted": "DUP.dll+0x10",
    }
    assert get_module_for_address(0x100010, session=server.SESSION) is None
    assert get_module_for_address(0x200010, session=server.SESSION) == ("DUP.dll", 0x10)
