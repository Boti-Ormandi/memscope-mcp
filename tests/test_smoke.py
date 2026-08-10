"""Smoke tests - verify imports, tool registration, and engine initialization."""

import asyncio
import inspect


def _registered_tool_names() -> list[str]:
    from memscope_mcp.server import mcp

    return [tool.name for tool in asyncio.run(mcp.list_tools())]


def test_server_imports():
    """All server modules load without error."""
    from memscope_mcp.server import mcp  # noqa: F401


def test_tool_count():
    """Server registers exactly 11 MCP tools."""
    tools = _registered_tool_names()
    assert len(tools) == 11, f"Expected 11 tools, got {len(tools)}: {tools}"


def test_tool_names():
    """All expected tools are registered."""
    tools = set(_registered_tool_names())
    expected = {
        "processes",
        "attach",
        "modules",
        "read",
        "write",
        "dump",
        "chain",
        "scan",
        "scan_many",
        "lua",
        "scripts",
    }
    assert tools == expected, f"Tool mismatch. Missing: {expected - tools}, Extra: {tools - expected}"


def test_ordinary_tool_functions_remain_directly_synchronous():
    """Business functions stay synchronous even though their MCP registration is async-wrapped."""
    import memscope_mcp.server as server

    ordinary_tools = ("processes", "attach", "modules", "read", "write", "dump", "chain", "lua", "scripts")
    assert all(not inspect.iscoroutinefunction(getattr(server, name)) for name in ordinary_tools)


def test_lua_engine_initializes():
    """Lua engine creates successfully."""
    from memscope_mcp.tools.lua.engine import LUA_ENGINE

    assert LUA_ENGINE is not None
    assert LUA_ENGINE.lua is not None


def test_lua_engine_basic_execution():
    """Lua engine can execute a simple script."""
    from memscope_mcp.tools.lua.engine import LUA_ENGINE

    result = LUA_ENGINE.execute('addResult("test", 42)')
    assert result["success"] is True
    assert result["results"]["test"] == 42


def test_lua_engine_addr_function():
    """Lua addr() function handles large hex values."""
    from memscope_mcp.tools.lua.engine import LUA_ENGINE

    result = LUA_ENGINE.execute('addResult("addr", toHex(addr("0x1F58E12ECF0")))')
    assert result["success"] is True
    assert result["results"]["addr"] == "0x1F58E12ECF0"


def test_lua_engine_print():
    """Lua print() captures output."""
    from memscope_mcp.tools.lua.engine import LUA_ENGINE

    result = LUA_ENGINE.execute('print("hello", "world")')
    assert result["success"] is True
    assert "hello" in result["output"][0]


def test_plugin_loader():
    """Plugin loader runs without error (may find 0 plugins if dir is empty)."""
    from memscope_mcp.plugins import load_plugins

    plugins = load_plugins()
    assert isinstance(plugins, list)


def test_instructions_build():
    """Instructions builder produces non-empty string."""
    from memscope_mcp.instructions import build_instructions

    instructions = build_instructions([])
    assert isinstance(instructions, str)
    assert len(instructions) > 100


def test_session_initial_state():
    """Session starts detached."""
    from memscope_mcp.session import SESSION

    assert SESSION.pm is None
    assert SESSION.target_process == ""
