"""Smoke tests - verify imports, tool registration, and engine initialization."""


def test_server_imports():
    """All server modules load without error."""
    from memscope_mcp.server import mcp  # noqa: F401


def test_tool_count():
    """Server registers exactly 10 MCP tools."""
    from memscope_mcp.server import mcp

    tools = mcp._tool_manager._tools
    assert len(tools) == 10, f"Expected 10 tools, got {len(tools)}: {sorted(tools.keys())}"


def test_tool_names():
    """All expected tools are registered."""
    from memscope_mcp.server import mcp

    tools = set(mcp._tool_manager._tools.keys())
    expected = {
        "processes",
        "attach",
        "modules",
        "read",
        "write",
        "dump",
        "chain",
        "scan",
        "lua",
        "scripts",
    }
    assert tools == expected, f"Tool mismatch. Missing: {expected - tools}, Extra: {tools - expected}"


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
