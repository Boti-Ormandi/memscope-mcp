"""Dependency-injection tripwires for generic Lua hooking."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from memscope_mcp.extensions.base import ExtensionContext
from memscope_mcp.extensions.core.hooking import HookingExtension
from memscope_mcp.tools.lua.hooking import build_hooking_functions


def _table(*args, **kwargs):
    result = {index: value for index, value in enumerate(args, 1)}
    result.update(kwargs)
    return result


def test_hook_and_unhook_parse_with_registered_session_and_use_injected_manager(monkeypatch):
    import memscope_mcp.tools.lua.hooking as lua_hooking

    session_a = MagicMock(name="session_a")
    hostile_b = MagicMock(name="hostile_session_b")
    manager_a = MagicMock(name="manager_a")
    manager_a.session = session_a
    manager_a.install_hook.return_value = {"hook_id": 7}
    manager_a.remove_hook.return_value = True
    parsed = []

    def fake_parse(value, *, session):
        parsed.append((value, session))
        return 0x12345678 if len(parsed) == 1 else 0x87654321

    monkeypatch.setattr(lua_hooking, "parse_address", fake_parse)
    functions = build_hooking_functions(
        _table,
        lambda *_args: None,
        [],
        session=session_a,
        hook_manager=manager_a,
    )

    result = functions["hookFunction"]("module.dll+10")
    assert result["hook_id"] == 7
    assert functions["unhookFunction"]("module.dll+20") is True

    assert parsed == [("module.dll+10", session_a), ("module.dll+20", session_a)]
    assert manager_a.install_hook.call_args.args[0] == 0x12345678
    manager_a.remove_hook.assert_called_once_with(0x87654321)
    assert hostile_b.mock_calls == []


def test_all_ring_wrappers_use_injected_manager():
    session_a = MagicMock(name="session_a")
    manager_a = MagicMock(name="manager_a")
    manager_a.session = session_a
    manager_a.create_ring_buffer.return_value = {"address": "0x1000"}
    manager_a.list_hooks.return_value = []
    manager_a.read_ring_buffer.return_value = []
    manager_a.ring_buffer_stats.return_value = {"total_captured": 0}
    manager_a.ring_buffer_marker.return_value = True

    functions = build_hooking_functions(
        _table,
        lambda *_args: None,
        [],
        session=session_a,
        hook_manager=manager_a,
    )

    functions["createRingBuffer"]({"entry_count": 32, "max_data_size": 512})
    functions["listHooks"]()
    functions["readRingBuffer"](25, {"min_result": 4})
    assert functions["ringBufferStats"]()["total_captured"] == 0
    assert functions["ringBufferMarker"]("checkpoint") is True
    assert functions["destroyRingBuffer"]() is True

    manager_a.create_ring_buffer.assert_called_once_with(32, 512)
    manager_a.list_hooks.assert_called_once_with()
    manager_a.read_ring_buffer.assert_called_once_with(25, min_result=4)
    manager_a.ring_buffer_stats.assert_called_once_with()
    manager_a.ring_buffer_marker.assert_called_once_with("checkpoint")
    manager_a.destroy_ring_buffer.assert_called_once_with()


def test_hooking_extension_rejects_manager_session_mismatch():
    session_a = MagicMock(name="session_a")
    session_b = MagicMock(name="session_b")
    manager_b = MagicMock(name="manager_b")
    manager_b.session = session_b
    ctx = ExtensionContext(
        engine=SimpleNamespace(_output=[]),
        session=session_a,
        table_factory=_table,
        log_error=lambda *_args: None,
        hook_manager=manager_b,
    )

    with pytest.raises(ValueError, match="HookManager/session ownership mismatch"):
        HookingExtension().register(ctx)


def test_hooking_extension_requires_manager():
    session_a = MagicMock(name="session_a")
    ctx = ExtensionContext(
        engine=SimpleNamespace(_output=[]),
        session=session_a,
        table_factory=_table,
        log_error=lambda *_args: None,
    )

    with pytest.raises(RuntimeError, match="requires a HookManager"):
        HookingExtension().register(ctx)
