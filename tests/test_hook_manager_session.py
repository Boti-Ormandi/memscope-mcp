"""Ownership and cleanup invariants for session-bound HookManager instances."""

from unittest.mock import MagicMock, call

import pytest

from memscope_mcp.tools.hooking import HookManager, RingBufferConfig


def _ring(address: int = 0x4000) -> RingBufferConfig:
    return RingBufferConfig(
        address=address,
        entry_count=16,
        max_data_size=256,
        entry_total_size=0x50 + 256,
        total_size=0x100 + 16 * (0x50 + 256),
    )


def test_remote_operations_only_use_owned_session():
    session_a = MagicMock(name="session_a")
    session_b = MagicMock(name="hostile_session_b")
    session_a.allocate.return_value = 0x100000

    manager = HookManager(session_a)
    result = manager.create_ring_buffer(entry_count=16, max_data_size=256)

    assert result["address"] == "0x100000"
    session_a.allocate.assert_called_once()
    assert session_a.write_uint64.call_count == 5
    assert session_b.mock_calls == []


def test_managers_share_no_process_state():
    session_a = MagicMock(name="session_a")
    session_b = MagicMock(name="session_b")
    manager_a = HookManager(session_a)
    manager_b = HookManager(session_b)

    manager_a.hooks[0x1000] = object()
    manager_a._hooks_by_id[7] = object()
    manager_a.ring_buffer = _ring()
    manager_a.next_hook_id = 8
    manager_a._deferred_trampolines.append((0x9000, 4096))

    assert manager_b.hooks == {}
    assert manager_b._hooks_by_id == {}
    assert manager_b.ring_buffer is None
    assert manager_b.next_hook_id == 1
    assert manager_b._deferred_trampolines == []


def test_session_binding_is_read_only_and_has_no_rebind_api():
    session_a = MagicMock(name="session_a")
    session_b = MagicMock(name="session_b")
    manager = HookManager(session_a)

    assert manager.session is session_a
    with pytest.raises(AttributeError):
        manager.session = session_b
    assert manager.session is session_a
    assert not hasattr(manager, "bind_session")


def test_cleanup_dead_target_makes_no_remote_calls_and_clears_all_state():
    session = MagicMock(name="session")
    manager = HookManager(session)
    hook = object()
    manager.hooks[0x1000] = hook
    manager._hooks_by_id[4] = hook
    manager._deferred_trampolines.extend([(0x8000, 4096), (0x9000, 4096)])
    manager.ring_buffer = _ring()
    manager.next_hook_id = 9

    manager.cleanup(process_alive=False)

    assert session.mock_calls == []
    assert manager.hooks == {}
    assert manager._hooks_by_id == {}
    assert manager._deferred_trampolines == []
    assert manager.ring_buffer is None
    assert manager.next_hook_id == 1


def test_cleanup_live_target_frees_deferred_trampolines_without_hooks_or_ring():
    session = MagicMock(name="session")
    manager = HookManager(session)
    manager._deferred_trampolines.extend([(0x8000, 4096), (0x9000, 8192)])

    manager.cleanup(process_alive=True)

    assert session.free.call_args_list == [call(0x8000), call(0x9000)]
    assert manager._deferred_trampolines == []
    assert manager.hooks == {}
    assert manager.ring_buffer is None
    assert manager.next_hook_id == 1
