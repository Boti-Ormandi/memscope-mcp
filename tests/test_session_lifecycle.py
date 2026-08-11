"""Tests for session lifecycle callbacks.

Verifies attach/detach callbacks fire correctly, are isolated on failure,
and integrate with the canonical switch_process path.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import memscope_mcp.session as session_module
from memscope_mcp.attachment import ModuleSnapshot, build_module_records
from memscope_mcp.extensions.base import ExtensionContext
from memscope_mcp.extensions.core.hooking import HookingExtension
from memscope_mcp.session import DebugSession
from memscope_mcp.tools.hooking import HookManager, RingBufferConfig


def _module_snapshot(name: str = "test.dll", base: int = 0x1000, size: int = 0x100) -> ModuleSnapshot:
    module = SimpleNamespace(
        name=name,
        lpBaseOfDll=base,
        SizeOfImage=size,
        filename=rf"C:\Target\{name}",
    )
    return ModuleSnapshot.create(build_module_records([module]), generation=1)


class TestCallbackRegistration:
    """Basic callback registration and deregistration."""

    def test_register_on_attach(self):
        session = DebugSession()
        calls = []
        session.register_on_attach("test", lambda s: calls.append("attached"))
        assert "test" in session._on_attach_callbacks

    def test_register_on_detach(self):
        session = DebugSession()
        calls = []
        session.register_on_detach("test", lambda s, alive: calls.append(("detached", alive)))
        assert "test" in session._on_detach_callbacks

    def test_overwrite_callback(self):
        """Re-registering with the same name overwrites."""
        session = DebugSession()
        calls = []
        session.register_on_attach("test", lambda s: calls.append("first"))
        session.register_on_attach("test", lambda s: calls.append("second"))
        session._fire_attach()
        assert calls == ["second"]


class TestFireAttach:
    """Attach callback firing."""

    def test_fire_attach_calls_all(self):
        session = DebugSession()
        calls = []
        session.register_on_attach("a", lambda s: calls.append("a"))
        session.register_on_attach("b", lambda s: calls.append("b"))
        session._fire_attach()
        assert "a" in calls
        assert "b" in calls

    def test_fire_attach_passes_session(self):
        session = DebugSession()
        received = []
        session.register_on_attach("test", lambda s: received.append(s))
        session._fire_attach()
        assert received[0] is session


class TestFireDetach:
    """Detach callback firing."""

    def test_fire_detach_alive(self):
        session = DebugSession()
        calls = []
        session.register_on_detach("test", lambda s, alive: calls.append(alive))
        session._fire_detach(process_alive=True)
        assert calls == [True]

    def test_fire_detach_dead(self):
        session = DebugSession()
        calls = []
        session.register_on_detach("test", lambda s, alive: calls.append(alive))
        session._fire_detach(process_alive=False)
        assert calls == [False]

    def test_fire_detach_calls_all(self):
        session = DebugSession()
        calls = []
        session.register_on_detach("a", lambda s, alive: calls.append("a"))
        session.register_on_detach("b", lambda s, alive: calls.append("b"))
        session._fire_detach(process_alive=True)
        assert "a" in calls
        assert "b" in calls


class TestCallbackIsolation:
    """Callback failures don't prevent other callbacks from running."""

    def test_attach_failure_isolated(self):
        session = DebugSession()
        calls = []

        def bad_cb(s):
            raise RuntimeError("boom")

        session.register_on_attach("bad", bad_cb)
        session.register_on_attach("good", lambda s: calls.append("good"))
        session._fire_attach()
        assert "good" in calls

    def test_detach_failure_isolated(self):
        session = DebugSession()
        calls = []

        def bad_cb(s, alive):
            raise RuntimeError("boom")

        session.register_on_detach("bad", bad_cb)
        session.register_on_detach("good", lambda s, alive: calls.append("good"))
        session._fire_detach(process_alive=True)
        assert "good" in calls

    def test_attach_keyboard_interrupt_isolated(self):
        """KeyboardInterrupt in one callback doesn't skip the rest."""
        session = DebugSession()
        calls = []

        def interrupt_cb(s):
            raise KeyboardInterrupt()

        session.register_on_attach("interrupt", interrupt_cb)
        session.register_on_attach("good", lambda s: calls.append("good"))
        session._fire_attach()
        assert "good" in calls

    def test_detach_keyboard_interrupt_isolated(self):
        """KeyboardInterrupt in one callback doesn't skip the rest."""
        session = DebugSession()
        calls = []

        def interrupt_cb(s, alive):
            raise KeyboardInterrupt()

        session.register_on_detach("interrupt", interrupt_cb)
        session.register_on_detach("good", lambda s, alive: calls.append("good"))
        session._fire_detach(process_alive=True)
        assert "good" in calls

    def test_detach_system_exit_isolated(self):
        """SystemExit in one callback doesn't skip the rest."""
        session = DebugSession()
        calls = []

        def exit_cb(s, alive):
            raise SystemExit(1)

        session.register_on_detach("exit", exit_cb)
        session.register_on_detach("good", lambda s, alive: calls.append("good"))
        session._fire_detach(process_alive=True)
        assert "good" in calls


class TestLegacyModulesCompatibility:
    def test_modules_property_is_getter_only_and_detached_reads_are_fresh(self):
        session = DebugSession()

        first = session.modules
        second = session.modules

        assert first == second == {}
        assert first is not second
        assert "modules" not in session.__dict__
        with pytest.raises(AttributeError):
            session.modules = {"test.dll": {"base": 0x1000, "size": 0x100}}
        assert "modules" not in session.__dict__

    def test_modules_property_materializes_fresh_nested_mappings(self):
        session = DebugSession()
        snapshot = _module_snapshot()
        session._module_snapshot = snapshot

        first = session.modules
        second = session.modules

        assert first == second == snapshot.to_legacy_dict()
        assert first is not second
        assert first["test.dll"] is not second["test.dll"]

    def test_modules_property_mutations_do_not_write_through(self):
        session = DebugSession()
        snapshot = _module_snapshot()
        session._module_snapshot = snapshot
        expected = snapshot.to_legacy_dict()

        modules = session.modules
        modules["test.dll"]["base"] = 0xDEADBEEF
        modules["test.dll"]["size"] = 0x200
        modules["inserted.dll"] = {"base": 0x2000, "size": 0x80, "path": r"C:\Target\inserted.dll"}
        del modules["test.dll"]

        assert session.modules == expected
        assert snapshot.to_legacy_dict() == expected
        assert session._module_snapshot is snapshot


class TestDetachFiresCallbacks:
    """detach() fires detach callbacks before teardown."""

    def test_detach_without_process_is_noop(self):
        """Detach on unattached session doesn't fire callbacks."""
        session = DebugSession()
        calls = []
        session.register_on_detach("test", lambda s, alive: calls.append(alive))
        session.detach()
        assert calls == []  # pm was None, no callbacks fired

    def test_detach_clears_state(self):
        """After detach, pid and modules are cleared."""
        session = DebugSession()
        session.pid = 1234
        snapshot = _module_snapshot()
        session._module_snapshot = snapshot
        assert session.modules == snapshot.to_legacy_dict()

        session.detach()

        assert session.pid == 0
        assert session.module_snapshot is None
        assert session.modules == {}

    def test_detach_clears_tracked_allocations(self):
        """Detach clears allocation tracking even without a process."""
        session = DebugSession()
        session._tracked_allocations = {0x1000, 0x2000}
        session.detach()
        assert session._tracked_allocations == set()


class TestAllocationTracking:
    """Allocation tracking for orphan cleanup on detach."""

    def test_initial_state_empty(self):
        session = DebugSession()
        assert session._tracked_allocations == set()

    def test_free_removes_from_tracking(self):
        """free() removes address from tracking set (even if VirtualFreeEx fails)."""
        session = DebugSession()
        session._tracked_allocations.add(0xDEAD)
        # pm is None so free returns False, but tracking is still updated
        session.free(0xDEAD)
        assert 0xDEAD not in session._tracked_allocations

    def test_free_unknown_address_is_safe(self):
        """free() of untracked address doesn't raise."""
        session = DebugSession()
        result = session.free(0x9999)
        assert result is False


class TestWritableMemoryRange:
    def test_writable_range_walks_all_covered_regions(self, monkeypatch):
        session = DebugSession()
        session.pm = SimpleNamespace(process_handle=1)
        queries = []

        committed = session_module.structs.MEMORY_STATE.MEM_COMMIT.value
        writable = session_module.structs.MEMORY_PROTECTION.PAGE_READWRITE.value

        def fake_virtual_query(process_handle, address):
            queries.append((process_handle, address))
            if address < 0x1008:
                return SimpleNamespace(State=committed, Protect=writable, BaseAddress=0x1000, RegionSize=8)
            return SimpleNamespace(State=committed, Protect=writable, BaseAddress=0x1008, RegionSize=8)

        monkeypatch.setattr(session_module.pymem.memory, "virtual_query", fake_virtual_query)

        assert session.is_memory_range_writable(0x1004, 8) is True
        assert queries == [(1, 0x1004), (1, 0x1008)]

    def test_writable_range_fails_when_any_covered_region_is_read_only(self, monkeypatch):
        session = DebugSession()
        session.pm = SimpleNamespace(process_handle=1)

        committed = session_module.structs.MEMORY_STATE.MEM_COMMIT.value
        writable = session_module.structs.MEMORY_PROTECTION.PAGE_READWRITE.value
        read_only = session_module.structs.MEMORY_PROTECTION.PAGE_READONLY.value

        def fake_virtual_query(_process_handle, address):
            if address < 0x1008:
                return SimpleNamespace(State=committed, Protect=writable, BaseAddress=0x1000, RegionSize=8)
            return SimpleNamespace(State=committed, Protect=read_only, BaseAddress=0x1008, RegionSize=8)

        monkeypatch.setattr(session_module.pymem.memory, "virtual_query", fake_virtual_query)

        assert session.is_memory_range_writable(0x1004, 8) is False


class TestSwitchProcess:
    """switch_process() is the canonical process switch path."""

    def test_switch_preserves_target(self):
        """After switch, target_process and pid are set."""
        session = DebugSession()
        # This will fail to open (no such process), but should set the target
        session.switch_process("nonexistent_process_12345.exe", 0)
        assert session.target_process == "nonexistent_process_12345.exe"

    def test_switch_fires_detach_on_old_process(self):
        """switch_process fires detach callbacks when switching away."""
        session = DebugSession()
        calls = []
        session.register_on_detach("test", lambda s, alive: calls.append("detached"))
        # No current process attached, so detach is a no-op
        session.switch_process("nonexistent.exe")
        # With no pm, detach doesn't fire callbacks
        assert calls == []


class TestHookManagerProcessTransitions:
    """Hook manager process state is retired before a replacement attachment is published."""

    @staticmethod
    def _register_hooking(session: DebugSession, manager: HookManager) -> HookingExtension:
        extension = HookingExtension()
        extension.register(
            ExtensionContext(
                engine=SimpleNamespace(_output=[]),
                session=session,
                table_factory=dict,
                log_error=lambda *_args: None,
                hook_manager=manager,
            )
        )
        session.register_on_detach("hooking", extension.on_process_detaching)
        return extension

    def test_switch_cleans_old_target_before_new_target_opens(self, monkeypatch):
        session = DebugSession()
        session.target_process = "A.exe"
        session.pid = 111
        old_pm = SimpleNamespace(close_process=MagicMock())
        session.pm = old_pm
        manager = HookManager(session)
        manager._deferred_trampolines = [(0xA000, 4096)]
        manager.next_hook_id = 8
        self._register_hooking(session, manager)

        remote_frees = []
        monkeypatch.setattr(session, "_begin_retirement_locked", lambda: None)
        monkeypatch.setattr(session, "_is_process_alive", lambda: True)
        monkeypatch.setattr(session, "free", lambda addr: remote_frees.append((session.target_process, addr)) or True)

        def open_b():
            assert session.target_process == "B.exe"
            assert manager.hooks == {}
            assert manager._hooks_by_id == {}
            assert manager._deferred_trampolines == []
            assert manager.ring_buffer is None
            assert manager.next_hook_id == 1
            session.pm = SimpleNamespace(close_process=MagicMock())
            return True

        monkeypatch.setattr(session, "_open_process_locked", open_b)

        assert session.switch_process("B.exe", 222) is True
        assert remote_frees == [("A.exe", 0xA000)]
        old_pm.close_process.assert_called_once_with()
        assert session.target_process == "B.exe"
        assert session.pid == 222

    def test_restart_clears_dead_target_state_without_remote_calls(self, monkeypatch):
        session = DebugSession()
        session.target_process = "A.exe"
        session.pid = 111
        session.pm = SimpleNamespace(close_process=MagicMock())
        session._attachment_state = session_module.AttachmentState.ATTACHED
        manager = HookManager(session)
        manager.hooks[0x1000] = object()
        manager._hooks_by_id[4] = object()
        manager._deferred_trampolines = [(0xA000, 4096)]
        manager.ring_buffer = RingBufferConfig(
            address=0xB000,
            entry_count=16,
            max_data_size=256,
            entry_total_size=0x150,
            total_size=0x1600,
        )
        manager.next_hook_id = 9
        self._register_hooking(session, manager)

        monkeypatch.setattr(session, "_begin_retirement_locked", lambda: None)
        monkeypatch.setattr(session, "_is_process_alive", lambda: False)
        monkeypatch.setattr(session, "free", MagicMock(side_effect=AssertionError("dead target remote call")))

        def reopen_a():
            assert manager.hooks == {}
            assert manager._hooks_by_id == {}
            assert manager._deferred_trampolines == []
            assert manager.ring_buffer is None
            assert manager.next_hook_id == 1
            session.pm = SimpleNamespace(close_process=MagicMock())
            session._attachment_state = session_module.AttachmentState.ATTACHED
            return True

        monkeypatch.setattr(session, "_open_process_locked", reopen_a)

        assert session.ensure_attached() is True
        session.free.assert_not_called()
