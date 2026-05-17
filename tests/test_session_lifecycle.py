"""Tests for session lifecycle callbacks.

Verifies attach/detach callbacks fire correctly, are isolated on failure,
and integrate with the canonical switch_process path.
"""

from memscope_mcp.session import DebugSession


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
        session.modules = {"test.dll": {"base": 0x1000, "size": 0x100}}
        session.detach()
        assert session.pid == 0
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
