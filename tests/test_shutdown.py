"""Tests for server shutdown cleanup and composition-owned HookManager ordering."""

from unittest.mock import MagicMock, patch

import memscope_mcp.server as server_mod


class TestShutdown:
    def setup_method(self):
        server_mod._shutdown_done = False

    def test_shutdown_no_process_still_cleans_manager(self):
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = None
            server_mod._shutdown()

        manager.cleanup.assert_called_once_with(process_alive=False)
        session.detach.assert_not_called()
        assert server_mod._shutdown_done is True

    def test_shutdown_is_idempotent(self):
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = None
            server_mod._shutdown()
            server_mod._shutdown()

        manager.cleanup.assert_called_once_with(process_alive=False)
        assert server_mod._shutdown_done is True

    def test_application_manager_cleanup_precedes_detach(self):
        events = []
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = MagicMock()
            session._is_process_alive.return_value = True
            manager.cleanup.side_effect = lambda **_kwargs: events.append("cleanup")
            session.detach.side_effect = lambda: events.append("detach")
            server_mod._shutdown()

        assert events == ["cleanup", "detach"]
        manager.cleanup.assert_called_once_with(process_alive=True)

    def test_deferred_trampoline_only_state_still_causes_cleanup(self):
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = MagicMock()
            session._is_process_alive.return_value = True
            manager.hooks = {}
            manager.ring_buffer = None
            manager._deferred_trampolines = [(0x5000, 4096)]
            server_mod._shutdown()

        manager.cleanup.assert_called_once_with(process_alive=True)

    def test_dead_target_passes_false_before_detach(self):
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = MagicMock()
            session._is_process_alive.return_value = False
            server_mod._shutdown()

        manager.cleanup.assert_called_once_with(process_alive=False)
        session.detach.assert_called_once_with()

    def test_detach_failure_does_not_undo_manager_cleanup(self):
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = MagicMock()
            session._is_process_alive.return_value = True
            session.detach.side_effect = OSError("handle closed")
            server_mod._shutdown()

        manager.cleanup.assert_called_once_with(process_alive=True)
        assert server_mod._shutdown_done is True

    def test_cleanup_baseexception_does_not_skip_detach(self):
        with (
            patch.object(server_mod, "SESSION") as session,
            patch.object(server_mod, "_hook_manager") as manager,
        ):
            session.pm = MagicMock()
            session._is_process_alive.return_value = True
            manager.cleanup.side_effect = KeyboardInterrupt()
            server_mod._shutdown()

        session.detach.assert_called_once_with()
        assert server_mod._shutdown_done is True
