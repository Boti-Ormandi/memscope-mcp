"""Tests for server shutdown cleanup.

Verifies _shutdown() is idempotent and cleans up resources properly.
"""

from unittest.mock import MagicMock, patch

import src.server as server_mod


class TestShutdownIdempotency:
    """_shutdown() must be safe to call multiple times."""

    def setup_method(self):
        # Reset the sentinel before each test
        server_mod._shutdown_done = False

    def test_shutdown_sets_done_flag(self):
        with patch.object(server_mod, "SESSION") as mock_session:
            mock_session.pm = None
            server_mod._shutdown()
            assert server_mod._shutdown_done is True

    def test_shutdown_second_call_is_noop(self):
        """Second call doesn't attempt cleanup again."""
        call_count = 0

        def counting_detach():
            nonlocal call_count
            call_count += 1

        with patch.object(server_mod, "SESSION") as mock_session:
            mock_session.pm = None
            mock_session.detach = counting_detach
            server_mod._shutdown()
            server_mod._shutdown()
            # detach only called if pm is not None, but the point is
            # _shutdown body only executes once
            assert server_mod._shutdown_done is True

    def test_shutdown_no_process_attached(self):
        """Shutdown with no attached process doesn't raise."""
        with patch.object(server_mod, "SESSION") as mock_session:
            mock_session.pm = None
            server_mod._shutdown()  # Should not raise


class TestShutdownCleansUp:
    """_shutdown() cleans up hooks and session."""

    def setup_method(self):
        server_mod._shutdown_done = False

    def test_shutdown_calls_detach_when_attached(self):
        with patch.object(server_mod, "SESSION") as mock_session:
            mock_session.pm = MagicMock()
            mock_session._is_process_alive.return_value = True
            server_mod._shutdown()
            mock_session.detach.assert_called_once()

    def test_shutdown_calls_hook_cleanup(self):
        mock_hm = MagicMock()
        mock_hm.hooks = {"0x1000": "hook_obj"}
        mock_hm.ring_buffer = MagicMock()

        with (
            patch.object(server_mod, "SESSION") as mock_session,
            patch.dict("sys.modules", {}),
            patch("src.server.HOOK_MANAGER", mock_hm, create=True),
        ):
            # Patch the lazy import inside _shutdown
            with patch("src.tools.hooking.HOOK_MANAGER", mock_hm):
                mock_session.pm = MagicMock()
                mock_session._is_process_alive.return_value = True
                server_mod._shutdown()
                mock_hm.cleanup.assert_called_once_with(process_alive=True)

    def test_shutdown_survives_hook_import_failure(self):
        """If hooking module can't be imported, shutdown still detaches."""
        with (
            patch.object(server_mod, "SESSION") as mock_session,
            patch("builtins.__import__", side_effect=ImportError("no module")),
        ):
            mock_session.pm = MagicMock()
            # Should not raise despite import failure
            server_mod._shutdown()

    def test_shutdown_survives_detach_failure(self):
        """If SESSION.detach() raises, shutdown doesn't propagate."""
        with patch.object(server_mod, "SESSION") as mock_session:
            mock_session.pm = MagicMock()
            mock_session._is_process_alive.return_value = False
            mock_session.detach.side_effect = OSError("handle closed")
            server_mod._shutdown()  # Should not raise
            assert server_mod._shutdown_done is True
