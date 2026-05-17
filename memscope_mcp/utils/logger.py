"""MCP request/response logging for debugging and analysis.

Logs all tool calls to JSON Lines files organized by process name and date.
Auto-cleans logs older than 2 years.
"""

import json
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional


class MCPLogger:
    """Logger for MCP tool calls.

    Session-based logging: one log file per MCP server session.
    Path: logs/sessions/<session_id>.jsonl
    Session ID format: YYYY-MM-DD_HH-MM-SS (server start time)
    """

    def __init__(self, retention_days: int = 730):
        from ..paths import LOGS_DIR

        self.log_dir = LOGS_DIR
        self.retention_days = retention_days

        # Session-based logging
        self.session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.session_dir = self.log_dir / "sessions"
        self.current_file: Optional[Path] = None
        self._file_handle = None
        self._last_cleanup: Optional[datetime] = None

        # Ensure session directory exists
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def set_process(self, process_name: str):
        """Set current process name (for logging context, doesn't change log file)."""
        # Session-based: log file doesn't change, but we track process for log entries
        self._current_process = process_name
        self._maybe_cleanup()

    def _ensure_log_dir(self):
        """Create session log directory."""
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def _get_log_file(self) -> Path:
        """Get current session log file path."""
        return self.session_dir / f"{self.session_id}.jsonl"

    def get_session_info(self) -> dict:
        """Get session info for documentation/debugging."""
        return {
            "session_id": self.session_id,
            "log_file": str(self._get_log_file()),
        }

    def _close_file(self):
        """Close current file handle."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
            self.current_file = None

    def _get_handle(self):
        """Get file handle, opening new file if needed."""
        log_file = self._get_log_file()

        # Check if we need a new file (new day or new process)
        if self.current_file != log_file:
            self._close_file()
            self.current_file = log_file
            self._file_handle = open(log_file, "a", encoding="utf-8")

        return self._file_handle

    def _maybe_cleanup(self):
        """Run cleanup if not done recently (once per day max)."""
        now = datetime.now()
        if self._last_cleanup and (now - self._last_cleanup).days < 1:
            return

        self._last_cleanup = now
        self._cleanup_old_logs()

    def _cleanup_old_logs(self):
        """Delete session log files older than retention_days."""
        if not self.session_dir.exists():
            return

        cutoff = datetime.now() - timedelta(days=self.retention_days)

        for log_file in self.session_dir.glob("*.jsonl"):
            try:
                # Parse date from filename (YYYY-MM-DD_HH-MM-SS.jsonl)
                date_str = log_file.stem.split("_")[0]  # Get YYYY-MM-DD part
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                if file_date < cutoff:
                    log_file.unlink()
            except (ValueError, OSError):
                pass  # Skip files with unexpected names

    def log(self, tool: str, args: dict, result: dict, duration_ms: float):
        """Log a tool call."""
        entry = {
            "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "tool": tool,
        }

        # Include process context if set
        if hasattr(self, "_current_process") and self._current_process:
            entry["process"] = self._current_process

        entry["args"] = self._sanitize_args(args)
        entry["success"] = result.get("success", False)

        # Add error info if failed
        if not entry["success"]:
            if "error" in result:
                entry["error"] = result["error"]
            if "detail" in result or "error_detail" in result:
                entry["detail"] = result.get("detail") or result.get("error_detail")

        # Add result summary (truncate large results)
        if entry["success"] and "result" in result:
            entry["result"] = result["result"]

        entry["ms"] = round(duration_ms, 1)

        try:
            handle = self._get_handle()
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
            handle.flush()
        except Exception as e:
            # Don't let logging errors break the MCP, but print for debugging
            import sys

            print(f"[LOGGER ERROR] {e}", file=sys.stderr)

    def _sanitize_args(self, args: dict) -> dict:
        """Sanitize args for logging (handle non-serializable types)."""
        result = {}
        for k, v in args.items():
            try:
                # Test if serializable
                json.dumps(v)
                result[k] = v
            except (TypeError, ValueError):
                result[k] = str(v)
        return result


# Global logger instance
LOGGER = MCPLogger()


def logged_tool(tool_name: str):
    """Decorator to log MCP tool calls."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()

            # Capture args for logging
            log_args = kwargs.copy()

            # Execute tool
            result = func(*args, **kwargs)

            # Log
            duration_ms = (time.perf_counter() - start) * 1000
            LOGGER.log(tool_name, log_args, result, duration_ms)

            return result

        return wrapper

    return decorator
