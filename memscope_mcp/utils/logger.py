"""MCP request/response logging for debugging and analysis.

Logs bounded tool-call summaries to JSON Lines files organized by server session.
Auto-cleans logs older than 2 years.
"""

import hashlib
import json
import math
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from functools import wraps
from itertools import islice
from pathlib import Path
from typing import Any, Optional

MAX_STRING_CHARS = 240
MAX_LUA_PREVIEW_CHARS = 160
MAX_BYTES_PREVIEW = 32
MAX_CONTAINER_ITEMS = 8
MAX_DEPTH = 3


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

        self.session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.session_dir = self.log_dir / "sessions"
        self.current_file: Optional[Path] = None
        self._file_handle = None
        self._last_cleanup: Optional[datetime] = None
        self._current_process: Optional[str] = None
        self._request_id = 0

        self.session_dir.mkdir(parents=True, exist_ok=True)

    def set_process(self, process_name: str):
        """Set current process name for subsequent log entries."""
        self._current_process = process_name
        self._maybe_cleanup()

    def clear_process(self):
        """Clear process context for subsequent log entries."""
        self._current_process = None

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
                date_str = log_file.stem.split("_")[0]
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                if file_date < cutoff:
                    log_file.unlink()
            except (ValueError, OSError):
                pass

    def log(self, tool: str, args: dict, result: dict, duration_ms: float):
        """Log a tool call."""
        success = self._is_success(result)
        entry = {
            "request_id": self._next_request_id(),
            "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "tool": tool,
            "args": self._sanitize_args(args, tool),
            "success": success,
            "ms": round(duration_ms, 1),
        }

        if self._current_process:
            entry["process"] = self._current_process

        if success:
            entry["result"] = self._summarize_value(result)
        else:
            self._add_failure_fields(entry, result)

        try:
            handle = self._get_handle()
            handle.write(json.dumps(entry, ensure_ascii=False, allow_nan=False) + "\n")
            handle.flush()
        except Exception as e:
            import sys

            print(f"[LOGGER ERROR] {e}", file=sys.stderr)

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _is_success(self, result: Any) -> bool:
        if not isinstance(result, Mapping):
            return True
        return not (result.get("success") is False or "error" in result)

    def _add_failure_fields(self, entry: dict, result: Any) -> None:
        if not isinstance(result, Mapping):
            entry["failure"] = self._summarize_value(result)
            return

        if "error" in result:
            entry["error"] = self._summarize_value(result["error"])

        detail = result.get("detail")
        if detail is not None:
            entry["detail"] = self._summarize_value(detail)

        extras = {key: value for key, value in result.items() if key not in {"success", "error", "detail"}}
        if extras:
            entry["failure"] = self._summarize_value(extras)

    def _sanitize_args(self, args: dict, tool: Optional[str] = None) -> dict:
        """Sanitize and bound args for logging."""
        if not isinstance(args, Mapping):
            return self._summarize_value(args)

        result = {}
        for key, value in args.items():
            key_text = self._summarize_key(key)
            if tool == "lua" and key_text == "script":
                result[key_text] = self._summarize_lua_source(value)
            else:
                result[key_text] = self._summarize_value(value)
        return result

    def _summarize_lua_source(self, value: Any) -> Any:
        if not isinstance(value, str):
            return self._summarize_value(value)

        return {
            "type": "lua_source",
            "length": len(value),
            "lines": len(value.splitlines()) if value else 0,
            "preview": self._preview(value, MAX_LUA_PREVIEW_CHARS),
            "sha256": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
        }

    def _summarize_value(self, value: Any, depth: int = 0) -> Any:
        if value is None or isinstance(value, bool | int):
            return value

        if isinstance(value, float):
            if math.isfinite(value):
                return value
            return {"type": "float", "value": str(value)}

        if isinstance(value, str):
            return self._summarize_string(value)

        if isinstance(value, bytes | bytearray | memoryview):
            return self._summarize_bytes(bytes(value))

        if isinstance(value, Mapping):
            return self._summarize_mapping(value, depth)

        if isinstance(value, set | frozenset):
            ordered = sorted(value, key=repr)
            return self._summarize_sequence(ordered, "set", depth)

        if isinstance(value, Sequence):
            return self._summarize_sequence(value, type(value).__name__, depth)

        return {"type": type(value).__name__, "repr": self._summarize_string(repr(value))}

    def _summarize_string(self, value: str) -> Any:
        if len(value) <= MAX_STRING_CHARS:
            return value
        return {
            "type": "str",
            "length": len(value),
            "preview": self._preview(value, MAX_STRING_CHARS),
            "sha256": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
        }

    def _summarize_bytes(self, value: bytes) -> dict:
        preview = value[:MAX_BYTES_PREVIEW]
        return {
            "type": "bytes",
            "length": len(value),
            "preview_hex": preview.hex(" ").upper(),
            "sha256": hashlib.sha256(value).hexdigest(),
        }

    def _summarize_mapping(self, value: Mapping, depth: int) -> dict:
        if depth >= MAX_DEPTH:
            return {"type": "dict", "length": len(value), "truncated": True}

        result = {}
        length = len(value)
        for index, (key, item) in enumerate(islice(value.items(), MAX_CONTAINER_ITEMS)):
            key_text = self._summarize_key(key)
            if key_text in result:
                key_text = f"{key_text}#{index}"
            result[key_text] = self._summarize_value(item, depth + 1)

        if length > MAX_CONTAINER_ITEMS:
            result["_truncated"] = f"{length - MAX_CONTAINER_ITEMS} more entries"

        return result

    def _summarize_sequence(self, value: Sequence, type_name: str, depth: int) -> Any:
        length = len(value)
        if depth >= MAX_DEPTH:
            return {"type": type_name, "length": length, "truncated": True}

        items = [self._summarize_value(value[index], depth + 1) for index in range(min(length, MAX_CONTAINER_ITEMS))]
        if length <= MAX_CONTAINER_ITEMS:
            return items

        return {
            "type": type_name,
            "length": length,
            "items": items,
            "truncated_items": length - MAX_CONTAINER_ITEMS,
        }

    def _summarize_key(self, key: Any) -> str:
        if isinstance(key, str):
            text = key
        else:
            text = repr(key)
        return self._preview(text, MAX_STRING_CHARS)

    def _preview(self, value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        return value[:limit] + "..."


LOGGER = MCPLogger()


def logged_tool(tool_name: str):
    """Decorator to log MCP tool calls."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            log_args = kwargs.copy()
            result = func(*args, **kwargs)
            duration_ms = (time.perf_counter() - start) * 1000
            LOGGER.log(tool_name, log_args, result, duration_ms)
            return result

        return wrapper

    return decorator
