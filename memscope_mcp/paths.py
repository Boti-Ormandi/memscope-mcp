"""Resolve runtime data directories under MEMSCOPE_HOME.

Resolution happens once at import time. Each subdirectory is created lazily
by callers via `.mkdir(parents=True, exist_ok=True)` at first use, so pure
introspection does not side-effect-create anything.

The session logger is the one stateful exception: MCPLogger.__init__ creates
its session subdirectory eagerly because it owns long-lived state and a log
filename is reserved per process invocation.
"""

from __future__ import annotations

import os
from pathlib import Path


def _resolve_home() -> Path:
    raw = os.environ.get("MEMSCOPE_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return Path.home() / ".memscope-mcp"


MEMSCOPE_HOME: Path = _resolve_home()
LOGS_DIR: Path = MEMSCOPE_HOME / "logs"
SCRIPTS_DIR: Path = MEMSCOPE_HOME / "scripts"
PLUGINS_DIR: Path = MEMSCOPE_HOME / "plugins"
