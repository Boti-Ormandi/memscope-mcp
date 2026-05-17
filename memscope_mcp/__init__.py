"""memscope-mcp: a Model Context Protocol server for memory research on Windows."""

from __future__ import annotations

import sys

if sys.platform != "win32":
    raise RuntimeError(
        f"memscope-mcp requires Windows (sys.platform == 'win32'); detected sys.platform={sys.platform!r}"
    )
