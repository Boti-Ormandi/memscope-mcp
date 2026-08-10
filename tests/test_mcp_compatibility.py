"""Real stdio interoperability tests against the installed memscope executable."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import TextContent

EXPECTED_TOOLS = {
    "processes",
    "attach",
    "modules",
    "read",
    "write",
    "dump",
    "chain",
    "scan",
    "scan_many",
    "lua",
    "scripts",
}
EXPECTED_INVALID_SCAN = {
    "success": False,
    "error": "INVALID_ARGUMENT",
    "detail": "Unknown scan argument 'offset'",
    "field": "offset",
}


def _memscope_executable() -> str:
    executable_name = "memscope-mcp.exe" if os.name == "nt" else "memscope-mcp"
    adjacent = Path(sys.executable).with_name(executable_name)
    if adjacent.is_file():
        return str(adjacent)
    resolved = shutil.which("memscope-mcp")
    assert resolved is not None, "memscope-mcp console executable is not installed in the test environment"
    return resolved


async def _exercise_stdio(tmp_path: Path, *, mode: str | None) -> None:
    environment = os.environ.copy()
    environment["MEMSCOPE_HOME"] = str(tmp_path / (mode or "default"))
    transport = stdio_client(
        StdioServerParameters(
            command=_memscope_executable(),
            env=environment,
            cwd=Path(__file__).parents[1],
        )
    )
    client = Client(transport) if mode is None else Client(transport, mode=mode)

    async with client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS

        invalid = await client.call_tool("scan", {"pattern": "AA", "offset": 1})
        assert invalid.structured_content == EXPECTED_INVALID_SCAN
        assert invalid.is_error is False
        assert len(invalid.content) == 1
        assert isinstance(invalid.content[0], TextContent)
        assert json.loads(invalid.content[0].text) == EXPECTED_INVALID_SCAN


def test_stdio_client_default_mode_interoperates_with_memscope_executable(tmp_path):
    asyncio.run(_exercise_stdio(tmp_path, mode=None))


def test_stdio_client_legacy_mode_interoperates_with_same_memscope_executable(tmp_path):
    asyncio.run(_exercise_stdio(tmp_path, mode="legacy"))
