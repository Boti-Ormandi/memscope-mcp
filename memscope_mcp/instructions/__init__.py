"""MCP server instruction assembly.

Builds the server-level instruction bundle from base instructions plus
extension-owned instruction fragments. This is separate from MCP tool docstrings.
"""

from ..extensions.base import LuaExtension
from .base import BASE_INSTRUCTIONS


def build_instructions(extensions: list[LuaExtension] | list | None = None) -> str:
    """Build full server instructions from base text plus extension docs.

    Args:
        extensions: Ordered list of loaded extensions (core + plugins).
            Each extension's .instructions property is appended if non-empty.

    Returns:
        Combined server instruction string used by the generic Lua workflow.
    """
    parts = [BASE_INSTRUCTIONS]

    if extensions:
        for ext in extensions:
            if ext.instructions:
                parts.append(ext.instructions)

    return "\n\n".join(parts)


__all__ = ["BASE_INSTRUCTIONS", "build_instructions"]
