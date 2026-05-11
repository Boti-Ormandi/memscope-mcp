"""MCP Server Instructions Module.

Builds AI-facing documentation from base instructions + loaded plugins.
"""

from .base import BASE_INSTRUCTIONS


def build_instructions(plugins: list = None) -> str:
    """Build full instructions from base + plugin docs.

    Args:
        plugins: List of loaded plugin instances with .instructions property.

    Returns:
        Combined instructions string.
    """
    parts = [BASE_INSTRUCTIONS]

    if plugins:
        for plugin in plugins:
            if plugin.instructions:
                parts.append(plugin.instructions)

    return "\n\n".join(parts)


__all__ = ["BASE_INSTRUCTIONS", "build_instructions"]
