"""Lua context for dependency injection into extracted modules."""

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class LuaContext:
    """Context passed to extracted Lua helper modules.

    Provides access to shared state without tight coupling to the engine class.
    """

    table_factory: Callable[..., Any]  # Creates Lua tables: self.lua.table()
    output: list[str]  # Reference to self._output for print capture
    log_error: Callable[[str, Exception], None]  # Reference to self._log_error()
