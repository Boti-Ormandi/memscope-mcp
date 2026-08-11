"""Extension contract shared by core features and user plugins.

Every Lua-capable feature -- built-in or plugin -- implements LuaExtension.
Core extensions live under src/extensions/core/ and are always loaded.
User plugins live in plugins/ and are loaded at startup when present.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ..tools.hooking import HookManager


@dataclass(slots=True)
class ExtensionContext:
    """Shared context passed to extensions during registration.

    Attributes:
        engine: MemscopeLuaEngine instance (for per-execution helpers like print, results).
        session: DebugSession belonging to this bootstrap domain.
        table_factory: Guarded callable that creates Lua tables only during
            engine-owned bootstrap or execution operations.
        log_error: Callable[[func_name, exception], None] for error reporting.
        hook_manager: HookManager shared by hook-capable extensions in this bootstrap domain.
    """

    engine: Any
    session: Any
    table_factory: Callable[..., Any]
    log_error: Callable[[str, Exception], None]
    hook_manager: "HookManager | None" = None


class LuaExtension(ABC):
    """Base contract for core extensions and user plugins.

    Subclasses must implement ``name`` and ``register()``.
    Lifecycle callbacks are optional -- override them when the extension
    holds process-bound state that needs cleanup (e.g. hooks, allocations).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier, e.g. 'memory' or 'il2cpp'."""
        ...

    @property
    def description(self) -> str:
        """One-line summary for log output."""
        return ""

    @property
    def instructions(self) -> str:
        """AI-facing docs appended to the server instruction bundle.

        Extension-owned instruction fragment. Not an MCP tool docstring.
        Return empty string if the extension has no user-facing docs.
        """
        return ""

    @abstractmethod
    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        """Build and return one complete Lua function mapping at startup.

        Bootstrap preflights the returned mapping before installing any name.
        Registration runs before the composition is ready, so extensions must
        not execute scripts or publish lifecycle callbacks themselves. Arbitrary
        external side effects performed here are not rollback-guaranteed; a hard
        bootstrap failure instead permanently quarantines the composition.

        Args:
            ctx: Shared context with engine, session, and helpers.

        Returns:
            Dict mapping Lua global names to Python callables.
        """
        ...

    def on_process_attached(self, session: Any) -> None:
        """Called after a successful process attach/switch."""

    def on_process_detaching(self, session: Any, process_alive: bool) -> None:
        """Called before the process handle is closed.

        Args:
            session: The DebugSession being detached.
            process_alive: True if the process is still running (cleanup possible).
                False if the process already exited (only clear local state).
        """
