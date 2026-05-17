"""Plugin system for domain-specific Lua helpers.

Plugins are user-activated extensions: single .py files placed in the
$MEMSCOPE_HOME/plugins/ directory (~/.memscope-mcp/plugins/ by default). They
share the same LuaExtension contract as core features, but are loaded from an
external directory and isolated on failure.

At server startup, the bootstrap loads them, registers their Lua functions, and
appends their `instructions` fragments to the assembled server instructions bundle.

Loading is based on the plugin file being present in the plugins directory, not on
whether some target DLL or module is currently loaded in the attached process.

See contrib/plugins/ for available plugins and plugins/README.md for the interface.
"""

import importlib.util
import inspect
import logging
from abc import abstractmethod
from pathlib import Path
from typing import Callable

from ..extensions.base import ExtensionContext, LuaExtension

logger = logging.getLogger(__name__)


class PluginBase(LuaExtension):
    """Base class for user plugins. Thin specialization of LuaExtension.

    Subclass this to create a plugin. Place your .py file in the plugins/ directory.

    Example:
        class MyPlugin(PluginBase):
            name = "my_domain"
            description = "Helpers for My Domain"
            instructions = "## My Domain\\n..."

            def register(self, ctx: ExtensionContext) -> dict[str, callable]:
                self.table = ctx.table_factory
                return {"myFunction": self._my_func}

            def _my_func(self, addr):
                ...
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier, e.g. 'il2cpp'."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description for logs."""
        ...

    @property
    @abstractmethod
    def instructions(self) -> str:
        """AI-facing Lua/plugin docs appended to the server instruction bundle."""
        ...

    @abstractmethod
    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        """Register plugin functions.

        Args:
            ctx: ExtensionContext with engine, session, table_factory, log_error.

        Returns:
            Dict mapping Lua function names to Python callables.
        """
        ...


def _find_plugin_class(module) -> type[PluginBase] | None:
    """Find the PluginBase subclass in a module."""
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, PluginBase) and obj is not PluginBase:
            return obj
    return None


def load_plugins(plugins_dir: Path | None = None) -> list[PluginBase]:
    """Load all plugins from the plugins directory.

    Args:
        plugins_dir: Path to plugins directory. Defaults to <project_root>/plugins/

    Returns:
        List of instantiated plugin objects, sorted by name.
    """
    if plugins_dir is None:
        from ..paths import PLUGINS_DIR

        plugins_dir = PLUGINS_DIR

    if not plugins_dir.is_dir():
        return []

    plugins = []
    plugin_files = sorted(plugins_dir.glob("*.py"))

    for filepath in plugin_files:
        if filepath.name.startswith("_"):
            continue

        module_name = f"plugin_{filepath.stem}"

        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                logger.warning(f"Plugin: could not load {filepath.name}, skipping")
                continue

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            plugin_class = _find_plugin_class(module)
            if plugin_class is None:
                logger.warning(f"Plugin: no PluginBase subclass found in {filepath.name}, skipping")
                continue

            plugin = plugin_class()
            plugins.append(plugin)
            logger.info(f"Plugin: loaded '{plugin.name}' - {plugin.description}")

        except Exception as e:
            logger.warning(f"Plugin: failed to load {filepath.name}: {e}", exc_info=True)
            continue

    return plugins
