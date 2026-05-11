"""Plugin system for domain-specific helpers.

Plugins are single .py files placed in the `plugins/` directory at the project root.
At server startup, all plugins are loaded and their Lua functions + instructions registered.

See contrib/plugins/ for available plugins and plugins/README.md for the interface.
"""

import importlib.util
import inspect
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class PluginBase(ABC):
    """Base class for domain plugins.

    Subclass this to create a plugin. Place your .py file in the plugins/ directory.

    Example:
        class MyPlugin(PluginBase):
            name = "my_domain"
            description = "Helpers for My Domain"
            instructions = "## My Domain\\n..."

            def register(self, engine) -> dict[str, callable]:
                self.table = engine.lua.table
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
        """AI-facing documentation. Appended to server instructions."""
        ...

    @abstractmethod
    def register(self, engine) -> dict[str, callable]:
        """Register plugin functions with the Lua engine.

        Called once at startup. Use `engine.lua.table` to create Lua tables
        in your helper functions.

        Args:
            engine: The Lua engine instance.

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
        # Project root is 2 levels up from src/plugins/
        project_root = Path(__file__).parent.parent.parent
        plugins_dir = project_root / "plugins"

    if not plugins_dir.is_dir():
        return []

    # Ensure PluginBase is importable from plugins
    # Add src parent to sys.path if not already there
    project_root = plugins_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

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
