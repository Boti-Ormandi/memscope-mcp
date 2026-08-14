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

import ast
import importlib.util
import inspect
import logging
import tokenize
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..extensions.base import ExtensionContext, LuaExtension
from .diagnostics import emit_plugin_failure

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
            ctx: ExtensionContext whose supported plugin fields are
                session, table_factory, and hook_manager.

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


@dataclass(frozen=True, slots=True)
class _PluginMetadata:
    filename: str
    declared_name: str | None
    source_path: Path | None


class _LoadedPlugins(list[PluginBase]):
    """List-compatible plugin result with identity-bound source metadata."""

    def __init__(self) -> None:
        super().__init__()
        self._metadata_by_identity: dict[int, _PluginMetadata] = {}

    def append_loaded(self, plugin: PluginBase, metadata: _PluginMetadata) -> None:
        self.append(plugin)
        self._metadata_by_identity[id(plugin)] = metadata

    def metadata_for(self, plugin: LuaExtension) -> _PluginMetadata | None:
        return self._metadata_by_identity.get(id(plugin))


class _PluginContractError(RuntimeError):
    pass


def _get_plugin_metadata(plugins: list[PluginBase], plugin: LuaExtension) -> _PluginMetadata:
    """Return loader metadata or a safe synthetic fallback for injected plugins."""

    if isinstance(plugins, _LoadedPlugins):
        metadata = plugins.metadata_for(plugin)
        if metadata is not None:
            return metadata

    source_path: Path | None = None
    try:
        source = inspect.getsourcefile(type(plugin))
        if source:
            source_path = Path(source)
    except (OSError, TypeError):
        pass
    filename = source_path.name if source_path is not None else f"{type(plugin).__name__}.py"
    return _PluginMetadata(filename=filename, declared_name=None, source_path=source_path)


def load_plugins(plugins_dir: Path | None = None) -> list[PluginBase]:
    """Load activated plugins nonrecursively in sorted filename order.

    Args:
        plugins_dir: Activated plugin directory. Defaults to
            ``$MEMSCOPE_HOME/plugins``.

    Returns:
        A list-compatible sequence of instantiated plugin objects in filename
        order. Bundled catalog sources are never scanned by this runtime path.
    """

    if plugins_dir is None:
        from ..paths import PLUGINS_DIR

        plugins_dir = PLUGINS_DIR
    plugins_dir = Path(plugins_dir)

    plugins = _LoadedPlugins()
    if not plugins_dir.is_dir():
        return plugins

    for filepath in sorted(plugins_dir.glob("*.py"), key=lambda path: path.name):
        if filepath.name.startswith("_"):
            continue

        declared_name: str | None = None
        module_name = f"plugin_{filepath.stem}"

        try:
            declared_name = _read_declared_plugin_name(filepath)
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                raise _PluginContractError("Python could not create a plugin module specification")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            plugin_class = _find_plugin_class(module)
            if plugin_class is None:
                raise _PluginContractError("No PluginBase subclass was declared")

            plugin = plugin_class()
        except Exception as exc:
            emit_plugin_failure(
                filename=filepath.name,
                declared_name=declared_name,
                exc=exc,
                source_path=filepath,
            )
            continue

        plugins.append_loaded(
            plugin,
            _PluginMetadata(
                filename=filepath.name,
                declared_name=declared_name,
                source_path=filepath,
            ),
        )
        try:
            logger.info("Plugin file '%s' imported", filepath.name)
        except Exception:
            pass

    return plugins


def _read_declared_plugin_name(filepath: Path) -> str | None:
    """Read one unambiguous literal PluginBase class name without importing."""

    try:
        with tokenize.open(filepath) as handle:
            tree = ast.parse(handle.read(), filename=filepath.name)
    except (LookupError, OSError, SyntaxError, UnicodeError):
        return None

    declared_names: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not any(_is_plugin_base_reference(base) for base in node.bases):
            continue
        for statement in node.body:
            value: ast.expr | None = None
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == "name"
            ):
                value = statement.value
            elif (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.target.id == "name"
            ):
                value = statement.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                declared_names.append(value.value)
                break

    return declared_names[0] if len(declared_names) == 1 else None


def _is_plugin_base_reference(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "PluginBase"
    return isinstance(node, ast.Attribute) and node.attr == "PluginBase"
