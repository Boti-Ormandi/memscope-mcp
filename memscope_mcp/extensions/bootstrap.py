"""Extension bootstrap -- single entry point for loading all extensions.

Instantiates core extensions, loads user plugins, registers Lua functions
and lifecycle callbacks with the engine and session.
"""

import logging
from typing import Any

from ..extensions.base import ExtensionContext, LuaExtension
from ..extensions.core import CORE_EXTENSIONS
from ..plugins import load_plugins
from ..session import DebugSession

logger = logging.getLogger(__name__)


def bootstrap_extensions(
    engine: Any,
    session: DebugSession,
) -> list[LuaExtension]:
    """Load and register all extensions (core + plugins).

    1. Instantiates core extensions in stable order.
    2. Loads user plugins from plugins/.
    3. Registers Lua functions through the engine.
    4. Registers lifecycle callbacks with the session.
    5. Returns the ordered extension list for instruction assembly.

    Args:
        engine: MemscopeLuaEngine instance.
        session: DebugSession singleton.

    Returns:
        Ordered list of all loaded extensions (core first, then plugins).
    """
    ctx = ExtensionContext(
        engine=engine,
        session=session,
        lua=engine.lua,
        table_factory=engine.lua.table,
        log_error=engine._log_error,
    )

    extensions: list[LuaExtension] = []

    # --- Core extensions (always loaded, stable order) ---
    for ext_cls in CORE_EXTENSIONS:
        ext = ext_cls()
        try:
            funcs = ext.register(ctx)
            engine.register_functions(ext.name, funcs)
            _register_lifecycle(session, ext)
            extensions.append(ext)
            logger.debug(f"Core extension '{ext.name}' registered ({len(funcs)} functions)")
        except Exception as e:
            # Core extension failure is a hard error
            raise RuntimeError(f"Core extension '{ext.name}' failed to register: {e}") from e

    # --- User plugins (isolated failures) ---
    plugins = load_plugins()
    for plugin in plugins:
        try:
            funcs = plugin.register(ctx)
            engine.register_functions(plugin.name, funcs)
            _register_lifecycle(session, plugin)
            extensions.append(plugin)
            logger.info(f"Plugin '{plugin.name}' registered ({len(funcs)} functions)")
        except Exception as e:
            logger.warning(f"Plugin '{plugin.name}' registration failed: {e}")

    return extensions


def _register_lifecycle(session: DebugSession, ext: LuaExtension) -> None:
    """Register lifecycle callbacks if the extension overrides them."""
    has_attach = type(ext).on_process_attached is not LuaExtension.on_process_attached
    has_detach = type(ext).on_process_detaching is not LuaExtension.on_process_detaching

    if has_attach:
        session.register_on_attach(ext.name, ext.on_process_attached)
    if has_detach:
        session.register_on_detach(ext.name, ext.on_process_detaching)
