"""Extension bootstrap -- single entry point for loading all extensions.

Instantiates core extensions, loads user plugins, stages Lua functions, and
commits function/lifecycle publication as one engine composition.
"""

import logging
from collections.abc import Callable
from typing import Any

from ..extensions.base import ExtensionContext, LuaExtension
from ..extensions.core import CORE_EXTENSIONS
from ..plugins import _get_plugin_metadata, load_plugins
from ..plugins.diagnostics import emit_plugin_failure
from ..session import DebugSession
from ..tools.hooking import HookManager

logger = logging.getLogger(__name__)


def bootstrap_extensions(
    engine: Any,
    session: DebugSession,
    *,
    hook_manager: HookManager | None = None,
) -> list[LuaExtension]:
    """Load and transactionally register all core extensions and plugins.

    Core failures and plugin ``BaseException`` failures quarantine a claimed
    composition. Ordinary plugin failures are logged and skipped before any of
    that plugin's mapping or lifecycle callbacks are accepted.
    """

    manager = hook_manager if hook_manager is not None else HookManager(session)
    if manager.session is not session:
        raise ValueError("HookManager/session ownership mismatch")

    with engine._bootstrap_transaction(session) as transaction:
        ctx = ExtensionContext(
            engine=engine,
            session=session,
            table_factory=engine.table_factory,
            log_error=engine._log_error,
            hook_manager=manager,
        )
        existing_attach, existing_detach = session._lua_composition_callback_names_snapshot(engine)
        attach_names = set(existing_attach)
        detach_names = set(existing_detach)

        extensions: list[LuaExtension] = []
        extension_names: set[str] = set()
        attach_callbacks: dict[str, Callable[..., Any]] = {}
        detach_callbacks: dict[str, Callable[..., Any]] = {}

        for ext_cls in CORE_EXTENSIONS:
            label = getattr(ext_cls, "__name__", "<core extension>")
            try:
                extension = ext_cls()
                name = _extension_name(extension)
                label = name
                _require_unique_extension_name(name, extension_names)
                prepared = transaction.prepare_functions(name, extension.register(ctx))
                on_attach, on_detach = _prepare_lifecycle(
                    extension,
                    name,
                    attach_names,
                    detach_names,
                )
                function_count = len(prepared.registrations)
                logger.debug("Core extension '%s' registered (%d functions)", name, function_count)
            except Exception as exc:
                raise RuntimeError(f"Core extension '{label}' failed to register: {exc}") from exc

            transaction.accept_functions(prepared)
            _accept_lifecycle(
                name,
                on_attach,
                on_detach,
                attach_names,
                detach_names,
                attach_callbacks,
                detach_callbacks,
            )
            extension_names.add(name)
            extensions.append(extension)

        plugins = load_plugins()
        for plugin in plugins:
            metadata = _get_plugin_metadata(plugins, plugin)
            label = metadata.declared_name or type(plugin).__name__
            name: str | None = None
            try:
                name = _extension_name(plugin)
                label = name
                _require_unique_extension_name(name, extension_names)
                prepared = transaction.prepare_functions(name, plugin.register(ctx))
                on_attach, on_detach = _prepare_lifecycle(
                    plugin,
                    name,
                    attach_names,
                    detach_names,
                )
                function_count = len(prepared.registrations)
                # Logging stays before acceptance so an ordinary handler failure
                # cannot strand an accepted plugin mapping without callbacks.
                logger.info("Plugin '%s' registered (%d functions)", name, function_count)
            except Exception as exc:
                emit_plugin_failure(
                    filename=metadata.filename,
                    declared_name=name or metadata.declared_name,
                    exc=exc,
                    source_path=metadata.source_path,
                )
                continue

            transaction.accept_functions(prepared)
            _accept_lifecycle(
                name,
                on_attach,
                on_detach,
                attach_names,
                detach_names,
                attach_callbacks,
                detach_callbacks,
            )
            extension_names.add(name)
            extensions.append(plugin)

        transaction.commit(session, attach_callbacks, detach_callbacks)
        return extensions


def _extension_name(extension: LuaExtension) -> str:
    name = extension.name
    if not isinstance(name, str) or str.__len__(name) == 0:
        raise TypeError("Extension name must be a non-empty string")
    return bytes.decode(str.encode(name, "utf-8", errors="replace"), "utf-8")


def _require_unique_extension_name(name: str, existing_names: set[str]) -> None:
    if name in existing_names:
        raise ValueError(f"Extension name '{name}' is already registered")


def _prepare_lifecycle(
    extension: LuaExtension,
    name: str,
    attach_names: set[str],
    detach_names: set[str],
) -> tuple[Callable[..., Any] | None, Callable[..., Any] | None]:
    """Inspect and validate lifecycle intent without publishing it."""

    extension_type = type(extension)
    on_attach = None
    if extension_type.on_process_attached is not LuaExtension.on_process_attached:
        on_attach = extension.on_process_attached
        if not callable(on_attach):
            raise TypeError(f"Extension '{name}' attach lifecycle callback must be callable")
        if name in attach_names:
            raise ValueError(f"Attach lifecycle callback '{name}' is already registered")

    on_detach = None
    if extension_type.on_process_detaching is not LuaExtension.on_process_detaching:
        on_detach = extension.on_process_detaching
        if not callable(on_detach):
            raise TypeError(f"Extension '{name}' detach lifecycle callback must be callable")
        if name in detach_names:
            raise ValueError(f"Detach lifecycle callback '{name}' is already registered")

    return on_attach, on_detach


def _accept_lifecycle(
    name: str,
    on_attach: Callable[..., Any] | None,
    on_detach: Callable[..., Any] | None,
    attach_names: set[str],
    detach_names: set[str],
    attach_callbacks: dict[str, Callable[..., Any]],
    detach_callbacks: dict[str, Callable[..., Any]],
) -> None:
    if on_attach is not None:
        attach_names.add(name)
        attach_callbacks[name] = on_attach
    if on_detach is not None:
        detach_names.add(name)
        detach_callbacks[name] = on_detach
