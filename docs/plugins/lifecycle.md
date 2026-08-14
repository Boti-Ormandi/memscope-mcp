# Plugin lifecycle

The plugin lifecycle has two boundaries: composition-time registration and process-time attach/detach. Keep those phases separate so a plugin cannot expose a partial Lua namespace or retain process resources after a target switch.

## Composition

At startup, bootstrap:

1. creates one `ExtensionContext` bound to the engine, `DebugSession`, table factory, logger callback, and shared `HookManager`;
2. instantiates core extensions in fixed order;
3. loads activated plugin files in sorted filename order;
4. validates extension names and complete Lua mappings;
5. stages lifecycle intent and checks callback names; and
6. publishes all accepted mappings and callbacks at one ready commit.

No plugin mapping or callback is supported before commit. A normal plugin exception isolates that plugin and lets core and later files continue. A later duplicate declared name, Lua function name, or lifecycle name is isolated without replacing the earlier owner. Core failures, fatal plugin `BaseException` failures, and shared commit failures quarantine the composition.

## Attach and detach

Implement optional callbacks when the plugin owns process-bound state:

```python
class HookPlugin(PluginBase):
    name = "hook_plugin"
    description = "Process-bound hook example"
    instructions = "Provides hookPluginStatus()."

    def register(self, ctx):
        self._session = ctx.session
        self._hook_manager = ctx.hook_manager
        return {"hookPluginStatus": self._status}

    def on_process_attached(self, session):
        if session is self._session:
            self._start_target_state()

    def on_process_detaching(self, session, process_alive):
        if session is self._session:
            self._stop_target_state(process_alive)
            self._clear_target_state()
```

`on_process_attached` runs after a successful process open or switch. `on_process_detaching` runs before the handle closes. If `process_alive` is false, clear local state without assuming target-side calls succeed. Callback failures are logged and isolated from other callbacks.

The session snapshots callbacks before invocation and releases its lock. A callback can register a callback for a later firing, but composition callbacks cannot be replaced.

## Hook and state ownership

Core hooking and a hook-using plugin receive the same session-bound `HookManager`. Do not construct or import a module-level manager. Keep hook IDs, ring-buffer state, allocations, file handles, and pending asynchronous state on the plugin instance. Remove target hooks before freeing associated buffers, and close local handles during both explicit detach and server shutdown.

Use the shared manager only through `ctx.hook_manager`. Check `ctx.hook_manager.session is ctx.session` when a plugin needs an explicit ownership assertion.

## Thread and table rules

Lua execution is serialized by the engine's logical runtime lease. `ctx.table_factory` is valid during registration and engine-owned callbacks, not from arbitrary background threads. A plugin that uses worker threads must move plain data across the thread boundary and arrange any Lua-table construction or Lua call on an engine-owned operation.

Do not retain raw Lua objects, runtime handles, `ctx.lua`, `ctx.engine.lua`, or module/session globals. The engine rejects executable handles and cyclic tables when converting results.

## Failure behavior

Registration and lifecycle failures have different effects:

- ordinary plugin failures isolate one plugin and emit structured diagnostics;
- callback failures during attach/detach are logged and do not stop other callbacks;
- core failures and shared composition failures quarantine the engine; and
- a process that exits can limit cleanup to local state, so callbacks must tolerate `process_alive=false`.

See [Plugin troubleshooting](troubleshooting.md), [Session lifecycle](../concepts/session-lifecycle.md), and [Plugin API](../reference/plugin-api.md).
