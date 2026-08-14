# Plugin API

A plugin is a Python file activated under `$MEMSCOPE_HOME/plugins/`. It contributes Lua functions to the existing `lua` MCP tool. The supported public contract consists of `PluginBase`, `LuaExtension`, and `ExtensionContext`.

## Imports

```python
from memscope_mcp.extensions.base import ExtensionContext, LuaExtension
from memscope_mcp.plugins import PluginBase
```

`PluginBase` is a thin specialization of `LuaExtension`. A plugin implements `name`, `description`, `instructions`, and `register(ctx)`.

## Registration context

The registration callback receives a context bound to the current `DebugSession` and engine composition:

```python
class ExamplePlugin(PluginBase):
    name = "example"
    description = "Small example helper"
    instructions = "## Example\nProvides exampleValue()."

    def register(self, ctx: ExtensionContext):
        session = ctx.session
        table = ctx.table_factory
        hook_manager = ctx.hook_manager

        def example_value():
            return table(attached=session.pm is not None)

        return {"exampleValue": example_value}
```

The supported context fields for plugin implementation are `ctx.session`, `ctx.table_factory`, and `ctx.hook_manager`. A plugin stores its state on `self`, checks manager/session identity when it uses hooks, and returns a complete mapping of Lua names to callables.

The raw Lua runtime is not a plugin interface. Do not use `ctx.lua`, `ctx.engine.lua`, `ExtensionContext.lua`, `memscope_mcp.tools.hooking.HOOK_MANAGER`, module-level `SESSION`, or module/session globals. `table_factory` is guarded and is valid only during engine-owned bootstrap or execution callbacks.

## Function mappings

`register` returns a `dict[str, callable]`. Bootstrap validates the complete mapping before accepting any name. Duplicate Lua names, duplicate extension names, invalid names, non-callables, and lifecycle-name collisions isolate the ordinary plugin without publishing a partial mapping. A later plugin cannot replace an earlier accepted function.

Use ordinary Python values and tables from `ctx.table_factory` at the boundary. The Lua engine rejects executable Lua handles, userdata, threads, functions, and cyclic tables when converting results to MCP data.

## Lifecycle

Optional callbacks are:

```python
def on_process_attached(self, session):
    ...

def on_process_detaching(self, session, process_alive):
    ...
```

Attach callbacks run after a successful process attach or switch. Detach callbacks run before the process handle closes. `process_alive` indicates whether target-side cleanup can still run. Callback failures are isolated; plugin state must still reset on both live and already-exited detach paths.

Use the session passed to `register` and lifecycle callbacks. The retained `DebugSession.modules` property provides a defensive dictionary compatibility view; it does not permit write-through mutation of the immutable module snapshot. `openProcess` remains a supported Lua alias for attach-by-PID behavior.

## Plugin metadata

`name` is the declared extension name. `description` is a short summary. `instructions` is appended to the server instruction bundle only when the plugin activates successfully. A plugin does not add an MCP tool.

## Loading rules

The runtime scans only `$MEMSCOPE_HOME/plugins/*.py`, nonrecursively, in sorted **filename** order, excluding underscore-prefixed files. The loader instantiates the first `PluginBase` subclass it finds in each file. Bundled files under `memscope_mcp/_contrib/plugins/` are catalog/install sources, not an automatic runtime root.

Earlier activated files win extension-name and Lua-function collisions. Import, metadata, construction, registration, and lifecycle failures are isolated for ordinary exceptions. Core failures and fatal composition failures quarantine the engine. See [Extension composition](../concepts/extension-composition.md) and [Plugin lifecycle](../plugins/lifecycle.md).

## Source and tests

- [`memscope_mcp/extensions/base.py`](../../memscope_mcp/extensions/base.py)
- [`memscope_mcp/extensions/bootstrap.py`](../../memscope_mcp/extensions/bootstrap.py)
- [`memscope_mcp/plugins/__init__.py`](../../memscope_mcp/plugins/__init__.py)
- [`memscope_mcp/_contrib/plugins/il2cpp.py`](../../memscope_mcp/_contrib/plugins/il2cpp.py)
- [`memscope_mcp/_contrib/plugins/netcap.py`](../../memscope_mcp/_contrib/plugins/netcap.py)
- [`tests/test_extension_bootstrap.py`](../../tests/test_extension_bootstrap.py)
