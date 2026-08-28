---
title: "Author a plugin"
description: "Create a session-bound plugin with atomic Lua registration."
---

A plugin is one activated Python file that subclasses `PluginBase` and returns a complete Lua function mapping. Start with read-only helpers and add writes, native calls, hooks, or local recording only when the capability is explicit in the plugin's purpose.

## Minimal read-only plugin

```python
from memscope_mcp.extensions.base import ExtensionContext
from memscope_mcp.plugins import PluginBase


class ProcessProbe(PluginBase):
    name = "process_probe"
    description = "Read-only process probe"
    instructions = """
## Process probe
`probeProcess()` returns the attached PID and process name.
""".strip()

    def register(self, ctx: ExtensionContext):
        table = ctx.table_factory
        session = ctx.session

        def probe_process():
            return table(pid=session.pid, process=session.target_process)

        return {"probeProcess": probe_process}
```

Copy the file to the activated directory:

```powershell
Copy-Item .\process_probe.py (Join-Path $env:MEMSCOPE_HOME "plugins\process_probe.py")
```

Restart the server, then discover the successful registration from Lua:

```lua
local found = false
for _, item in ipairs(listLuaFunctions("process_probe")) do
    found = true
    print(item.name, item.owner)
end
assert(found)
```

## Supported imports and context

Use these public imports:

```python
from memscope_mcp.extensions.base import ExtensionContext, LuaExtension
from memscope_mcp.plugins import PluginBase
```

Registration uses the session-bound `ctx.session`, guarded `ctx.table_factory`, and shared `ctx.hook_manager`. A plugin stores references on `self` only when it owns state for the current composition.

Do not use `ctx.lua`, `ctx.engine.lua`, `ExtensionContext.lua`, the module-level `HOOK_MANAGER`, module-level `SESSION`, or module/session globals. The raw Lua runtime is private, and the table factory is valid only during engine-owned bootstrap or execution callbacks.

## Registration rules

- Return one complete `dict` of Lua names to callables.
- Use unique Lua names and a unique extension `name`.
- Keep `instructions` concise and document only functions that the plugin registers.
- Use `ctx.table_factory` to build tables returned to Lua.
- Validate sizes, addresses, names, options, and target state before acting on Lua input.
- Keep process-bound resources on the plugin instance and release them in detach cleanup.
- Avoid side effects during registration that cannot be rolled back.

Bootstrap stages and validates a plugin mapping before publishing it. A failure does not publish a partial mapping or lifecycle callback. An earlier sorted filename wins a later extension-name or Lua-function collision.

## Session binding example

```python
class ModuleReader(PluginBase):
    name = "module_reader"
    description = "Reads the bound module view"
    instructions = "moduleBase(name) returns the current module base."

    def register(self, ctx: ExtensionContext):
        self._session = ctx.session
        return {
            "moduleBase": lambda name: self._session.get_module_base(str(name)),
        }
```

The instance reads only from the session supplied to this composition. Do not import a global `SESSION` to bypass that ownership.

## Add tests and docs

Use a disposable `MEMSCOPE_HOME` and test activation ordering, underscore exclusion, nested-file exclusion, duplicate names, function collisions, context ownership, lifecycle cleanup, diagnostic records, and target/resource failure paths. Link the user-facing page from [Plugin overview](/plugins/overview/) and keep the full API in [Plugin API](/reference/plugin-api/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/plugins/authoring.md)
