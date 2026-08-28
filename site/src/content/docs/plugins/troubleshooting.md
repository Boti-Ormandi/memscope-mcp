---
title: "Troubleshoot plugins"
description: "Diagnose isolated plugin failures without bypassing composition boundaries."
---

Plugin failures are isolated when they are ordinary exceptions; core startup remains available unless composition itself encounters a fatal failure.

## Confirm activation

```powershell
memscope-mcp paths
Get-ChildItem (Join-Path $env:MEMSCOPE_HOME "plugins") -Filter *.py
```

The runtime scans only direct `.py` children, sorts by filename, and ignores names beginning with `_`. Nested files and bundled `_contrib` files do not activate automatically.

After restarting the server, inspect the Lua registry:

```lua
print(getLoadedExtensions())
for _, item in ipairs(listLuaFunctions("netcap")) do
    print(item.name, item.owner)
end
```

`getLoadedExtensions()` preserves first-seen owner order. A plugin with no successful mapping is absent.

## Read the structured diagnostic

An isolated failure emits one compact JSON record on stderr and one in the session log. The schema is `memscope-plugin-diagnostic/v1`; the code is `PLUGIN_CONTEXT_INCOMPATIBLE` or `PLUGIN_LOAD_FAILED`.

`PLUGIN_CONTEXT_INCOMPATIBLE` is narrow. It identifies structural access to removed `lua`/runtime or module-level hook-manager globals. A user-thrown exception whose text merely mentions those words remains `PLUGIN_LOAD_FAILED`.

The diagnostic guidance is fixed:

```text
https://memscope.esrc.dev/plugins/upgrading/
```

The ordered required context fields are:

```text
ctx.session
ctx.table_factory
ctx.hook_manager
```

Cause messages are bounded and sanitized. Inspect the activated file locally when the record does not include exception details. The diagnostic never needs arbitrary source paths, tokens, or secrets.

## Common fixes

| Symptom | Check |
| --- | --- |
| `PLUGIN_CONTEXT_INCOMPATIBLE` | Replace `ctx.lua`, `ctx.engine.lua`, `ExtensionContext.lua`, or `HOOK_MANAGER` access with the supported context fields. |
| Plugin absent with no expected Lua functions | Check the filename extension, underscore prefix, direct directory, syntax, and `PluginBase` subclass. |
| Later plugin is absent | Compare sorted filenames and check declared extension/Lua-function/lifecycle collisions; earlier accepted files win. |
| Netcap or hook registration fails | Verify an attached x64 target, a session-bound `ctx.hook_manager`, required module exports, and hook permissions. |
| Attach callback raises | Release process-bound resources in detach as well and tolerate `process_alive=false`. |
| Lua table construction raises | Call `ctx.table_factory` only during registration or an engine-owned execution callback; do not call it from a worker thread. |
| Plugin file changes do not appear | Restart the MCP server. Runtime activation reads the activated copy at startup. |
| Install refuses to copy | An activated file already exists; `memscope-mcp install-plugin <name> --force` overwrites it. |

## Keep failures isolated

A plugin's ordinary import or registration exception does not publish partial functions or callbacks. A fatal `BaseException` or shared composition failure quarantines the engine and requires correcting the composition before another server start. Do not work around a quarantined engine by importing a module-level session or hook manager.

See [Plugin upgrading](/plugins/upgrading/), [Plugin lifecycle](/plugins/lifecycle-and-contract/), [Errors and status](/reference/errors-and-status/), and [Security model](/concepts/security-model/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/plugins/troubleshooting.md)
