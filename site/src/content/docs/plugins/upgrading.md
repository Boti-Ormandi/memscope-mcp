---
title: "Upgrade plugins"
description: "Keep activated plugins on the current session-bound ExtensionContext contract."
---

Older plugins may use Lua runtime or hook-manager globals that are no longer exposed. Update them to use the session-bound `ExtensionContext` fields below.

## Current context contract

A plugin imports:

```python
from memscope_mcp.extensions.base import ExtensionContext, LuaExtension
from memscope_mcp.plugins import PluginBase
```

Registration uses these session-bound fields in this order when a migration diagnostic points to the contract:

1. `ctx.session`
2. `ctx.table_factory`
3. `ctx.hook_manager`

The plugin stores state on its instance and uses lifecycle callbacks for process-bound resources. The raw runtime is private.

Replace unsupported access patterns:

| Do not use | Use |
| --- | --- |
| `ctx.lua` | `ctx.table_factory` for guarded result tables |
| `ctx.engine.lua` | ordinary values and `ctx.table_factory` |
| `ExtensionContext.lua` | `ctx.session`, `ctx.table_factory`, or `ctx.hook_manager` |
| `memscope_mcp.tools.hooking.HOOK_MANAGER` | `ctx.hook_manager` |
| module-level `SESSION` | the session passed through `ctx.session` and lifecycle callbacks |
| module/session globals for plugin state | attributes on the plugin instance |

`openProcess` remains a supported Lua attach alias, and `DebugSession.modules` remains a defensive compatibility view; neither exposes the raw Lua runtime or module-level globals.

## Activation and refresh

The runtime scans only `$MEMSCOPE_HOME/plugins/*.py`, nonrecursively, sorted by activated filename, excluding underscore-prefixed files. Bundled `_contrib` files are catalog/install sources, not an automatic second root.

`memscope-mcp install-plugin <name>` is non-overwriting by default; `memscope-mcp install-plugin <name> --force` overwrites the activated copy. Package upgrades preserve saved scripts and activated plugin copies; they do not rewrite scripts or refresh activated copies implicitly.

## Structured migration diagnostic

An isolated plugin failure emits one record on the default `stderr` channel and one on the default `session_log` channel. The record uses the exact schema name `memscope-plugin-diagnostic/v1` and one of these codes:

- `PLUGIN_CONTEXT_INCOMPATIBLE` — a structurally recognized access to a removed Lua runtime or hook-manager global;
- `PLUGIN_LOAD_FAILED` — any other import, metadata, construction, registration, or ordinary plugin failure.

The record has these ordered top-level fields:

```json
{
  "schema": "memscope-plugin-diagnostic/v1",
  "severity": "warning",
  "code": "PLUGIN_LOAD_FAILED",
  "plugin": {
    "filename": "example.py",
    "declared_name": "example"
  },
  "cause": {
    "type": "RuntimeError",
    "message": "Plugin failure details are not included; inspect the activated plugin locally."
  },
  "guidance": {
    "url": "https://memscope.esrc.dev/plugins/upgrading/",
    "required_context_fields": [
      "ctx.session",
      "ctx.table_factory",
      "ctx.hook_manager"
    ]
  },
  "channel": "stderr"
}
```

The paired session-log record uses `"channel": "session_log"`. Filename and declared-name values are bounded basenames/strings. Cause type and message are bounded; arbitrary paths, plugin-controlled exception text, and secrets are not exposed. Sink failures remain isolated.

## Update the plugin

1. Inspect the activated filename named by the diagnostic.
2. Replace raw runtime and global-manager access with the supported context fields.
3. Move process state to the plugin instance.
4. Add `on_process_attached` and `on_process_detaching` for target-bound resources.
5. Run the plugin in a disposable `MEMSCOPE_HOME`.
6. Check `listLuaFunctions("<plugin-name>")` and `getLoadedExtensions()` after restart.
7. Expect any `--force` copy from a bundled source to overwrite the local file.

See [Plugin authoring](/plugins/authoring/), [Plugin lifecycle](/plugins/lifecycle-and-contract/), [Plugin troubleshooting](/plugins/troubleshooting/), and [Plugin API](/reference/plugin-api/).
