# Plugin upgrading

This page is evergreen guidance for keeping an activated plugin on the current context and activation contract. It does not describe release history.

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

`openProcess` remains a supported Lua attach alias, and `DebugSession.modules` remains a defensive compatibility view. These facts do not authorize raw global access.

## Activation and refresh

The runtime scans only `$MEMSCOPE_HOME/plugins/*.py`, nonrecursively, sorted by activated filename, excluding underscore-prefixed files. Bundled `_contrib` files are catalog/install sources, not an automatic second root.

`memscope-mcp install-plugin <name>` is non-overwriting by default. Review local modifications before explicit `memscope-mcp install-plugin <name> --force` refresh. Package upgrades preserve saved scripts and activated plugin copies; they do not rewrite scripts or refresh activated copies implicitly.

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

The diagnostic guidance route is a canonical destination. It does not imply that a web site is deployed.

## Repair checklist

1. Inspect the activated filename named by the diagnostic.
2. Replace raw runtime and global-manager access with the supported context fields.
3. Move process state to the plugin instance.
4. Add `on_process_attached` and `on_process_detaching` for target-bound resources.
5. Run the plugin in a disposable `MEMSCOPE_HOME`.
6. Check `listLuaFunctions("<plugin-name>")` and `getLoadedExtensions()` after restart.
7. Review the local file before any `--force` copy from a bundled source.

See [Plugin authoring](authoring.md), [Plugin lifecycle](lifecycle.md), [Plugin troubleshooting](troubleshooting.md), and [Plugin API](../reference/plugin-api.md).
