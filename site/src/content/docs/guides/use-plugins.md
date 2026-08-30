---
title: "Use plugins"
description: "Activate opt-in IL2CPP, Netcap, or local Python plugins."
---

Plugins are opt-in Python extensions. List bundled sources, activate one, and inspect the resulting Lua registry after restarting the server.

## Activate a bundled plugin

```powershell
memscope-mcp list-plugins
memscope-mcp install-plugin il2cpp
memscope-mcp install-plugin netcap
memscope-mcp paths
```

The default install refuses to overwrite an existing activated copy. Overwrite one explicitly with:

```powershell
memscope-mcp install-plugin netcap --force
```

`--force` is the explicit overwrite operation. Package upgrades preserve activated plugin copies and saved scripts; they do not refresh local files implicitly.

## Confirm the runtime

Restart the MCP server, then use Lua:

```lua
print(getLoadedExtensions())
for _, item in ipairs(listLuaFunctions("il2cpp")) do
    print(item.name)
end
```

A successful plugin contributes Lua functions to `lua`; it does not add an MCP tool. Runtime scanning uses only direct `$MEMSCOPE_HOME/plugins/*.py` files in sorted filename order and excludes underscore-prefixed files.

## Choose a plugin

- Use [IL2CPP](/plugins/il2cpp/) for Unity runtime structures and thread-local native calls.
- Use [Netcap](/plugins/netcap/) for Winsock hooks, packet analysis, and recordings.
- Use [Plugin authoring](/plugins/authoring/) when writing a local domain helper.

## Execution and data

An activated plugin runs as Python in the server process. It can read the attached target through its session, invoke registered hooks or native helpers, and write local files. Registration mappings, lifecycle callbacks, and data paths follow the contracts in [Plugin lifecycle](/plugins/lifecycle-and-contract/) and [Plugin API](/reference/plugin-api/). Testing can use a disposable `MEMSCOPE_HOME` so activation artifacts stay out of the default root.

Netcap captures target traffic, and environment reads can return credentials or other secret material. Recordings, logs, and diagnostics persist under `MEMSCOPE_HOME`.

See [Plugin overview](/plugins/overview/), [Plugin troubleshooting](/plugins/troubleshooting/), and [Security model](/concepts/security-model/).
