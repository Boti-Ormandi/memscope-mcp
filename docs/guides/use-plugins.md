# Use plugins

Plugins are opt-in Python extensions. Start by listing bundled sources, review the file that you activate, and inspect the resulting Lua registry after restarting the server.

## Activate a bundled plugin

```powershell
memscope-mcp list-plugins
memscope-mcp install-plugin il2cpp
memscope-mcp install-plugin netcap
memscope-mcp paths
```

The default install is non-overwriting. If a local activated copy already exists, compare and review it before using:

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

- Use [IL2CPP](../plugins/il2cpp.md) for Unity runtime structures and thread-local native calls.
- Use [Netcap](../plugins/netcap.md) for Winsock hooks, packet analysis, and recordings.
- Use [Plugin authoring](../plugins/authoring.md) when writing a local domain helper.

## Trust and data

An activated plugin runs as Python in the server process. It can read the attached target through its session, invoke registered hooks or native helpers, and write local files. Review source, imports, registration mappings, lifecycle callbacks, and data paths. Keep activation in a disposable `MEMSCOPE_HOME` while testing.

Netcap can capture target traffic and environment data can contain secrets. Protect the data root and do not paste logs, plugin diagnostics, or recordings into public reports.

See [Plugin overview](../plugins/overview.md), [Plugin troubleshooting](../plugins/troubleshooting.md), and [Security model](../concepts/security-model.md).
