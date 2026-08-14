# Plugin overview

Plugins add domain-specific Lua functions without expanding the MCP tool list. They are opt-in Python files, so activation is both a capability choice and a code-trust decision.

## Activation boundary

The runtime scans exactly `$MEMSCOPE_HOME/plugins/*.py`:

- the scan is nonrecursive;
- filenames sort before import and registration;
- underscore-prefixed files are excluded; and
- bundled `_contrib` files are catalog/install sources, not a second automatic root.

A file becomes active because it is present in the activated directory. It does not activate because a target DLL, process module, or package resource exists.

List and install bundled sources explicitly:

```powershell
memscope-mcp list-plugins
memscope-mcp install-plugin il2cpp
memscope-mcp install-plugin netcap
```

The default install refuses to overwrite an existing file. `--force` explicitly overwrites after local review. A package upgrade preserves saved scripts and activated plugin copies; it does not rewrite scripts or refresh plugin files implicitly.

## Bundled reference plugins

| Plugin | Focus | Entry source |
| --- | --- | --- |
| `il2cpp` | Unity IL2CPP strings, arrays, lists, dictionaries, and thread-local native-call guidance. | [`il2cpp.py`](../../memscope_mcp/_contrib/plugins/il2cpp.py) |
| `netcap` | Winsock hooks, packet analysis, stream assembly, framing, searches, and durable recordings. | [`netcap.py`](../../memscope_mcp/_contrib/plugins/netcap.py) |

Plugins use core capabilities such as memory reads, strict scans, native calls, and inline hooks. They do not add direct MCP methods; their functions are available through `lua` only after successful activation.

## Trust and state

Review every activated file as executable Python. A plugin can read target memory through its session, invoke any operation exposed by its imports, write local data, and register arbitrary Lua callbacks. Keep plugin state on the instance and bind it to the `ExtensionContext` session. Use `on_process_detaching` to release target hooks, allocations, files, and buffers.

See [Plugin authoring](authoring.md), [Plugin lifecycle](lifecycle.md), [Plugin upgrading](upgrading.md), and the [security model](../concepts/security-model.md).
