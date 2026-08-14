# Compatibility

The current public compatibility boundary is intentionally small and explicit.

## Host and transport

- Windows x64 host.
- x64 target process.
- 64-bit Python 3.10 or newer.
- MCP over stdio.
- Lua 5.4 through Lupa.

PEB inspection does not provide WOW64 translation. A target with a different bitness is outside the supported process-introspection layout.

## MCP surface

The server exposes exactly 11 tools: `processes`, `attach`, `modules`, `read`, `write`, `dump`, `chain`, `scan`, `scan_many`, `lua`, and `scripts`. Configuration uses an MCP client command entry with `command: "memscope-mcp"`.

`openProcess(pid)` remains a supported Lua attach alias. `DebugSession.modules` remains a defensive dictionary view of the current module snapshot. Plugins use the session-bound context rather than raw global session or hook-manager objects.

## Data and plugins

The runtime data root is `$MEMSCOPE_HOME` with `logs/`, `scripts/`, and `plugins/` subdirectories. Plugin loading is nonrecursive and filename-sorted under `$MEMSCOPE_HOME/plugins/*.py`; bundled `_contrib` files are catalog/install sources.

Netcap canonical recordings use `$MEMSCOPE_HOME/scripts/<process>/recordings/`. The cwd-relative `scripts/<process>/recordings/` path is a read-only legacy fallback with explicit warning behavior. File selection, component validation, append semantics, compression publication, and residuals are in [Netcap](../plugins/netcap.md).

## Contract references

- [MCP tools](../reference/mcp-tools.md)
- [Lua reference](../lua-reference.md)
- [Scanning](../scanning.md)
- [Plugin API](../reference/plugin-api.md)
- [CLI and paths](../reference/cli-paths.md)
