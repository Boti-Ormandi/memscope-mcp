# memscope-mcp — a Windows process-memory MCP server for reverse engineering and authorized live-process research.

memscope-mcp gives Windows reverse engineers and live-process researchers a small MCP surface over a session-bound Lua runtime. It serves native Windows/debugging users and MCP integrators next, with game, IL2CPP, and network research as secondary domains. It supports read-first process discovery, module inspection, typed memory access, strict pattern scans, saved scripts, native calls, inline hooks, and opt-in domain plugins.

Use it only with processes and data that you own or are authorized to inspect. The server can read and write target memory, execute native code in a target, install hooks, capture network data, read process environment data, and run trusted local plugin Python. Treat every write, execution, hook, plugin, and captured recording as a deliberate operation.

## Requirements and installation

- Windows x64 host and x64 target processes.
- 64-bit Python 3.10 or newer.
- An MCP client with stdio support.
- Sufficient Windows permissions for the selected process and operation.

Install from the package source configured for your environment:

```powershell
python -m pip install memscope-mcp
```

Configure the client to start the server over stdio:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "memscope-mcp"
    }
  }
}
```

The bare `memscope-mcp` command starts the stdio server. The explicit equivalent is `memscope-mcp server`.

## First task: discover, attach, and read

Start with read-only operations. Find a process, choose the exact PID when names repeat, attach, and inspect modules:

```text
processes(filter="notepad", limit=10)
attach(process_name="notepad.exe", pid=<selected_pid>)
modules(filter="notepad", limit=10)
```

A safe Lua read resolves the executable base and reads the PE DOS signature:

```lua
local base = getModuleBase("notepad.exe")
if not base then
    error("notepad.exe module not found")
end

addResult("module_base", toHex(base))
addResult("dos_signature", readBytesHex(base, 2))
```

A normal PE image returns `dos_signature` as `"4D 5A"`. This task discovers a process, opens a session, resolves a module, and reads memory; it does not write target memory, execute a target function, or install a hook.

See [Getting started](docs/getting-started.md) for permissions, data roots, and the first-session checklist. See [Discover and attach](docs/guides/discover-attach.md) for a longer read-only workflow.

## The MCP surface

The server exposes exactly 11 MCP tools:

`processes`, `attach`, `modules`, `read`, `write`, `dump`, `chain`, `scan`, `scan_many`, `lua`, and `scripts`.

The surface remains small; composed work belongs in Lua, and domain-specific helpers belong in opt-in plugins. See the [MCP tool reference](docs/reference/mcp-tools.md) and [Lua reference](docs/lua-reference.md) for current contracts.

## Capabilities

- **Process and module research:** enumerate processes, services, threads, memory regions, PEB data, remote modules, module bases, and exports.
- **Memory research:** read typed values and structures, inspect unknown regions, follow pointer chains, and write typed values with optional verified readback and rollback attempts.
- **Scanning:** run strict AOB, string, pointer, and keyed batch scans over modules or bounded ranges with explicit status and authenticated continuation for MCP address pages.
- **Automation:** execute Lua loops and dependent operations in-process; save reusable scripts under the data root.
- **Capture:** install user-mode inline hooks, collect arguments and bounded buffers in a shared ring buffer, and use the netcap plugin for protocol-aware capture.

Writes, remote allocation, native calls, hooks, and captures have target-process effects. Read [Read and write memory](docs/guides/read-write.md), [Capture calls](docs/guides/capture-calls.md), and the [security model](docs/concepts/security-model.md) before using them.

## Plugins and data

Plugins are opt-in. Runtime activation scans only `$MEMSCOPE_HOME/plugins/*.py` as a nonrecursive, filename-sorted directory. Bundled `_contrib` files are catalog and install sources; they are not a second automatic runtime root.

The bundled reference plugins are:

- **`il2cpp`** — Unity IL2CPP strings, arrays, lists, and dictionaries.
- **`netcap`** — Winsock capture, stream analysis, framing, packet search, and durable recording.

Install a bundled plugin explicitly, review the local file, and restart the server:

```powershell
memscope-mcp list-plugins
memscope-mcp install-plugin il2cpp
memscope-mcp install-plugin netcap
```

Installation does not overwrite an existing activated file unless `--force` is present. A package upgrade preserves saved scripts and activated plugin copies. Review local changes before an explicit `memscope-mcp install-plugin <name> --force` refresh.

By default, the data root is `~/.memscope-mcp`. Set `MEMSCOPE_HOME` before starting the server to use a disposable or dedicated root. Inspect the resolved locations with:

```powershell
memscope-mcp paths
```

The root contains `logs/`, `scripts/`, and `plugins/`. Netcap recordings use `$MEMSCOPE_HOME/scripts/<process>/recordings/`; its read-only legacy fallback is the cwd-relative `scripts/<process>/recordings/` location. See [CLI and paths](docs/reference/cli-paths.md) and [Netcap](docs/plugins/netcap.md).

## Documentation map

### Start and guides

- [Getting started](docs/getting-started.md) — installation, client configuration, permissions, data, and the first read-only session.
- [Discover and attach](docs/guides/discover-attach.md) — process selection, exact-PID attachment, and module snapshots.
- [Inspect before attach](docs/guides/inspect-before-attach.md) — read-only PEB and remote-module inspection.
- [Read and write memory](docs/guides/read-write.md) — typed reads, verified writes, and target-safety checks.
- [Scan target memory](docs/guides/scan.md) — task-first scan examples.
- [Use saved scripts](docs/guides/saved-scripts.md) — namespaces, arguments, and safe disposable data roots.
- [Capture calls](docs/guides/capture-calls.md) — generic hooks, ring buffers, and capture risks.
- [Use plugins](docs/guides/use-plugins.md) — activation, trust, and plugin discovery.

### Plugins

- [Plugin overview](docs/plugins/overview.md) — activation and the runtime loading boundary.
- [Plugin authoring](docs/plugins/authoring.md) — supported imports, context, registration, and examples.
- [Plugin lifecycle](docs/plugins/lifecycle.md) — atomic composition, attach/detach callbacks, and state ownership.
- [Plugin upgrading](docs/plugins/upgrading.md) — current contract corrections and structured diagnostics.
- [Plugin troubleshooting](docs/plugins/troubleshooting.md) — failure isolation and diagnostic records.
- [IL2CPP plugin](docs/plugins/il2cpp.md) — structure layouts and thread-local native calls.
- [Netcap plugin](docs/plugins/netcap.md) — Winsock capture and safe recording storage.

### Reference and concepts

- [MCP tools](docs/reference/mcp-tools.md) — exact tool names, configuration shape, and request summaries.
- [Lua reference](docs/lua-reference.md) — core Lua functions and scan options.
- [Scanning reference](docs/scanning.md) — scopes, filters, modes, continuation, status, and errors.
- [Plugin API](docs/reference/plugin-api.md) — `PluginBase`, `LuaExtension`, and `ExtensionContext`.
- [CLI and paths](docs/reference/cli-paths.md) — commands and exact data roots.
- [Errors and status](docs/reference/errors-status.md) — envelopes, scan status, and failure handling.
- [Architecture](docs/architecture.md) — source layout and subsystem composition.
- [Session lifecycle](docs/concepts/session-lifecycle.md) — attachment generations, leases, and cleanup.
- [Extension composition](docs/concepts/extension-composition.md) — core and plugin registration.
- [Security model](docs/concepts/security-model.md) — process powers, trust boundaries, and residual filesystem limits.
- [PEB introspection](docs/peb.md) — pre-attach process information and limits.
- [Inline hooking](docs/hooking.md) — trampoline and ring-buffer design.

### Support and project work

- [Troubleshooting](docs/support/troubleshooting.md) — common startup, attach, scan, plugin, and recording issues.
- [Compatibility](docs/support/compatibility.md) — supported host shape and retained compatibility surfaces.
- [Security support](docs/support/security.md) — how to report security concerns.
- [Contributing](CONTRIBUTING.md) — repository setup, tests, plugin development, and safe local data.
- [Release process](docs/releases.md) — high-level maintainer workflow without publication credentials or authority.
- [Site route inventory](docs/site-routes.md) — canonical route destinations and repository source mappings.

The canonical destination prefix is `https://memscope.esrc.dev/`; stable route paths and their repository sources are listed in [the route inventory](docs/site-routes.md). These links identify canonical destinations; they do not assert that a site or package distribution is deployed.

## Project links

- [Source repository](https://github.com/Boti-Ormandi/memscope-mcp)
- [Issues](https://github.com/Boti-Ormandi/memscope-mcp/issues)
- [MIT License](LICENSE)
- [Private vulnerability reporting](SECURITY.md)
