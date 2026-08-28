---
title: "memscope-mcp"
description: "Windows process-memory MCP server for reverse engineering and live-process research."
template: splash
hero:
  tagline: "A focused MCP surface for read-first Windows process discovery, memory research, Lua automation, and opt-in domain plugins."
  actions:
    - text: "Get started"
      link: "/get-started/install/"
      icon: "right-arrow"
      variant: "primary"
    - text: "Browse MCP tools"
      link: "/reference/mcp-tools/"
      icon: "document"
      variant: "secondary"
    - text: "View source"
      link: "https://github.com/Boti-Ormandi/memscope-mcp"
      icon: "external"
      variant: "minimal"
---

## Start with a bounded read

Use a Windows x64 host, a 64-bit Python 3.10 or newer, an x64 target, and an MCP client with stdio support. Install the package from the source configured for your environment and configure the client to run `memscope-mcp`.

```powershell
python -m pip install memscope-mcp
memscope-mcp paths
```

A first read-only session discovers a process, selects an exact PID, attaches, and checks the PE signature without writing or installing a hook:

```text
processes(filter="notepad", limit=10)
attach(process_name="notepad.exe", pid=<selected_pid>)
modules(filter="notepad", limit=10)
```

```lua
local base = getModuleBase("notepad.exe")
if not base then
    error("notepad.exe module not found")
end
addResult("module_base", toHex(base))
addResult("dos_signature", readBytesHex(base, 2))
```

Continue with [installation](/get-started/install/), [client configuration](/get-started/configure-client/), and the [first-session guide](/get-started/first-session/).

## Eleven tools, composed work

The MCP surface is intentionally small: `processes`, `attach`, `modules`, `read`, `write`, `dump`, `chain`, `scan`, `scan_many`, `lua`, and `scripts`. Composed work belongs in Lua; domain-specific helpers belong in opt-in plugins.

- **Discover and inspect:** enumerate processes, services, threads, modules, PEB data, and memory regions.
- **Read and write:** use typed values, bounded dumps, pointer chains, and optional verified write readback.
- **Scan:** run strict AOB, string, pointer, and keyed batch scans with bounded scopes and explicit status.
- **Automate and capture:** execute Lua, save scripts, make native calls, and use inline hooks.

Read the [generated MCP tool reference](/reference/mcp-tools/), [Lua reference](/reference/lua/), and [scanning reference](/reference/scanning/) for the current contracts.

## Plugins stay opt-in

Runtime activation scans only `$MEMSCOPE_HOME/plugins/*.py` as a nonrecursive, filename-sorted directory. The bundled catalog includes:

- **IL2CPP** for Unity strings, arrays, lists, dictionaries, and thread-local native-call guidance.
- **Netcap** for Winsock capture, stream analysis, framing, search, and durable recordings.

See [Use plugins](/guides/use-plugins/) for activation, the [plugin lifecycle](/plugins/lifecycle-and-contract/) for composition rules, and the [security model](/concepts/security-model/) for execution and data behavior.

## Local data and support

`MEMSCOPE_HOME` defaults to `~/.memscope-mcp` and contains logs, saved scripts, activated plugins, and optional recordings. Set it before startup to relocate these artifacts. Use the [CLI and paths reference](/reference/cli-and-paths/) for exact locations.

For help, use [troubleshooting](/support/troubleshooting/), [compatibility](/support/compatibility/), and [security support](/support/security/).

## Project links

- [Source repository](https://github.com/Boti-Ormandi/memscope-mcp)
- [Issues](https://github.com/Boti-Ormandi/memscope-mcp/issues)
- [MIT License](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/LICENSE)
- [Private vulnerability reporting](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/SECURITY.md)
- [README source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/README.md)
