---
title: "memscope-mcp"
description: "Windows process-memory MCP server for reverse engineering and live-process research."
template: splash
hero:
  tagline: "Inspect and automate Windows x64 processes with typed memory tools, scanning, Lua, inline hooks, and opt-in plugins."
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

## Connect to a process and read its PE signature

1. [Install memscope-mcp](/get-started/install/).
2. [Configure VS Code](/get-started/configure-client/) with a fresh `MEMSCOPE_HOME`.
3. [Select a process by PID, attach, and read its first two bytes](/get-started/first-session/).

A loaded Windows executable normally starts with the PE DOS signature `4D 5A`. Reading it confirms that Memscope can resolve the process's main module and access its memory.

## Memory tools and Lua automation

Memscope provides `processes`, `attach`, `modules`, `read`, `write`, `dump`, `chain`, `scan`, `scan_many`, `lua`, and `scripts`. Use Lua to combine dependent operations, and add domain-specific helpers through opt-in plugins.

- **Discover and inspect:** enumerate processes, services, threads, modules, PEB data, and memory regions.
- **Read and write:** use typed values, bounded dumps, pointer chains, and optional verified write readback.
- **Scan:** run strict AOB, string, pointer, and keyed batch scans with bounded scopes and explicit status.
- **Automate and capture:** execute Lua, save scripts, call native target functions, and install inline hooks.

See the [MCP tool reference](/reference/mcp-tools/) for request and response schemas, the [Lua reference](/reference/lua/) for available functions, and the [scanning reference](/reference/scanning/) for scan modes and status fields.

## Execution and local data

Windows permissions apply to each selected process operation. Writes modify target memory. Lua/native calls and hooks execute or modify target behavior. Activated files under `$MEMSCOPE_HOME/plugins/*.py` load as Python when the server starts. Session logs, saved scripts, plugin files, and optional recordings persist under `MEMSCOPE_HOME`.

See [permissions and local data](/get-started/permissions-and-data/), [plugin overview](/plugins/overview/), and the [security model](/concepts/security-model/) for details.

## Project links

- [Source repository](https://github.com/Boti-Ormandi/memscope-mcp)
- [Issues](https://github.com/Boti-Ormandi/memscope-mcp/issues)
- [GitHub Release history](https://github.com/Boti-Ormandi/memscope-mcp/releases)
- [Contributing](/contribute/)
- [Private vulnerability reporting](https://github.com/Boti-Ormandi/memscope-mcp/security/advisories/new)
