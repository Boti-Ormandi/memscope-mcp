# memscope-mcp

[![Tests](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/memscope-mcp.svg)](https://pypi.org/project/memscope-mcp/)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/LICENSE)

**Scriptable Windows process-memory research through MCP.**

memscope-mcp is a Windows x64 Model Context Protocol (MCP) server for process-memory
research and reverse engineering. It combines a small direct MCP surface with
in-process Lua composition through Lupa, so multi-step work can execute near the
target instead of becoming a sequence of client round trips.

Core workflows include Windows process memory inspection, typed reads and writes,
AOB scanning, pointer chains, Lua scripting, inline hooking, and pre-attach PEB
inspection. Optional plugins add specialized Lua functions without adding MCP tools.

**Windows x64 host and x64 targets · 64-bit Python 3.10+ · CI: Python 3.10–3.14 ·
MCP over stdio · MIT**

## Quickstart

Requirements: Windows x64, 64-bit Python 3.10 or newer, and an MCP-compatible client.

```powershell
python -m pip install memscope-mcp
```

Configure an MCP client to start the installed stdio server:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "memscope-mcp"
    }
  }
}
```

### Read the Notepad MZ signature

Open Notepad and locate its process:

```text
processes(filter="notepad", limit=10)
```

Attach to that exact instance and inspect its modules:

```text
attach(process_name="notepad.exe", pid=<selected_pid>)
modules(filter="notepad", limit=10)
```

Resolve the executable base and read its DOS signature in one Lua call:

```text
lua(script="""
local base = getModuleBase("notepad.exe")
if not base then
    error("notepad.exe module not found")
end

addResult("module_base", toHex(base))
addResult("dos_signature", readBytesHex(base, 2))
""")
```

A normal PE image returns `dos_signature` as `"4D 5A"`. This workflow performs
process discovery, exact-PID attachment, module resolution, and memory reads without
modifying the target.

## Capabilities and MCP tools

The current source exposes exactly 11 MCP tools. Detailed parameter contracts belong
in the linked reference documentation rather than this overview.

| Area | MCP tools | Capabilities |
| --- | --- | --- |
| Processes and session | `processes`, `attach`, `modules` | Filter running processes, inspect process and service details, attach to a selected PID, and inspect or refresh the module snapshot. |
| Memory | `read`, `write`, `dump`, `chain` | Read and write typed scalar, string, byte, pointer, and common structured values; inspect unknown regions; follow pointer chains with trace output. Addresses may use hexadecimal or module-plus-offset forms. |
| Scanning | `scan`, `scan_many` | Strict AOB scanning over structured scopes. `scan` supports `addresses`, `first`, and `count`, including resumable address pages; `scan_many` supports keyed `first` and `count` queries in one shared traversal. Both return explicit status. |
| Automation and scripts | `lua`, `scripts` | Run composed Lua work in-process through Lupa, or list and run saved Lua scripts with arguments. |

Scanning supports all-module, selected-module, and bounded range scopes with
memory-type and executable/writable filters. Module-based scopes may also use
case-insensitive PE-section filters. Address results are paged; batch scans
evaluate keyed patterns in a shared traversal. See the
[scanning contract](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/scanning.md)
for request forms, continuation, validation, and status semantics.

## How MCP tools, Lua, and plugins fit together

```text
MCP client
    |
    | stdio
    v
11-tool MCP surface --------------------+
    |                                   |
    | direct operation tools            | `lua`
    v                                   v
process session                    Lupa runtime
                                        |
                         core Lua functions + optional plugins
                                        |
                                        v
                              Windows user-mode x64 target
```

Direct tools cover common discovery, session, memory, scanning, and script operations.
The Lua layer exposes finer-grained building blocks for work that benefits from loops,
branches, dependent reads, or server-side result shaping.

Core Lua capabilities include typed and bulk memory access, module and PE export
resolution, AOB and pointer-reference scans, declarative structure reads, process,
thread, service and memory-region inspection, allocations, supported x64 native calls,
inline hooks, shared ring-buffer capture, and 64-bit-safe utilities. Native
calls and hooks are intentionally summarized here; their detailed contracts are in the
[Lua reference](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/lua-reference.md)
and
[hooking documentation](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/hooking.md).
Installed plugins may add further Lua functions.

PEB inspection can identify process details, environment data, debugger state, and
remote modules before attachment. See
[PEB process introspection](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/peb.md).

Saved scripts can preserve finder logic rather than fixed addresses, making them
reusable across restarts and ASLR changes.

## Optional plugins and local data

Two bundled reference plugins are available but remain opt-in:

- **`il2cpp`** — Unity IL2CPP runtime and object-layout helpers.
- **`netcap`** — Winsock capture and analysis built on the core hooking layer.

Install either plugin explicitly, then restart the MCP server:

```powershell
memscope-mcp install-plugin il2cpp
memscope-mcp install-plugin netcap
```

Logs, saved scripts, and installed plugins live under `MEMSCOPE_HOME`, which defaults
to `~/.memscope-mcp`. Set the environment variable before startup to relocate the data
root. Inspect the resolved directories with:

```powershell
memscope-mcp paths
```

## Documentation

- [Architecture and internals](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/architecture.md)
  — subsystem design, repository layout, extension model, and session lifecycle.
- [Scanning](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/scanning.md)
  — MCP and Lua scanning contracts, scopes, modes, continuation, and status.
- [Lua reference](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/lua-reference.md)
  — core Lua functions; installed plugins may add functions.
- [Inline hooking](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/hooking.md)
  — supported hooks, capture behavior, and lifecycle.
- [PEB process introspection](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/peb.md)
  — pre-attach process and module inspection.

## Project links

See
[CONTRIBUTING.md](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/CONTRIBUTING.md)
for development and test guidance, and
[SECURITY.md](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/SECURITY.md)
for vulnerability reporting. Published changes are listed in
[GitHub Releases](https://github.com/Boti-Ormandi/memscope-mcp/releases).
memscope-mcp is distributed under the
[MIT License](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/LICENSE).
