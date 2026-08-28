---
title: "Architecture"
description: "The Windows x64 stdio, session, Lua, scanning, and plugin architecture."
---

`memscope-mcp` is a Windows x64 process-memory MCP server with a narrow stdio boundary and a session-bound Lua composition layer. The server keeps common operations in core extensions and loads domain behavior only from explicitly activated plugin files.

For task-first use, start with [Getting started](/get-started/install/). For the public surface, use [MCP tools](/reference/mcp-tools/), [Lua reference](/reference/lua/), and [Scanning](/reference/scanning/).

## Runtime shape

```text
MCP client
    |
    | stdio
    v
11 MCP tools
    |                    +------------------+
    | direct wrappers    | strict scan      |
    +-------------------> boundary models  |
    |                    +------------------+
    v
DebugSession + immutable module snapshot
    |
    +--> Lua 5.4 runtime
          |
          +--> seven core extensions
          +--> activated user plugins
          |
          +--> Windows x64 target process
```

The 11 tools are `processes`, `attach`, `modules`, `read`, `write`, `dump`, `chain`, `scan`, `scan_many`, `lua`, and `scripts`. The synchronous business functions remain ordinary Python callables; the MCP boundary supplies same-thread dispatch for those wrappers. `scan` and `scan_many` use strict Pydantic input/output models and explicit application error envelopes.

## Repository layout

```text
memscope_mcp/
  server.py                 MCP registrations and stdio entry point
  boundary.py               strict scan-model MCP boundary
  session.py                attach/detach, generations, leases, memory primitives
  attachment.py             immutable module snapshots and scan identity
  scanning/                 strict scan contracts and bounded execution
  tools/
    types.py                typed memory reads and writes
    memory.py               dumps and raw formatted reads
    pointers.py             pointer-chain helpers
    hooking.py              inline hooks and shared ring buffer
    lua/                    Lua engine and function modules
    lua_scripts.py          saved-script list/run operations
  extensions/
    base.py                 LuaExtension and ExtensionContext
    bootstrap.py            transactional core/plugin composition
    core/                   seven always-loaded extensions
  plugins/
    __init__.py             PluginBase and activated-file loader
  _contrib/plugins/         bundled il2cpp.py and netcap.py install sources
  utils/                    process, PEB, PE, logging, and x64 helpers

docs/                       human-facing source content
benchmarks/                 repository-only benchmark tooling
 tests/                      unit, smoke, integration, and plugin tests
```

The runtime data root is separate from the repository:

```text
$MEMSCOPE_HOME/
  logs/sessions/<session-id>.jsonl
  scripts/<process>/<name>.lua
  plugins/<activated-filename>.py
  scripts/<process>/recordings/<name>.jsonl[.gz]
```

`MEMSCOPE_HOME` defaults to `~/.memscope-mcp`. Netcap also recognizes the cwd-relative `scripts/<process>/recordings/` location as a read-only legacy fallback. See [CLI and paths](/reference/cli-and-paths/).

## Session and attachment identity

`DebugSession` owns the process handle, target name and PID, tracked target allocations, lifecycle callbacks, attachment generation, and immutable module snapshot. A successful attach or module refresh publishes a new generation. A scan borrows a stable lease; switching, detaching, reconnecting, or refreshing retires the current lease and waits for active readers before replacing attachment identity.

The `modules` MCP tool preserves module records with `name`, `base`, `size`, and `path`. `DebugSession.modules` remains a defensive legacy dictionary view of the current snapshot, and `openProcess` remains a Lua attach alias. Neither surface gives plugins a raw global session object.

See [Session lifecycle](/concepts/session-lifecycle/).

## Core extensions

Seven core extensions register in this order:

1. `general`
2. `memory`
3. `module_scan`
4. `execution`
5. `hooking`
6. `process`
7. `network`

They provide the common Lua functions for address handling, memory, scans, native execution, hooks, process/PEB inspection, and socket identification. Core registration failure is a hard startup failure. The [Lua reference](/reference/lua/) lists the resulting functions.

## Scanning engine

The scanner compiles strict AOB patterns before target reads, normalizes scopes against one module snapshot, plans readable spans, reads bounded chunks, preserves exact overlap continuity, and returns explicit termination/status. Module and range scopes use memory-type and permission filters; module scopes also support case-insensitive PE-section filters. MCP address pages use an authenticated cursor bound to the attachment identity. `scan_many` shares one traversal across 1–32 keyed patterns and supports only `first` and `count` modes.

The scan package is an internal engine boundary rather than a supported Python API. Use the MCP tools or Lua helpers. Full request shapes and statuses are in [Scanning](/reference/scanning/).

## Lua runtime

The Lua runtime is private and serialized through an engine-owned operation lease. The engine converts ordinary tables and scalars across the boundary but rejects Lua functions, threads, userdata, and cyclic tables from results. The `table_factory` capability is valid only during engine-owned bootstrap or execution callbacks. Large hexadecimal literals are normalized to `addr("0x...")`; explicit `addr()` remains clear for 64-bit addresses.

Scripts, native calls, hooks, and plugin callbacks share the session boundary but not a raw runtime handle. See [Extension composition](/concepts/extension-composition/) and [Lua reference](/reference/lua/).

## Plugins

The plugin loader scans only `$MEMSCOPE_HOME/plugins/*.py`, nonrecursively, in sorted activated filename order. It skips underscore-prefixed filenames. `_contrib/plugins/` is a packaged catalog/install source, not an automatic runtime root. Each activated file supplies one `PluginBase`/`LuaExtension` implementation and is isolated if ordinary registration fails.

Plugins receive a session-bound `ExtensionContext` and register Lua mappings transactionally. A plugin instance owns domain state; attach and detach callbacks own process-bound cleanup. The generic core and plugins share the same `HookManager` when both use hooks. See [Plugin overview](/plugins/overview/), [Plugin API](/reference/plugin-api/), and [Plugin lifecycle](/plugins/lifecycle-and-contract/).

## Hooking and target effects

The hooking extension allocates target-side trampoline/ring-buffer memory, patches user-mode function entries, captures registers and optional buffers, and restores hooks on removal or detach. Native execution uses x64 shellcode and remote threads. PEB helpers open separate read-oriented handles. Read [Inline hooking](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/hooking.md), [PEB introspection](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/peb.md), and the [security model](/concepts/security-model/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/architecture.md)
