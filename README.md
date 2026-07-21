# memscope-mcp

[![Tests](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

An MCP server for low-level Windows process memory research.

AI agents attach to processes, scan byte patterns, read and write typed memory, follow pointer chains, execute remote x64 code, install generic inline function hooks with shared ring-buffer capture, and read the Process Environment Block of processes the server has not even attached to -- all through 11 MCP tools. A server-side Lua environment batches multi-step operations into a single round-trip, so an agent can dereference a pointer chain, decode a structure, hook an API, and report results without paying per-call latency.

## Installation

**Requirements:** Windows x64, Python 3.10+, an [MCP-compatible client](https://modelcontextprotocol.io/clients).

```bash
pip install memscope-mcp
```

Configure your MCP client with a server entry. The cleanest form uses the installed console script:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "memscope-mcp"
    }
  }
}
```

If the client doesn't have the script on `PATH`, use the module form:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "python",
      "args": ["-m", "memscope_mcp.server"]
    }
  }
}
```

Verify the install:

```bash
memscope-mcp list-plugins
```

This exercises the CLI, the package import, and the plugin discovery in one command. If it lists `il2cpp` and `netcap`, the install is good.

### For development

```bash
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
cd memscope-mcp
pip install -e ".[dev]"
pytest tests/
```

## Quick tour

Everything happens through MCP tool calls. A typical exploration session:

**Find and attach to a process:**
```
> processes(filter="notepad")
  {processes: [{pid: 1234, name: "notepad.exe", threads: 6, path: "C:\\Windows\\System32\\notepad.exe"}]}

> attach("notepad.exe")
  {pid: 1234, key_modules: {"notepad.exe": {base: "0x7FF6A0000000", size: 245760}, ...}, ...}
```

**Find which svchost hosts a service:**
```
> processes(service="EventLog")
  {processes: [{pid: 1820, name: "svchost.exe", services: [{name: "EventLog", state: "RUNNING"}]}]}
```

**Scan for a pattern, follow pointers:**
```
> scan(pattern="48 8B 05 ?? ?? ?? ??", scope={"kind": "modules", "names": ["target.dll"]}, mode="first")
  {success: true, mode: "first", match: {address: "0x7FF6A1A208D8", module: "target.dll", module_offset: "0x1A208D8"}, status: {termination: "first_hit", read_gaps_detected: false}}

> chain(base="0x183C13300", offsets=["0x50", "0x18", "0x100"], read_final="float")
  {final_address: "0x184A52118", final_value: 100.0}
```

**Run a multi-step Lua script in one call:**
```
> lua(script="""
    local matches, err = AOBScan("48 8B 05 ?? ?? ?? ??", {
      scope = {kind = "modules", names = {"target.dll"}},
      mode = "addresses",
      max_matches = 100
    })
    if not matches then error(err.detail) end
    for i, addr in ipairs(matches) do
      local ptr = readPointer(addr + 3)
      local val = readFloat(ptr + 0x100)
      addResult("match_" .. i, {address = toHex(ptr), value = val})
    end
  """)
  {results: {"match_1": {address: "0x183C13300", value: 100.0}}, output: []}
```

## Tools

Addresses accept hex strings (`"0x1234"`), module+offset (`"module.dll+0x1234"`), or hex arithmetic (`"0xBASE+0xOFFSET"`).

| Tool | Purpose |
|------|---------|
| `processes` | List/filter running processes. Filter by name, PID, parent PID, or hosted service. Auto-enumerates services for svchost processes via the Windows SCM |
| `attach` | Attach to process, cache module bases. Auto-reconnects if the target restarts |
| `modules` | List loaded modules with base addresses, sizes, and paths. Set `refresh=true` to rebuild the immutable module snapshot and advance its attachment generation |
| `read` | Read typed memory (int8-64, uint8-64, char, float, double, bool, ptr, cstring, bytes/bytes[N], vector2/3/4, quaternion, color, color32, rect, bounds, matrix4x4). Supports `count` for consecutive values |
| `write` | Write typed memory, including bytes/bytes[N], with optional verified writes: writable range check, pre-image capture, byte-for-byte readback, and pre-image restore attempt on post-write verification failure |
| `dump` | Smart memory dump with automatic type detection and pagination/filter knobs (`start_offset`, `pointers_only`, `non_null_only`, `max_entries`, `annotation_level`). `full` annotations include confidence |
| `chain` | Follow pointer chains: `[[base+off0]+off1]...` with configurable final read type |
| `scan` | Strict AOB scanning with `??` wildcards, address/first/count modes, authenticated cursor continuation, structured scopes including PE-section filters, bounded diagnostics, and explicit termination status |
| `scan_many` | Search 1-32 keyed AOB patterns in one shared memory traversal with bounded first-hit or count results and shared diagnostics |
| `lua` | Execute Lua scripts server-side for multi-step operations |
| `scripts` | Manage saved Lua scripts. Actions: `list` (with paths), `run` (with args and namespace checks) |

### Typed byte values

The `read` tool returns `bytes` and `bytes[N]` values as uppercase spaced hex. The `write` tool accepts byte payloads as JSON-friendly compact hex (`"DEADBEEF"`), whitespace-separated hex (`"DE AD BE EF"`), or integer arrays (`[222, 173, 190, 239]`). `bytes[N]` requires exactly `N` bytes. Empty payloads, `bytes[0]`, `0x` prefixes, non-whitespace separators, non-integer array elements, and integers outside `0..255` are rejected.

## Lua scripting

A server-side Lua 5.4 environment with ~110 always-loaded functions exposing memscope's primitives. Use it when an operation needs loops, conditionals, or chained reads that would otherwise require many MCP round-trips.

```lua
-- Find a RIP-relative singleton reference and read fields off it
local matches, err = AOBScan("48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8", {
  scope = {kind = "modules", names = {"target.dll"}},
  mode = "first"
})
if not matches then error(err.detail) end
if #matches > 0 then
  local rip_offset = readInteger(matches[1] + 3)
  local singleton = matches[1] + 7 + rip_offset
  local ptr = readPointer(singleton)
  if ptr and ptr ~= 0 then
    addResult("address", toHex(ptr))
    addResult("version", readUInt32(ptr + 0x10))
    addResult("name", readString(ptr + 0x20, 64))
  end
end
```

The MCP and Lua scan contracts, continuation rules, and 0.2.x migration table are documented in [`docs/scanning.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/scanning.md).

Function categories (full reference in [`docs/lua-reference.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/lua-reference.md)):

| Category | Functions |
|----------|-----------|
| Memory read (typed + bulk) | 20 |
| Memory write | 13 |
| Struct helpers (vectors, matrix, declarative struct read) | 5 |
| Module / address resolution (incl. `resolveExport`) | 7 |
| Scanning (AOB, batch AOB, string, pointer xrefs) | 4 |
| Pointer chains | 1 |
| Code execution (shellcode, alloc, callSequence) | 8 |
| Hooking (inline hooks + ring buffer) | 8 |
| Process introspection (pre-attach, PEB) | 10 |
| Network utilities | 1 |
| 64-bit safe comparisons | 9 |
| Bitwise | 7 |
| Utilities | 19 |

## Plugins

Domain-specific helpers without touching the core. Drop a custom `.py` file into `$MEMSCOPE_HOME/plugins/` and restart; the loader instantiates the `PluginBase` subclass it finds, registers the plugin's Lua functions, and appends its instructions to the AI-facing documentation.

```bash
# Activate the reference IL2CPP plugin (Unity runtime helpers)
memscope-mcp install-plugin il2cpp

# Or the reference netcap plugin (Winsock capture and analysis, built on the hooking layer)
memscope-mcp install-plugin netcap
```

`il2cpp.py` is the template for plugins that walk a managed-runtime object layout. `netcap.py` is the template for plugins that hook a known API surface and add protocol-aware parsing on top -- it uses the generic `HOOK_MANAGER` to install Winsock hooks and exposes packet capture, stream assembly, framing, search, and recording through ~38 Lua functions.

## Data directory

Logs, saved Lua scripts, and user plugins live under `MEMSCOPE_HOME`, which defaults to `~/.memscope-mcp/`. Override with the `MEMSCOPE_HOME` environment variable. On server startup, a single line is printed to stderr indicating the resolved location.

Subdirectories:

- `$MEMSCOPE_HOME/logs/sessions/` -- per-session JSONL logs.
- `$MEMSCOPE_HOME/scripts/<process>/` -- Lua scripts saved per process namespace.
- `$MEMSCOPE_HOME/plugins/` -- user plugins (see `memscope-mcp install-plugin` for the bundled reference plugins).

### Saved scripts

Save working Lua scripts as `.lua` files, organized by process:

```
scripts/
  target.exe/
    find_struct.lua
    dump_vtable.lua
```

- First-line comment becomes the script description
- Version control friendly (plain text)
- AI agents discover saved scripts on attach and reuse them automatically
- Create scripts with your MCP client's file tools, run them with the `scripts` tool
- For `scripts(action="run")`, `process=` selects the saved-script namespace only; it does not attach or switch targets
- Detached runs require `process=`; when already attached, an explicit `process=` must match the attached target
- Run responses include `requested_process` (caller-provided namespace, or `null` when implicit), `attached_process`, `attached_pid`, and `detached_execution`

ASLR invalidates absolute addresses across restarts. Save the finder script, not the address.

## Session logging

Every tool call is logged to `$MEMSCOPE_HOME/logs/sessions/<timestamp>.jsonl` -- one JSONL file per server session, one line per call with a session-local request ID, bounded argument and result summaries, success status, and duration in milliseconds. Direct Lua calls store source length, line count, preview, and SHA-256 instead of the full script body. Logs older than two years are auto-cleaned and are intended for diagnostics, not full replay transcripts.

## Platform

Windows only. The package installs cleanly on Linux and macOS via `pip install memscope-mcp` (the `pymem` dependency is skipped via an environment marker), but the first `import memscope_mcp` raises `RuntimeError`. The underlying memory primitives depend on Win32 APIs that have no cross-platform analogue.

## Security

memscope-mcp can read and write arbitrary memory in attached processes and execute code in them. Intended uses: malware analysis, vulnerability research, security testing of software you own or are authorized to test, modding-tool development for offline software, and educational reverse engineering. Only target processes and systems you are authorized to analyze.

User-mode access only. Targets with anti-tampering or debugger-detection mitigations (commercial obfuscators, EDR-hooked binaries, kernel-level protection) may detect or block the tool.

Plugins execute arbitrary Python code at server startup -- only activate plugins you have read.

## Architecture

Generic core, plugins for domains. Core extensions are always loaded; user plugins are gated on file presence in `$MEMSCOPE_HOME/plugins/`. Both implement the same `LuaExtension` ABC.

- Generic core, plugins for domains: no target-specific code in `memscope_mcp/`
- Minimal tool surface: 11 well-shaped MCP tools, with Lua for everything that needs composition
- One contract (`LuaExtension`), two activation paths: core extensions are always loaded; user plugins are gated on file presence in `$MEMSCOPE_HOME/plugins/` and isolated on failure
- Plugin instructions are only loaded when the plugin is active (AI context costs tokens)
- Scripts persist, addresses don't: ASLR shifts everything, save the finder

Full repository layout, subsystem deep-dives, and design notes in [`docs/architecture.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/architecture.md).

## Documentation

- [Architecture and internals](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/architecture.md) -- repository layout, design philosophy, subsystem deep-dives
- [Inline hooking](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/hooking.md) -- trampolines, ring buffer, prologue relocation
- [PEB introspection](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/peb.md) -- pre-attach process inspection
- [Lua reference](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/lua-reference.md) -- full function-by-function API

## Contributing

See [CONTRIBUTING.md](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/CONTRIBUTING.md).

## License

[MIT](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/LICENSE)
