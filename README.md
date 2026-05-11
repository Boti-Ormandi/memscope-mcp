# memscope-mcp

[![Tests](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

An MCP server for low-level Windows process memory research.

AI agents attach to processes, scan byte patterns, read and write typed memory, follow pointer chains, execute remote x64 code, install generic inline function hooks with shared ring-buffer capture, and read the Process Environment Block of processes the server has not even attached to -- all through 10 MCP tools. A server-side Lua environment batches multi-step operations into a single round-trip, so an agent can dereference a pointer chain, decode a structure, hook an API, and report results without paying per-call latency.

## What It Looks Like

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
> scan(pattern="48 8B 05 ?? ?? ?? ??", module="target.dll")
  {data: [{address: "target.dll+0x1A208D8"}], _pagination: {total: 1}}

> chain(base="0x183C13300", offsets=["0x50", "0x18", "0x100"], read_final="float")
  {final_address: "0x184A52118", final_value: 100.0}
```

**Run a multi-step Lua script in one call:**
```
> lua(script="""
    local matches = AOBScanModule("target.dll", "48 8B 05 ?? ?? ?? ??")
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
| `modules` | List loaded modules with base addresses, sizes, and paths |
| `read` | Read typed memory (int8-64, uint8-64, float, double, bool, ptr, cstring, vector2/3/4, quaternion, color, rect, bounds, matrix4x4). Supports `count` for consecutive values |
| `write` | Write typed memory with optional pre-write verification against page protection |
| `dump` | Smart memory dump with automatic type detection (pointers, strings, ints, floats) and confidence scoring |
| `chain` | Follow pointer chains: `[[base+off0]+off1]...` with configurable final read type |
| `scan` | AOB pattern scanning with wildcards (`??`, `?`, `**`). Module scans by default; bounded scans walk committed readable regions |
| `lua` | Execute Lua scripts server-side for multi-step operations |
| `scripts` | Manage saved Lua scripts. Actions: `list` (with paths), `run` (with args) |

## Lua Scripting

A server-side Lua 5.4 environment with ~110 always-loaded functions exposing memscope's primitives. Use it when an operation needs loops, conditionals, or chained reads that would otherwise require many MCP round-trips.

```lua
-- Find a RIP-relative singleton reference and read fields off it
local matches = AOBScanModule("target.dll", "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8")
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

The full reference lives in [`docs/lua-reference.md`](docs/lua-reference.md). Hooking and PEB-introspection design notes live in [`docs/hooking.md`](docs/hooking.md) and [`docs/peb.md`](docs/peb.md). Categories:

| Category | Functions |
|----------|-----------|
| Memory read (typed + bulk) | 20 |
| Memory write | 13 |
| Struct helpers (vectors, matrix, declarative struct read) | 5 |
| Module / address resolution (incl. `resolveExport`) | 7 |
| Scanning (AOB, string, pointer xrefs) | 4 |
| Pointer chains | 1 |
| Code execution (shellcode, alloc, callSequence) | 8 |
| Hooking (inline hooks + ring buffer) | 8 |
| Process introspection (pre-attach, PEB) | 10 |
| Network utilities | 1 |
| 64-bit safe comparisons | 9 |
| Bitwise | 7 |
| Utilities | 18 |

Plus ~38 functions under the optional netcap plugin (`contrib/plugins/netcap.py`) when activated.

Lua 5.4 rejects hex literals beyond 32 bits; the server transparently rewrites large literals like `0x1F58E12ECF0` to `addr("0x1F58E12ECF0")` before execution, so scripts can paste raw 64-bit addresses verbatim.

## Plugins

Domain-specific helpers without touching the core. Drop a `.py` file into `plugins/` and restart; the loader instantiates the `PluginBase` subclass it finds, registers the plugin's Lua functions, and appends its instructions to the AI-facing documentation.

```bash
# Activate the reference IL2CPP plugin (Unity runtime helpers)
cp contrib/plugins/il2cpp.py plugins/

# Or the reference netcap plugin (Winsock capture and analysis, built on the hooking layer)
cp contrib/plugins/netcap.py plugins/
```

`il2cpp.py` is the template for plugins that walk a managed-runtime object layout. `netcap.py` is the template for plugins that hook a known API surface and add protocol-aware parsing on top -- it uses the generic `HOOK_MANAGER` to install Winsock hooks and exposes packet capture, stream assembly, framing, search, and recording through ~38 Lua functions. See [`plugins/README.md`](plugins/README.md) for the interface and authoring guidelines.

## Script Persistence

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

ASLR invalidates absolute addresses across restarts. Save the finder script, not the address.

## Architecture

```
src/
  server.py              # MCP tool definitions (thin wrappers + session logging)
  session.py             # Process attach/detach, memory primitives, threads,
                         #   VirtualProtect, allocate_near, suspend/resume,
                         #   lifecycle callbacks
  extensions/            # Generic LuaExtension contract + bootstrap
    base.py              # LuaExtension ABC and ExtensionContext
    bootstrap.py         # Core extension + user plugin registration
    core/                # Always-loaded extensions
      general.py memory.py module_scan.py execution.py
      hooking.py process.py network.py
  tools/
    memory.py            # Smart memory dump
    scanning.py          # AOB pattern scanning
    pointers.py          # Pointer chain resolution
    types.py             # Typed memory read/write
    execute.py           # Remote code execution
    hooking.py           # HookManager: ring buffer + install/remove/cleanup
    lua_scripts.py       # Script persistence
    lua/                 # Lua engine and themed function modules
  plugins/               # PluginBase (specialization of LuaExtension) + loader
  instructions/          # AI context builder (base + extensions + plugins)
  utils/
    shellcode.py         # x64 codegen: native calls + hook trampolines
    disasm.py            # Table-driven x64 length decoder + RIP-relative relocation
    pe.py                # PE export resolver (resolveExport)
    peb.py               # PEB reader: cmdline, env, debugger, remote modules
    memory_utils.py heuristics.py logger.py pointers.py
plugins/                 # Active plugins (user-curated, gitignored)
contrib/plugins/         # Reference plugins (il2cpp, netcap)
scripts/                 # Saved Lua scripts per process (gitignored)
logs/                    # Session logs in JSONL format (gitignored)
docs/
  hooking.md             # Inline hooking architecture
  peb.md                 # PEB introspection design
  lua-reference.md       # Full Lua function reference
```

**Design choices:**
- Generic core, plugins for domains: no target-specific code in `src/`
- Minimal tool surface: 10 well-shaped MCP tools, with Lua for everything that needs composition
- One contract (`LuaExtension`), two activation paths: core extensions are always loaded; user plugins are gated on file presence in `plugins/` and isolated on failure
- Plugin instructions are only loaded when the plugin is active (AI context costs tokens)
- Scripts persist, addresses don't: ASLR shifts everything, save the finder

## Implementation Notes

### Inline function hooking with shared ring buffer
Hook any user-mode function by address, capture register args plus optional buffer data, and read the capture stream from Lua -- without DLL injection. `HookManager` ([`src/tools/hooking.py`](src/tools/hooking.py)) reads the target's function prologue through a table-driven x64 instruction length decoder ([`src/utils/disasm.py`](src/utils/disasm.py)), allocates an RWX trampoline page within +-2 GiB of the target so a 5-byte `JMP rel32` patch suffices, and falls back to a 14-byte `JMP [RIP+0]` with thread-suspension + IP redirect when near allocation fails. RIP-relative prologue instructions are rewritten by the relocator so the displaced bytes still resolve to the original target. Trampoline shellcode ([`src/utils/shellcode.py`](src/utils/shellcode.py)) implements pre- and post-call capture with optional struct-deref (WSABUF-style buffer pointers) and output-pointer deref. All hooks share one lock-free ring buffer in target memory; writes claim slots with `lock cmpxchg`, overflow drops without blocking, and a status field gates partial reads. Full architecture in [`docs/hooking.md`](docs/hooking.md).

### PEB introspection without attaching
`getProcessInfo`, `isBeingDebugged`, `getEnvironment`, and `getModulesRemote` read the Process Environment Block of any process the server can open with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` -- no debug session, no injection, no leaked handles. The reader ([`src/utils/peb.py`](src/utils/peb.py)) is pure ctypes: `NtQueryInformationProcess(ProcessBasicInformation)` returns the PEB base, then `ReadProcessMemory` walks `ProcessParameters` (cmdline, cwd, environment), the `BeingDebugged` byte, and the `Ldr.InLoadOrderModuleList` linked list. The `processes` MCP tool surfaces the per-entry command line directly, which means filters like `processes(filter="electron")` distinguish renderer / GPU / browser instances without further work. Full structure layout in [`docs/peb.md`](docs/peb.md).

### x64 shellcode generation
`executeCode` and `callSequence` work by assembling raw x64 machine code in the target process. The codegen ([`src/utils/shellcode.py`](src/utils/shellcode.py)) implements the Microsoft x64 calling convention end to end: 32-byte shadow space, 16-byte stack alignment before each `CALL`, RCX/RDX/R8/R9 for the first four integer arguments and XMM0-XMM3 for floats, stack spill for arguments past the fourth, and RAX (or XMM0 for float returns) captured into a thread-local result slot. The Lua wrapper smart-detects argument types: numeric strings become integer arguments, text strings are allocated as buffers in the target process and freed after the call.

### Extension system
Core features and user plugins share one ABC: `LuaExtension` ([`src/extensions/base.py`](src/extensions/base.py)). Each extension owns a name, a description, an AI-facing instructions fragment, a `register(ctx)` method that returns Lua function bindings, and optional `on_process_attached` / `on_process_detaching` lifecycle callbacks. The bootstrap ([`src/extensions/bootstrap.py`](src/extensions/bootstrap.py)) instantiates the seven built-in extensions in order, loads any user plugins from `plugins/` (failures logged and isolated), wires the returned function dicts into the Lua engine, and assembles the instruction bundle. The contract is what makes hooking, PEB introspection, netcap, and any future domain helper pluggable on the same shape.

### PE export resolution
`resolveExport(module, name)` ([`src/utils/pe.py`](src/utils/pe.py)) reads the PE export directory directly from target memory and binary-searches the sorted name pointer table. Forwarded exports are resolved recursively with a depth cap of 5. The hooking layer uses this to find addresses like `ws2_32!WSARecv` without symbol files or AOB-scanning known entry points.

### Transparent reconnection
A reverse-engineering session typically outlives the target process. `DebugSession.ensure_attached` ([`src/session.py`](src/session.py)) polls the cached handle with `GetExitCodeProcess` on every tool call; if the process has exited, it transparently re-opens by name and re-caches modules. Tools never surface a "process disappeared" error on a transient restart.

### Lua large-hex preprocessor
Lua 5.4 has 64-bit integers, but its parser still rejects hex literals beyond 32 bits -- `local p = 0x1F58E12ECF0` is a syntax error. The engine's preprocessor ([`src/tools/lua/engine.py`](src/tools/lua/engine.py)) rewrites such literals to `addr("0x...")` calls, but only after protecting long strings, single- and double-quoted strings, and already-wrapped `addr()` / `parseHex()` calls from accidental rewrite.

### Service-to-PID enumeration
Identifying which `svchost.exe` hosts a given Windows service is normally a multi-step chore. The `processes` tool calls `EnumServicesStatusExW` through the Service Control Manager and joins the result onto the process list, so `processes(service="EventLog")` returns the right PID in one call. Lazy-loaded: the SCM enumeration only runs when a query actually needs it.

## Installation

**Requirements:**
- Windows x64
- Python 3.10+
- An MCP client ([Claude Desktop](https://claude.ai/download), [Claude Code](https://claude.ai/code), or any [MCP-compatible client](https://modelcontextprotocol.io/clients))

**Install:**
```bash
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
cd memscope-mcp
pip install -e .
```

**Configure your MCP client.** Add a server entry; the cleanest form uses the installed console script:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "memscope-mcp"
    }
  }
}
```

If the client doesn't have the script on `PATH`, fall back to the module form:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "python",
      "args": ["-m", "src.server"]
    }
  }
}
```

Where this goes:

| Client | Config location |
|--------|----------------|
| Claude Desktop | Settings > Developer > Edit Config ([docs](https://modelcontextprotocol.io/docs/develop/connect-local-servers)) |
| Claude Code | `.mcp.json` in project root, or `~/.claude.json` for global ([docs](https://code.claude.com/docs/en/settings)) |
| Other clients | See [MCP client docs](https://modelcontextprotocol.io/clients) |

**Verify:**
```bash
pytest tests/test_smoke.py -v
```

The smoke suite checks that all 10 tools register, the Lua engine initializes, the plugin loader runs cleanly, and the instructions builder produces output.

## Session Logging

Every tool call is logged to `logs/sessions/<timestamp>.jsonl` — one JSONL file per server session, one line per call with tool name, arguments, success status, and duration in milliseconds. Logs older than two years are auto-cleaned. Useful for debugging and replaying sessions.

## Platform

Windows x64 only. Uses pymem, which wraps Windows APIs (`ReadProcessMemory`, `WriteProcessMemory`, `CreateRemoteThread`, etc.). The pymem dependency is unconditional; the package will not install on non-Windows hosts.

## Security

memscope-mcp can read and write arbitrary memory in attached processes and execute code in them. Intended uses: malware analysis, vulnerability research, security testing of software you own or are authorized to test, modding-tool development for offline software, and educational reverse engineering. Only target processes and systems you are authorized to analyze.

User-mode access only. Targets with anti-tampering or debugger-detection mitigations (commercial obfuscators, EDR-hooked binaries, kernel-level protection) may detect or block the tool.

Plugins execute arbitrary Python code at server startup — only activate plugins you have read.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
