# memscope-mcp

[![Tests](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/Boti-Ormandi/memscope-mcp/actions/workflows/test.yml)

AI-native memory research via the Model Context Protocol.

The bridge between AI agents and live process memory. No GUI, no manual clicking -- AI agents attach to processes, read memory, scan patterns, and script complex operations in real time.

## What This Is

memscope-mcp is an MCP server for reverse engineering and memory research. It gives AI agents 10 tools to:

- Attach to any Windows process and enumerate modules
- Read and write typed memory (int32, float, vector3, pointers, etc.)
- Scan for byte patterns (AOB) with wildcards
- Follow pointer chains through memory structures
- Execute complex Lua scripts server-side in a single call
- Persist reusable scripts across sessions

Built for AI workflows from scratch. Not a human tool with an API bolted on.

## Quick Start

```bash
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
cd memscope-mcp
pip install -e .
```

Add to your MCP client config (see [Installation](#installation) for client-specific locations):

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

Restart your MCP client. 10 memory research tools are now available.

## What It Looks Like

Everything happens through MCP tool calls. Here's a typical exploration session:

**Find and attach to a process:**
```
> processes(filter="notepad")
  {processes: [{pid: 1234, name: "notepad.exe", threads: 6, path: "C:\\Windows\\System32\\notepad.exe"}]}

> attach("notepad.exe")
  {pid: 1234, key_modules: {"notepad.exe": {base: "0x7FF6A0000000", size: 245760}, "kernel32.dll": {...}}, ...}
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

> dump(address="target.dll+0x1A208D8", size=64)
  [{offset: 0, hex: "48 8B 05 ...", annotation: "-> 0x183C13300"}, ...]

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

All tools accept addresses as hex strings (`"0x1234"`), module+offset (`"module.dll+0x1234"`), or hex arithmetic (`"0xBASE+0xOFFSET"`).

| Tool | Purpose |
|------|---------|
| `processes` | List/filter running processes. Filter by name, PID, parent PID, or hosted service. Auto-enumerates services for svchost processes via the Windows Service Control Manager |
| `attach` | Attach to process, cache module bases. Auto-reconnects if the target process restarts |
| `modules` | List loaded modules with base addresses, sizes, and paths |
| `read` | Read typed memory (int8-64, uint8-64, float, double, bool, ptr, cstring, vector2/3/4, quaternion, color, rect, bounds, matrix4x4). Supports `count` for consecutive values |
| `write` | Write typed memory with optional pre-write verification. Checks page protection to prevent writes to read-only memory |
| `dump` | Smart memory dump with automatic type detection (pointers, strings, ints, floats) and confidence scoring. Use `pointers_only` to filter to valid pointers |
| `chain` | Follow pointer chains: `[[base+off0]+off1]...` with configurable final read type |
| `scan` | AOB pattern scanning with wildcards (`??`, `?`, `**`). Module scans by default; `start_addr`/`end_addr` scan committed readable regions. Paginated results with scan metadata |
| `lua` | Execute Lua scripts server-side for multi-step operations |
| `scripts` | Manage saved Lua scripts. Actions: `list` (with paths), `run` (with args). Use `process='*'` to list across all processes |

## Lua Scripting

Multi-step memory operations as a single MCP call. No round-trip overhead.

90+ built-in functions. Large hex literals (>32-bit) are automatically converted to `addr()` calls to avoid Lua parse errors.

### Memory Read

```lua
readByte(addr)                    -- uint8
readSmallInteger(addr)            -- int16
readInteger(addr)                 -- int32
readIntegerSafe(addr)             -- int32 or nil if garbage value
readQword(addr)                   -- int64
readUInt16(addr)                  -- uint16
readUInt32(addr)                  -- uint32
readUInt64(addr)                  -- uint64
readPointer(addr)                 -- uint64, nil if invalid pointer
readPointerRaw(addr)              -- uint64, no validation
readFloat(addr)                   -- float32
readDouble(addr)                  -- float64
readBool(addr)                    -- boolean (1 byte)
readString(addr, maxlen?)         -- null-terminated C string
readWideString(addr, maxlen?)     -- null-terminated UTF-16LE string
readBytes(addr, count)            -- table of bytes
readBytesHex(addr, count)         -- "48 8B 05..." hex string
```

### Bulk Array Reads

Single bulk read for performance. Use for vtables, ID arrays, float buffers.

```lua
readPointerArray(addr, count)     -- table of pointers (nil for invalid entries)
readIntArray(addr, count)         -- table of int32 values
readFloatArray(addr, count)       -- table of float values
```

### Memory Write

```lua
writeByte(addr, val)              writeSmallInteger(addr, val)
writeInteger(addr, val)           writeQword(addr, val)
writeUInt16(addr, val)            writeUInt32(addr, val)
writeUInt64(addr, val)            writePointer(addr, val)
writeFloat(addr, val)             writeDouble(addr, val)
writeBool(addr, val)              writeString(addr, str, maxlen?)
writeBytes(addr, table)
```

### Struct Helpers

```lua
readVector3(addr)                 -- {x, y, z} (3 floats)
readVector4(addr)                 -- {x, y, z, w} (4 floats)
readQuaternion(addr)              -- alias for readVector4
readMatrix4x4(addr)               -- 4x4 matrix with position field
readStruct(addr, {                -- read multiple fields at once
    version = "uint32@0x10",
    flags = "uint32@0x14",
    timestamp = "uint64@0x20"
})
```

### Module/Address

```lua
getAddress("mod.dll+0x1234")      -- resolve to absolute address
getModuleBase("mod.dll")          -- module base address
getModuleSize("mod.dll")          -- module size in bytes
getModules(filter?)               -- table of {name, base, size, path}
getModuleFromAddress(addr)        -- reverse lookup: {name, base, offset} or nil
formatAddress(addr)               -- "module.dll+0xOFFSET" or "0xADDR"
```

### Scanning

```lua
AOBScan(pattern, start?, end?, limit?) -- modules by default; bounded scans readable regions
AOBScanModule(mod, pattern, limit?)    -- scan one module
scanString(str, module?, wide?)   -- find string (ASCII or UTF-16)
scanPointer(target, module?)      -- find all pointers to target (xrefs)
```

Bounded `AOBScan` and MCP `scan(start_addr=..., end_addr=...)` walk committed
readable VirtualQueryEx regions, including MEM_PRIVATE heap pages. MCP results
include `scan_metadata`; Lua results include `hits.metadata`.

### Pointer Chains

```lua
readPointerChain(base, off1, off2, ...)  -- follow chain, return final address
```

### Code Execution

Custom x64 shellcode generator with full Microsoft calling convention support (shadow space, stack alignment, float XMM args).

```lua
executeCode(func, arg1, ...)      -- call function, return RAX
executeCodeEx(flags, timeout, func, ...)  -- extended call with options
callSequence({{address=x, args={...}}, ...})  -- multi-call in ONE thread
callSequenceResults({{address=x, args={...}}, ...})  -- final + per-call RAX values
alloc(size)                       -- allocate RW memory
alloc("string")                   -- allocate + write string
alloc("string", true)             -- allocate + write wide string (UTF-16)
freeMemory(addr)                  -- free allocation
```

String arguments to `executeCode` are smart-handled: numeric strings (`"0x1234"`) are passed as integers, text strings are auto-allocated in the target process and freed after the call.

`executeCode` and `executeCodeEx` create a remote thread for each call. Lua scripts warn after 25 calls and block after 100 unless `allowUnsafeCodeExecution(true)` is set for that script. Prefer `callSequence` for thread-local APIs and dependent native calls:

```lua
callSequence({
  {address=thread_attach, args={domain}},
  {address=get_object, args={image, index}},
  {address=use_object, args={{result=2}, iterator}}
})
```

`{result=N}` passes the RAX value from the Nth prior call as an argument.
Use `callSequenceResults` when the sequence ends with cleanup but you still need
an earlier return value; it returns `{result=..., call_results={...}, calls_executed=N}`.

### Process Introspection

These work without attaching to a process.

```lua
getProcessList(filter?, limit?)   -- {pid, name, parent_pid, threads}
getProcessInfo(pid?)              -- {pid, name, path, parent_pid, threads}
getMemoryRegions(filter?, limit?) -- {base, size, protection, type, state}
getRegionInfo(addr)               -- {base, size, protection, is_readable/writable/executable}
getThreads(pid?)                  -- {tid, owner_pid, priority}
getServices(pid?)                 -- {name, display_name, pid, state}
openProcess(pid)                  -- attach to process from within a script
```

### 64-bit Safe Comparisons

Lua numeric comparisons overflow on large 64-bit values. These functions handle it safely.

```lua
safeEq(a, b)    safeNe(a, b)    safeLt(a, b)    safeGt(a, b)
safeLe(a, b)    safeGe(a, b)    safeIsZero(x)   safeNotZero(x)
safeInt(val)                      -- val if small int, else nil
```

### Bitwise

Lua 5.4 also supports native operators: `a & b`, `a | b`, `a ~ b`, `a << n`, `a >> n`.

```lua
band(a, b)    bor(a, b)    bxor(a, b)    bnot(a)
lshift(a, n)  rshift(a, n) bextract(val, offset, width?)
```

### Utilities

```lua
addr("0x...")  parseHex("0x...")  -- parse large hex strings (REQUIRED for >32-bit literals)
toHex(val)                        -- convert to hex string
fmt("0x%X", val)                  -- C-style string format
print(...)                        -- output to results
addResult(key, val)               -- add to results dict
setResult(val)                    -- set single result value
isNil(x)       orZero(x)         orEmpty(x)
isValidPointer(addr)              -- check if address is valid
isWritableMemory(addr)            -- check page protection
backupMemory(addr, size)          -- backup region as byte table
clock()                           -- high-resolution timer (milliseconds)
sleep(ms)                         -- pause execution
enableDebug()  disableDebug()     -- toggle error logging in output
getLastError()                    -- last error message
```

### Example

Find a RIP-relative singleton reference and read fields off it:

```lua
local pattern = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8"
local matches = AOBScanModule("target.dll", pattern)

if #matches > 0 then
  local rip_offset = readInteger(matches[1] + 3)
  local singleton = matches[1] + 7 + rip_offset
  local ptr = readPointer(singleton)

  if ptr and ptr ~= 0 then
    addResult("address", toHex(ptr))
    addResult("version", readUInt32(ptr + 0x10))
    addResult("flags", readUInt32(ptr + 0x14))
    addResult("name", readString(ptr + 0x20, 64))
  end
end
```

## Plugins

Domain-specific extensions without touching core code. Drop a `.py` file into `plugins/` and restart.

```bash
# Activate the reference IL2CPP plugin (Unity runtime helpers)
cp contrib/plugins/il2cpp.py plugins/
```

The IL2CPP plugin is a reference implementation for reverse engineering Unity's IL2CPP runtime. It adds Lua functions for reading IL2CPP strings, arrays, lists, dictionaries, and managing thread attachment.

### Writing a Plugin

```python
from src.plugins import PluginBase

class MyPlugin(PluginBase):
    name = "my_domain"
    description = "Domain-specific helpers"

    instructions = """
    ## My Domain Helpers
    Available when: my_domain.dll present in modules

    ```lua
    myRead(addr)  -- Read domain-specific structure
    ```
    """

    def register(self, engine):
        return {"myRead": self._read}

    def _read(self, address):
        # Implementation using engine.session for memory access
        return value
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full plugin interface.

## Script Persistence

Save working Lua scripts as `.lua` files, organized by process:

```
scripts/
  target.exe/
    find_struct.lua
    dump_vtable.lua
  other_target.exe/
    scan_config.lua
```

- First-line comment becomes the script description
- Version control friendly (plain text files)
- AI agents discover saved scripts on attach and reuse them automatically
- Create scripts with your MCP client's file tools, run them with the `scripts` tool

## Session Logging

All tool calls are automatically logged to `logs/sessions/<timestamp>.jsonl` -- one JSONL file per server session. Each line records the tool name, arguments, success status, and duration in milliseconds. Logs older than 2 years are auto-cleaned. Useful for debugging and replaying sessions.

## Architecture

```
src/
  server.py              # MCP tool definitions (thin wrappers)
  session.py             # Process attachment and memory primitives
  tools/
    memory.py            # Smart memory dump
    scanning.py          # AOB pattern scanning
    pointers.py          # Pointer chain resolution
    types.py             # Typed memory read/write
    lua_engine.py        # Lua script execution
    lua_scripts.py       # Script persistence
    execute.py           # Remote code execution
    lua/                 # Lua function registrations (9 modules)
  plugins/               # Plugin loader
  instructions/          # AI context builder (base + plugins)
  utils/                 # Address parsing, heuristics, shellcode
plugins/                 # Active plugins (user-curated, gitignored)
contrib/plugins/         # Available plugins (checked in)
scripts/                 # Saved Lua scripts per process (gitignored)
logs/                    # Session logs in JSONL format (gitignored)
```

**Design principles:**
- Generic core, plugins for domains -- no target-specific code in `src/`
- AI context is expensive -- plugin instructions only loaded when plugin is active
- Lua for complexity -- simple reads use MCP tools, multi-step logic uses Lua
- Scripts persist, addresses don't -- ASLR invalidates addresses on restart, save the finder script instead
- Minimal tools -- 10 well-designed tools, not 100 overlapping ones

**Under the hood:**
- Custom x64 shellcode builder handles Microsoft calling convention (shadow space, stack alignment, XMM registers for floats) for `executeCode` and `callSequence`
- `dump` uses type detection heuristics with confidence scoring to annotate raw memory as pointers, strings, ints, or floats
- Auto-reconnection: if the target process restarts, the session detects it via `GetExitCodeProcess` and re-attaches transparently on the next tool call
- Lua script preprocessor auto-converts large hex literals (`0x10000000000`) to `addr()` calls before execution
- Service enumeration uses the Windows Service Control Manager API (`EnumServicesStatusExW`) to map services to PIDs

## Installation

**Requirements:**
- Python 3.10+
- Windows x64
- An MCP client ([Claude Desktop](https://claude.ai/download), [Claude Code](https://claude.ai/code), or any [MCP-compatible client](https://modelcontextprotocol.io/clients))

**Install:**
```bash
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
cd memscope-mcp
pip install -e .
```

**Configure your MCP client:**

Add a `memscope` server entry to your client's MCP config:

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

Where this goes depends on your client:

| Client | Config location |
|--------|----------------|
| Claude Desktop | Settings > Developer > Edit Config ([docs](https://modelcontextprotocol.io/docs/develop/connect-local-servers)) |
| Claude Code | `.mcp.json` in project root, or `~/.claude.json` for global ([docs](https://code.claude.com/docs/en/settings)) |
| Other clients | See [MCP client docs](https://modelcontextprotocol.io/clients) |

If your client doesn't run commands from the project directory, you may need to add `cwd` and `env` to the server config.

**Verify:**
```bash
python -c "from src.server import mcp; print(len(mcp._tool_manager._tools), 'tools')"
```

## Platform

Windows x64 only. Uses pymem which wraps Windows APIs (ReadProcessMemory, WriteProcessMemory, CreateRemoteThread, etc.).

User-mode access only. Targets with anti-tampering or debugger-detection mitigations (commercial obfuscators, EDR-hooked binaries, kernel-level protection) may detect or block this tool.

## Security

memscope-mcp is a memory research tool. It can read/write arbitrary process memory and execute code in attached processes.

Intended uses: malware analysis, vulnerability research, security testing of software you own or are authorized to test, modding-tool development for offline software, and educational reverse engineering. Only use against processes and systems you are authorized to analyze.

Plugins execute arbitrary Python code at startup -- only install plugins you trust.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. PRs welcome.

## License

[MIT](LICENSE)
