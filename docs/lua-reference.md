# Lua Reference

Complete reference for the Lua functions exposed by the memscope-mcp `lua` tool. The same surface is summarized in [`memscope_mcp/instructions/base.py`](../memscope_mcp/instructions/base.py) for AI consumption (kept terse because that text ships as the MCP `instructions` channel and is token-priced). When adding or renaming a function, update both files.

The Lua runtime is Lua 5.4 via [lupa](https://github.com/scoder/lupa). All address parameters accept Lua integers, hex strings (`"0x1234"`), and module+offset strings (`"module.dll+0x1234"`).

## Contents

- [Memory read](#memory-read)
- [Bulk array reads](#bulk-array-reads)
- [Memory write](#memory-write)
- [Struct helpers](#struct-helpers)
- [Module / address resolution](#module--address-resolution)
- [Scanning](#scanning)
- [Pointer chains](#pointer-chains)
- [Code execution](#code-execution)
- [Hooking](#hooking)
- [Process introspection](#process-introspection)
- [Network utilities](#network-utilities)
- [64-bit safe comparisons](#64-bit-safe-comparisons)
- [Bitwise](#bitwise)
- [Utilities](#utilities)
- [Netcap plugin](#netcap-plugin)
- [Important notes](#important-notes)

## Memory read

```lua
readByte(addr)                    -- uint8
readSmallInteger(addr)            -- int16
readInteger(addr)                 -- int32
readIntegerSafe(addr)             -- int32 or nil if value looks like garbage
readQword(addr)                   -- int64
readUInt16(addr)                  -- uint16
readUInt32(addr)                  -- uint32
readUInt64(addr)                  -- uint64
readPointer(addr)                 -- uint64, nil if address fails pointer-validity check
readPointerRaw(addr)              -- uint64, no validation
readFloat(addr)                   -- float32
readDouble(addr)                  -- float64
readBool(addr)                    -- boolean (1 byte)
readString(addr, maxlen?)         -- null-terminated C string
readWideString(addr, maxlen?)     -- null-terminated UTF-16LE string
readBytes(addr, count)            -- table of bytes
readBytesHex(addr, count)         -- "48 8B 05 ..." hex string
```

## Bulk array reads

Single bulk read for performance. Use for vtables, ID arrays, float buffers — much faster than a Lua loop of single reads.

```lua
readPointerArray(addr, count)     -- table of pointers (nil entries for invalid pointers)
readIntArray(addr, count)         -- table of int32 values
readFloatArray(addr, count)       -- table of float values
```

## Memory write

```lua
writeByte(addr, val)              writeSmallInteger(addr, val)
writeInteger(addr, val)           writeQword(addr, val)
writeUInt16(addr, val)            writeUInt32(addr, val)
writeUInt64(addr, val)            writePointer(addr, val)
writeFloat(addr, val)             writeDouble(addr, val)
writeBool(addr, val)              writeString(addr, str, maxlen?)
writeBytes(addr, table)
```

## Struct helpers

```lua
readVector3(addr)                 -- {x, y, z} (3 floats)
readVector4(addr)                 -- {x, y, z, w} (4 floats)
readQuaternion(addr)              -- alias for readVector4
readMatrix4x4(addr)               -- 4x4 matrix table with .position field
readStruct(addr, {                -- read multiple fields at once
    version = "uint32@0x10",
    flags = "uint32@0x14",
    timestamp = "uint64@0x20"
})
```

## Module / address resolution

```lua
getAddress("mod.dll+0x1234")      -- resolve to absolute address
getModuleBase("mod.dll")          -- module base address
getModuleSize("mod.dll")          -- module size in bytes
getModules(filter?)               -- table of {name, base, size, path}
getModuleFromAddress(addr)        -- reverse lookup: {name, base, offset} or nil
formatAddress(addr)               -- "module.dll+0xOFFSET" or "0xADDR"
resolveExport("mod.dll", "func")  -- PE export resolution, follows forwarders (depth 5)
```

## Scanning

```lua
AOBScan(pattern, start?, end?, limit?)  -- modules by default; with bounds, scans readable regions
AOBScanModule(mod, pattern, limit?)     -- scan one module
scanString(str, module?, wide?)         -- find string (ASCII or UTF-16)
scanPointer(target, module?)            -- find all pointers to target address (xrefs)
```

Bounded `AOBScan` walks committed readable regions via `VirtualQueryEx`, including MEM_PRIVATE heap pages. Results include `hits.metadata` with region counts, bytes scanned, timeout state, and result count.

## Pointer chains

```lua
readPointerChain(base, off1, off2, ...)  -- follow chain, return final address
```

Standard reverse-engineering semantics: add offset, dereference, repeat. Equivalent to `[[base+off1]+off2]+...`.

## Code execution

A custom x64 shellcode generator with full Microsoft calling convention support (shadow space, 16-byte stack alignment, RCX/RDX/R8/R9 for integers, XMM0-XMM3 for floats).

```lua
executeCode(func, arg1, ...)                  -- call function, return RAX
executeCodeEx(flags, timeout, func, ...)      -- extended call with options
callSequence({{address=x, args={...}}, ...})  -- multi-call in ONE thread
callSequenceResults({...})                    -- final + per-call RAX values
alloc(size)                                   -- allocate RW memory
alloc("string")                               -- allocate + write string
alloc("string", true)                         -- allocate + write wide string (UTF-16)
freeMemory(addr)                              -- free allocation
```

String arguments to `executeCode` are smart-handled: numeric strings (`"0x1234"`) are passed as integers, text strings are auto-allocated in the target process and freed after the call.

`executeCode` and `executeCodeEx` each create a remote thread per call. Lua scripts warn after 25 such calls and block after 100 unless `allowUnsafeCodeExecution(true)` is set on the script. Prefer `callSequence` for thread-local APIs and for sequences of dependent native calls:

```lua
callSequence({
  {address=thread_attach, args={domain}},
  {address=get_object, args={image, index}},
  {address=use_object, args={{result=2}, iterator}}
})
```

`{result=N}` passes the RAX value from the Nth prior call (1-based) as an argument. Use `callSequenceResults` when the sequence ends in a cleanup call but you still need an earlier return value; it returns `{result=..., call_results={...}, calls_executed=N}`.

## Hooking

Generic inline function hooking with a shared ring buffer in the target process. Hook any function by address, capture register args + optional buffer payload + optional stack args, read entries through Lua. Requires an attached process. See [`docs/hooking.md`](hooking.md) for architecture.

```lua
createRingBuffer({entry_count=512, max_data_size=4096}?)  -- one shared buffer per session

hookFunction(address, {
    name = "label",                        -- identifier for listHooks / entry["hook_name"]
    type = "pre" | "post",                 -- capture before or after the call
    buffer_arg = 1..4 | -1,                -- which register arg is a buffer pointer
    length_arg = 0..4 | -1,                -- which arg is length; 0 = use return value
    max_capture = 4096,                    -- byte cap per entry
    stack_args = {5, 6, ...},              -- optional capture of stack args (max 7)
    deref_args = {[N]=4|8, ...},           -- post-call: re-read arg N as 4/8 bytes (output params)
    buffer_deref = {arg=N, offset=K},      -- indirect buffer: [arg+K] = buffer pointer (e.g. WSABUF)
    length_deref = {arg=N, offset=K, size=4|8},  -- indirect length: [arg+K] = length
})                                          -- returns {hook_id, trampoline, saved_bytes, jmp_size}

unhookFunction(address_or_hook_id)         -- restore original bytes; defer trampoline free
listHooks()                                -- table of installed hooks
destroyRingBuffer()                        -- free buffer (all hooks must be removed first)

readRingBuffer(limit?, {min_result=N}?)    -- pending entries; optionally skip entries with low result
ringBufferMarker("label")                  -- inject a marker entry with timestamp 0
ringBufferStats()                          -- {total_captured, total_dropped, entries_pending, utilization_pct}
```

Each entry returned by `readRingBuffer` carries `sequence`, `hook_id`, `hook_name`, `timestamp`, `return_addr`, `arg0..arg3`, optional `extra_args`, `result`, `data_length`, `captured_length`, `data` (byte table), `data_hex` (printable hex), and `is_marker`. Pre-call hooks have `result=0`. Post-call hooks have `result` set to the original function's RAX as a signed int32.

Minimal capture-and-read cycle:

```lua
createRingBuffer({entry_count=512, max_data_size=4096})

local send_addr = resolveExport("ws2_32.dll", "send")
hookFunction(send_addr, {
    name = "send",
    type = "pre",
    buffer_arg = 2,    -- send(socket, *buf, len, flags)
    length_arg = 3,
    max_capture = 4096,
})

-- ... let the app run ...

for _, e in ipairs(readRingBuffer(100)) do
    print(e.hook_name, e.captured_length, e.data_hex)
end
```

Indirect capture for APIs whose buffer lives in a struct (WSABUF):

```lua
hookFunction(resolveExport("ws2_32.dll", "WSASend"), {
    name = "WSASend",
    type = "pre",
    buffer_deref = {arg=2, offset=8},                -- LPWSABUF -> {len@0, buf@8}
    length_deref = {arg=2, offset=0, size=4},
    max_capture = 8192,
})
```

## Process introspection

These functions work without an attached process. Useful for discovery scripts.

```lua
getProcessList(filter?, limit?)   -- {pid, name, parent_pid, threads}
getProcessInfo(pid?)              -- {pid, name, path, parent_pid, threads,
                                  --  command_line, current_directory, being_debugged, image_path}
getMemoryRegions(filter?, limit?) -- {base, size, protection, type, state}
getRegionInfo(addr)               -- {base, size, protection, is_readable/writable/executable}
getThreads(pid?)                  -- {tid, owner_pid, priority}
getServices(pid?)                 -- {name, display_name, pid, state}
isBeingDebugged(pid?)             -- boolean from PEB.BeingDebugged, or nil on access failure
getEnvironment(pid?)              -- {KEY="value", ...} from the target's PEB
getModulesRemote(pid?)            -- {name, base, size, path} via PEB Ldr (no attach required)
openProcess(pid)                  -- attach to process from within a script
```

The `pid?`-suffixed functions default to the attached process when called without arguments. PEB reads (`command_line`, `getEnvironment`, `getModulesRemote`, `isBeingDebugged`) work pre-attach on any process the server can open with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`. See [`docs/peb.md`](peb.md) for limits (64 KiB env, 1024 modules, 32 KiB strings).

## Network utilities

```lua
getSocketInfo(socket_handle)      -- {remote_addr, remote_port, local_addr, local_port, family}
                                  -- family is "IPv4" or "IPv6"; nil on error or unconnected socket
```

Calls `getpeername` and `getsockname` in the target process. Use after a network hook to identify which connection a socket belongs to.

## 64-bit safe comparisons

Lua numeric comparisons can overflow on large 64-bit values (pointers and high addresses). These helpers handle wraparound correctly.

```lua
safeEq(a, b)    safeNe(a, b)    safeLt(a, b)    safeGt(a, b)
safeLe(a, b)    safeGe(a, b)    safeIsZero(x)   safeNotZero(x)
safeInt(val)                      -- val if it fits int64, else nil
```

## Bitwise

Lua 5.4 supports native operators (`a & b`, `a | b`, `a ~ b`, `a << n`, `a >> n`). These named helpers exist for readability and for cases where the operands need uint64 coercion.

```lua
band(a, b)    bor(a, b)    bxor(a, b)    bnot(a)
lshift(a, n)  rshift(a, n) bextract(val, offset, width?)
```

## Utilities

```lua
addr("0x...")                     -- parse hex string to integer (required for >32-bit literals)
parseHex("0x...")                 -- alias for addr()
toHex(val)                        -- convert to hex string
fmt("0x%X", val)                  -- C-style string format
print(...)                        -- output to results.output array
addResult(key, val)               -- add to results dict
setResult(val)                    -- set single top-level result value
isNil(x)       orZero(x)         orEmpty(x)
isValidPointer(addr)              -- user-mode range check
isWritableMemory(addr)            -- VirtualQueryEx page-protection check
backupMemory(addr, size)          -- backup region as byte table (for later writeBytes restore)
clock()                           -- high-resolution timer (milliseconds)
sleep(ms)                         -- pause execution
enableDebug()  disableDebug()     -- toggle error logging into output array
getLastError()                    -- last error message from a returning-nil call
```

## Netcap plugin

These functions are available only when the netcap plugin is installed to `$MEMSCOPE_HOME/plugins/netcap.py` (run `memscope-mcp install-plugin netcap`). The plugin builds on the [Hooking](#hooking) primitives and adds protocol-aware capture, stream assembly, framing, search, and recording for Winsock traffic.

### Capture lifecycle

```lua
startCapture({                          -- begin capturing on the named Winsock hooks
    hooks = {"send", "recv", "WSASend", "WSARecv", "sendto", "recvfrom"},
    connect = true,                     -- track connect/closesocket lifecycle
    iocp = true,                        -- correlate IOCP async I/O via GQCS
    lifecycle = true,                   -- track accept/bind for server sockets
    header_only = false,                -- capture only headers (smaller entries)
    buffer_size = 512,                  -- ring buffer entry_count
    max_packet_size = 4096,             -- ring buffer max_data_size
})
stopCapture()
readPackets(limit?)                     -- per-packet entries with direction, socket, parsed args
captureStats()                          -- bytes captured, packets seen, drops
getConnections()                        -- {socket, type, remote_addr, remote_port, local_addr, local_port}
filterPackets(packets, {direction?, socket?, min_size?, max_size?, hook_name?, contains?})
```

### Buffer pack/unpack helpers

```lua
unpackUInt16(data, offset)   unpackInt16(data, offset)
unpackUInt32(data, offset)   unpackInt32(data, offset)
unpackUInt64(data, offset)
unpackFloat(data, offset)    unpackDouble(data, offset)
unpackString(data, offset, maxlen?)
unpackBytes(data, offset, len)
unpackVector3(data, offset)

packUInt16(val)   packUInt32(val)   packInt32(val)
packUInt64(val)   packFloat(val)

bufferFind(data, pattern)              -- byte-table search; returns offset or nil
bufferContains(data, pattern)          -- boolean
bufferFindAll(data, pattern)           -- table of offsets
```

### Stream assembly

```lua
feedPackets(packets)                   -- merge packets into per-socket streams
getStream(socket_hex, direction?)      -- byte table of assembled stream
consumeStream(socket_hex, direction, n)-- pop n bytes from the head
listStreams()                          -- known socket/direction pairs
clearStream(socket_hex?)               -- drop one stream or all
```

### Protocol framing

```lua
splitLengthPrefixed(data, {length_offset, length_size, header_size, endian?, includes_header?})
splitDelimited(data, delimiter)        -- delimiter as string or byte table
splitFixed(data, size)
```

### Cross-reference search

```lua
searchPackets(packets, pattern)        -- byte pattern across captured payloads
searchPacketsForValue(packets, type, value)  -- type in {"uint32", "int32", "uint64", "float", "double"}
```

### Session recording

```lua
startRecording(filename?, {compress?, max_size_mb?}?)
stopRecording()
loadRecording(filename)                -- returns packet table
listRecordings(process?)               -- recordings for the named process (or attached)
```

Recordings are JSONL (or `.jsonl.gz` when `compress=true`) under `recordings/<process>/`. `max_size_mb` triggers size-based rotation.

## Important notes

### 64-bit address literals

Lua 5.4's parser rejects hex literals beyond 32 bits even though its integers are 64-bit. The server preprocesses scripts to rewrite large literals to `addr()` calls before execution, but this is best-effort — if you're constructing addresses dynamically, use `addr()` explicitly:

```lua
-- Correct:
local ptr = addr("0x1F58E12ECF0")

-- Also fine (preprocessor handles it):
local ptr = 0x1F58E12ECF0
```

The preprocessor protects long strings, single- and double-quoted strings, and already-wrapped `addr()` / `parseHex()` calls from rewrite, so it's safe to use either form.

### Thread-local APIs

Some runtime APIs (IL2CPP's `thread_attach`, Mono's `mono_thread_attach`, etc.) only affect the calling thread. Each `executeCode` call creates a fresh thread, so the attachment is gone by the next call. Use `callSequence` to run the attach and the subsequent API call in the same thread; reference prior return values with `{result=N}`:

```lua
callSequence({
    {address=thread_attach, args={domain}},
    {address=get_object, args={image, index}},
    {address=api_function, args={{result=2}, iterator}}
})
```

### Script persistence

Scripts are stored as `.lua` files in `scripts/<process>/`. The first-line comment becomes the script description shown by `scripts(action="list")`. Create and edit scripts with your MCP client's file tools; run them with the `scripts` tool.

### Example: locate a singleton from a RIP-relative reference

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
