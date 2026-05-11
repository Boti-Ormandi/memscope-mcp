"""Base instructions for the MCP server - always loaded."""

BASE_INSTRUCTIONS = """
# Memory Research MCP Server

Low-level memory inspection and manipulation for reverse engineering.
Attach to any process, read/write memory, scan patterns, execute code.

## Lua Scripting

Use `lua` tool for complex operations (loops, conditionals, multi-step logic).
Scripts can run WITHOUT an attached process for discovery tasks.

### Process Introspection (pre-attach)

```lua
getProcessList(filter?, limit?)  -- List processes: {pid, name, parent_pid}
getProcessInfo(pid?)             -- Details: {pid, name, path, threads}
getServices(pid?)                -- Services: {name, display_name, pid, state}
getThreads(pid?)                 -- Threads: {tid, priority}
getMemoryRegions(filter?, limit?) -- Regions: {base, size, protection, type}
getRegionInfo(addr)              -- Region at address
openProcess(pid)                 -- Attach to process by PID
```

### Memory Read (post-attach)

```lua
readPointer(addr)         -- 64-bit pointer, nil if invalid
readByte(addr)            -- Single byte (0-255)
readInteger(addr)         -- int32
readQword(addr)           -- int64
readFloat(addr)           -- float
readDouble(addr)          -- double
readString(addr, maxlen)  -- C string (null-terminated)
readBytes(addr, count)    -- Byte table
```

### Bulk Array Reads

```lua
readPointerArray(addr, count)  -- Array of pointers (nil for invalid entries)
readIntArray(addr, count)      -- Array of int32 values
readFloatArray(addr, count)    -- Array of float values
```

Single bulk read for performance. Use for vtables, ID arrays, float buffers.

### Memory Write (post-attach)

```lua
writeInteger(addr, val)
writePointer(addr, val)
writeFloat(addr, val)
writeDouble(addr, val)
writeBytes(addr, {b1, b2, ...})
```

### Modules & Scanning

```lua
getModuleBase("name.dll")      -- Module base address
getModuleSize("name.dll")      -- Module size
getAddress("mod.dll+0x123")    -- Resolve module+offset
getModules(filter?)             -- List modules: {name, base, size, path}
getModuleFromAddress(addr)      -- Reverse lookup: {name, base, offset} or nil
formatAddress(addr)             -- "module.dll+0xOFFSET" or "0xADDR"
AOBScan(pattern, start?, end?, limit?) -- Modules by default; bounded scans readable regions
AOBScanModule(mod, pattern, limit?)    -- Scan specific module
scanString(str, module?, wide?) -- Scan for string (ASCII or UTF-16)
scanPointer(target, module?)    -- Find all pointers to target address (xrefs)
```

Bounded `AOBScan` walks committed readable VirtualQueryEx regions, including
MEM_PRIVATE heap pages. Results include `hits.metadata` with region counts,
bytes scanned, timeout state, and result count.

### Pointer Chains

```lua
readPointerChain(base, off1, off2, ...)  -- Follow chain, return final value
```

### Struct Helpers

```lua
readVector3(addr)     -- {x, y, z} (3 floats)
readVector4(addr)     -- {x, y, z, w} (4 floats)
readMatrix4x4(addr)   -- 4x4 matrix with position field
readStruct(addr, {    -- Read multiple fields at once
    version = "uint32@0x10",
    flags = "uint32@0x14",
    timestamp = "uint64@0x20"
})
```

### Code Execution

```lua
executeCode(func, arg1, arg2, ...)  -- Call function
callSequence({{address=x, args={...}}, ...})  -- Multi-call in ONE thread
callSequenceResults({{address=x, args={...}}, ...})  -- Final + per-call RAX values
alloc(64)        -- Allocate N bytes
alloc("string")  -- Allocate string
freeMemory(addr) -- Free allocation
```

`executeCode` and `executeCodeEx` create a remote thread per call. Lua scripts
warn after 25 such calls and block after 100 unless
`allowUnsafeCodeExecution(true)` is set for that script. Prefer `callSequence`
for thread-local APIs or repeated dependent calls.

### Utilities

```lua
toHex(val)           -- Convert to hex string
fmt("0x%X", val)     -- String format
print(...)           -- Output to results
addResult(key, val)  -- Add to results dict
addr("0x...")        -- Parse large hex (see below)
isNil(x)             -- nil check
orZero(x)            -- x or 0
orEmpty(x)           -- x or ""
clock()              -- High-resolution timer (milliseconds)
sleep(ms)            -- Pause execution
```

### Bitwise Operations

```lua
band(a, b)               -- AND
bor(a, b)                -- OR
bxor(a, b)               -- XOR
bnot(a)                  -- NOT (32-bit)
lshift(a, n)             -- Left shift
rshift(a, n)             -- Logical right shift
bextract(val, offset, width?)  -- Extract bit field (width default 1)
```

Lua 5.4 also supports native operators: `a & b`, `a | b`, `a ~ b`, `a << n`, `a >> n`.

## Important Notes

### 64-bit Addresses
Large hex literals cause Lua parse errors. Always use addr():
```lua
-- CORRECT:
local ptr = addr("0x1F58E12ECF0")

-- WRONG (parse error):
local ptr = 0x1F58E12ECF0
```

### Thread-Local APIs
Some runtime APIs (like thread_attach) only affect the calling thread.
Use `callSequence` to run multiple calls in the same thread. Later calls can
consume prior RAX results with `{result=N}` where `N` is the 1-based call index:
```lua
callSequence({
    {address=thread_attach, args={domain}},
    {address=get_object, args={image, index}},
    {address=api_function, args={{result=2}, iterator}}
})
```
Use `callSequenceResults` when you need a prior call's RAX after a cleanup call
has run; it returns `{result=..., call_results={...}, calls_executed=N}`.

### Scripts Directory
Scripts are stored as `.lua` files in `scripts/<process>/`.
- Use `scripts(action="list")` to see available scripts
- Use `scripts(action="run", name="x")` to run
- Create/edit scripts using file tools on the returned paths
- First line comment becomes the script description
""".strip()
