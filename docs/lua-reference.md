# Lua reference

The `lua` MCP tool executes Lua 5.4 through the private Lupa runtime. This page describes the core functions registered by the seven core extensions. Activated plugins append their own functions; see [Plugin overview](plugins/overview.md) and [Netcap](plugins/netcap.md).

Use numeric addresses for memory helpers. Resolve string expressions first with `addr`, `getAddress`, or `getModuleBase`.

## Contents

- [Results and utilities](#results-and-utilities)
- [Memory reads](#memory-reads)
- [Memory writes](#memory-writes)
- [Structures and modules](#structures-and-modules)
- [Scanning](#scanning)
- [Pointer chains](#pointer-chains)
- [Code execution](#code-execution)
- [Session management](#session-management)
- [Hooking](#hooking)
- [Process and PEB inspection](#process-and-peb-inspection)
- [Network utilities](#network-utilities)
- [Saved scripts](#saved-scripts)

## Results and utilities

```lua
addr("0x1F58E12ECF0")       -- parse a large hexadecimal address
parseHex("0x1234")           -- alias for addr
toHex(value)                  -- format as hexadecimal
fmt("0x%X", value)           -- C-style formatting
print(...)                   -- append to output
addResult("key", value)      -- add a result field
setResult(value)             -- set the top-level value field
isNil(value)
orZero(value)
orEmpty(value)
isValidPointer(value)
clock()                      -- high-resolution milliseconds
sleep(milliseconds)
enableDebug()
disableDebug()
getLastError()
listLuaFunctions(owner?)
getLoadedExtensions()
getCapabilities()
```

`getCapabilities()` reports attached state, resolved data paths, the 11-tool count, scan contracts, verified writes, and typed byte writes. `listLuaFunctions(owner?)` reports registered `{name, owner}` entries. `getLoadedExtensions()` preserves first-seen owner order.

`isValidPointer(value)` performs only a user-mode pointer-range check—it does not prove that the address belongs to a committed or readable page. The check accepts values from `0x10000` through `0x7FFFFFFFFFFF`; use a target read or memory query when you need stronger evidence.

Safe 64-bit comparisons and bitwise helpers:

```lua
safeEq(a, b) safeNe(a, b) safeLt(a, b) safeGt(a, b)
safeLe(a, b) safeGe(a, b) safeIsZero(value) safeNotZero(value)
safeInt(value)
band(a, b) bor(a, b) bxor(a, b) bnot(value)
lshift(value, bits) rshift(value, bits) bextract(value, offset, width?)
```

The engine handles large hexadecimal literals by converting them to `addr("0x...")` before Lua parsing. Explicit `addr()` remains the clearest form.

## Memory reads

```lua
readByte(addr)
readSmallInteger(addr)
readInteger(addr)
readIntegerSafe(addr, max_value?)
readQword(addr)
readUInt16(addr) readUInt32(addr) readUInt64(addr)
readPointer(addr, validate?)
readPointerRaw(addr)
readFloat(addr) readDouble(addr)
readBool(addr)
readString(addr, maxlen?)
readWideString(addr, maxlen?)
readBytes(addr, count)
readBytesHex(addr, count)
```

Bulk reads use one target read:

```lua
readPointerArray(addr, count)
readIntArray(addr, count)
readFloatArray(addr, count)
```

Read helpers use returning-`nil` behavior for many target read failures and record a last error where applicable. `readPointer` applies a user-mode pointer check; `readPointerRaw` does not.

## Memory writes

```lua
writeByte(addr, value)
writeSmallInteger(addr, value)
writeInteger(addr, value)
writeQword(addr, value)
writeUInt16(addr, value) writeUInt32(addr, value) writeUInt64(addr, value)
writePointer(addr, value)
writeFloat(addr, value) writeDouble(addr, value)
writeBool(addr, value)
writeString(addr, text, maxlen?)
writeBytes(addr, byte_table)
backupMemory(addr, size)
isWritableMemory(addr)
```

Writes change target memory. `backupMemory` reads a byte table; `isWritableMemory` checks the target page range before a script write. The MCP `write` tool provides the stronger `verify=true` path with pre-image/readback and a restore attempt.

## Structures and modules

```lua
readVector3(addr)
readVector4(addr)
readQuaternion(addr)
readMatrix4x4(addr)
readStruct(addr, {
    health = "uint32@0x10",
    position = "vector3@0x20"
})
```

Module and address helpers:

```lua
getAddress("module.dll+0x1234")
getModuleBase("module.dll")
getModuleSize("module.dll")
getModules(filter?)
getModuleFromAddress(addr)
formatAddress(addr)
resolveExport("module.dll", "function")
```

`resolveExport` reads the attached process PE export directory and follows forwarders with a bounded depth. `getModules` returns module `name`, `base`, `size`, and `path`.

## Scanning

```lua
AOBScan(pattern, options?)
AOBScanMany(patterns, options?)
scanString(text, options?)
scanPointer(target, options?)
```

Use named options only: `scope`, `mode`, `max_matches`, `timeout_ms`, and `diagnostics`. `scanString` adds `encoding="ascii"` or `"utf-16le"`; `scanPointer` adds `alignment` from 1 through 4096. AOB patterns accept `??` as the only wildcard. Single-query modes are `addresses`, `first`, and `count`; batch mode is `first` or `count`. Expected failures return `nil, error_table` and valid no-match results remain non-nil. See [Scanning](scanning.md).

## Pointer chains

```lua
readPointerChain(base, offset1, offset2, ...)
```

The helper adds each offset, reads a pointer, validates intermediate pointers, and returns the final address. This matches `[[base+offset1]+offset2]...` semantics.

## Code execution

```lua
executeCode(function_address, arg1, ...)
executeCodeEx(flags, timeout, function_address, ...)
callSequence({
    {address = function_address, args = {arg1}},
    {address = next_function, args = {{result = 1}}}
})
callSequenceResults(calls, timeout?)
allowUnsafeCodeExecution(true)
alloc(size)
alloc("text")
alloc("text", true)          -- UTF-16 string
freeMemory(addr)
```

`executeCode` and `executeCodeEx` create one remote thread per call. The script guard warns after 25 calls and blocks after 100 unless `allowUnsafeCodeExecution(true)` is set. `callSequence` keeps dependent calls on one target thread and supports `{result=N}` references to earlier RAX results. `callSequenceResults` returns the final result and per-call results.

Native calls execute target code and can mutate or crash the target. Validate function addresses, argument widths, thread-local requirements, timeout, and cleanup. `alloc` uses target memory and detach cleanup tracks allocations.

## Session management

```lua
attach(target, pid?)
detach()
isAttached()
getAttachedProcess()
openProcess(pid)
```

`attach` accepts a process name or PID and an optional disambiguating PID. `openProcess(pid)` remains supported as an attach-by-PID alias. Attach/switch/detach invoke extension lifecycle callbacks. `getAttachedProcess()` returns PID, name, and module count or `nil`.

## Hooking

```lua
createRingBuffer({entry_count = 512, max_data_size = 4096}?)
hookFunction(address, {
    name = "send",
    type = "pre",
    buffer_arg = 2,
    length_arg = 3,
    max_capture = 4096,
    stack_args = {5, 6},
    deref_args = {[4] = 4},
    buffer_deref = {arg = 2, offset = 8},
    length_deref = {arg = 2, offset = 0, size = 4}
})
readRingBuffer(limit?, {min_result = value}?)
ringBufferMarker("label")
ringBufferStats()
listHooks()
unhookFunction(address_or_hook_id)
destroyRingBuffer()
```

Entries include sequence, hook ID/name, timestamp, return address, `arg0`–`arg3`, optional `extra_args`, result, data lengths, data, `data_hex`, and marker state. See [Inline hooking](hooking.md) for trampoline, relocation, thread-suspension, and cleanup behavior.

## Process and PEB inspection

These helpers can work before attachment:

```lua
getProcessList(filter?, limit?)
getProcessInfo(pid?)
isBeingDebugged(pid?)
getEnvironment(pid?)
getModulesRemote(pid?)
getThreads(pid?)
getServices(pid?)
```

The process list returns PID, name, parent PID, and thread count. PEB helpers return command line, current directory, debugger state, image path, environment, or remote module records when access permits. Results are bounded; environment reads use a 64 KiB cap, module walks use a 1024-entry cap, and wide strings use a 32 KiB cap. Treat environment and command-line data as sensitive. See [PEB introspection](peb.md).

Attached-session region helpers:

```lua
getMemoryRegions(filter?, limit?)
getRegionInfo(addr)
```

These helpers operate on the current attached session, so call them after `attach`. When detached, `getMemoryRegions` returns an empty table and `getRegionInfo` returns `nil`.

## Network utilities

```lua
getSocketInfo(socket_handle)
```

The helper calls target `getpeername` and `getsockname` and returns remote/local address, port, and `IPv4`/`IPv6` family when available. Netcap adds the packet and recording functions described in [Netcap](plugins/netcap.md).

When Netcap is active, its buffer-search helpers accept dense 1-indexed sequences and return 1-indexed offsets. Values from `0` through `255` use the byte-search fast path; other integers use the exact fallback path—the comparison semantics remain unchanged for converted values. Arbitrary converted integers retain exact legacy comparison semantics.

## Saved scripts

```lua
-- Script files live under $MEMSCOPE_HOME/scripts/<process>/.
```

The MCP `scripts` tool lists and runs files. File tools create/edit them. The first line comment is the description. `process="Target.exe"` selects a namespace only; it does not attach or switch. Detached runs require an explicit process namespace. See [Saved scripts](guides/saved-scripts.md).
