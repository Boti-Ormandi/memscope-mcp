# Inline Function Hooking

Pure shellcode inline hooking with a shared ring buffer in the target process. Hook any function by address, capture register arguments plus optional buffer data, and read entries back through Lua. No DLL injection, no kernel components.

The hooking layer is a core extension (`src/extensions/core/hooking.py`) registered on every server start. All hooking operations require a process to be attached first via the `attach` MCP tool. The netcap plugin builds on top of this layer; see [`plugins/README.md`](../plugins/README.md) for activation.

## Scope

- **Generic function hooking.** Hook any user-mode function at a known address. Capture register args 1-4, optional stack args 5-11, and optional buffer payloads.
- **Shared ring buffer.** All hooks share one lock-free buffer in target memory. Entries carry `hook_id`, timestamp, return address, args, captured bytes.
- **Pre- and post-call capture.** `type = "pre"` captures before the original executes; `type = "post"` captures after, with access to the return value and post-call pointer derefs for output parameters.
- **Indirect captures.** `buffer_deref` and `length_deref` pull buffer pointer and length through a struct (e.g. WSABUF), and `deref_args` rewrites a saved arg pointer with its dereferenced value after the call (e.g. `lpNumberOfBytesRecvd`).
- **No new MCP tools.** Everything is reachable from the existing `lua` MCP tool.

## Non-goals

- Kernel-mode interception (WFP, NDIS, ETW).
- General-purpose instruction relocation. We refuse to hook when the prologue contains RIP-relative addressing that cannot be safely rewritten.
- In-flight argument or buffer modification. Hooks observe; they do not mutate.
- Cross-platform support. Windows x64 only.

## Architecture

```
+--------------------------------------------------+
|             Core Lua API (Hooking)               |
|                                                  |
|   createRingBuffer(opts)                         |
|   hookFunction(addr, spec)                       |
|   unhookFunction(addr_or_hook_id)                |
|   listHooks()                                    |
|   readRingBuffer(limit, {min_result?})           |
|   ringBufferMarker(label)                        |
|   ringBufferStats()                              |
|   destroyRingBuffer()                            |
|                                                  |
|   (resolveExport is provided by module_scan)     |
+----------------------+---------------------------+
                       |
                       v
+--------------------------------------------------+
|             Hook Manager (Python)                |
|                                                  |
|   install_hook / remove_hook / lifecycle         |
|   build_hook_trampoline(spec)                    |
|   ring buffer allocation, read, stats            |
|   x64 instruction length decoder                 |
|   RIP-relative relocation                        |
+----------------------+---------------------------+
                       |
   VirtualAllocEx / WriteProcessMemory /
   VirtualProtectEx / ReadProcessMemory /
   SuspendThread / GetThreadContext / SetThreadContext
                       |
                       v
+--------------------------------------------------+
|                Target Process                    |
|                                                  |
|   Hooked functions (E9 / FF25 JMP at entry)      |
|              |                                   |
|              v                                   |
|   Trampolines (RWX)                              |
|     save regs                                    |
|     capture args + buffer                        |
|     CALL original-bytes stub                     |
|     capture return value (post hooks)            |
|     JMP back to function+N                       |
|              |                                   |
|              v                                   |
|   Ring buffer (RW)                               |
|     control block + N entry slots                |
+--------------------------------------------------+
```

## Key design decisions

### Ring buffer

A single RW memory block allocated in the target process and shared by all hooks. Entries are distinguished by `hook_id`. Writes are claimed with `lock cmpxchg` on the write index. Overflow is non-blocking: the writer drops the entry and increments a counter rather than waiting for the reader.

Each entry has a fixed 80-byte header (sequence, status, hook_id, timestamp, return address, four register args, `result` as a signed int32 holding post-call RAX, `data_length`, `captured_length`, `flags` with bit 0 = has data and bits 8-11 = extra stack-arg count) followed by optional captured bytes. Status transitions from `WRITING` to `COMPLETE` (or `MARKER` for server-injected timeline markers). The reader stops at the first `WRITING` slot to preserve ordering of in-flight entries.

Capture is gated by the control-block `FLAGS` field; the trampoline skips writes when bit 0 is clear. `ringBufferMarker` uses that to disable capture, inject a synthetic `MARKER` entry with timestamp 0 and the marker label as data, and re-enable.

Server-side reads advance the read pointer atomically. `readRingBuffer(limit, {min_result})` optionally filters entries whose `result` is below a threshold (e.g. to skip `recv` calls returning -1). Stats expose `total_captured`, `total_dropped`, `entries_pending`, `utilization_pct`.

### Trampoline pattern

Both pre-call and post-call hooks use the same shape:

1. Save volatile registers.
2. Capture register args 1-4 (RCX, RDX, R8, R9) and optional stack args 5+ into a staged entry.
3. For pre hooks, read the buffer-arg pointer (or, when `buffer_deref` is set, dereference the named arg to a struct pointer and read the buffer pointer at `struct + offset`) and copy up to `max_capture` bytes into the entry.
4. CALL the original-bytes stub. The stub lives at the end of the trampoline allocation; it is the saved prologue followed by an absolute JMP back to `target + saved_length`.
5. For post hooks, capture RAX as the `result`. If `deref_args` is set, re-read each named arg pointer and overwrite that arg's slot in the entry with the 4- or 8-byte dereferenced value (used for output parameters such as `lpNumberOfBytesRecvd`). Then copy the buffer.
6. Mark the entry `COMPLETE`. Restore registers. Return.

This uniform CALL pattern means the same shellcode generator produces both pre and post variants; only the capture order changes.

### Instruction decoder

A table-driven x64 length decoder in `src/utils/disasm.py` covers integer ALU, control flow, and the prologue subset of two-byte opcodes. It is conservative: unrecognized opcodes raise. RIP-relative operands are flagged for the relocator.

`decode_prologue_ex(data, min_bytes)` returns the minimum number of full instructions whose total length meets `min_bytes`, plus per-instruction metadata used by the relocator.

### RIP-relative relocation

When a prologue instruction reads `[RIP+disp32]`, copying it verbatim into the trampoline would point at the wrong memory because RIP has changed. The relocator rewrites the 32-bit displacement so the effective address in the trampoline still resolves to the original target.

There are two distinct failure modes. If near (+-2 GiB) allocation for the trampoline fails and the prologue contains RIP-relative instructions, the hook refuses immediately. If near allocation succeeds but a relocated displacement still cannot fit in a signed 32-bit field, `relocate_instructions` raises `RelocationOverflowError` and the install aborts before the patch is written.

### Hook install and remove

Install: validate the spec, read the prologue, prefer a near (`+-2 GiB`) trampoline allocation so a 5-byte `JMP rel32` suffices, decode the prologue, build the trampoline shellcode, write it, then patch the function entry. If near allocation fails and the prologue is RIP-relative-free, fall back to a 14-byte `JMP [RIP+0]` patch.

The 14-byte patch is not atomic. Before writing it, we suspend all target threads, read each thread's RIP, and if any thread is inside the patch zone we redirect it to the equivalent offset in the trampoline stub. Then we write the patch and resume.

Remove: restore the saved prologue bytes (with the same thread-suspension safety for 14-byte patches) and defer the trampoline free until detach. The defer is intentional: another thread may still be executing inside the trampoline at the moment of removal, and freeing the memory immediately would crash it.

### PE export resolution

`resolveExport(module, name)` is registered by the `module_scan` extension and works against the attached process's loaded modules. It parses the PE export directory directly from target memory and binary-searches the sorted name pointer table. Forwarded exports are resolved recursively with a depth cap of 5. Removes the need to AOB-scan for known Win32 entry points.

## Lua reference

The full function list with parameter details lives in [`docs/lua-reference.md`](lua-reference.md) under the **Hooking** category. A minimal capture-and-read cycle:

```lua
createRingBuffer({entry_count = 512, max_data_size = 4096})

local send = resolveExport("ws2_32.dll", "send")
hookFunction(send, {
    name = "send",
    type = "pre",
    buffer_arg = 2,   -- send(socket, *buf, len, flags)
    length_arg = 3,
    max_capture = 4096,
})

-- ... let the app run ...

for _, e in ipairs(readRingBuffer(100)) do
    print(e.hook_name, e.captured_length, e.data_hex)
end
```

For per-API patterns (WSASend/WSARecv with WSABUF deref, sendto/recvfrom UDP, IOCP correlation via GQCS, header-only mode), see `memscope_mcp/_contrib/plugins/netcap.py`. It is the canonical example of building protocol-aware capture on the generic primitive.

## Constraints

| Concern | Mitigation |
|---------|------------|
| Decoder boundary error in unusual prologues | Conservative refusal on unrecognized opcodes; tests cover common Win32 entry patterns. |
| Ring buffer race | Lock-free claim via `lock cmpxchg`; status field gates partial reads. |
| Non-atomic 14-byte JMP | Prefer 5-byte JMP; thread suspension + IP redirect when 14-byte is unavoidable. |
| Target crash from a bad hook | Test against stable system APIs first. Original bytes are saved before the patch is written. `unhookFunction` always reverses cleanly. |
| Anti-cheat / anti-tamper detection | Out of scope. The README states the tool is intended for software you own or have authorization to inspect. |
| Hook chaining on the same address | `hookFunction` refuses if the entry already contains a JMP. One hook per function. |
| Ring buffer throughput ceiling under sustained load | The lock-free design tolerates burst drops, but the upper bound under adversarial load has not been measured. |
