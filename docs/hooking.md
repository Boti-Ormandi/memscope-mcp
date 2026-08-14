# Inline function hooking

The core hooking extension observes user-mode x64 functions with inline trampolines and one shared ring buffer in target memory. It uses no DLL injection and no kernel component. Every hook changes target code and requires an attached authorized process.

## Lua surface

```lua
createRingBuffer({entry_count = 512, max_data_size = 4096}?)
hookFunction(address, {
    name = "label",
    type = "pre" or "post",
    buffer_arg = 1..4 or -1,
    length_arg = 0..4 or -1,
    max_capture = 4096,
    stack_args = {5, 6},
    deref_args = {[N] = 4 or 8},
    buffer_deref = {arg = N, offset = K},
    length_deref = {arg = N, offset = K, size = 4 or 8}
})
readRingBuffer(limit?, {min_result = N}?)
ringBufferMarker("label")
ringBufferStats()
listHooks()
unhookFunction(address_or_hook_id)
destroyRingBuffer()
```

`pre` captures before the original function. `post` captures after the original returns and can record the return value or dereference output pointers. Register arguments 1–4 map to RCX/RDX/R8/R9; `stack_args` captures up to seven stack arguments.

## Ring buffer

A ring buffer allocates lazily in the target process and is shared by all installed hooks. The writer claims slots with an atomic compare-and-swap. Overflow drops entries rather than blocking the target. The reader stops at an in-flight slot to preserve event order. `ringBufferMarker` inserts a synthetic timestamp-zero marker.

Each entry contains sequence, status, hook ID, timestamp, return address, four register arguments, signed result, data lengths, flags, and optional captured bytes. `readRingBuffer` returns `data` as a byte table and includes display previews such as `data_hex`. `ringBufferStats` reports captured/dropped totals, pending entries, utilization, and active hooks.

## Trampoline and relocation

Install follows this sequence:

1. validate the hook specification;
2. read and decode a complete target prologue;
3. allocate an executable trampoline near the target when possible;
4. relocate RIP-relative instructions when required;
5. write the trampoline and original-byte stub; and
6. patch the target function entry.

A near trampoline uses a 5-byte relative jump. If near allocation fails and the prologue has no RIP-relative instruction, the manager can use a 14-byte absolute jump. The 14-byte entry patch suspends target threads and redirects an instruction pointer inside the patch zone. A relocation overflow or unsupported prologue aborts before the patch is written.

The trampoline saves volatile registers, captures arguments/buffers, calls the original bytes, captures post-call data when requested, marks the ring slot complete, restores registers, and returns. Removal restores saved bytes and defers trampoline freeing until detach so an in-flight thread does not run freed code.

## Indirect capture

For a `WSABUF`-style API, the buffer lives in a struct:

```lua
hookFunction(resolveExport("ws2_32.dll", "WSASend"), {
    name = "WSASend",
    type = "pre",
    buffer_deref = {arg = 2, offset = 8},
    length_deref = {arg = 2, offset = 0, size = 4},
    max_capture = 8192
})
```

`deref_args` is for post-call output pointers. The netcap plugin supplies the Winsock, UDP, lifecycle, and IOCP patterns built on this primitive.

## Constraints and risk

The decoder refuses opcodes it cannot safely classify. One hook per function entry is supported. Hooking can be visible to target integrity checks, can change timing, and can crash a target when a specification or address is wrong. Test against a stable authorized target, keep capture bounded, remove hooks before detach, and treat all captured buffers as sensitive. See [Capture calls](guides/capture-calls.md), [Netcap](plugins/netcap.md), and [Security model](concepts/security-model.md).
