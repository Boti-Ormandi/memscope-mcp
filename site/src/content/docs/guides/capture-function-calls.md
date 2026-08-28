---
title: "Capture function calls"
description: "Use inline hooks and bounded target-side ring buffers."
---

The core hooking extension observes user-mode function calls through inline trampolines and a shared target-side ring buffer. It does not inject a DLL or provide kernel interception. A hook changes target code and can expose sensitive buffers.

## Minimal read cycle

```lua
createRingBuffer({entry_count = 512, max_data_size = 4096})

local send = resolveExport("ws2_32.dll", "send")
hookFunction(send, {
    name = "send",
    type = "pre",
    buffer_arg = 2,
    length_arg = 3,
    max_capture = 4096
})

-- Let the target run, then inspect bounded entries.
for _, entry in ipairs(readRingBuffer(100)) do
    print(entry.hook_name, entry.captured_length, entry.data_hex)
end
```

`pre` captures before the original call. `post` captures after the call and can use the return value or output-pointer dereferences. Register arguments 1–4 map to RCX/RDX/R8/R9; optional stack arguments 5–11 are captured with `stack_args`.

## Hook specification

```lua
hookFunction(address, {
    name = "label",
    type = "pre",                  -- "pre" or "post"
    buffer_arg = 2,                 -- register argument 1..4, or -1
    length_arg = 3,                 -- argument 0..4, or -1
    max_capture = 4096,
    stack_args = {5, 6},
    deref_args = {[4] = 4},         -- post-call output-pointer read
    buffer_deref = {arg = 2, offset = 8},
    length_deref = {arg = 2, offset = 0, size = 4}
})
```

A 14-byte patch can suspend target threads and redirect an instruction pointer while the patch is in flight. Trampolines remain allocated until detach so an in-flight thread does not execute freed memory. Conservative instruction decoding refuses unsupported prologues or unsafe RIP-relative relocation.

## Read and manage entries

```lua
local entries = readRingBuffer(100, {min_result = 0})
ringBufferMarker("before-request")
local stats = ringBufferStats()
listHooks()
unhookFunction("send")
destroyRingBuffer()
```

Entries include sequence, hook ID/name, timestamp, return address, register arguments, optional stack arguments, result, data lengths, byte data, and marker state. `ringBufferStats()` reports captured/dropped totals, pending entries, utilization, and active hooks. Remove all hooks before destroying the ring buffer.

## Target effects and captured data

Hook installation writes target function entries and allocates executable trampoline memory. Native calls create remote threads and can change target state. Captured buffers can contain credentials, tokens, plaintext network data, or personal data; session logs and Netcap recordings persist local summaries and payloads.

Stop hooks and capture before detach. A process exit can make target cleanup unavailable, so the extension clears local state and defers only what the target permits. See [Inline hooking](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/hooking.md), [Read and write memory](/guides/read-and-write-memory/), [Netcap](/plugins/netcap/), and [Security model](/concepts/security-model/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/guides/capture-calls.md)
