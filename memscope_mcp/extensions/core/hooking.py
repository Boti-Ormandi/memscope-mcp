"""Generic inline function hooking and ring buffer capture."""

from typing import Callable

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.hooking import HOOK_MANAGER
from ...tools.lua.hooking import build_hooking_functions


class HookingExtension(LuaExtension):
    """Hook any function by address, capture args + buffer to a ring buffer."""

    name = "hooking"
    description = "Generic inline function hooking and ring buffer capture"

    instructions = """
## Function Hooking

Hook any function by address. Capture register args + optional stack args
+ optional buffer data to a shared ring buffer.

### Setup

```lua
createRingBuffer({entry_count = 512, max_data_size = 4096})
```

For large payloads (TLS records, video packets), use a bigger data size:
```lua
createRingBuffer({entry_count = 256, max_data_size = 16384})
```

### Hook a Function

```lua
hookFunction(address, {
    name = "send",          -- label for identification
    type = "pre",           -- "pre" (capture before call) or "post" (capture after)
    buffer_arg = 2,         -- which arg (1-4) is buffer pointer, -1 = no buffer
    length_arg = 3,         -- which arg (1-4) is length, 0 = use return value, -1 = fixed
    max_capture = 4096,     -- max bytes per entry (capped by ring buffer max_data_size)
    stack_args = {5, 6},    -- optional: capture 5th+ args from stack (max 7)
    deref_args = {[2] = 4, [4] = 8},  -- optional: post-call output pointer dereference
                                        -- {arg_index = read_size (4 or 8)}
                                        -- replaces arg value in entry with *arg
                                        -- only valid with type = "post"
})
```

### Indirect Buffer Capture (struct dereference)

For APIs where the buffer pointer is inside a struct (e.g. WSABUF), use `buffer_deref`
and/or `length_deref` instead of `buffer_arg`/`length_arg`:

```lua
-- WSASend: arg2 (RDX) = LPWSABUF -> {len@0, buf@8}
hookFunction(WSASend_addr, {
    name = "WSASend",
    type = "pre",
    buffer_deref = { arg = 2, offset = 8 },   -- [arg2 + 8] = buffer ptr
    length_deref = { arg = 2, offset = 0, size = 4 },  -- [arg2 + 0] = length
    max_capture = 8192
})

-- WSARecv: buffer in WSABUF, length in *lpNumberOfBytesRecvd (arg4)
hookFunction(WSARecv_addr, {
    name = "WSARecv",
    type = "post",
    buffer_deref = { arg = 2, offset = 8 },
    length_deref = { arg = 4, offset = 0, size = 4 },
    max_capture = 8192
})
```

- `buffer_deref = {arg=N, offset=N}`: dereferences arg N to get struct ptr, reads buffer pointer at struct+offset
- `length_deref = {arg=N, offset=N, size=4|8}`: dereferences arg N, reads length at ptr+offset (default size=4)
- Mutually exclusive with `buffer_arg`/`length_arg` respectively

### Read Captured Data

```lua
local entries = readRingBuffer(100)  -- read up to 100 entries
-- Each entry: {sequence, hook_id, hook_name, timestamp, return_addr,
--              arg0, arg1, arg2, arg3, extra_args?, result,
--              data_length, captured_length, data, data_hex, is_marker}
-- data: byte table (for processing)
-- data_hex: hex string "17 03 03 ..." (for display)

-- Filter out failed calls (e.g. recv returning -1):
local entries = readRingBuffer(100, {min_result = 0})

ringBufferMarker("event label")      -- inject timeline marker
ringBufferStats()                    -- {total_captured, total_dropped, entries_pending, utilization_pct}
```

### Manage Hooks

```lua
listHooks()                          -- all active hooks
unhookFunction(address_or_hook_id)   -- remove hook, restore original bytes
destroyRingBuffer()                  -- free ring buffer (all hooks must be removed first)
```

### Pre-call vs Post-call

- **pre**: captures buffer BEFORE the function executes. Use for `send`.
- **post**: captures buffer AFTER the function returns. Use for `recv`.
  Set `length_arg = 0` to use the return value as data length.
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        return build_hooking_functions(ctx.table_factory, ctx.log_error, ctx.engine._output)

    def on_process_detaching(self, session, process_alive: bool) -> None:
        HOOK_MANAGER.cleanup(process_alive=process_alive)
