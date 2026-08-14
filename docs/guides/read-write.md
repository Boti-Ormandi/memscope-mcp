# Read and write memory

Read first, resolve addresses explicitly, and choose write verification when a pre-image and readback reduce risk. Memory operations require an attached target.

## Read typed data

The MCP `read` tool accepts an address expression, a type name, and an optional count:

```text
read(address="Target.exe+0x1000", type_name="uint32")
read(address="Target.exe+0x2000", type_name="bytes", count=16)
read(address="Target.exe+0x3000", type_name="vector3")
```

Addresses accept hexadecimal, decimal, and `module.dll+0xoffset` forms. Supported primitive aliases include integer widths, floats, doubles, booleans, and pointers. Special reads include `cstring`, `bytes`, and `bytes[N]`; composites include vectors, quaternion, colors, rect, bounds, and `matrix4x4`.

Lua reads use numeric addresses; resolve module expressions first:

```lua
local base = getModuleBase("Target.exe")
local health = readInteger(base + 0x120)
local position = readVector3(base + 0x200)
addResult("health", health)
addResult("position", position)
```

For unknown structures, `dump` gives an annotated 4096-byte window. For pointer paths, `chain` follows standard add-then-dereference semantics:

```text
chain(base="Target.exe+0x1000", offsets=["0x148", "0x10"], read_final="float")
```

## Write with an explicit safety choice

The MCP `write` tool writes typed data or bytes:

```text
write(
  address="Target.exe+0x2000",
  type_name="int32",
  value=100,
  verify=true
)
```

`verify=true`:

1. validates the whole target range as writable;
2. captures the exact pre-write bytes;
3. performs the write;
4. reads the range back and compares bytes; and
5. attempts to restore the pre-image after a post-write readback failure.

This is verification and rollback attempt, not a transaction against a concurrently changing target. A direct write with `verify=false` has no pre-image/readback guarantee.

Byte values accept compact hex, whitespace-separated two-digit hex, or a JSON array of integers 0–255. `bytes[N]` requires exactly `N` bytes. Composite writes accept the shape documented in the [MCP tool reference](../reference/mcp-tools.md).

Lua writes expose `writeByte`, `writeInteger`, `writePointer`, `writeBytes`, typed unsigned forms, floating-point forms, strings, and composites. Use `isWritableMemory(addr)` and `backupMemory(addr, size)` when a script needs an explicit preflight and backup.

## Safety checklist

- Confirm the target name and exact PID before a write.
- Resolve the address from a current module snapshot rather than reusing a stale absolute address.
- Read the target value and surrounding bytes before changing them.
- Use `verify=true` for bounded typed writes where the extra readback is appropriate.
- Keep a copy of important bytes outside the target and record the intended restoration operation.
- Stop hooks, captures, and native work before detach.
- Treat pointers, native calls, and target-provided strings as untrusted data.

See [Errors and status](../reference/errors-status.md), [Lua reference](../lua-reference.md), and the [security model](../concepts/security-model.md).
