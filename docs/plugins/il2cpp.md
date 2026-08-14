# IL2CPP plugin

The opt-in `il2cpp` plugin provides Lua readers for common Unity IL2CPP runtime structures. It uses the session supplied during registration and adds no MCP tool.

Activate it explicitly:

```powershell
memscope-mcp install-plugin il2cpp
```

Restart the server and check `listLuaFunctions("il2cpp")` before use. Review the activated Python file because plugins run in the server process.

## Lua functions

```lua
readUnityString(address)
readIL2CppString(address)
readListCount(address)
readListElement(address, index)
readIL2CppList(address, limit?)
readIL2CppArray(address, element_type?, limit?)
readDictCount(address)
readIL2CppDict(address, key_type?, value_type?, limit?)
```

The string reader uses `length` at `object + 0x10` and UTF-16 characters at `object + 0x14`, with a bounded length. Lists use `_items` at `+0x10` and `_size` at `+0x18`; list data starts at the array's `+0x20`. Arrays use length at `+0x18` and data at `+0x20`. Dictionaries use entries at `+0x18`, count at `+0x20`, and bounded entries from the entries array.

Array element types include `ptr`/`pointer`, `int32`, `float`, and `byte`; unknown types use pointer reads. Dictionary keys and values support the types implemented by the plugin, including `int32`, `float`, `string`, and pointer values.

## Thread-local native calls

IL2CPP runtime calls can require thread attachment. The attachment is thread-local, so keep attachment and dependent calls in one `callSequence`, not separate `executeCode` calls:

```lua
local attach_func = getAddress("GameAssembly.dll+0x<thread_attach_offset>")
local domain = readPointer(getAddress("GameAssembly.dll+0x<domain_offset>"))

local result = callSequence({
    {address = attach_func, args = {domain}},
    {address = api_func, args = {}}
})
```

Use `callSequenceResults` when cleanup ends the sequence but an earlier return value is still needed. Resolve build-specific functions and offsets through exports or scans; do not treat the example offsets as universal.

## Safety

IL2CPP readers interpret target memory layouts. Validate pointers, lengths, element types, and limits before reading. A malformed target object can make a read fail or return `nil`. Native calls can execute arbitrary target code and change target state; read [Code execution and native calls](../lua-reference.md#code-execution) and [Security model](../concepts/security-model.md) first.

See the [source plugin](../../memscope_mcp/_contrib/plugins/il2cpp.py), [Plugin API](../reference/plugin-api.md), and [Plugin lifecycle](lifecycle.md).
