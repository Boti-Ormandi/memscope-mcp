"""Memory read/write, arrays, struct helpers."""

from typing import Callable

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.lua.memory_read import (
    read_bool,
    read_byte,
    read_bytes,
    read_bytes_hex,
    read_double,
    read_float,
    read_float_array,
    read_int16,
    read_int32,
    read_int32_safe,
    read_int64,
    read_int_array,
    read_pointer,
    read_pointer_array,
    read_pointer_raw,
    read_string,
    read_uint16,
    read_uint32,
    read_uint64,
    read_wide_string,
)
from ...tools.lua.memory_write import (
    write_bool,
    write_byte,
    write_bytes,
    write_double,
    write_float,
    write_int16,
    write_int32,
    write_int64,
    write_pointer,
    write_string,
    write_uint16,
    write_uint32,
    write_uint64,
)
from ...tools.lua.struct_helpers import (
    read_matrix4x4,
    read_struct,
    read_vector3,
    read_vector4,
)
from ...utils.memory_utils import is_valid_pointer


class MemoryExtension(LuaExtension):
    """Typed memory reads/writes, bulk arrays, struct helpers, memory safety."""

    name = "memory"
    description = "Memory read/write and struct helpers"

    instructions = """
### Memory Read (post-attach)

```lua
readPointer(addr)         -- 64-bit pointer, nil if invalid
readPointerRaw(addr)      -- 64-bit pointer, no validation
readByte(addr)            -- Single byte (0-255)
readSmallInteger(addr)    -- int16
readInteger(addr)         -- int32
readIntegerSafe(addr)     -- int32 or nil if garbage
readQword(addr)           -- int64
readUInt16(addr)          -- uint16
readUInt32(addr)          -- uint32
readUInt64(addr)          -- uint64
readFloat(addr)           -- float
readDouble(addr)          -- double
readBool(addr)            -- boolean (1 byte)
readString(addr, maxlen)  -- C string (null-terminated)
readWideString(addr, maxlen) -- UTF-16LE string
readBytes(addr, count)    -- Byte table
readBytesHex(addr, count) -- "48 8B 05..." hex string
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
writeByte(addr, val)         writeSmallInteger(addr, val)
writeInteger(addr, val)      writeQword(addr, val)
writeUInt16(addr, val)       writeUInt32(addr, val)
writeUInt64(addr, val)       writePointer(addr, val)
writeFloat(addr, val)        writeDouble(addr, val)
writeBool(addr, val)         writeString(addr, str, maxlen?)
writeBytes(addr, {b1, b2, ...})
```

### Struct Helpers

```lua
readVector3(addr)     -- {x, y, z} (3 floats)
readVector4(addr)     -- {x, y, z, w} (4 floats)
readQuaternion(addr)  -- alias for readVector4
readMatrix4x4(addr)   -- 4x4 matrix with position field
readStruct(addr, {    -- Read multiple fields at once
    health = "float@0x100",
    name = "cstring@0x10",
    position = "vector3@0x200"
})
```

### Memory Safety

```lua
isWritableMemory(addr)      -- Check page protection before write
backupMemory(addr, size)    -- Backup region as byte table
```
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        self._table = ctx.table_factory
        self._session = ctx.session
        engine = ctx.engine
        table = ctx.table_factory
        log_err = engine._log_error

        return {
            # Reads
            "readByte": read_byte,
            "readBytes": lambda addr, count: read_bytes(addr, count, table),
            "readBytesHex": read_bytes_hex,
            "readSmallInteger": read_int16,
            "readInteger": read_int32,
            "readIntegerSafe": read_int32_safe,
            "readQword": read_int64,
            "readPointer": read_pointer,
            "readPointerRaw": read_pointer_raw,
            "readFloat": read_float,
            "readDouble": read_double,
            "readString": lambda addr, maxlen=256: read_string(addr, maxlen, log_err),
            "readWideString": lambda addr, maxlen=256: read_wide_string(addr, maxlen, log_err),
            "readBool": lambda addr: read_bool(addr, log_err),
            # Unsigned reads
            "readUInt16": lambda addr: read_uint16(addr, log_err),
            "readUInt32": lambda addr: read_uint32(addr, log_err),
            "readUInt64": lambda addr: read_uint64(addr, log_err),
            # Bulk arrays
            "readPointerArray": lambda addr, count: read_pointer_array(addr, count, table, log_err),
            "readIntArray": lambda addr, count: read_int_array(addr, count, table, log_err),
            "readFloatArray": lambda addr, count: read_float_array(addr, count, table, log_err),
            # Writes
            "writeByte": lambda addr, val: write_byte(addr, val, log_err),
            "writeBytes": lambda addr, tbl: write_bytes(addr, tbl, log_err),
            "writeSmallInteger": lambda addr, val: write_int16(addr, val, log_err),
            "writeInteger": lambda addr, val: write_int32(addr, val, log_err),
            "writeQword": lambda addr, val: write_int64(addr, val, log_err),
            "writePointer": lambda addr, val: write_pointer(addr, val, log_err),
            "writeFloat": lambda addr, val: write_float(addr, val, log_err),
            "writeDouble": lambda addr, val: write_double(addr, val, log_err),
            "writeString": lambda addr, s, maxlen=256: write_string(addr, s, maxlen, log_err),
            "writeBool": lambda addr, val: write_bool(addr, val, log_err),
            "writeUInt16": lambda addr, val: write_uint16(addr, val, log_err),
            "writeUInt32": lambda addr, val: write_uint32(addr, val, log_err),
            "writeUInt64": lambda addr, val: write_uint64(addr, val, log_err),
            # Struct helpers
            "readVector3": lambda addr: read_vector3(addr, table),
            "readVector4": lambda addr: read_vector4(addr, table),
            "readQuaternion": lambda addr: read_vector4(addr, table),
            "readMatrix4x4": lambda addr: read_matrix4x4(addr, table),
            "readStruct": lambda addr, fields: read_struct(
                addr,
                fields,
                table,
                lambda a: read_vector3(a, table),
                lambda a: read_vector4(a, table),
                log_err,
                engine._output,
            ),
            # Safety
            "backupMemory": self._backup_memory,
            "isWritableMemory": self._is_writable_memory,
        }

    def _backup_memory(self, address, size):
        """Backup memory region. Returns Lua table of bytes or nil."""
        try:
            addr = int(address)
            sz = int(size)
            data = self._session.read_bytes(addr, sz)
            return self._table(*list(data))
        except:
            return None

    def _is_writable_memory(self, address) -> bool:
        """Check if memory address is writable."""
        try:
            addr = int(address)
            if not is_valid_pointer(addr):
                return False
            return self._session.is_memory_writable(addr)
        except:
            return False
