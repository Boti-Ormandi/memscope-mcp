"""Memory reading functions for Lua engine.

All functions depend on SESSION for memory access.
Includes single-value reads and bulk array reads.
"""

import struct
from typing import Any, Callable, Optional

from ...session import SESSION
from ...utils.memory_utils import is_valid_pointer
from .comparisons import to_lua_int64


def read_byte(address) -> Optional[int]:
    """Read single byte from memory."""
    try:
        addr = int(address)
        return SESSION.read_bytes(addr, 1)[0]
    except:
        return None


def read_bytes(address, count, table_factory: Callable[..., Any]):
    """Read bytes from memory. Returns Lua table (empty on failure).

    Returns a Lua table so that indexing empty results returns nil instead
    of crashing with 'list index out of range'. Safe patterns:
        local bytes = readBytes(addr, 4)
        local first = bytes[1]  -- nil if failed, no crash
        for i, b in ipairs(bytes) do ... end  -- zero iterations if failed
    """
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, int(count))
        return table_factory(*list(data))
    except:
        return table_factory()


def read_bytes_hex(address, count) -> Optional[str]:
    """Read bytes and return as hex string for easy printing.

    Example:
        print("Bytes: " .. readBytesHex(ptr, 16))
        -- Output: "Bytes: 48 8B 05 FF 00 00 00 ..."
    """
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, int(count))
        return " ".join(f"{b:02X}" for b in data)
    except:
        return None


def read_int16(address) -> Optional[int]:
    """Read signed 16-bit integer."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 2)
        return struct.unpack("<h", data)[0]
    except:
        return None


def read_int32(address) -> Optional[int]:
    """Read signed 32-bit integer."""
    try:
        addr = int(address)
        return SESSION.read_int32(addr)
    except:
        return None


def read_int32_safe(address, max_val: int = 0x7FFFFFFF) -> Optional[int]:
    """Read 32-bit integer with validation - returns nil for garbage values.

    Use this when reading values that SHOULD be small positive integers
    (counts, lengths, indices). Returns nil if:
    - Read fails
    - Value is negative
    - Value exceeds max_val

    This prevents Lua comparison overflow when the address is invalid
    and readInteger returns garbage.

    Example:
        local strLen = readIntegerSafe(ptr + 0x10)
        if strLen and strLen == 24 then  -- Safe: strLen is nil if garbage
    """
    try:
        addr = int(address)
        val = SESSION.read_int32(addr)
        if val < 0 or val > int(max_val):
            return None
        return val
    except:
        return None


def read_int64(address) -> Optional[int]:
    """Read signed 64-bit integer."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 8)
        return struct.unpack("<q", data)[0]
    except:
        return None


def read_uint16(address, log_error: Callable[[str, Exception], None]) -> Optional[int]:
    """Read unsigned 16-bit integer."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 2)
        return struct.unpack("<H", data)[0]
    except Exception as e:
        log_error("readUInt16", e)
        return None


def read_uint32(address, log_error: Callable[[str, Exception], None]) -> Optional[int]:
    """Read unsigned 32-bit integer."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 4)
        return struct.unpack("<I", data)[0]
    except Exception as e:
        log_error("readUInt32", e)
        return None


def read_uint64(address, log_error: Callable[[str, Exception], None]) -> Optional[int]:
    """Read unsigned 64-bit integer (returned as signed for Lua compatibility)."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 8)
        return to_lua_int64(struct.unpack("<Q", data)[0])
    except Exception as e:
        log_error("readUInt64", e)
        return None


def read_pointer(address, validate: bool = True) -> Optional[int]:
    """Read a 64-bit pointer from memory.

    By default, validates the result and returns nil if it doesn't look
    like a valid user-mode pointer. This prevents garbage reads from
    causing Lua comparison overflows.

    Args:
        address: Memory address to read from
        validate: If True (default), return nil for invalid pointer values

    Returns:
        Pointer value or nil if invalid/error
    """
    try:
        addr = int(address)
        ptr = SESSION.read_ptr(addr)
        if validate and not is_valid_pointer(ptr):
            return None
        return ptr
    except:
        return None


def read_pointer_raw(address) -> Optional[int]:
    """Read a 64-bit pointer without validation.

    Returns raw value as signed int64 for Lua compatibility.
    Use readPointer() for validated pointer reads.
    """
    try:
        addr = int(address)
        return to_lua_int64(SESSION.read_ptr(addr))
    except:
        return None


def read_float(address) -> Optional[float]:
    """Read 32-bit float."""
    try:
        addr = int(address)
        return SESSION.read_float(addr)
    except:
        return None


def read_double(address) -> Optional[float]:
    """Read 64-bit double."""
    try:
        addr = int(address)
        return SESSION.read_double(addr)
    except:
        return None


def read_string(address, maxlen, log_error: Callable[[str, Exception], None]) -> Optional[str]:
    """Read null-terminated C string."""
    try:
        addr = int(address)
        return SESSION.read_string(addr, int(maxlen))
    except Exception as e:
        log_error("readString", e)
        return None


def read_bool(address, log_error: Callable[[str, Exception], None]) -> Optional[bool]:
    """Read a boolean (1 byte, 0=false, non-zero=true)."""
    try:
        addr = int(address)
        val = SESSION.read_bytes(addr, 1)[0]
        return val != 0
    except Exception as e:
        log_error("readBool", e)
        return None


def read_wide_string(address, maxlen, log_error: Callable[[str, Exception], None]) -> Optional[str]:
    """Read null-terminated UTF-16LE (wide) string."""
    try:
        addr = int(address)
        max_chars = int(maxlen)
        # Read up to maxlen * 2 bytes (UTF-16 = 2 bytes per char)
        data = SESSION.read_bytes(addr, max_chars * 2)
        # Decode as UTF-16LE, stop at null terminator
        result = []
        for i in range(0, len(data) - 1, 2):
            char_code = data[i] | (data[i + 1] << 8)
            if char_code == 0:
                break
            result.append(chr(char_code))
        return "".join(result)
    except Exception as e:
        log_error("readWideString", e)
        return None


# ========== Bulk Array Reads ==========


def read_pointer_array(address, count, table_factory: Callable, log_error: Callable):
    """Read an array of consecutive 64-bit pointers.

    Reads count * 8 bytes in a single call, then unpacks into pointers.
    Each pointer is validated -- invalid pointers become nil in the table.

    Args:
        address: Start address of the pointer array.
        count: Number of pointers to read.
        table_factory: Lua table constructor.
        log_error: Error callback.

    Returns:
        Lua table of pointer values (1-indexed). Invalid pointers are nil.
        Returns empty table on read failure. Example::

            -- Read a vtable (array of function pointers)
            local vtable = readPointerArray(vtableAddr, 20)
            for i, fn in ipairs(vtable) do
                print(i .. ": " .. formatAddress(fn))
            end

            -- Read object array (pointers to objects)
            local objects = readPointerArray(arrayBase, objCount)
    """
    try:
        addr = int(address)
        n = int(count)
        data = SESSION.read_bytes(addr, n * 8)
        t = table_factory()
        for i in range(n):
            ptr = struct.unpack_from("<Q", data, i * 8)[0]
            if is_valid_pointer(ptr):
                t[i + 1] = ptr
            else:
                t[i + 1] = None
        return t
    except Exception as e:
        log_error("readPointerArray", e)
        return table_factory()


def read_int_array(address, count, table_factory: Callable, log_error: Callable):
    """Read an array of consecutive 32-bit signed integers.

    Reads count * 4 bytes in a single call, then unpacks.

    Args:
        address: Start address of the int array.
        count: Number of int32 values to read.
        table_factory: Lua table constructor.
        log_error: Error callback.

    Returns:
        Lua table of int32 values (1-indexed).
        Returns empty table on read failure. Example::

            -- Read an array of IDs
            local ids = readIntArray(idArrayBase, 10)
            for i, id in ipairs(ids) do print(id) end
    """
    try:
        addr = int(address)
        n = int(count)
        data = SESSION.read_bytes(addr, n * 4)
        values = struct.unpack_from(f"<{n}i", data)
        return table_factory(*values)
    except Exception as e:
        log_error("readIntArray", e)
        return table_factory()


def read_float_array(address, count, table_factory: Callable, log_error: Callable):
    """Read an array of consecutive 32-bit floats.

    Reads count * 4 bytes in a single call, then unpacks.

    Args:
        address: Start address of the float array.
        count: Number of float values to read.
        table_factory: Lua table constructor.
        log_error: Error callback.

    Returns:
        Lua table of float values (1-indexed).
        Returns empty table on read failure. Example::

            -- Read position data (x, y, z as separate floats)
            local coords = readFloatArray(posAddr, 3)
            print("x=" .. coords[1] .. " y=" .. coords[2] .. " z=" .. coords[3])

            -- Read a float buffer
            local weights = readFloatArray(bufferAddr, 64)
    """
    try:
        addr = int(address)
        n = int(count)
        data = SESSION.read_bytes(addr, n * 4)
        values = struct.unpack_from(f"<{n}f", data)
        return table_factory(*values)
    except Exception as e:
        log_error("readFloatArray", e)
        return table_factory()
