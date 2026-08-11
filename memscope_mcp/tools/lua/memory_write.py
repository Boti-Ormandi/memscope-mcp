"""Memory writing functions for Lua engine.

All memory access and validation use an explicitly supplied session.
"""

import struct
from typing import Callable

from ...utils.memory_utils import is_valid_pointer


def write_byte(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a single byte to memory."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        val = int(value) & 0xFF
        session.write_byte(addr, val)
        return True
    except Exception as e:
        log_error("writeByte", e)
        return False


def write_bytes(address, bytes_table, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write raw bytes from a Lua table."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        byte_list = [int(b) & 0xFF for b in bytes_table.values()]
        data = bytes(byte_list)
        session.write_bytes(addr, data)
        return True
    except Exception as e:
        log_error("writeBytes", e)
        return False


def write_int16(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a 16-bit signed integer."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        val = int(value)
        data = struct.pack("<h", val)
        session.write_bytes(addr, data)
        return True
    except Exception as e:
        log_error("writeSmallInteger", e)
        return False


def write_int32(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a 32-bit signed integer."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        session.write_int32(addr, int(value))
        return True
    except Exception as e:
        log_error("writeInteger", e)
        return False


def write_int64(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a 64-bit signed integer."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        session.write_int64(addr, int(value))
        return True
    except Exception as e:
        log_error("writeQword", e)
        return False


def write_pointer(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a 64-bit pointer (unsigned)."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        session.write_uint64(addr, int(value))
        return True
    except Exception as e:
        log_error("writePointer", e)
        return False


def write_float(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a 32-bit float."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        session.write_float(addr, float(value))
        return True
    except Exception as e:
        log_error("writeFloat", e)
        return False


def write_double(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a 64-bit double."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        session.write_double(addr, float(value))
        return True
    except Exception as e:
        log_error("writeDouble", e)
        return False


def write_string(address, string, maxlen, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a null-terminated C string."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        text = str(string)
        if len(text) >= maxlen:
            text = text[: maxlen - 1]
        data = text.encode("ascii", errors="replace") + b"\x00"
        session.write_bytes(addr, data)
        return True
    except Exception as e:
        log_error("writeString", e)
        return False


def write_bool(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write a boolean (1 byte, 0 or 1)."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        val = 1 if value else 0
        session.write_byte(addr, val)
        return True
    except Exception as e:
        log_error("writeBool", e)
        return False


def write_uint16(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write unsigned 16-bit integer."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        data = struct.pack("<H", int(value) & 0xFFFF)
        session.write_bytes(addr, data)
        return True
    except Exception as e:
        log_error("writeUInt16", e)
        return False


def write_uint32(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write unsigned 32-bit integer."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        data = struct.pack("<I", int(value) & 0xFFFFFFFF)
        session.write_bytes(addr, data)
        return True
    except Exception as e:
        log_error("writeUInt32", e)
        return False


def write_uint64(address, value, log_error: Callable[[str, Exception], None], *, session) -> bool:
    """Write unsigned 64-bit integer."""
    try:
        addr = int(address)
        if not is_valid_pointer(addr) or not session.is_memory_writable(addr):
            return False
        data = struct.pack("<Q", int(value) & 0xFFFFFFFFFFFFFFFF)
        session.write_bytes(addr, data)
        return True
    except Exception as e:
        log_error("writeUInt64", e)
        return False
