"""High-level scanning helpers for Lua engine.

Wraps AOB scanning with convenient interfaces for common patterns:
string scanning and pointer/reference scanning.
"""

import struct
import time
from typing import Callable, Optional

from ...session import SESSION
from ...utils.memory_utils import is_valid_pointer
from ...utils.pattern import match_pattern, parse_aob_pattern

# Limits
SCAN_TIMEOUT_SECONDS = 30


def scan_string(
    lua_table_fn: Callable,
    search: str,
    module: Optional[str] = None,
    wide: bool = False,
    max_results: int = 100,
    log_error: Callable = None,
):
    """Scan memory for a string literal.

    Converts the string to a byte pattern and runs an AOB scan.
    Supports both ASCII (C strings) and UTF-16LE (wide strings).

    Args:
        lua_table_fn: Lua table constructor.
        search: The string to find (e.g. "PlayerHealth").
        module: Limit scan to this module (faster). nil scans all.
        wide: If true, search for UTF-16LE encoding (Windows wide strings).
        max_results: Stop after this many matches.
        log_error: Error callback.

    Returns:
        Lua table of addresses where the string was found. Example::

            -- Find ASCII string in a specific module
            local hits = scanString("Health", "GameAssembly.dll")

            -- Find wide string (UTF-16) anywhere
            local hits = scanString("PlayerName", nil, true)

            for i, addr in ipairs(hits) do
                print(toHex(addr) .. ": " .. readString(addr, 64))
            end
    """
    try:
        if not search:
            return lua_table_fn()

        # Convert string to bytes
        if wide:
            raw = search.encode("utf-16-le")
        else:
            raw = search.encode("ascii")

        # Build AOB pattern string ("48 65 61 6C 74 68")
        pattern_str = " ".join(f"{b:02X}" for b in raw)
        parsed = parse_aob_pattern(pattern_str)

        results = []
        start_time = time.time()

        if module:
            mod_info = SESSION.modules.get(module)
            if not mod_info:
                return lua_table_fn()
            results = _scan_region(mod_info["base"], mod_info["size"], parsed, max_results, start_time)
        else:
            for mod_name, mod_info in SESSION.modules.items():
                if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
                    break
                if len(results) >= max_results:
                    break
                hits = _scan_region(mod_info["base"], mod_info["size"], parsed, max_results - len(results), start_time)
                results.extend(hits)

        return lua_table_fn(*results)

    except Exception as e:
        if log_error:
            log_error("scanString", e)
        return lua_table_fn()


def scan_pointer(
    lua_table_fn: Callable,
    target_address,
    module: Optional[str] = None,
    alignment: int = 8,
    max_results: int = 100,
    log_error: Callable = None,
):
    """Find all pointers that reference a target address (cross-references).

    Scans module memory for the 8-byte little-endian representation of
    the target address at aligned boundaries.

    Args:
        lua_table_fn: Lua table constructor.
        target_address: The address to find references to.
        module: Limit scan to this module. nil scans all.
        alignment: Only check aligned addresses (default 8, pointer-aligned).
        max_results: Stop after this many matches.
        log_error: Error callback.

    Returns:
        Lua table of addresses where the pointer was found. Example::

            -- Find what points to this object
            local refs = scanPointer(objectAddr)

            -- Find references within a specific module
            local refs = scanPointer(vtableAddr, "GameAssembly.dll")

            for i, ref in ipairs(refs) do
                print("xref: " .. formatAddress(ref))
            end
    """
    try:
        addr = int(target_address)
        if not is_valid_pointer(addr):
            return lua_table_fn()

        target_bytes = struct.pack("<Q", addr)
        results = []
        start_time = time.time()

        if module:
            mod_info = SESSION.modules.get(module)
            if not mod_info:
                return lua_table_fn()
            results = _scan_for_pointer_value(
                mod_info["base"], mod_info["size"], target_bytes, alignment, max_results, start_time
            )
        else:
            for mod_name, mod_info in SESSION.modules.items():
                if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
                    break
                if len(results) >= max_results:
                    break
                hits = _scan_for_pointer_value(
                    mod_info["base"], mod_info["size"], target_bytes, alignment, max_results - len(results), start_time
                )
                results.extend(hits)

        return lua_table_fn(*results)

    except Exception as e:
        if log_error:
            log_error("scanPointer", e)
        return lua_table_fn()


def _scan_region(base: int, size: int, parsed, max_results: int, start_time: float) -> list[int]:
    """Scan a memory region for an AOB pattern."""
    results = []
    chunk_size = 0x100000  # 1MB
    overlap = parsed.length - 1

    for chunk_start in range(0, size, chunk_size - overlap):
        if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
            break
        if len(results) >= max_results:
            break

        chunk_end = min(chunk_start + chunk_size, size)
        try:
            data = SESSION.read_bytes(base + chunk_start, chunk_end - chunk_start)
        except Exception:
            continue

        matches = match_pattern(data, parsed, start=base + chunk_start)
        results.extend(matches[: max_results - len(results)])

    return results


def _scan_for_pointer_value(
    base: int, size: int, target_bytes: bytes, alignment: int, max_results: int, start_time: float
) -> list[int]:
    """Scan a memory region for a specific pointer value."""
    results = []
    chunk_size = 0x100000  # 1MB

    for chunk_start in range(0, size, chunk_size):
        if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
            break
        if len(results) >= max_results:
            break

        chunk_end = min(chunk_start + chunk_size, size)
        try:
            data = SESSION.read_bytes(base + chunk_start, chunk_end - chunk_start)
        except Exception:
            continue

        for i in range(0, len(data) - 7, alignment):
            if data[i : i + 8] == target_bytes:
                results.append(base + chunk_start + i)
                if len(results) >= max_results:
                    break

    return results
