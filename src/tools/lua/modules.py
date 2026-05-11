"""Module enumeration and address resolution for Lua engine.

Exposes the session's module cache to Lua scripts so they can
enumerate, filter, and reverse-lookup modules without relying
on the MCP modules tool.
"""

from typing import Callable, Optional

from ...session import SESSION
from ...utils.memory_utils import is_valid_pointer


def get_modules(lua_table_fn: Callable, filter_str: Optional[str] = None):
    """List loaded modules with optional substring filter.

    Args:
        lua_table_fn: Lua table constructor (injected by engine).
        filter_str: Case-insensitive substring match on module name.
            nil returns all modules.

    Returns:
        Lua table of {name, base, size, path}. Example::

            local mods = getModules("Unity")
            for i, m in ipairs(mods) do
                print(m.name, toHex(m.base), m.size)
            end
    """
    t = lua_table_fn()
    idx = 1
    for name, info in SESSION.modules.items():
        if filter_str and filter_str.lower() not in name.lower():
            continue
        entry = lua_table_fn()
        entry["name"] = name
        entry["base"] = info["base"]
        entry["size"] = info["size"]
        entry["path"] = info.get("path", "")
        t[idx] = entry
        idx += 1
    return t


def get_module_from_address(lua_table_fn: Callable, address, log_error: Callable):
    """Find which module contains a given address.

    Args:
        lua_table_fn: Lua table constructor.
        address: Memory address (int or large-int from addr()).
        log_error: Error callback.

    Returns:
        Lua table {name, base, offset} or nil if address is not
        inside any loaded module. Example::

            local info = getModuleFromAddress(ptr)
            if info then
                print(info.name .. "+0x" .. toHex(info.offset))
            end
    """
    try:
        addr = int(address)
        if not is_valid_pointer(addr):
            return None

        for name, info in SESSION.modules.items():
            base = info["base"]
            size = info["size"]
            if base <= addr < base + size:
                result = lua_table_fn()
                result["name"] = name
                result["base"] = base
                result["offset"] = addr - base
                return result
        return None
    except Exception as e:
        log_error("getModuleFromAddress", e)
        return None


def format_address(address, log_error: Callable) -> str:
    """Format an address as module+offset if possible, raw hex otherwise.

    Args:
        address: Memory address (int or large-int from addr()).
        log_error: Error callback.

    Returns:
        String like ``"UnityPlayer.dll+0x1A23748"`` when the address
        falls inside a known module, or ``"0x7FFC8E9F3748"`` otherwise.
        Returns ``"nil"`` for nil input. Example::

            print("entry: " .. formatAddress(vtable_ptr))
            -- "entry: UnityPlayer.dll+0x1A23748"
    """
    if address is None:
        return "nil"
    try:
        addr = int(address)
        for name, info in SESSION.modules.items():
            base = info["base"]
            size = info["size"]
            if base <= addr < base + size:
                return f"{name}+0x{addr - base:X}"
        return f"0x{addr:X}"
    except Exception as e:
        log_error("formatAddress", e)
        return "0x0"
