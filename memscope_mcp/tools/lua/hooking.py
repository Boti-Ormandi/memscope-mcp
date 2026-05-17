"""Lua function wrappers for the hooking API.

Bridges between Lua-callable signatures and HookManager methods.
"""

from typing import Any, Callable

from ...tools.hooking import HOOK_MANAGER
from ...utils.memory_utils import parse_address


def build_hooking_functions(table_factory: Callable, log_error: Callable, output: list[str]) -> dict[str, Callable]:
    """Build Lua-callable hooking functions.

    Args:
        table_factory: Callable that creates Lua tables (engine.lua.table).
        log_error: Error logging function (engine._log_error).
        output: Output list for print statements (engine._output).

    Returns:
        Dict mapping Lua function names to Python callables.
    """

    def _to_lua(value: Any) -> Any:
        """Recursively convert Python dicts/lists to Lua tables."""
        if isinstance(value, dict):
            converted = {k: _to_lua(v) for k, v in value.items()}
            return table_factory(**converted)
        if isinstance(value, (list, tuple)):
            converted = [_to_lua(v) for v in value]
            return table_factory(*converted)
        if isinstance(value, bytes):
            return table_factory(*list(value))
        return value

    def _lua_table_to_int_list(tbl: Any) -> list[int]:
        """Convert a Lua table to a Python list of ints."""
        result = []
        i = 1
        while True:
            val = tbl[i]
            if val is None:
                break
            result.append(int(val))
            i += 1
        return result

    def create_ring_buffer(opts=None):
        """Lua: createRingBuffer({entry_count=512, max_data_size=4096})"""
        try:
            entry_count = 512
            max_data_size = 4096
            if opts is not None:
                ec = opts["entry_count"]
                if ec is not None:
                    entry_count = int(ec)
                mds = opts["max_data_size"]
                if mds is not None:
                    max_data_size = int(mds)
            result = HOOK_MANAGER.create_ring_buffer(entry_count, max_data_size)
            return _to_lua(result)
        except Exception as e:
            log_error("createRingBuffer", e)
            return None

    def hook_function(address, opts=None):
        """Lua: hookFunction(address, {name, type, buffer_arg, length_arg, max_capture, stack_args})"""
        try:
            addr = parse_address(address)
            name = "hook"
            hook_type = "pre"
            buffer_arg = -1
            length_arg = -1
            max_capture = 4096
            stack_args = None
            deref_args = None
            buffer_deref = None
            length_deref = None

            if opts is not None:
                n = opts["name"]
                if n is not None:
                    name = str(n)
                t = opts["type"]
                if t is not None:
                    hook_type = str(t)
                ba = opts["buffer_arg"]
                if ba is not None:
                    buffer_arg = int(ba)
                la = opts["length_arg"]
                if la is not None:
                    length_arg = int(la)
                mc = opts["max_capture"]
                if mc is not None:
                    max_capture = int(mc)
                sa = opts["stack_args"]
                if sa is not None:
                    stack_args = _lua_table_to_int_list(sa)
                da = opts["deref_args"]
                if da is not None:
                    deref_args = {}
                    for k, v in da.items():
                        deref_args[int(k)] = int(v)
                bd = opts["buffer_deref"]
                if bd is not None:
                    buffer_deref = {"arg": int(bd["arg"]), "offset": int(bd["offset"])}
                ld = opts["length_deref"]
                if ld is not None:
                    length_deref = {"arg": int(ld["arg"]), "offset": int(ld["offset"])}
                    ld_size = ld["size"]
                    if ld_size is not None:
                        length_deref["size"] = int(ld_size)

            result = HOOK_MANAGER.install_hook(
                addr,
                name,
                hook_type,
                buffer_arg,
                length_arg,
                max_capture,
                stack_args,
                deref_args,
                buffer_deref=buffer_deref,
                length_deref=length_deref,
            )
            return _to_lua(result)
        except Exception as e:
            log_error("hookFunction", e)
            return None

    def unhook_function(addr_or_id):
        """Lua: unhookFunction(address_or_hook_id)"""
        try:
            val = parse_address(addr_or_id)
            return HOOK_MANAGER.remove_hook(val)
        except Exception as e:
            log_error("unhookFunction", e)
            return False

    def list_hooks():
        """Lua: listHooks()"""
        try:
            hooks = HOOK_MANAGER.list_hooks()
            return _to_lua(hooks)
        except Exception as e:
            log_error("listHooks", e)
            return None

    def read_ring_buffer(limit=None, opts=None):
        """Lua: readRingBuffer(limit?, {min_result=N}?)"""
        try:
            lim = int(limit) if limit is not None else 100
            min_result = None
            if opts is not None:
                mr = opts["min_result"]
                if mr is not None:
                    min_result = int(mr)
            entries = HOOK_MANAGER.read_ring_buffer(lim, min_result=min_result)
            return _to_lua(entries)
        except Exception as e:
            log_error("readRingBuffer", e)
            return None

    def ring_buffer_stats():
        """Lua: ringBufferStats()"""
        try:
            stats = HOOK_MANAGER.ring_buffer_stats()
            return _to_lua(stats)
        except Exception as e:
            log_error("ringBufferStats", e)
            return None

    def ring_buffer_marker(label):
        """Lua: ringBufferMarker(label)"""
        try:
            return HOOK_MANAGER.ring_buffer_marker(str(label))
        except Exception as e:
            log_error("ringBufferMarker", e)
            return False

    def destroy_ring_buffer():
        """Lua: destroyRingBuffer()"""
        try:
            HOOK_MANAGER.destroy_ring_buffer()
            return True
        except Exception as e:
            log_error("destroyRingBuffer", e)
            return False

    return {
        "createRingBuffer": create_ring_buffer,
        "hookFunction": hook_function,
        "unhookFunction": unhook_function,
        "listHooks": list_hooks,
        "readRingBuffer": read_ring_buffer,
        "ringBufferStats": ring_buffer_stats,
        "ringBufferMarker": ring_buffer_marker,
        "destroyRingBuffer": destroy_ring_buffer,
    }
