"""Lua scripting engine for memory operations.

Core engine class that imports helpers from submodules.
"""

import re
from typing import Any, Optional

from lupa import LuaError, LuaRuntime

from ...session import SESSION
from ...utils.memory_utils import is_valid_pointer, parse_address
from ..scanning import SCAN_TIMEOUT_SECONDS, scan_aob_addresses
from .code_execution import (
    LuaExecutionGuard,
    alloc_lua,
    call_sequence_lua,
    call_sequence_results_lua,
    execute_code_ex_lua,
    execute_code_lua,
    free_memory_lua,
)
from .comparisons import parse_hex_address, safe_eq, safe_ge, safe_gt, safe_int, safe_le, safe_lt, safe_ne, to_uint64
from .memory_read import (
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
from .memory_write import (
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
from .modules import format_address as lua_format_address
from .modules import get_module_from_address, get_modules
from .process_info import (
    get_memory_regions,
    get_process_info,
    get_process_list,
    get_region_info,
    get_services,
    get_threads,
    open_process,
)
from .scanning_helpers import scan_pointer, scan_string
from .struct_helpers import (
    read_matrix4x4,
    read_struct,
    read_vector3,
    read_vector4,
)
from .utilities import bit_and, bit_extract, bit_lshift, bit_not, bit_or, bit_rshift, bit_xor, lua_clock, lua_sleep


class MemscopeLuaEngine:
    """Lua scripting environment exposing memscope's memory primitives."""

    def __init__(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self._output = []
        self._last_error = None
        self._debug_errors = False
        self._execution_guard = LuaExecutionGuard()
        self._register_functions()

    def _log_error(self, func_name: str, e: Exception) -> None:
        """Log error for debugging. Stores in _last_error, optionally prints."""
        self._last_error = f"{func_name}: {type(e).__name__}: {e}"
        if self._debug_errors:
            self._output.append(f"[DEBUG] {self._last_error}")

    def _register_functions(self):
        """Register memscope's Lua functions in the global namespace."""
        g = self.lua.globals()

        g["readByte"] = read_byte
        g["readBytes"] = lambda addr, count: read_bytes(addr, count, self.lua.table)
        g["readBytesHex"] = read_bytes_hex
        g["readSmallInteger"] = read_int16
        g["readInteger"] = read_int32
        g["readQword"] = read_int64
        g["readPointer"] = read_pointer
        g["readPointerRaw"] = read_pointer_raw
        g["readFloat"] = read_float
        g["readDouble"] = read_double
        g["readString"] = lambda addr, maxlen=256: read_string(addr, maxlen, self._log_error)
        g["readWideString"] = lambda addr, maxlen=256: read_wide_string(addr, maxlen, self._log_error)
        g["readBool"] = lambda addr: read_bool(addr, self._log_error)

        g["readUInt16"] = lambda addr: read_uint16(addr, self._log_error)
        g["readUInt32"] = lambda addr: read_uint32(addr, self._log_error)
        g["readUInt64"] = lambda addr: read_uint64(addr, self._log_error)

        g["readIntegerSafe"] = read_int32_safe

        g["readPointerArray"] = lambda addr, count: read_pointer_array(addr, count, self.lua.table, self._log_error)
        g["readIntArray"] = lambda addr, count: read_int_array(addr, count, self.lua.table, self._log_error)
        g["readFloatArray"] = lambda addr, count: read_float_array(addr, count, self.lua.table, self._log_error)

        g["writeByte"] = lambda addr, val: write_byte(addr, val, self._log_error)
        g["writeBytes"] = lambda addr, tbl: write_bytes(addr, tbl, self._log_error)
        g["writeSmallInteger"] = lambda addr, val: write_int16(addr, val, self._log_error)
        g["writeInteger"] = lambda addr, val: write_int32(addr, val, self._log_error)
        g["writeQword"] = lambda addr, val: write_int64(addr, val, self._log_error)
        g["writePointer"] = lambda addr, val: write_pointer(addr, val, self._log_error)
        g["writeFloat"] = lambda addr, val: write_float(addr, val, self._log_error)
        g["writeDouble"] = lambda addr, val: write_double(addr, val, self._log_error)
        g["writeString"] = lambda addr, s, maxlen=256: write_string(addr, s, maxlen, self._log_error)
        g["writeBool"] = lambda addr, val: write_bool(addr, val, self._log_error)

        # Unsigned integer writes
        g["writeUInt16"] = lambda addr, val: write_uint16(addr, val, self._log_error)
        g["writeUInt32"] = lambda addr, val: write_uint32(addr, val, self._log_error)
        g["writeUInt64"] = lambda addr, val: write_uint64(addr, val, self._log_error)

        # Address/module functions
        g["getAddress"] = self._get_address
        g["getModuleBase"] = self._get_module_base
        g["getModuleSize"] = self._get_module_size
        g["getModules"] = lambda filt=None: get_modules(self.lua.table, filt)
        g["getModuleFromAddress"] = lambda addr: get_module_from_address(self.lua.table, addr, self._log_error)
        g["formatAddress"] = lambda addr: lua_format_address(addr, self._log_error)

        # Scanning functions
        g["AOBScan"] = self._aob_scan
        g["AOBScanModule"] = self._aob_scan_module
        g["scanString"] = lambda s, mod=None, wide=False, limit=100: scan_string(
            self.lua.table, s, mod, wide, limit, self._log_error
        )
        g["scanPointer"] = lambda target, mod=None, align=8, limit=100: scan_pointer(
            self.lua.table, target, mod, align, limit, self._log_error
        )

        # Pointer chain
        g["readPointerChain"] = self._read_pointer_chain

        g["readVector3"] = lambda addr: read_vector3(addr, self.lua.table)
        g["readVector4"] = lambda addr: read_vector4(addr, self.lua.table)
        g["readQuaternion"] = lambda addr: read_vector4(addr, self.lua.table)  # Alias
        g["readMatrix4x4"] = lambda addr: read_matrix4x4(addr, self.lua.table)

        # Utility functions
        g["toHex"] = self._to_hex
        g["fmt"] = self._safe_format
        g["isValidPointer"] = lambda x: x is not None and x != 0 and is_valid_pointer(int(x)) if x else False
        g["print"] = self._lua_print
        g["isNil"] = lambda x: x is None
        g["orZero"] = lambda x: x if x is not None else 0
        g["orEmpty"] = lambda x: x if x is not None else ""

        # Timing
        g["clock"] = lua_clock
        g["sleep"] = lua_sleep

        # Bitwise operations
        g["band"] = bit_and
        g["bor"] = bit_or
        g["bxor"] = bit_xor
        g["bnot"] = bit_not
        g["lshift"] = bit_lshift
        g["rshift"] = bit_rshift
        g["bextract"] = bit_extract

        g["readStruct"] = lambda addr, fields: read_struct(
            addr,
            fields,
            self.lua.table,
            lambda a: read_vector3(a, self.lua.table),
            lambda a: read_vector4(a, self.lua.table),
            self._log_error,
            self._output,
        )

        # Debug helpers
        g["enableDebug"] = lambda: setattr(self, "_debug_errors", True)
        g["disableDebug"] = lambda: setattr(self, "_debug_errors", False)
        g["getLastError"] = lambda: self._last_error
        g["allowUnsafeCodeExecution"] = self._allow_unsafe_execution

        # Memory safety helpers
        g["backupMemory"] = self._backup_memory
        g["isWritableMemory"] = self._is_writable_memory

        g["executeCode"] = lambda func, *args: execute_code_lua(
            func, args, self._output, self._log_error, self._execution_guard
        )
        g["executeCodeEx"] = lambda flags, timeout, func, *args: execute_code_ex_lua(
            flags, timeout, func, args, self._output, self._log_error, self._execution_guard
        )
        g["callSequence"] = lambda calls, timeout=5000: call_sequence_lua(calls, timeout, self._output, self._log_error)
        g["callSequenceResults"] = lambda calls, timeout=5000: call_sequence_results_lua(
            calls, timeout, self.lua.table, self._output, self._log_error
        )
        g["alloc"] = lambda size_or_str, wide=False: alloc_lua(size_or_str, wide, self._output)
        g["freeMemory"] = lambda addr: free_memory_lua(addr, self._log_error)

        # Aliases for consistency
        g["call"] = g["executeCode"]
        g["allocateMemory"] = g["alloc"]
        g["allocString"] = g["alloc"]
        g["freeString"] = g["freeMemory"]
        g["free"] = g["freeMemory"]

        g["getProcessList"] = lambda filt=None, limit=500: get_process_list(self.lua.table, filt, limit)
        g["getProcessInfo"] = lambda pid=None: get_process_info(self.lua.table, pid)
        g["getMemoryRegions"] = lambda filt=None, limit=1000: get_memory_regions(self.lua.table, filt, limit)
        g["getRegionInfo"] = lambda addr: get_region_info(self.lua.table, addr)
        g["getThreads"] = lambda pid=None: get_threads(self.lua.table, pid)
        g["getServices"] = lambda pid=None: get_services(self.lua.table, pid)
        g["openProcess"] = lambda pid: open_process(self.lua.table, pid, self._log_error)

        g["addr"] = parse_hex_address
        g["parseHex"] = parse_hex_address

        g["safeEq"] = safe_eq
        g["safeNe"] = safe_ne
        g["safeLt"] = safe_lt
        g["safeGt"] = safe_gt
        g["safeLe"] = safe_le
        g["safeGe"] = safe_ge
        g["safeIsZero"] = lambda x: x is None or x == 0
        g["safeNotZero"] = lambda x: x is not None and x != 0
        g["safeInt"] = safe_int

        # Results collection
        g["_results"] = self.lua.table()
        g["addResult"] = self._add_result
        g["setResult"] = self._set_result

        # Args table (set per-execution)
        g["args"] = self.lua.table()

    def register_plugin_functions(self, plugin_name: str, funcs: dict[str, callable]) -> None:
        """Register functions from a plugin into the Lua global namespace.

        Args:
            plugin_name: Plugin identifier (for logging).
            funcs: Dict mapping Lua function names to Python callables.
        """
        g = self.lua.globals()
        for name, func in funcs.items():
            if g[name] is not None:
                import logging

                logging.getLogger(__name__).warning(
                    f"Plugin '{plugin_name}': overwriting existing Lua function '{name}'"
                )
            g[name] = func

    def _python_to_lua(self, value):
        """Convert Python value to Lua-compatible value."""
        if value is None:
            return None
        elif isinstance(value, dict):
            t = self.lua.table()
            for k, v in value.items():
                t[k] = self._python_to_lua(v)
            return t
        elif isinstance(value, (list, tuple)):
            t = self.lua.table()
            for i, v in enumerate(value, 1):
                t[i] = self._python_to_lua(v)
            return t
        else:
            return value

    def _lua_print(self, *args):
        """Capture Lua print statements."""
        parts = []
        for a in args:
            if a is None:
                parts.append("nil")
            else:
                parts.append(str(a))
        self._output.append(" ".join(parts))

    def _to_hex(self, x) -> str:
        """Convert value to hex string. Nil-safe."""
        if x is None:
            return "nil"
        try:
            return f"0x{to_uint64(x):X}"
        except (ValueError, TypeError, OverflowError):
            return "0x0"

    def _allow_unsafe_execution(self, enabled=True) -> bool:
        """Allow high-volume executeCode loops for the current script only."""
        self._execution_guard.allow_unsafe = bool(enabled)
        return self._execution_guard.allow_unsafe

    def _safe_format(self, fmt_str: str, *args) -> str:
        """Nil-safe string formatting."""
        safe_args = []
        for a in args:
            if a is None:
                safe_args.append(0)
            else:
                safe_args.append(a)
        try:
            return fmt_str % tuple(safe_args)
        except (TypeError, ValueError):
            return f"[format error: {fmt_str} with {args}]"

    def _add_result(self, key, value):
        """Add a result to the results table."""
        g = self.lua.globals()
        g["_results"][key] = value

    def _set_result(self, value):
        """Set single result value."""
        g = self.lua.globals()
        g["_results"]["value"] = value

    # ========== Memory Safety Helpers ==========

    def _backup_memory(self, address, size):
        """Backup memory region. Returns Lua table of bytes or nil."""
        try:
            addr = int(address)
            sz = int(size)
            data = SESSION.read_bytes(addr, sz)
            return self.lua.table(*list(data))
        except:
            return None

    def _is_writable_memory(self, address) -> bool:
        """Check if memory address is writable."""
        try:
            addr = int(address)
            if not is_valid_pointer(addr):
                return False
            return SESSION.is_memory_writable(addr)
        except:
            return False

    # ========== Address/Module Functions ==========

    def _get_address(self, expr: str) -> Optional[int]:
        """Parse address expression like 'module.dll+0x1A208D8'."""
        try:
            return parse_address(expr)
        except:
            return None

    def _get_module_base(self, name: str) -> Optional[int]:
        """Get module base address."""
        try:
            return SESSION.get_module_base(name)
        except:
            return None

    def _get_module_size(self, name: str) -> Optional[int]:
        """Get module size."""
        try:
            return SESSION.get_module_size(name)
        except:
            return None

    # ========== Scanning Functions ==========

    def _aob_scan(self, pattern: str, start_addr=None, end_addr=None, max_results=100, timeout_ms=None):
        """Scan modules or a bounded readable memory range for an AOB pattern."""
        try:
            if not SESSION.ensure_attached():
                return self._scan_table([], {"error": "PROCESS_NOT_ATTACHED"})

            start = self._optional_address(start_addr)
            end = self._optional_address(end_addr)
            timeout = int(timeout_ms) if timeout_ms is not None else SCAN_TIMEOUT_SECONDS * 1000

            result = scan_aob_addresses(
                pattern,
                start_addr=start,
                end_addr=end,
                max_results=int(max_results),
                timeout_ms=timeout,
            )
            if not result["success"]:
                self._last_error = result.get("error_detail", result.get("error", "AOBScan failed"))
                return self._scan_table([], {"error": self._last_error})

            return self._scan_table(result["matches"], result["metadata"])
        except Exception as e:
            self._last_error = str(e)
            return self._scan_table([], {"error": str(e)})

    def _aob_scan_module(self, module: str, pattern: str, max_results=100, timeout_ms=None):
        """Scan specific module for AOB pattern."""
        try:
            if not SESSION.ensure_attached():
                return self._scan_table([], {"error": "PROCESS_NOT_ATTACHED"})

            timeout = int(timeout_ms) if timeout_ms is not None else SCAN_TIMEOUT_SECONDS * 1000
            result = scan_aob_addresses(pattern, module=module, max_results=int(max_results), timeout_ms=timeout)
            if not result["success"]:
                self._last_error = result.get("error_detail", result.get("error", "AOBScanModule failed"))
                return self._scan_table([], {"error": self._last_error})

            return self._scan_table(result["matches"], result["metadata"])
        except Exception as e:
            self._last_error = str(e)
            return self._scan_table([], {"error": str(e)})

    def _optional_address(self, value) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, str):
            return parse_address(value)
        return int(value)

    def _scan_table(self, matches: list[int], metadata: dict[str, Any]):
        result = self.lua.table(*matches)
        meta = self.lua.table()
        for key, value in metadata.items():
            meta[key] = value
        result["metadata"] = meta
        return result

    # ========== Pointer Chain ==========

    def _read_pointer_chain(self, base, *offsets):
        """Follow pointer chain: [[base + off1] + off2] + off3..."""
        try:
            if isinstance(base, str):
                current = parse_address(base)
            else:
                current = int(base)

            for offset in offsets:
                ptr = SESSION.read_ptr(current)
                if not is_valid_pointer(ptr):
                    return None
                current = ptr + int(offset)

            return current
        except:
            return None

    # ========== Script Preprocessing ==========

    def _preprocess_script(self, script: str) -> tuple[str, list[str]]:
        """Auto-convert large hex literals to addr() calls."""
        conversions = []
        protected = {}
        placeholder_counter = [0]

        def make_placeholder():
            placeholder = f"__PROTECTED_{placeholder_counter[0]}__"
            placeholder_counter[0] += 1
            return placeholder

        # Protect long strings
        def protect_long_string(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"\[(=*)\[.*?\]\1\]", protect_long_string, script, flags=re.DOTALL)

        # Protect double-quoted strings
        def protect_double_string(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r'"(?:[^"\\]|\\.)*"', protect_double_string, temp_script)

        # Protect single-quoted strings
        def protect_single_string(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"'(?:[^'\\]|\\.)*'", protect_single_string, temp_script)

        # Protect already-wrapped addr()/parseHex() calls
        def protect_wrapped(match):
            placeholder = make_placeholder()
            protected[placeholder] = match.group(0)
            return placeholder

        temp_script = re.sub(r"(addr|parseHex)\(([^)]+)\)", protect_wrapped, temp_script)

        # Replace large hex literals
        pattern = r"\b(0x[0-9A-Fa-f]{9,})\b"

        def replace_hex(match):
            hex_val = match.group(1)
            conversions.append(hex_val)
            return f'addr("{hex_val}")'

        processed = re.sub(pattern, replace_hex, temp_script)

        # Restore protected content (iterate until stable - handles nested placeholders)
        prev = None
        while processed != prev:
            prev = processed
            for placeholder, original in protected.items():
                processed = processed.replace(placeholder, original)

        return processed, conversions

    # ========== Script Execution ==========

    def execute(self, script: str, args: Optional[dict] = None) -> dict[str, Any]:
        """Execute Lua script and return results.

        Scripts can run without an attached process. Process introspection
        functions (getProcessList, getServices, etc.) work without attachment.
        Memory functions return nil when no process is attached.
        Use openProcess(pid) from Lua to attach to a process.
        """
        self._output = []
        self._last_error = None
        self._execution_guard = LuaExecutionGuard()

        # Preprocess script
        processed_script, conversions = self._preprocess_script(script)
        conversion_warning = None
        if conversions:
            conversion_warning = (
                f"Auto-converted {len(conversions)} large hex literal(s) to addr() calls: {', '.join(conversions[:3])}"
            )
            if len(conversions) > 3:
                conversion_warning += f" and {len(conversions) - 3} more"

        g = self.lua.globals()
        g["_results"] = self.lua.table()
        g["args"] = self._python_to_lua(args) if args else self.lua.table()

        try:
            result = self.lua.execute(processed_script)

            # Collect results
            results_table = g["_results"]
            collected_results = {}

            if results_table:
                for k, v in results_table.items():
                    if hasattr(v, "items"):
                        collected_results[k] = dict(v.items())
                    else:
                        collected_results[k] = v

            # Handle direct return value
            if result is not None:
                if hasattr(result, "items"):
                    collected_results["return"] = dict(result.items())
                elif hasattr(result, "__iter__") and not isinstance(result, str):
                    collected_results["return"] = list(result)
                else:
                    collected_results["return"] = result

            response = {
                "success": True,
                "results": collected_results,
                "output": self._output,
            }

            if conversion_warning:
                response["_warning"] = conversion_warning

            return response

        except LuaError as e:
            error_msg = str(e)

            if "malformed number" in error_msg.lower() or "invalid" in error_msg.lower():
                large_hex = re.findall(r"0x[0-9A-Fa-f]{10,}", script)
                if large_hex:
                    return {
                        "success": False,
                        "error": "LUA_PARSE_ERROR",
                        "error_detail": (
                            f"Large hex literals detected: {', '.join(large_hex[:3])}. "
                            f'Use addr() function instead: addr("{large_hex[0]}")'
                        ),
                        "output": self._output,
                        "hint": (
                            'For 64-bit addresses, use: local myAddr = addr("0x1F58E12ECF0") '
                            "instead of: local myAddr = 0x1F58E12ECF0"
                        ),
                    }

            return {
                "success": False,
                "error": "LUA_ERROR",
                "error_detail": error_msg,
                "output": self._output,
            }
        except Exception as e:
            error_msg = str(e)

            if "int too big" in error_msg.lower() or "cannot convert" in error_msg.lower():
                return {
                    "success": False,
                    "error": "EXECUTION_ERROR",
                    "error_detail": f"Lua numeric overflow with 64-bit value: {error_msg}",
                    "output": self._output,
                    "hint": (
                        "64-bit integer comparison overflow. Solutions:\n"
                        "  1. Use safeEq(a, b), safeNe(a, b), safeLt(a, b), safeGt(a, b) instead of ==, ~=, <, >\n"
                        "  2. For pointers: readPointer() returns nil for invalid pointers"
                        " - use 'if ptr then' instead of 'if ptr ~= 0 then'\n"
                        "  3. For integers: use readIntegerSafe() or safeInt(readInteger(...))"
                        " to get nil for garbage values\n"
                        "  4. For address comparisons: use isValidPointer(addr) instead of addr > 0x10000"
                    ),
                }

            return {
                "success": False,
                "error": "EXECUTION_ERROR",
                "error_detail": error_msg,
                "output": self._output,
            }


LUA_ENGINE = MemscopeLuaEngine()


def execute_lua(script: str, args: Optional[dict] = None) -> dict[str, Any]:
    """Execute a Lua script in the memscope runtime.

    Scripts can run WITHOUT an attached process:
      - Process introspection functions work without attachment
      - Memory functions return nil when no process is attached
      - Use openProcess(pid) to attach from within a script

    Available functions:
        Memory Read:
            readByte(addr)              -> int8
            readBytes(addr, count)      -> table of bytes
            readBytesHex(addr, count)   -> "48 8B 05..." string
            readBool(addr)              -> bool (1 byte)
            readSmallInteger(addr)      -> int16
            readInteger(addr)           -> int32
            readIntegerSafe(addr)       -> int32 or nil if garbage
            readQword(addr)             -> int64
            readUInt16(addr)            -> uint16
            readUInt32(addr)            -> uint32
            readUInt64(addr)            -> uint64
            readPointer(addr)           -> uint64, nil if invalid pointer
            readPointerRaw(addr)        -> uint64 raw (no validation)
            readFloat(addr)             -> float32
            readDouble(addr)            -> float64
            readString(addr, maxlen)    -> null-terminated C string
            readWideString(addr, maxlen) -> null-terminated UTF-16LE string

        Memory Write:
            writeByte(addr, val)        -> bool
            writeBytes(addr, table)     -> bool
            writeBool(addr, val)        -> bool
            writeSmallInteger(addr, v)  -> bool
            writeInteger(addr, val)     -> bool
            writeQword(addr, val)       -> bool
            writeUInt16(addr, val)      -> bool
            writeUInt32(addr, val)      -> bool
            writeUInt64(addr, val)      -> bool
            writePointer(addr, val)     -> bool
            writeFloat(addr, val)       -> bool
            writeDouble(addr, val)      -> bool
            writeString(addr, str)      -> bool

        Bulk Array Reads:
            readPointerArray(addr, count) -> table of pointers (nil for invalid)
            readIntArray(addr, count)     -> table of int32 values
            readFloatArray(addr, count)   -> table of float values

        Module/Address:
            getAddress("mod.dll+0x1234")  -> resolve module+offset to address
            getModuleBase("mod.dll")      -> module base address
            getModuleSize("mod.dll")      -> module size in bytes
            getModules(filter?)           -> table of {name, base, size, path}
            getModuleFromAddress(addr)    -> {name, base, offset} or nil
            formatAddress(addr)           -> "module.dll+0xOFFSET" or "0xADDR"

        Scanning:
            AOBScan(pattern, start?, end?, limit?) -> table of addresses; bounded scans readable regions
            AOBScanModule(mod, pattern, limit?)    -> table of addresses (one module)
            scanString(str, mod?, wide?)  -> table of addresses (string scan)
            scanPointer(target, mod?)     -> table of addresses (xref scan)
            AOBScan results include hits.metadata with region counts, bytes scanned, timeout_hit, result_count

        Pointer Chains:
            readPointerChain(base, off1, off2, ...)  -> final address

        Struct Helpers:
            readVector3(addr)             -> {x, y, z} (3 floats)
            readVector4(addr)             -> {x, y, z, w} (4 floats)
            readQuaternion(addr)          -> alias for readVector4
            readMatrix4x4(addr)           -> {position={x,y,z}, m00, m01, ...}

        Code Execution:
            executeCode(func, arg1, ...)  -> RAX result (strings auto-allocated)
            executeCodeEx(flags, timeout, func, ...)  -> RAX result
            callSequence({{address=..., args={...}}, ...})  -> RAX of LAST call
            alloc(size)                   -> raw buffer address
            alloc("string")               -> string address (auto-written)
            alloc("string", true)         -> wide string (UTF-16)
            freeMemory(addr)              -> bool

        64-bit Safe Comparisons:
            safeEq(a, b), safeNe(a, b), safeLt(a, b), safeGt(a, b)
            safeLe(a, b), safeGe(a, b), safeIsZero(x), safeNotZero(x)
            safeInt(val)    -> val if small int, else nil

        Struct Reading:
            readStruct(addr, fields)      -> table with field values

        Process Introspection:
            getProcessList(filter?, limit?)   -> table of {pid, name, parent_pid, threads}
            getProcessInfo(pid?)              -> {pid, name, path, parent_pid, threads}
            getMemoryRegions(filter?, limit?) -> table of {base, size, protection, type, state}
            getRegionInfo(addr)               -> {base, size, protection, is_readable/writable/executable}
            getThreads(pid?)                  -> table of {tid, owner_pid, priority}
            getServices(pid?)                 -> table of {name, display_name, pid, state}
            openProcess(pid)                  -> attach to different process, returns {success, pid, name}

        Utility:
            addr("0x..."), parseHex("0x...")  -> parse hex string
            toHex(val), fmt(str, ...), print(...)
            isValidPointer(val), isWritableMemory(addr)
            backupMemory(addr, size), addResult(key, val), setResult(val)
            clock()                       -> milliseconds (high-res timer)
            sleep(ms)                     -> pause execution

        Bitwise:
            band(a, b), bor(a, b), bxor(a, b), bnot(a)
            lshift(a, n), rshift(a, n)
            bextract(val, offset, width?) -> extract bit field
    """
    return LUA_ENGINE.execute(script, args)
