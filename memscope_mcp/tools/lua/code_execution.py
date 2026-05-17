"""Code execution functions for Lua engine.

Functions for calling code in the target process.
"""

from typing import Any, Callable, Generator, Optional

from ...session import SESSION
from ...utils.memory_utils import parse_address
from .comparisons import to_lua_int64, to_uint64


class LuaExecutionGuard:
    """Per-script guard for repeated native execution from Lua."""

    def __init__(self, warn_after: int = 25, fail_after: int = 100, allow_unsafe: bool = False):
        self.warn_after = warn_after
        self.fail_after = fail_after
        self.allow_unsafe = allow_unsafe
        self.count = 0
        self.warned = False

    def check(self, output: list[str], func_name: str) -> bool:
        if self.allow_unsafe:
            return True

        self.count += 1
        if self.count > self.fail_after:
            output.append(
                f"{func_name} blocked: more than {self.fail_after} native calls in one Lua script. "
                "Call allowUnsafeCodeExecution(true) before the loop to override."
            )
            return False

        if self.count > self.warn_after and not self.warned:
            output.append(
                f"warning: Lua script made more than {self.warn_after} executeCode/executeCodeEx calls. "
                f"Calls after {self.fail_after} will be blocked unless allowUnsafeCodeExecution(true) is set."
            )
            self.warned = True

        return True


def parse_lua_arg(arg) -> int | str:
    """Parse argument from Lua, handling various representations of large integers.

    Large 64-bit integers may come through lupa as:
    - Python int (normal case)
    - Hex string "0x..." (when lupa serializes large values)
    - Decimal string (unlikely but possible)

    Returns int for numeric values, or original string for text args.
    """
    if arg is None:
        return 0

    # Already a string - could be hex, decimal, or text
    if isinstance(arg, str):
        arg_stripped = arg.strip()
        # Hex string like "0x265BF4F0000"
        if arg_stripped.lower().startswith("0x"):
            try:
                return to_uint64(int(arg_stripped, 16))
            except ValueError:
                return arg  # Not valid hex, treat as text
        # Decimal string like "12345"
        if arg_stripped.lstrip("-").isdigit():
            try:
                return to_uint64(int(arg_stripped))
            except ValueError:
                return arg  # Treat as text
        # Text string - return as-is for auto-allocation
        return arg

    # Try to convert to int (handles Python int, lupa int types, etc.)
    try:
        return to_uint64(int(arg))
    except (ValueError, TypeError, OverflowError):
        # Last resort - convert to string and try hex parse
        s = str(arg)
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                pass
        return 0  # Give up, use 0


def iter_lua_array(table) -> Generator[tuple[int, Any], None, None]:
    """Iterate a Lua array table (1-indexed), yielding (index, value) pairs.

    Handles lupa table objects properly without brute-force range iteration.
    """
    if table is None:
        return

    # Try to get length via Lua's # operator
    try:
        length = len(table)
        for i in range(1, length + 1):
            yield i, table[i]
        return
    except (TypeError, AttributeError):
        pass

    # Fallback: iterate via .values() if available (array-style)
    if hasattr(table, "values"):
        for i, val in enumerate(table.values(), 1):
            yield i, val
        return

    # Last resort: indexed access until nil
    for i in range(1, 100):
        try:
            val = table[i]
            if val is None:
                break
            yield i, val
        except (KeyError, TypeError, IndexError):
            break


def execute_code_lua(
    func_addr,
    args: tuple,
    output: list[str],
    log_error: Callable[[str, Exception], None],
    guard: Optional[LuaExecutionGuard] = None,
) -> Optional[int]:
    """Execute function in target process with smart arg handling.

    Accepts both calling conventions:
        call(func, arg1, arg2)    - varargs style
        call(func, {arg1, arg2})  - table style

    Args:
        func_addr: Function address (int or string like "module+offset" or "0x...")
        args: Arguments - hex strings parsed as ints, text strings auto-allocated
        output: Output list for error messages
        log_error: Error logging function

    Returns:
        Return value (RAX) or nil on error

    Example:
        local klass = call(class_from_name, image, "Namespace", "ClassName")
        local result = call(func, {image, "Namespace", "ClassName"})  -- also works
    """
    from ..execute import execute_code

    try:
        if guard and not guard.check(output, "executeCode"):
            return None

        if isinstance(func_addr, str):
            addr = parse_address(func_addr)
        else:
            addr = to_uint64(func_addr)

        # Check if first arg is a Lua table (user passed args as table)
        if len(args) == 1 and hasattr(args[0], "__iter__") and not isinstance(args[0], str):
            table_args = [val for _, val in iter_lua_array(args[0])]
            if table_args:
                args = tuple(table_args)

        # Convert args - handle Lua types and large integers
        py_args = [parse_lua_arg(arg) for arg in args]

        result = execute_code(addr, py_args, timeout_ms=5000)

        if result.get("success"):
            res = result.get("result")
            if isinstance(res, str) and res.startswith("0x"):
                return to_lua_int64(int(res, 16))
            return to_lua_int64(int(res)) if res else 0
        else:
            output.append(f"executeCode error: {result.get('error')} - {result.get('detail')}")
            return None
    except Exception as e:
        log_error("executeCode", e)
        return None


def execute_code_ex_lua(
    flags,
    timeout,
    func_addr,
    args: tuple,
    output: list[str],
    log_error: Callable[[str, Exception], None],
    guard: Optional[LuaExecutionGuard] = None,
) -> Optional[int]:
    """Execute function with extended options.

    Args:
        flags: Execution flags (0 = default, wait for completion)
        timeout: Timeout in ms (use nil for default 5000ms)
        func_addr: Function address
        args: Function arguments
        output: Output list for error messages
        log_error: Error logging function

    Returns:
        Return value (RAX) or nil on error
    """
    from ..execute import execute_code_ex

    try:
        if guard and not guard.check(output, "executeCodeEx"):
            return None

        if isinstance(func_addr, str):
            addr = parse_address(func_addr)
        else:
            addr = to_uint64(func_addr)

        flags_int = int(flags) if flags is not None else 0
        timeout_ms = int(timeout) if timeout else 5000
        py_args = [parse_lua_arg(arg) for arg in args]

        result = execute_code_ex(flags_int, timeout_ms, addr, *py_args)

        if result.get("success"):
            res = result.get("result")
            if isinstance(res, str) and res.startswith("0x"):
                return to_lua_int64(int(res, 16))
            return to_lua_int64(int(res)) if res else 0
        else:
            output.append(f"executeCodeEx error: {result.get('error')} - {result.get('detail')}")
            return None
    except Exception as e:
        log_error("executeCodeEx", e)
        return None


def _lua_result_int(value) -> int:
    if isinstance(value, str) and value.startswith("0x"):
        return to_lua_int64(int(value, 16))
    return to_lua_int64(int(value)) if value else 0


def _run_call_sequence_lua(calls_table, timeout: int, output: list[str]) -> Optional[dict]:
    from ..execute import call_sequence

    py_calls = []

    for i, call_spec in iter_lua_array(calls_table):
        if call_spec is None:
            continue

        # Extract address - support both 'address' and 'addr' keys
        addr = None
        if hasattr(call_spec, "__getitem__"):
            addr = get_lua_key(call_spec, "address")
            if addr is None:
                addr = get_lua_key(call_spec, "addr")

        if addr is None:
            output.append(f"callSequence: call {i} missing 'address'")
            return None

        # Convert address to hex string if needed
        if not isinstance(addr, str):
            addr = f"0x{to_uint64(addr):X}"

        # Extract args using proper iteration
        py_args = []
        args_table = None
        if hasattr(call_spec, "__getitem__"):
            args_table = get_lua_key(call_spec, "args")

        if args_table:
            for _, arg in iter_lua_array(args_table):
                result_ref = get_lua_key(arg, "result")
                if result_ref is not None:
                    py_args.append({"result": int(result_ref)})
                else:
                    py_args.append(parse_lua_arg(arg))

        py_calls.append({"address": addr, "args": py_args})

    if not py_calls:
        output.append("callSequence: no valid calls in table")
        return None

    timeout_ms = int(timeout) if timeout else 5000
    result = call_sequence(py_calls, timeout_ms)

    if not result.get("success"):
        output.append(f"callSequence error: {result.get('error')} - {result.get('detail')}")
        return None

    return result


def call_sequence_lua(
    calls_table, timeout: int, output: list[str], log_error: Callable[[str, Exception], None]
) -> Optional[int]:
    """Execute multiple calls in ONE thread. Critical for thread-local APIs.

    All calls execute in the same remote thread, so thread-local state persists
    across subsequent calls. Returns result of the LAST call.

    Args:
        calls_table: Lua table of call specs, each with:
            - address: Function address (hex string or "module+offset")
            - args: Lua table of arguments (same rules as executeCode)
        timeout: Timeout in ms for entire sequence (default 5000)
        output: Output list for error messages
        log_error: Error logging function

    Returns:
        Return value (RAX) of last call, or nil on error

    Example:
        local result = callSequence({
            {address = thread_attach_addr, args = {domain}},
            {address = class_from_name, args = {image, "Namespace", "Class"}}
        })
        -- Both calls ran in same thread, so thread-local state persisted
    """
    try:
        result = _run_call_sequence_lua(calls_table, timeout, output)
        if result is None:
            return None
        return _lua_result_int(result.get("result", "0x0"))

    except Exception as e:
        log_error("callSequence", e)
        return None


def call_sequence_results_lua(
    calls_table, timeout: int, lua_table, output: list[str], log_error: Callable[[str, Exception], None]
):
    """Execute multiple calls and return final RAX plus every per-call RAX."""
    try:
        result = _run_call_sequence_lua(calls_table, timeout, output)
        if result is None:
            return None

        out = lua_table()
        out["result"] = _lua_result_int(result.get("result", "0x0"))
        out["calls_executed"] = int(result.get("calls_executed", 0))

        call_results = lua_table()
        for i, value in enumerate(result.get("call_results", []), 1):
            call_results[i] = _lua_result_int(value)
        out["call_results"] = call_results

        return out
    except Exception as e:
        log_error("callSequenceResults", e)
        return None


def get_lua_key(value, key: str):
    """Read a key from a Lua table-like value without treating plain strings as tables."""
    if value is None or isinstance(value, str) or not hasattr(value, "__getitem__"):
        return None
    if hasattr(value, "get"):
        try:
            result = value.get(key)
            if result is not None:
                return result
        except (KeyError, TypeError, AttributeError):
            pass
    try:
        return value[key]
    except (KeyError, TypeError, AttributeError):
        return None


def alloc_lua(size_or_string, wide: bool, output: list[str]) -> Optional[int]:
    """Allocate memory in target process. Remember to free with freeMemory().

    Smart allocation:
        alloc(64)           - allocate 64 bytes raw buffer
        alloc("text")       - allocate and write UTF-8 string
        alloc("text", true) - allocate and write UTF-16 string (Windows APIs)

    Use raw buffers for:
        - Output parameters (exception pointers, etc.)
        - Structs (RaycastHit, etc.)
        - Argument arrays for runtime_invoke

    Returns:
        Address (integer) or nil on error

    Example:
        local exc = alloc(8)  -- for exception out param
        local result = executeCode(invoke, method, obj, args, exc)
        freeMemory(exc)

        local namePtr = alloc("ConfigPath")  -- auto writes string
        executeCode(setConfig, obj, namePtr)
        freeMemory(namePtr)
    """
    try:
        if isinstance(size_or_string, str):
            # String allocation - allocate and write
            from ..execute import alloc_string

            result = alloc_string(size_or_string, wide)
            if result.get("success"):
                addr_str = result.get("address", "0x0")
                if isinstance(addr_str, str) and addr_str.startswith("0x"):
                    return int(addr_str, 16)
                return int(addr_str) if addr_str else None
            else:
                output.append(f"alloc error: {result.get('detail')}")
                return None
        else:
            # Raw buffer allocation
            size = int(size_or_string)
            if size <= 0 or size > 0x100000:  # 1MB limit
                output.append(f"alloc error: invalid size {size}")
                return None
            addr = SESSION.allocate(size, executable=False)
            return addr
    except Exception as e:
        output.append(f"alloc exception: {e}")
        return None


def free_memory_lua(address, log_error: Callable[[str, Exception], None]) -> bool:
    """Free memory allocated by alloc().

    Args:
        address: Address to free

    Returns:
        True if freed successfully
    """
    from ..execute import free_alloc

    try:
        addr = int(address)
        result = free_alloc(addr)
        return result.get("success", False)
    except Exception as e:
        log_error("freeMemory", e)
        return False
