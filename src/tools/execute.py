"""Remote code execution in target process.

Builds x64 shellcode to call functions in the target process with
auto-allocated string arguments, float/XMM register support, and cleanup.
"""

import re
import struct
from typing import Any, Union

from ..session import SESSION
from ..utils.memory_utils import format_address, parse_address
from ..utils.shellcode import build_call_x64, build_multi_call_x64

# Regex patterns for detecting numeric strings
HEX_PATTERN = re.compile(r"^0[xX][0-9A-Fa-f]+$")
DECIMAL_PATTERN = re.compile(r"^-?\d+$")

# Limits
MAX_RESULT_COPY_SIZE = 4096  # Max bytes for boxed return extraction
MAX_OUTPUT_SIZE = 4096  # Max bytes for output pointer capture
MAX_CALL_SEQUENCE_CALLS = 64
MAX_CALL_SEQUENCE_SHELLCODE_SIZE = 0x10000


def is_numeric_string(s: str) -> bool:
    """Check if string represents a number (hex or decimal).

    Returns True for:
        - "0x14222A03FC0" (hex)
        - "1383560396736" (decimal)
        - "-123" (negative decimal)

    Returns False for:
        - "MyNamespace.MyClass" (text)
        - "Init" (text)
        - "Hello World" (text)
        - "" (empty)
    """
    if not s:
        return False
    s = s.strip()
    return bool(HEX_PATTERN.match(s) or DECIMAL_PATTERN.match(s))


def parse_numeric_string(s: str) -> int:
    """Parse a numeric string (hex or decimal) to int.

    Assumes is_numeric_string(s) returned True.
    """
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def normalize_native_int(value: int) -> int:
    """Preserve a Python/Lua integer bit pattern for x64 native calls."""
    return int(value) & 0xFFFFFFFFFFFFFFFF


class CallContext:
    """Tracks allocations for automatic cleanup."""

    def __init__(self):
        self.allocations: list[int] = []
        self.shellcode_addr: int = 0
        self.result_addr: int = 0
        self.output_buffer_addr: int = 0
        self.thread_handle: int = 0

    def alloc_string(self, s: str) -> int:
        """Allocate null-terminated UTF-8 string in target process.

        Args:
            s: String to allocate

        Returns:
            Address of allocated string
        """
        data = s.encode("utf-8") + b"\x00"
        addr = SESSION.allocate(len(data), executable=False)
        SESSION.write_bytes(addr, data)
        self.allocations.append(addr)
        return addr

    def alloc_wide_string(self, s: str) -> int:
        """Allocate null-terminated UTF-16LE string (for Windows APIs).

        Args:
            s: String to allocate

        Returns:
            Address of allocated string
        """
        data = s.encode("utf-16-le") + b"\x00\x00"
        addr = SESSION.allocate(len(data), executable=False)
        SESSION.write_bytes(addr, data)
        self.allocations.append(addr)
        return addr

    def cleanup(self):
        """Free all tracked allocations. Always safe to call."""
        for addr in self.allocations:
            try:
                SESSION.free(addr)
            except Exception:
                pass
        self.allocations.clear()

        if self.shellcode_addr:
            try:
                SESSION.free(self.shellcode_addr)
            except Exception:
                pass
            self.shellcode_addr = 0

        if self.result_addr:
            try:
                SESSION.free(self.result_addr)
            except Exception:
                pass
            self.result_addr = 0

        if self.output_buffer_addr:
            try:
                SESSION.free(self.output_buffer_addr)
            except Exception:
                pass
            self.output_buffer_addr = 0

        if self.thread_handle:
            try:
                SESSION.close_handle(self.thread_handle)
            except Exception:
                pass
            self.thread_handle = 0


def execute_code(
    func_addr: Union[str, int],
    args: list[Any] = None,
    timeout_ms: int = 5000,
    float_args: list[int] = None,
    returns_float: bool = False,
    result_copy_offset: int = 0,
    result_copy_size: int = 0,
    output_arg: int = -1,
    output_size: int = 0,
) -> dict:
    """Execute function in target process with smart argument handling.

    Argument handling:
        - Integers: passed directly
        - Hex strings ("0x14222A03FC0"): parsed as integers
        - Decimal strings ("12345"): parsed as integers
        - Text strings ("MyNamespace"): auto-allocated in target, freed after call
        - Python floats: converted to double-precision bit pattern

    Args:
        func_addr: Function address (int, hex string, or "module+offset")
        args: List of arguments
        timeout_ms: Maximum wait time for function completion
        float_args: List of arg indices that are floats (0-3 only, for XMM registers)
        returns_float: If True, capture XMM0 as float return value
        result_copy_offset: Offset from RAX for boxed return extraction
        result_copy_size: Bytes to copy from RAX+offset (max 4096)
        output_arg: Index of arg that is output pointer (-1 = none)
        output_size: Bytes to capture from output pointer (max 4096)

    Returns:
        On success: {
            "success": True,
            "result": "0x..." (RAX as hex),
            "float_result"?: float (if returns_float),
            "boxed_data"?: "hex..." (if result_copy_size > 0),
            "output_data"?: "hex..." (if output_arg >= 0)
        }
        On failure: {"success": False, "error": str, "detail": str}

    Note:
        Float args are passed as 64-bit double-precision values.
        For functions expecting single-precision floats, the caller must
        handle the bit conversion appropriately.
    """
    if SESSION.pm is None:
        return {"success": False, "error": "NOT_ATTACHED", "detail": "Call attach first"}

    # Parse function address
    try:
        if isinstance(func_addr, str):
            func_addr = parse_address(func_addr)
        else:
            func_addr = int(func_addr)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "detail": str(e)}

    # Validate function address is in executable memory
    if not SESSION.is_valid_pointer(func_addr):
        return {
            "success": False,
            "error": "INVALID_ADDRESS",
            "detail": f"Address {format_address(func_addr)} is not a valid pointer",
        }

    # Validate size parameters
    if result_copy_size > MAX_RESULT_COPY_SIZE:
        return {
            "success": False,
            "error": "INVALID_SIZE",
            "detail": f"result_copy_size {result_copy_size} exceeds max {MAX_RESULT_COPY_SIZE}",
        }

    if output_size > MAX_OUTPUT_SIZE:
        return {
            "success": False,
            "error": "INVALID_SIZE",
            "detail": f"output_size {output_size} exceeds max {MAX_OUTPUT_SIZE}",
        }

    args = args or []
    float_args = float_args or []
    ctx = CallContext()

    try:
        # Process arguments - smart detection of numeric strings vs text strings
        processed_args = []
        string_info = []  # Track which args were allocated strings for debug

        for i, arg in enumerate(args):
            if isinstance(arg, str):
                # Check if it's a numeric string (hex like "0x123" or decimal like "456")
                if is_numeric_string(arg):
                    # Parse as integer, not as string to allocate
                    processed_args.append(normalize_native_int(parse_numeric_string(arg)))
                else:
                    # Actual text string - allocate in target process
                    ptr = ctx.alloc_string(arg)
                    processed_args.append(ptr)
                    string_info.append(
                        f"arg{i}='{arg[:32]}...' -> {format_address(ptr)}"
                        if len(arg) > 32
                        else f"arg{i}='{arg}' -> {format_address(ptr)}"
                    )
            elif isinstance(arg, int):
                processed_args.append(normalize_native_int(arg))
            elif isinstance(arg, float):
                # Convert float to double bit pattern (64-bit)
                float_bits = struct.unpack("<Q", struct.pack("<d", arg))[0]
                processed_args.append(float_bits)
            else:
                return {
                    "success": False,
                    "error": "INVALID_ARG",
                    "detail": f"Argument {i} has unsupported type: {type(arg).__name__}. "
                    f"Supported: int, str (hex/decimal or text), float",
                }

        float_mask = 0
        for idx in float_args:
            if 0 <= idx <= 3:
                float_mask |= 1 << idx

        result_size = 8  # RAX
        if returns_float:
            result_size = 16  # RAX + XMM0
        if result_copy_size > 0:
            result_size = 16 + result_copy_size  # RAX + XMM0 slot + boxed data

        ctx.result_addr = SESSION.allocate(result_size, executable=False)
        SESSION.write_bytes(ctx.result_addr, b"\x00" * result_size)

        if output_arg >= 0 and output_size > 0:
            ctx.output_buffer_addr = SESSION.allocate(output_size, executable=False)

        shellcode = build_call_x64(
            func_addr,
            processed_args,
            ctx.result_addr,
            float_mask=float_mask,
            returns_float=returns_float,
            result_copy_offset=result_copy_offset,
            result_copy_size=result_copy_size,
            output_arg_index=output_arg,
            output_size=output_size,
            output_buffer_addr=ctx.output_buffer_addr,
        )

        ctx.shellcode_addr = SESSION.allocate(len(shellcode), executable=True)
        SESSION.write_bytes(ctx.shellcode_addr, shellcode)

        ctx.thread_handle = SESSION.create_remote_thread(ctx.shellcode_addr)

        completed = SESSION.wait_for_thread(ctx.thread_handle, timeout_ms)

        if not completed:
            return {
                "success": False,
                "error": "TIMEOUT",
                "detail": f"Function did not return within {timeout_ms}ms. "
                f"Target may be hung or function takes longer than expected.",
            }

        result_data = SESSION.read_bytes(ctx.result_addr, result_size)
        rax_value = struct.unpack("<Q", result_data[0:8])[0]

        response = {"success": True, "result": format_address(rax_value)}

        # Extract float return if requested
        if returns_float and len(result_data) >= 16:
            xmm0_bits = struct.unpack("<Q", result_data[8:16])[0]
            response["float_result"] = struct.unpack("<d", struct.pack("<Q", xmm0_bits))[0]

        # Extract boxed return data if requested
        if result_copy_size > 0 and len(result_data) >= 16 + result_copy_size:
            response["boxed_data"] = result_data[16 : 16 + result_copy_size].hex()

        # Extract output pointer data if requested
        if ctx.output_buffer_addr and output_size > 0:
            output_data = SESSION.read_bytes(ctx.output_buffer_addr, output_size)
            response["output_data"] = output_data.hex()

        # Include string allocation info if any strings were passed
        if string_info:
            response["_string_allocs"] = string_info

        return response

    except MemoryError as e:
        return {"success": False, "error": "ALLOCATION_FAILED", "detail": str(e)}
    except OSError as e:
        return {"success": False, "error": "THREAD_FAILED", "detail": str(e)}
    except Exception as e:
        return {"success": False, "error": "EXECUTION_FAILED", "detail": str(e)}
    finally:
        # Always cleanup
        ctx.cleanup()


def execute_code_ex(flags: int, timeout_ms: int, func_addr: Union[str, int], *args) -> dict:
    """Execute function with extended options.

    Flags:
        0 (EX_DEFAULT): Wait for completion, return result
        1 (EX_ASYNC): Not implemented - use execute_code instead

    Args:
        flags: Execution flags (currently only 0 is supported)
        timeout_ms: Timeout in milliseconds (None = 5000ms default)
        func_addr: Function address
        *args: Function arguments

    Returns:
        Same as execute_code()
    """
    if flags != 0:
        return {
            "success": False,
            "error": "INVALID_FLAGS",
            "detail": f"Flags {flags} not supported. Only EX_DEFAULT (0) is implemented.",
        }

    timeout = timeout_ms if timeout_ms is not None else 5000
    return execute_code(func_addr, list(args), timeout)


def call_sequence(calls: list[dict], timeout_ms: int = 5000) -> dict:
    """Execute multiple function calls in a SINGLE thread.

    Critical for thread-local state: some APIs (e.g., thread_attach) only affect
    the calling thread. This lets you set up state and call functions in one sequence.

    Args:
        calls: List of call specs, each with:
            - "address": Function address (hex string, int, or "module+offset")
            - "args": List of arguments (same rules as call tool)
        timeout_ms: Maximum wait time for entire sequence

    Returns:
        On success: {"success": True, "result": "0x..."} (result of LAST call)
        On failure: {"success": False, "error": str, "detail": str}

    Example - thread attachment:
        call_sequence([
            {"address": "module.dll+0x1A23720", "args": ["0x25330257170"]},  # thread_attach(domain)
            {"address": "module.dll+0x4D2F10", "args": ["0x25330257170", "Namespace", "Class"]}
        ])
        # Both calls run in SAME thread - attachment persists for second call
    """
    if SESSION.pm is None:
        return {"success": False, "error": "NOT_ATTACHED", "detail": "Call attach first"}

    if not calls:
        return {"success": False, "error": "NO_CALLS", "detail": "calls list is empty"}

    if len(calls) > MAX_CALL_SEQUENCE_CALLS:
        return {
            "success": False,
            "error": "TOO_MANY_CALLS",
            "detail": f"callSequence supports at most {MAX_CALL_SEQUENCE_CALLS} calls",
        }

    ctx = CallContext()

    try:
        # Process each call spec into (func_addr, processed_args)
        processed_calls = []
        all_string_info = []

        for idx, call_spec in enumerate(calls):
            if not isinstance(call_spec, dict):
                return {
                    "success": False,
                    "error": "INVALID_CALL_SPEC",
                    "detail": f"Call {idx} must be dict with 'address' and 'args'",
                }

            addr_raw = call_spec.get("address")
            args_raw = call_spec.get("args", [])

            if addr_raw is None:
                return {"success": False, "error": "MISSING_ADDRESS", "detail": f"Call {idx} missing 'address'"}

            # Parse function address
            try:
                if isinstance(addr_raw, str):
                    func_addr = parse_address(addr_raw)
                else:
                    func_addr = normalize_native_int(addr_raw)
            except ValueError as e:
                return {"success": False, "error": "INVALID_ADDRESS", "detail": f"Call {idx}: {e}"}

            if not SESSION.is_valid_pointer(func_addr):
                return {
                    "success": False,
                    "error": "INVALID_ADDRESS",
                    "detail": f"Call {idx}: {format_address(func_addr)} is not a valid pointer",
                }

            # Process arguments
            processed_args = []
            for i, arg in enumerate(args_raw):
                if isinstance(arg, str):
                    if is_numeric_string(arg):
                        processed_args.append(normalize_native_int(parse_numeric_string(arg)))
                    else:
                        ptr = ctx.alloc_string(arg)
                        processed_args.append(ptr)
                        if len(arg) > 20:
                            all_string_info.append(f"call{idx}.arg{i}='{arg[:20]}' -> {format_address(ptr)}")
                        else:
                            all_string_info.append(f"call{idx}.arg{i}='{arg}' -> {format_address(ptr)}")
                elif isinstance(arg, int):
                    processed_args.append(normalize_native_int(arg))
                elif isinstance(arg, dict) and "result" in arg:
                    result_index = int(arg["result"])
                    if result_index < 1 or result_index > idx:
                        return {
                            "success": False,
                            "error": "INVALID_RESULT_REF",
                            "detail": f"Call {idx} arg {i}: result reference must point to a prior call",
                        }
                    processed_args.append({"result": result_index})
                else:
                    return {
                        "success": False,
                        "error": "INVALID_ARG",
                        "detail": f"Call {idx} arg {i}: unsupported type {type(arg).__name__}",
                    }

            processed_calls.append((func_addr, processed_args))

        # Allocate result storage
        result_size = len(processed_calls) * 8
        ctx.result_addr = SESSION.allocate(result_size, executable=False)
        SESSION.write_bytes(ctx.result_addr, b"\x00" * result_size)

        shellcode = build_multi_call_x64(processed_calls, ctx.result_addr)
        if len(shellcode) > MAX_CALL_SEQUENCE_SHELLCODE_SIZE:
            return {
                "success": False,
                "error": "SHELLCODE_TOO_LARGE",
                "detail": f"callSequence shellcode exceeds {MAX_CALL_SEQUENCE_SHELLCODE_SIZE} bytes",
            }

        ctx.shellcode_addr = SESSION.allocate(len(shellcode), executable=True)
        SESSION.write_bytes(ctx.shellcode_addr, shellcode)

        ctx.thread_handle = SESSION.create_remote_thread(ctx.shellcode_addr)

        completed = SESSION.wait_for_thread(ctx.thread_handle, timeout_ms)

        if not completed:
            return {"success": False, "error": "TIMEOUT", "detail": f"Sequence did not complete within {timeout_ms}ms"}

        result_data = SESSION.read_bytes(ctx.result_addr, result_size)
        call_results = [struct.unpack("<Q", result_data[i * 8 : i * 8 + 8])[0] for i in range(len(processed_calls))]
        result = call_results[-1]

        response = {
            "success": True,
            "result": format_address(result),
            "call_results": [format_address(value) for value in call_results],
            "calls_executed": len(processed_calls),
        }

        if all_string_info:
            response["_string_allocs"] = all_string_info

        return response

    except MemoryError as e:
        return {"success": False, "error": "ALLOCATION_FAILED", "detail": str(e)}
    except OSError as e:
        return {"success": False, "error": "THREAD_FAILED", "detail": str(e)}
    except Exception as e:
        return {"success": False, "error": "EXECUTION_FAILED", "detail": str(e)}
    finally:
        ctx.cleanup()


def alloc_string(s: str, wide: bool = False) -> dict:
    """Manually allocate a string in target process.

    Use this when you need to keep a string allocated across multiple calls.
    Remember to free it with free_alloc() when done.

    Args:
        s: String to allocate
        wide: If True, allocate as UTF-16LE (for Windows APIs)

    Returns:
        {"success": True, "address": "0x..." (hex string), "size": int}
    """
    if SESSION.pm is None:
        return {"success": False, "error": "NOT_ATTACHED", "detail": "Call attach first"}

    try:
        if wide:
            data = s.encode("utf-16-le") + b"\x00\x00"
        else:
            data = s.encode("utf-8") + b"\x00"

        addr = SESSION.allocate(len(data), executable=False)
        SESSION.write_bytes(addr, data)

        return {"success": True, "address": format_address(addr), "size": len(data)}
    except Exception as e:
        return {"success": False, "error": "ALLOCATION_FAILED", "detail": str(e)}


def free_alloc(address: Union[str, int]) -> dict:
    """Free manually allocated memory.

    Args:
        address: Address from alloc_string or similar

    Returns:
        {"success": True} or {"success": False, "error": ..., "detail": ...}
    """
    if SESSION.pm is None:
        return {"success": False, "error": "NOT_ATTACHED", "detail": "Call attach first"}

    try:
        if isinstance(address, str):
            address = parse_address(address)
        if SESSION.free(address):
            return {"success": True}
        else:
            return {"success": False, "error": "FREE_FAILED", "detail": "VirtualFreeEx returned false"}
    except Exception as e:
        return {"success": False, "error": "FREE_FAILED", "detail": str(e)}
