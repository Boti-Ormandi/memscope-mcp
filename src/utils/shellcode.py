"""x64 shellcode builder for remote function calls.

Builds position-independent shellcode that:
1. Sets up x64 Microsoft calling convention
2. Supports float args in XMM0-3
3. Calls target function
4. Captures RAX + XMM0 results
5. Optionally copies from RAX+offset (boxed returns)
6. Optionally copies from output pointer arg
7. Returns cleanly
"""

import struct
from typing import Any


MAX_MULTI_CALL_COUNT = 64
MAX_MULTI_CALL_SHELLCODE_SIZE = 0x10000


def _u64(value: int) -> int:
    return int(value) & 0xFFFFFFFFFFFFFFFF


def _result_ref(arg: Any) -> int | None:
    if isinstance(arg, dict) and "result" in arg:
        return int(arg["result"])
    return None


def build_call_x64(
    func_addr: int,
    args: list[int],
    result_addr: int,
    float_mask: int = 0,
    returns_float: bool = False,
    result_copy_offset: int = 0,
    result_copy_size: int = 0,
    output_arg_index: int = -1,
    output_size: int = 0,
    output_buffer_addr: int = 0,
) -> bytes:
    """Build x64 shellcode to call function and store result.

    Microsoft x64 calling convention:
    - Args 1-4: RCX, RDX, R8, R9 (or XMM0-3 for floats)
    - Args 5+: Stack at [RSP+0x20], [RSP+0x28], etc.
    - 32-byte shadow space required
    - Stack must be 16-byte aligned before CALL
    - Return value in RAX (int) or XMM0 (float)

    Args:
        func_addr: Address of function to call
        args: List of integer arguments (pointers/integers/float bit patterns)
        result_addr: Where to store results (needs 16+ bytes for RAX + XMM0 + boxed)
        float_mask: Bit i = args[i] is float (load to XMMi, positions 0-3 only)
        returns_float: If True, also capture XMM0 to result_addr+8
        result_copy_offset: Offset from RAX for boxed return extraction
        result_copy_size: Bytes to copy from RAX+offset (0 = disabled)
        output_arg_index: Which arg is output pointer (-1 = none)
        output_size: Bytes to copy from output pointer
        output_buffer_addr: Where to store output pointer data

    Returns:
        Shellcode bytes ready for execution

    Result layout at result_addr:
        +0x00: RAX (8 bytes)
        +0x08: XMM0 as uint64 (8 bytes) - if returns_float
        +0x10: boxed data (result_copy_size bytes) - if result_copy_size > 0
        Output data goes to output_buffer_addr (separate location)

    Note on float args:
        Float arguments are passed as 64-bit double-precision values.
        If function expects single-precision float, caller must convert
        the bit pattern appropriately before passing.
    """
    code = bytearray()
    num_args = len(args)

    # Calculate stack space
    # Shadow space (32) + stack args + alignment
    if num_args <= 4:
        stack_space = 0x28  # 32 shadow + 8 alignment
    else:
        extra_args = num_args - 4
        stack_space = 0x20 + extra_args * 8
        # Ensure stack_space ≡ 8 (mod 16) for proper alignment after CALL
        if stack_space % 16 == 0:
            stack_space += 8

    # Prologue: sub rsp, stack_space
    if stack_space < 0x80:
        code += b"\x48\x83\xec" + struct.pack("B", stack_space)
    else:
        code += b"\x48\x81\xec" + struct.pack("<I", stack_space)

    # Load arguments into registers
    # For floats: load to integer reg first, then movq to XMM

    # Arg 0 -> RCX or XMM0
    if num_args >= 1:
        code += b"\x48\xb9" + struct.pack("<Q", _u64(args[0]))  # mov rcx, arg0
        if float_mask & 1:
            code += b"\x66\x48\x0f\x6e\xc1"  # movq xmm0, rcx

    # Arg 1 -> RDX or XMM1
    if num_args >= 2:
        code += b"\x48\xba" + struct.pack("<Q", _u64(args[1]))  # mov rdx, arg1
        if float_mask & 2:
            code += b"\x66\x48\x0f\x6e\xca"  # movq xmm1, rdx

    # Arg 2 -> R8 or XMM2
    if num_args >= 3:
        code += b"\x49\xb8" + struct.pack("<Q", _u64(args[2]))  # mov r8, arg2
        if float_mask & 4:
            code += b"\x66\x49\x0f\x6e\xd0"  # movq xmm2, r8

    # Arg 3 -> R9 or XMM3
    if num_args >= 4:
        code += b"\x49\xb9" + struct.pack("<Q", _u64(args[3]))  # mov r9, arg3
        if float_mask & 8:
            code += b"\x66\x49\x0f\x6e\xd9"  # movq xmm3, r9

    # Stack args (5+) - use RAX as intermediate
    for i, arg in enumerate(args[4:]):
        stack_offset = 0x20 + i * 8
        code += b"\x48\xb8" + struct.pack("<Q", _u64(arg))  # mov rax, imm64
        if stack_offset < 0x80:
            code += b"\x48\x89\x44\x24" + struct.pack("B", stack_offset)
        else:
            code += b"\x48\x89\x84\x24" + struct.pack("<I", stack_offset)

    # Save output arg address to R12 if needed (callee-saved, survives call)
    if output_arg_index >= 0 and output_arg_index < num_args:
        code += b"\x49\xbc" + struct.pack("<Q", _u64(args[output_arg_index]))  # mov r12, output_ptr

    # Call function
    code += b"\x48\xb8" + struct.pack("<Q", _u64(func_addr))  # mov rax, func_addr
    code += b"\xff\xd0"  # call rax

    # Store RAX result
    code += b"\x48\xbb" + struct.pack("<Q", _u64(result_addr))  # mov rbx, result_addr
    code += b"\x48\x89\x03"  # mov [rbx], rax

    # Store XMM0 if float return
    if returns_float:
        code += b"\x66\x48\x0f\x7e\x43\x08"  # movq [rbx+8], xmm0

    # Copy from RAX+offset if boxed return requested
    # Both boxed copy and output copy can execute (not mutually exclusive)
    if result_copy_size > 0:
        # rax still has return value, rbx has result_addr
        # Copy from [rax+offset] to [rbx+0x10]

        # lea rsi, [rax+offset]
        if result_copy_offset == 0:
            code += b"\x48\x89\xc6"  # mov rsi, rax
        elif result_copy_offset < 0x80:
            code += b"\x48\x8d\x70" + struct.pack("B", result_copy_offset)  # lea rsi, [rax+off8]
        else:
            code += b"\x48\x8d\xb0" + struct.pack("<I", result_copy_offset)  # lea rsi, [rax+off32]

        # lea rdi, [rbx+0x10]
        code += b"\x48\x8d\x7b\x10"  # lea rdi, [rbx+0x10]

        # mov rcx, size
        code += b"\x48\xc7\xc1" + struct.pack("<I", result_copy_size)  # mov rcx, imm32

        # rep movsb
        code += b"\xf3\xa4"

    # Copy from output pointer if requested (independent of boxed copy)
    if output_arg_index >= 0 and output_size > 0 and output_buffer_addr != 0:
        # r12 has the output pointer address (saved before call)
        # Copy from [r12] to output_buffer_addr

        code += b"\x4c\x89\xe6"  # mov rsi, r12
        code += b"\x48\xbf" + struct.pack("<Q", _u64(output_buffer_addr))  # mov rdi, output_buffer_addr
        code += b"\x48\xc7\xc1" + struct.pack("<I", output_size)  # mov rcx, size
        code += b"\xf3\xa4"  # rep movsb

    # Epilogue
    if stack_space < 0x80:
        code += b"\x48\x83\xc4" + struct.pack("B", stack_space)
    else:
        code += b"\x48\x81\xc4" + struct.pack("<I", stack_space)

    code += b"\xc3"  # ret

    return bytes(code)


def build_multi_call_x64(calls: list[tuple[int, list[Any]]], result_addr: int) -> bytes:
    """Build x64 shellcode to call multiple functions in sequence.

    All calls execute in the SAME thread - critical for thread-local APIs.
    Stores each call's RAX into result_addr as an array of uint64 values.

    Args:
        calls: List of (func_addr, args_list) tuples to execute in order.
            Args may include {"result": N} descriptors to load the Nth prior
            call result (1-based) as an argument.
        result_addr: Base address of the result array

    Returns:
        Shellcode bytes ready for execution
    """
    if len(calls) > MAX_MULTI_CALL_COUNT:
        raise ValueError(f"too many calls: max {MAX_MULTI_CALL_COUNT}")

    code = bytearray()

    # Calculate max stack space needed across all calls
    max_args = max((len(args) for _, args in calls), default=0)

    if max_args <= 4:
        stack_space = 0x28
    else:
        extra_args = max_args - 4
        stack_space = 0x20 + extra_args * 8
        if stack_space % 16 == 0:
            stack_space += 8

    # Prologue
    if stack_space < 0x80:
        code += b"\x48\x83\xec" + struct.pack("B", stack_space)
    else:
        code += b"\x48\x81\xec" + struct.pack("<I", stack_space)

    def load_arg_to_reg(arg, call_index: int, reg: bytes, mem_opcode: bytes):
        result_index = _result_ref(arg)
        if result_index is None:
            code.extend(reg + struct.pack("<Q", _u64(arg)))
            return
        if result_index < 1 or result_index > call_index:
            raise ValueError("result references must point to a prior call")
        slot_addr = _u64(result_addr + (result_index - 1) * 8)
        code.extend(b"\x48\xb8" + struct.pack("<Q", slot_addr))
        code.extend(mem_opcode)

    # Execute each call
    for call_index, (func_addr, args) in enumerate(calls):
        if len(args) >= 1:
            load_arg_to_reg(args[0], call_index, b"\x48\xb9", b"\x48\x8b\x08")
        if len(args) >= 2:
            load_arg_to_reg(args[1], call_index, b"\x48\xba", b"\x48\x8b\x10")
        if len(args) >= 3:
            load_arg_to_reg(args[2], call_index, b"\x49\xb8", b"\x4c\x8b\x00")
        if len(args) >= 4:
            load_arg_to_reg(args[3], call_index, b"\x49\xb9", b"\x4c\x8b\x08")

        for i, arg in enumerate(args[4:]):
            stack_offset = 0x20 + i * 8
            result_index = _result_ref(arg)
            if result_index is None:
                code += b"\x48\xb8" + struct.pack("<Q", _u64(arg))
            else:
                if result_index < 1 or result_index > call_index:
                    raise ValueError("result references must point to a prior call")
                slot_addr = _u64(result_addr + (result_index - 1) * 8)
                code += b"\x48\xb8" + struct.pack("<Q", slot_addr)
                code += b"\x48\x8b\x00"
            if stack_offset < 0x80:
                code += b"\x48\x89\x44\x24" + struct.pack("B", stack_offset)
            else:
                code += b"\x48\x89\x84\x24" + struct.pack("<I", stack_offset)

        code += b"\x48\xb8" + struct.pack("<Q", _u64(func_addr))
        code += b"\xff\xd0"

        # Store this call's RAX result into result_addr[call_index].
        code += b"\x48\xbb" + struct.pack("<Q", _u64(result_addr + call_index * 8))
        code += b"\x48\x89\x03"

    if not calls:
        code += b"\x48\x31\xc0"
        code += b"\x48\xbb" + struct.pack("<Q", _u64(result_addr))
        code += b"\x48\x89\x03"

    # Epilogue
    if stack_space < 0x80:
        code += b"\x48\x83\xc4" + struct.pack("B", stack_space)
    else:
        code += b"\x48\x81\xc4" + struct.pack("<I", stack_space)

    code += b"\xc3"

    if len(code) > MAX_MULTI_CALL_SHELLCODE_SIZE:
        raise ValueError(f"multi-call shellcode exceeds {MAX_MULTI_CALL_SHELLCODE_SIZE} bytes")

    return bytes(code)


def build_simple_ret(return_value: int = 0) -> bytes:
    """Build shellcode that just returns a value (for testing)."""
    code = bytearray()
    code += b"\x48\xb8" + struct.pack("<Q", _u64(return_value))
    code += b"\xc3"
    return bytes(code)
