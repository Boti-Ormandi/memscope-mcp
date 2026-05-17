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

from .disasm import InstructionInfo, relocate_instructions

MAX_MULTI_CALL_COUNT = 64
MAX_MULTI_CALL_SHELLCODE_SIZE = 0x10000

# Ring buffer control block size (must match hooking.py)
RB_CONTROL_SIZE = 0x100


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


def _emit_mem_read(code: bytearray, reg_zero: bytes, reg_disp8: bytes, reg_disp32: bytes, offset: int) -> None:
    """Emit mov reg, [rax+offset] with appropriate ModRM encoding.

    Args:
        code: Bytecode buffer to append to.
        reg_zero: Opcode bytes for [rax] (mod=00).
        reg_disp8: Opcode bytes for [rax+disp8] (mod=01), without the displacement.
        reg_disp32: Opcode bytes for [rax+disp32] (mod=10), without the displacement.
        offset: Byte offset from rax.
    """
    if offset == 0:
        code += reg_zero
    elif -128 <= offset < 128:
        code += reg_disp8 + struct.pack("b", offset)
    else:
        code += reg_disp32 + struct.pack("<i", offset)


def build_hook_trampoline(
    hook_id: int,
    ring_buffer_addr: int,
    hook_type: str,
    buffer_arg: int,
    length_arg: int,
    max_capture: int,
    saved_bytes: bytes,
    target_continue_addr: int,
    stack_args: list[int] | None = None,
    deref_args: dict[int, int] | None = None,
    target_addr: int = 0,
    trampoline_addr: int = 0,
    relocation_info: list[InstructionInfo] | None = None,
    buffer_deref: dict | None = None,
    length_deref: dict | None = None,
) -> tuple[bytes, int]:
    """Build hook trampoline shellcode.

    The trampoline:
    1. Saves register args and callee-saved registers
    2. Claims a ring buffer slot (atomic lock cmpxchg)
    3. Writes entry header (args, timestamp, return addr)
    4. Captures optional stack args as data section prefix
    5. Captures optional buffer data (pre or post call)
    6. Calls original function via stub (saved bytes + JMP back)
    7. Writes return value and marks entry complete

    Args:
        hook_id: Unique hook identifier (embedded as immediate).
        ring_buffer_addr: Base address of ring buffer in target process.
        hook_type: "pre" (capture before call) or "post" (capture after call).
        buffer_arg: 0-indexed arg position (0-3) for buffer pointer, -1 = no buffer.
        length_arg: 0-indexed arg position (0-3) for length, -2 = return value, -1 = fixed.
        max_capture: Fixed capture size when length_arg == -1.
        saved_bytes: Original function prologue bytes to place in stub.
        target_continue_addr: Address to JMP to after stub (original func + saved_length).
        stack_args: List of 0-indexed arg positions >= 4 to capture from stack. Max 7.
        deref_args: Post-call pointer dereference. {0-indexed arg -> read_size (4 or 8)}.
            After the original function returns, dereferences saved arg pointers and
            overwrites the entry's arg fields with the dereferenced values. Only valid
            with hook_type="post".
        target_addr: Address of original function (needed for relocation).
        trampoline_addr: Address where trampoline will be written (needed for relocation).
        relocation_info: Instruction metadata from decode_prologue_ex(). When provided,
            saved_bytes in the stub are relocated to adjust RIP-relative displacements.
        buffer_deref: Indirect buffer pointer source. Dict with 'arg' (0-indexed register arg
            holding struct pointer) and 'offset' (byte offset to buffer pointer within struct).
            Mutually exclusive with buffer_arg >= 0.
        length_deref: Indirect length source. Dict with 'arg' (0-indexed register arg holding
            pointer), 'offset' (byte offset to length field), and 'size' (4 or 8, default 4).
            Mutually exclusive with length_arg >= 0.

    Returns:
        (trampoline_bytes, stub_offset) where stub_offset is the byte offset of the
        original-function stub (saved prologue bytes + JMP back to continue address).
    """
    if stack_args is None:
        stack_args = []

    code = bytearray()
    has_buffer = buffer_arg >= 0 or buffer_deref is not None
    extra_args_count = len(stack_args)
    extra_args_size = extra_args_count * 8  # bytes in data section prefix

    # ARG_OFFSETS: 0-indexed arg -> negative offset from RBP
    ARG_OFFSETS = [0x08, 0x10, 0x18, 0x20]  # arg0=RCX, arg1=RDX, arg2=R8, arg3=R9

    # FRAME_SIZE = 0x80 (128 bytes)
    FRAME_SIZE = 0x80

    # ==================== PROLOGUE ====================
    code += b"\x55"  # push rbp
    code += b"\x48\x89\xe5"  # mov rbp, rsp
    code += b"\x48\x81\xec" + struct.pack("<I", FRAME_SIZE)  # sub rsp, FRAME_SIZE

    # Save original args
    code += b"\x48\x89\x4d\xf8"  # mov [rbp-0x08], rcx  (arg0)
    code += b"\x48\x89\x55\xf0"  # mov [rbp-0x10], rdx  (arg1)
    code += b"\x4c\x89\x45\xe8"  # mov [rbp-0x18], r8   (arg2)
    code += b"\x4c\x89\x4d\xe0"  # mov [rbp-0x20], r9   (arg3)

    # Save callee-saved registers
    code += b"\x48\x89\x5d\xd0"  # mov [rbp-0x30], rbx
    code += b"\x4c\x89\x65\xc8"  # mov [rbp-0x38], r12
    code += b"\x4c\x89\x6d\xc0"  # mov [rbp-0x40], r13
    code += b"\x4c\x89\x75\xb8"  # mov [rbp-0x48], r14
    code += b"\x4c\x89\x7d\xb0"  # mov [rbp-0x50], r15
    code += b"\x48\x89\x75\xa8"  # mov [rbp-0x58], rsi
    code += b"\x48\x89\x7d\xa0"  # mov [rbp-0x60], rdi

    # ==================== RING BUFFER CAPTURE ====================
    # movabs r12, ring_buffer_addr
    code += b"\x49\xbc" + struct.pack("<Q", ring_buffer_addr)

    # Check active flag
    # mov rax, [r12+0x30]  (flags)
    code += b"\x49\x8b\x44\x24\x30"
    # test rax, 1
    code += b"\x48\xa9" + struct.pack("<I", 1)
    # jz skip_capture
    skip_capture_jz = len(code)
    code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz rel32 (patched later)

    # Claim slot: atomic cmpxchg
    # mov rax, [r12]  (read write_index)
    code += b"\x49\x8b\x04\x24"

    # .retry:
    retry_pos = len(code)
    # lea rdx, [rax+1]
    code += b"\x48\x8d\x50\x01"
    # lock cmpxchg [r12], rdx
    code += b"\xf0\x49\x0f\xb1\x14\x24"
    # jnz retry
    jnz_offset = retry_pos - (len(code) + 2)
    code += b"\x75" + struct.pack("b", jnz_offset)
    # rax = our claimed index

    # Check buffer full: (write_idx - read_idx) >= entry_count
    # mov rcx, [r12+0x08]  (read_index)
    code += b"\x49\x8b\x4c\x24\x08"
    # mov rdx, rax
    code += b"\x48\x89\xc2"
    # sub rdx, rcx
    code += b"\x48\x29\xca"
    # cmp rdx, [r12+0x10]  (entry_count)
    code += b"\x49\x3b\x54\x24\x10"
    # jge buffer_full
    buffer_full_jge = len(code)
    code += b"\x0f\x8d" + b"\x00\x00\x00\x00"  # jge rel32 (patched later)

    # Calculate entry address: slot = index & mask, offset = slot * entry_total_size
    # mov rdx, rax
    code += b"\x48\x89\xc2"
    # and rdx, [r12+0x40]  (mask)
    code += b"\x49\x23\x54\x24\x40"
    # imul rdx, [r12+0x38]  (entry_total_size)
    code += b"\x49\x0f\xaf\x54\x24\x38"
    # lea r13, [r12+0x100]  (entries base = control block size)
    code += b"\x4d\x8d\xac\x24" + struct.pack("<I", RB_CONTROL_SIZE)
    # add r13, rdx
    code += b"\x49\x01\xd5"

    # Store entry address for post-call update
    # mov [rbp-0x28], r13
    code += b"\x4c\x89\x6d\xd8"

    # ---- Write entry header ----
    # mov [r13+0x00], rax  (sequence)
    code += b"\x49\x89\x45\x00"
    # mov dword [r13+0x08], 1  (status = WRITING)
    code += b"\x41\xc7\x45\x08" + struct.pack("<I", 1)
    # mov dword [r13+0x0C], hook_id
    code += b"\x41\xc7\x45\x0c" + struct.pack("<I", hook_id)
    # rdtsc -> EDX:EAX
    code += b"\x0f\x31"
    # shl rdx, 32
    code += b"\x48\xc1\xe2\x20"
    # or rax, rdx
    code += b"\x48\x09\xd0"
    # mov [r13+0x10], rax  (timestamp)
    code += b"\x49\x89\x45\x10"
    # mov rax, [rbp+0x08]  (original return address)
    code += b"\x48\x8b\x45\x08"
    # mov [r13+0x18], rax  (return_addr)
    code += b"\x49\x89\x45\x18"

    # Write args from saved locations
    # arg0
    code += b"\x48\x8b\x45\xf8"  # mov rax, [rbp-0x08]
    code += b"\x49\x89\x45\x20"  # mov [r13+0x20], rax
    # arg1
    code += b"\x48\x8b\x45\xf0"  # mov rax, [rbp-0x10]
    code += b"\x49\x89\x45\x28"  # mov [r13+0x28], rax
    # arg2
    code += b"\x48\x8b\x45\xe8"  # mov rax, [rbp-0x18]
    code += b"\x49\x89\x45\x30"  # mov [r13+0x30], rax
    # arg3
    code += b"\x48\x8b\x45\xe0"  # mov rax, [rbp-0x20]
    code += b"\x49\x89\x45\x38"  # mov [r13+0x38], rax

    # ---- Stack arg capture ----
    # Stack args at [rbp + 0x08*(arg_idx+2)] in caller's frame
    # Written to data section at [r13+0x50+i*8]
    for i, internal_arg_idx in enumerate(stack_args):
        frame_offset = 0x08 * (internal_arg_idx + 2)
        data_offset = 0x50 + i * 8
        # mov rax, [rbp+frame_offset]
        if frame_offset < 0x80:
            code += b"\x48\x8b\x45" + struct.pack("b", frame_offset)
        else:
            code += b"\x48\x8b\x85" + struct.pack("<i", frame_offset)
        # mov [r13+data_offset], rax
        if data_offset < 0x80:
            code += b"\x49\x89\x45" + struct.pack("b", data_offset)
        else:
            code += b"\x49\x89\x85" + struct.pack("<i", data_offset)

    # ---- Buffer capture (pre-call or post-call setup) ----
    # Flags value: bit 0 = has_data, bits 8-11 = extra_args_count
    flags_no_data = extra_args_count << 8
    flags_has_data = 1 | (extra_args_count << 8)

    if hook_type == "pre" and has_buffer:
        # Collect all jump fixups that target the no_buffer label
        no_buffer_fixups = []

        # ---- Load buffer pointer into RSI ----
        if buffer_deref is not None:
            deref_arg_off = ARG_OFFSETS[buffer_deref["arg"]]
            # mov rax, [rbp-X]  ; load struct pointer from saved arg
            code += b"\x48\x8b\x45" + struct.pack("b", -deref_arg_off)
            # test rax, rax
            code += b"\x48\x85\xc0"
            no_buffer_fixups.append(len(code))
            code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz no_buffer
            # mov rsi, [rax + offset]  ; load buffer pointer from struct
            _emit_mem_read(code, b"\x48\x8b\x30", b"\x48\x8b\x70", b"\x48\x8b\xb0", buffer_deref["offset"])
        else:
            buf_offset = ARG_OFFSETS[buffer_arg]
            code += b"\x48\x8b\x75" + struct.pack("b", -buf_offset)  # mov rsi, [rbp-X]
        # test rsi, rsi
        code += b"\x48\x85\xf6"
        no_buffer_fixups.append(len(code))
        code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz no_buffer

        # ---- Load length into EAX ----
        if length_deref is not None:
            ld_arg_off = ARG_OFFSETS[length_deref["arg"]]
            # mov rax, [rbp-X]  ; load pointer from saved arg
            code += b"\x48\x8b\x45" + struct.pack("b", -ld_arg_off)
            # test rax, rax
            code += b"\x48\x85\xc0"
            no_buffer_fixups.append(len(code))
            code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz no_buffer
            ld_off = length_deref["offset"]
            if length_deref.get("size", 4) == 4:
                _emit_mem_read(code, b"\x8b\x00", b"\x8b\x40", b"\x8b\x80", ld_off)
            else:
                _emit_mem_read(code, b"\x48\x8b\x00", b"\x48\x8b\x40", b"\x48\x8b\x80", ld_off)
            # test eax, eax
            code += b"\x85\xc0"
            no_buffer_fixups.append(len(code))
            code += b"\x0f\x8e" + b"\x00\x00\x00\x00"  # jle no_buffer
        elif length_arg >= 0:
            len_offset = ARG_OFFSETS[length_arg]
            code += b"\x8b\x45" + struct.pack("b", -len_offset)  # mov eax, [rbp-X]
            code += b"\x85\xc0"  # test eax, eax
            no_buffer_fixups.append(len(code))
            code += b"\x0f\x8e" + b"\x00\x00\x00\x00"  # jle no_buffer
        elif length_arg == -1:
            code += b"\xb8" + struct.pack("<I", max_capture)  # mov eax, max_capture

        # ---- data_length, clamp, captured_length, flags, copy ----
        # mov [r13+0x44], eax  (data_length)
        code += b"\x41\x89\x45\x44"

        # Clamp: edx = max_data_size - extra_args_size
        code += b"\x41\x8b\x54\x24\x18"  # mov edx, [r12+0x18]
        if extra_args_size > 0:
            code += b"\x81\xea" + struct.pack("<I", extra_args_size)  # sub edx, extra_args_size
        code += b"\x39\xd0"  # cmp eax, edx
        code += b"\x76\x02"  # jbe +2
        code += b"\x89\xd0"  # mov eax, edx

        code += b"\x41\x89\x45\x48"  # mov [r13+0x48], eax  (captured_length)
        code += b"\x41\xc7\x45\x4c" + struct.pack("<I", flags_has_data)  # flags

        # lea rdi, [r13+0x50+extra_args_size]
        dest_offset = 0x50 + extra_args_size
        if dest_offset < 0x80:
            code += b"\x49\x8d\x7d" + struct.pack("b", dest_offset)
        else:
            code += b"\x49\x8d\xbd" + struct.pack("<i", dest_offset)
        code += b"\x89\xc1"  # mov ecx, eax
        code += b"\xf3\xa4"  # rep movsb
        # jmp buffer_done_pre
        buffer_done_pre_jmp = len(code)
        code += b"\xe9" + b"\x00\x00\x00\x00"

        # no_buffer_pre: (patch all fixups)
        no_buffer_pre_target = len(code)
        for fixup_pos in no_buffer_fixups:
            struct.pack_into("<i", code, fixup_pos + 2, no_buffer_pre_target - (fixup_pos + 6))

        # Zero data fields
        code += b"\x41\xc7\x45\x44" + struct.pack("<I", 0)  # data_length = 0
        code += b"\x41\xc7\x45\x48" + struct.pack("<I", 0)  # captured_length = 0
        code += b"\x41\xc7\x45\x4c" + struct.pack("<I", flags_no_data)  # flags

        # buffer_done_pre:
        buffer_done_pre_target = len(code)
        struct.pack_into("<i", code, buffer_done_pre_jmp + 1, buffer_done_pre_target - (buffer_done_pre_jmp + 5))

    elif hook_type == "pre" and not has_buffer:
        # No buffer capture -- just set fields
        code += b"\x41\xc7\x45\x44" + struct.pack("<I", 0)  # data_length = 0
        code += b"\x41\xc7\x45\x48" + struct.pack("<I", 0)  # captured_length = 0
        code += b"\x41\xc7\x45\x4c" + struct.pack("<I", flags_no_data)  # flags

    elif hook_type == "post":
        # Defer buffer capture until after call
        code += b"\x41\xc7\x45\x44" + struct.pack("<I", 0)  # data_length = 0
        code += b"\x41\xc7\x45\x48" + struct.pack("<I", 0)  # captured_length = 0
        code += b"\x41\xc7\x45\x4c" + struct.pack("<I", flags_no_data)  # flags (updated post-call if buffer)

    # jmp call_original
    call_original_jmp = len(code)
    code += b"\xe9" + b"\x00\x00\x00\x00"  # patched later

    # ---- buffer_full: ----
    buffer_full_target = len(code)
    struct.pack_into("<i", code, buffer_full_jge + 2, buffer_full_target - (buffer_full_jge + 6))
    # lock inc qword [r12+0x28]  (total_dropped++)
    code += b"\xf0\x49\xff\x44\x24\x28"

    # ---- skip_capture: ----
    skip_capture_target = len(code)
    struct.pack_into("<i", code, skip_capture_jz + 2, skip_capture_target - (skip_capture_jz + 6))
    # mov qword [rbp-0x28], 0  (no entry to update)
    code += b"\x48\xc7\x45\xd8" + struct.pack("<i", 0)

    # ==================== CALL ORIGINAL FUNCTION ====================
    call_original_target = len(code)
    struct.pack_into("<i", code, call_original_jmp + 1, call_original_target - (call_original_jmp + 5))

    # Restore args for original function call
    code += b"\x48\x8b\x4d\xf8"  # mov rcx, [rbp-0x08]  (arg0)
    code += b"\x48\x8b\x55\xf0"  # mov rdx, [rbp-0x10]  (arg1)
    code += b"\x4c\x8b\x45\xe8"  # mov r8, [rbp-0x18]   (arg2)
    code += b"\x4c\x8b\x4d\xe0"  # mov r9, [rbp-0x20]   (arg3)
    # sub rsp, 0x20  (shadow space)
    code += b"\x48\x83\xec\x20"
    # call original_function_stub (E8 rel32) -- patched after we know stub position
    call_insn_pos = len(code)
    code += b"\xe8" + b"\x00\x00\x00\x00"  # patched later
    # add rsp, 0x20
    code += b"\x48\x83\xc4\x20"
    # mov r15, rax  (save return value)
    code += b"\x49\x89\xc7"

    # ==================== POST-CALL UPDATE ====================
    # mov r13, [rbp-0x28]  (entry address, 0 if skipped)
    code += b"\x4c\x8b\x6d\xd8"
    # test r13, r13
    code += b"\x4d\x85\xed"
    # jz epilogue
    epilogue_jz = len(code)
    code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # patched later

    # Write return value: mov dword [r13+0x40], r15d
    code += b"\x45\x89\x7d\x40"

    # ---- Post-call buffer capture ----
    if hook_type == "post" and has_buffer:
        no_buffer_post_fixups = []

        # ---- Load length into EAX (before buffer ptr so we can test early) ----
        if length_deref is not None:
            ld_arg_off = ARG_OFFSETS[length_deref["arg"]]
            code += b"\x48\x8b\x45" + struct.pack("b", -ld_arg_off)  # mov rax, [rbp-X]
            code += b"\x48\x85\xc0"  # test rax, rax
            no_buffer_post_fixups.append(len(code))
            code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz no_buffer
            ld_off = length_deref["offset"]
            if length_deref.get("size", 4) == 4:
                _emit_mem_read(code, b"\x8b\x00", b"\x8b\x40", b"\x8b\x80", ld_off)
            else:
                _emit_mem_read(code, b"\x48\x8b\x00", b"\x48\x8b\x40", b"\x48\x8b\x80", ld_off)
            code += b"\x85\xc0"  # test eax, eax
            no_buffer_post_fixups.append(len(code))
            code += b"\x0f\x8e" + b"\x00\x00\x00\x00"  # jle no_buffer
        elif length_arg == -2:  # use return value
            code += b"\x45\x85\xff"  # test r15d, r15d
            no_buffer_post_fixups.append(len(code))
            code += b"\x0f\x8e" + b"\x00\x00\x00\x00"  # jle no_buffer
            code += b"\x44\x89\xf8"  # mov eax, r15d
        elif length_arg >= 0:
            len_offset = ARG_OFFSETS[length_arg]
            code += b"\x8b\x45" + struct.pack("b", -len_offset)  # mov eax, [rbp-X]
            code += b"\x85\xc0"  # test eax, eax
            no_buffer_post_fixups.append(len(code))
            code += b"\x0f\x8e" + b"\x00\x00\x00\x00"  # jle no_buffer
        elif length_arg == -1:
            code += b"\xb8" + struct.pack("<I", max_capture)  # mov eax, max_capture

        # ---- Load buffer pointer into RSI ----
        if buffer_deref is not None:
            deref_arg_off = ARG_OFFSETS[buffer_deref["arg"]]
            code += b"\x48\x8b\x45" + struct.pack("b", -deref_arg_off)  # mov rax, [rbp-X]
            # Save eax (length) to r14d before clobbering rax
            code += b"\x41\x89\xc6"  # mov r14d, eax
            code += b"\x48\x85\xc0"  # test rax, rax
            no_buffer_post_fixups.append(len(code))
            code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz no_buffer
            _emit_mem_read(code, b"\x48\x8b\x30", b"\x48\x8b\x70", b"\x48\x8b\xb0", buffer_deref["offset"])
            code += b"\x44\x89\xf0"  # mov eax, r14d  ; restore length
        else:
            buf_offset = ARG_OFFSETS[buffer_arg]
            code += b"\x48\x8b\x75" + struct.pack("b", -buf_offset)  # mov rsi, [rbp-X]
        code += b"\x48\x85\xf6"  # test rsi, rsi
        no_buffer_post_fixups.append(len(code))
        code += b"\x0f\x84" + b"\x00\x00\x00\x00"  # jz no_buffer

        # ---- data_length, clamp, captured_length, flags, copy ----
        code += b"\x41\x89\x45\x44"  # mov [r13+0x44], eax

        code += b"\x41\x8b\x54\x24\x18"  # mov edx, [r12+0x18]
        if extra_args_size > 0:
            code += b"\x81\xea" + struct.pack("<I", extra_args_size)
        code += b"\x39\xd0"  # cmp eax, edx
        code += b"\x76\x02"  # jbe +2
        code += b"\x89\xd0"  # mov eax, edx

        code += b"\x41\x89\x45\x48"  # mov [r13+0x48], eax
        code += b"\x41\xc7\x45\x4c" + struct.pack("<I", flags_has_data)

        dest_offset = 0x50 + extra_args_size
        if dest_offset < 0x80:
            code += b"\x49\x8d\x7d" + struct.pack("b", dest_offset)
        else:
            code += b"\x49\x8d\xbd" + struct.pack("<i", dest_offset)
        code += b"\x89\xc1"  # mov ecx, eax
        code += b"\xf3\xa4"  # rep movsb
        buffer_done_post_jmp = len(code)
        code += b"\xe9" + b"\x00\x00\x00\x00"  # jmp buffer_done_post

        # no_buffer_post: (patch all fixups)
        no_buffer_post_target = len(code)
        for fixup_pos in no_buffer_post_fixups:
            struct.pack_into("<i", code, fixup_pos + 2, no_buffer_post_target - (fixup_pos + 6))

        # buffer_done_post:
        buffer_done_post_target = len(code)
        struct.pack_into("<i", code, buffer_done_post_jmp + 1, buffer_done_post_target - (buffer_done_post_jmp + 5))

    # ---- Post-call deref_args: dereference output pointers ----
    if deref_args:
        # Entry offsets for arg0-arg3: 0x20, 0x28, 0x30, 0x38
        ENTRY_ARG_OFFSETS = {0: 0x20, 1: 0x28, 2: 0x30, 3: 0x38}
        for arg_idx, read_size in sorted(deref_args.items()):
            rbp_offset = ARG_OFFSETS[arg_idx]  # negative offset from rbp where arg was saved
            entry_offset = ENTRY_ARG_OFFSETS[arg_idx]

            # mov rax, [rbp - rbp_offset]  ; load saved arg (pointer value)
            code += b"\x48\x8b\x45" + struct.pack("b", -rbp_offset)
            # test rax, rax  ; NULL check
            code += b"\x48\x85\xc0"
            # jz skip_deref  (2-byte opcode + 1-byte displacement, patched)
            skip_jz_pos = len(code)
            code += b"\x74\x00"  # jz rel8, patched below

            if read_size == 4:
                # mov eax, [rax]  ; dereference 4 bytes (zero-extends to 64-bit)
                code += b"\x8b\x00"
            else:
                # mov rax, [rax]  ; dereference 8 bytes
                code += b"\x48\x8b\x00"

            # mov [r13 + entry_offset], rax  ; overwrite entry arg field
            if entry_offset < 0x80:
                code += b"\x49\x89\x45" + struct.pack("b", entry_offset)
            else:
                code += b"\x49\x89\x85" + struct.pack("<i", entry_offset)

            # Patch the jz to skip to here
            skip_target = len(code)
            code[skip_jz_pos + 1] = skip_target - (skip_jz_pos + 2)

    # Mark entry complete: mov dword [r13+0x08], 2  (STATUS_COMPLETE)
    code += b"\x41\xc7\x45\x08" + struct.pack("<I", 2)
    # lock inc qword [r12+0x20]  (total_captured++)
    code += b"\xf0\x49\xff\x44\x24\x20"

    # ==================== EPILOGUE ====================
    epilogue_target = len(code)
    struct.pack_into("<i", code, epilogue_jz + 2, epilogue_target - (epilogue_jz + 6))

    # mov rax, r15  (restore return value)
    code += b"\x4c\x89\xf8"

    # Restore callee-saved registers
    code += b"\x48\x8b\x5d\xd0"  # mov rbx, [rbp-0x30]
    code += b"\x4c\x8b\x65\xc8"  # mov r12, [rbp-0x38]
    code += b"\x4c\x8b\x6d\xc0"  # mov r13, [rbp-0x40]
    code += b"\x4c\x8b\x75\xb8"  # mov r14, [rbp-0x48]
    code += b"\x4c\x8b\x7d\xb0"  # mov r15, [rbp-0x50]
    code += b"\x48\x8b\x75\xa8"  # mov rsi, [rbp-0x58]
    code += b"\x48\x8b\x7d\xa0"  # mov rdi, [rbp-0x60]

    # mov rsp, rbp
    code += b"\x48\x89\xec"
    # pop rbp
    code += b"\x5d"
    # ret
    code += b"\xc3"

    # ==================== ORIGINAL FUNCTION STUB ====================
    stub_offset = len(code)

    # Patch the CALL instruction to point to the stub
    call_rel32 = stub_offset - (call_insn_pos + 5)
    struct.pack_into("<i", code, call_insn_pos + 1, call_rel32)

    # Append saved prologue bytes (relocated if needed)
    if relocation_info is not None:
        if not trampoline_addr:
            raise ValueError("trampoline_addr required when relocation_info is provided")
        stub_addr = trampoline_addr + stub_offset
        code += relocate_instructions(saved_bytes, relocation_info, target_addr, stub_addr)
    else:
        code += saved_bytes

    # JMP abs64 to target_continue_addr: FF 25 00 00 00 00 <addr64>
    code += b"\xff\x25\x00\x00\x00\x00"
    code += struct.pack("<Q", target_continue_addr)

    return bytes(code), stub_offset
