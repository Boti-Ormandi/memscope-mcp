"""Minimal x64 instruction length decoder for function prologue analysis.

Table-driven decoder that returns instruction byte lengths and relocation metadata.
Supports RIP-relative displacement rewriting for trampoline stubs.
"""

import struct
from dataclasses import dataclass


class RIPRelativeError(ValueError):
    """Raised when an instruction uses RIP-relative addressing."""


class RelocationOverflowError(ValueError):
    """Raised when a relocated displacement doesn't fit in its field."""


@dataclass
class InstructionInfo:
    """Decoded x64 instruction with relocation metadata."""

    offset: int  # byte offset within the data buffer
    length: int  # instruction length in bytes
    fixup_offset: int  # offset within instruction of RIP-relative field, or -1
    fixup_size: int  # 1 for rel8, 4 for rel32/disp32. 0 if no fixup.
    is_rip_memory: bool  # True if fixup is [RIP+disp32] memory operand.
    # False if fixup is a relative branch (E8/E9/EB/Jcc).
    # Meaningless when fixup_offset == -1.


# Immediate types
NONE = "none"
IMM8 = "imm8"
IMM16 = "imm16"
IMM32 = "imm32"
IMM16_32 = "imm16/32"  # 2 if 0x66 prefix, else 4
IMM32_64 = "imm32/64"  # 8 if REX.W, else 4
SPECIAL_F6 = "special_f6"  # TEST r/m8, imm8 when reg==0, else 0
SPECIAL_F7 = "special_f7"  # TEST r/m, imm16/32 when reg==0, else 0

# One-byte opcodes with relative immediate
RELATIVE_OPCODES_1BYTE = {0xE8, 0xE9, 0xEB} | set(range(0x70, 0x80))
# E8 = CALL rel32, E9 = JMP rel32, EB = JMP short rel8, 70-7F = Jcc short rel8

# Two-byte opcodes (0F xx) with relative immediate
RELATIVE_OPCODES_2BYTE = set(range(0x80, 0x90))
# 0F 80-8F = Jcc near rel32

# One-byte opcode table: opcode -> (has_modrm, imm_type)
OPCODE_TABLE: dict[int, tuple[bool, str]] = {}

# ALU r/m <-> r: 00-03, 08-0B, 10-13, 18-1B, 20-23, 28-2B, 30-33, 38-3B
for base in range(0, 0x40, 8):
    for i in range(4):
        OPCODE_TABLE[base + i] = (True, NONE)

# ALU rAX, imm: 05, 0D, 15, 1D, 25, 2D, 35, 3D
for base in range(0x05, 0x40, 8):
    OPCODE_TABLE[base] = (False, IMM16_32)

# PUSH/POP reg: 50-5F
for i in range(0x50, 0x60):
    OPCODE_TABLE[i] = (False, NONE)

# MOVSXD: 63
OPCODE_TABLE[0x63] = (True, NONE)

# PUSH imm: 68 (imm16/32), 6A (imm8)
OPCODE_TABLE[0x68] = (False, IMM16_32)
OPCODE_TABLE[0x6A] = (False, IMM8)

# IMUL: 69 (imm16/32), 6B (imm8)
OPCODE_TABLE[0x69] = (True, IMM16_32)
OPCODE_TABLE[0x6B] = (True, IMM8)

# Jcc short: 70-7F
for i in range(0x70, 0x80):
    OPCODE_TABLE[i] = (False, IMM8)

# ALU group: 80 (imm8), 81 (imm16/32), 83 (imm8)
OPCODE_TABLE[0x80] = (True, IMM8)
OPCODE_TABLE[0x81] = (True, IMM16_32)
OPCODE_TABLE[0x83] = (True, IMM8)

# TEST r/m, r: 84-85
OPCODE_TABLE[0x84] = (True, NONE)
OPCODE_TABLE[0x85] = (True, NONE)

# XCHG: 86-87
OPCODE_TABLE[0x86] = (True, NONE)
OPCODE_TABLE[0x87] = (True, NONE)

# MOV r/m <-> r: 88-8B
OPCODE_TABLE[0x88] = (True, NONE)
OPCODE_TABLE[0x89] = (True, NONE)
OPCODE_TABLE[0x8A] = (True, NONE)
OPCODE_TABLE[0x8B] = (True, NONE)

# MOV sreg: 8C, 8E
OPCODE_TABLE[0x8C] = (True, NONE)
OPCODE_TABLE[0x8E] = (True, NONE)

# LEA: 8D
OPCODE_TABLE[0x8D] = (True, NONE)

# POP r/m: 8F
OPCODE_TABLE[0x8F] = (True, NONE)

# NOP: 90
OPCODE_TABLE[0x90] = (False, NONE)

# TEST AL, imm8: A8
OPCODE_TABLE[0xA8] = (False, IMM8)

# TEST rAX, imm16/32: A9
OPCODE_TABLE[0xA9] = (False, IMM16_32)

# MOV r8, imm8: B0-B7
for i in range(0xB0, 0xB8):
    OPCODE_TABLE[i] = (False, IMM8)

# MOV r, imm32/64: B8-BF (imm64 with REX.W)
for i in range(0xB8, 0xC0):
    OPCODE_TABLE[i] = (False, IMM32_64)

# Shift by imm8: C0-C1
OPCODE_TABLE[0xC0] = (True, IMM8)
OPCODE_TABLE[0xC1] = (True, IMM8)

# RET imm16: C2
OPCODE_TABLE[0xC2] = (False, IMM16)

# RET: C3
OPCODE_TABLE[0xC3] = (False, NONE)

# MOV r/m, imm: C6 (imm8), C7 (imm16/32)
OPCODE_TABLE[0xC6] = (True, IMM8)
OPCODE_TABLE[0xC7] = (True, IMM16_32)

# LEAVE: C9
OPCODE_TABLE[0xC9] = (False, NONE)

# INT3: CC
OPCODE_TABLE[0xCC] = (False, NONE)

# Shift by 1: D0-D1, Shift by CL: D2-D3
OPCODE_TABLE[0xD0] = (True, NONE)
OPCODE_TABLE[0xD1] = (True, NONE)
OPCODE_TABLE[0xD2] = (True, NONE)
OPCODE_TABLE[0xD3] = (True, NONE)

# CALL rel32: E8
OPCODE_TABLE[0xE8] = (False, IMM32)

# JMP rel32: E9
OPCODE_TABLE[0xE9] = (False, IMM32)

# JMP short: EB
OPCODE_TABLE[0xEB] = (False, IMM8)

# TEST/NOT/NEG/MUL/DIV: F6 (special), F7 (special)
OPCODE_TABLE[0xF6] = (True, SPECIAL_F6)
OPCODE_TABLE[0xF7] = (True, SPECIAL_F7)

# INC/DEC/CALL/JMP/PUSH r/m: FE-FF
OPCODE_TABLE[0xFE] = (True, NONE)
OPCODE_TABLE[0xFF] = (True, NONE)

# Two-byte opcode table (0F xx): opcode2 -> (has_modrm, imm_type)
OPCODE_0F_TABLE: dict[int, tuple[bool, str]] = {}

# Multi-byte NOP: 0F 1F
OPCODE_0F_TABLE[0x1F] = (True, NONE)

# CMOV: 0F 40-4F
for i in range(0x40, 0x50):
    OPCODE_0F_TABLE[i] = (True, NONE)

# Jcc near: 0F 80-8F
for i in range(0x80, 0x90):
    OPCODE_0F_TABLE[i] = (False, IMM32)

# SETcc: 0F 90-9F
for i in range(0x90, 0xA0):
    OPCODE_0F_TABLE[i] = (True, NONE)

# IMUL r, r/m: 0F AF
OPCODE_0F_TABLE[0xAF] = (True, NONE)

# MOVZX: 0F B6-B7
OPCODE_0F_TABLE[0xB6] = (True, NONE)
OPCODE_0F_TABLE[0xB7] = (True, NONE)

# BT/BTS/BTR/BTC + imm8: 0F BA
OPCODE_0F_TABLE[0xBA] = (True, IMM8)

# MOVSX: 0F BE-BF
OPCODE_0F_TABLE[0xBE] = (True, NONE)
OPCODE_0F_TABLE[0xBF] = (True, NONE)

# XADD: 0F C0-C1
OPCODE_0F_TABLE[0xC0] = (True, NONE)
OPCODE_0F_TABLE[0xC1] = (True, NONE)

# BSWAP: 0F C8-CF
for i in range(0xC8, 0xD0):
    OPCODE_0F_TABLE[i] = (False, NONE)


def decode_instruction(data: bytes, offset: int = 0) -> InstructionInfo:
    """Decode a single x64 instruction with relocation metadata.

    Core decoder that returns full instruction details including fixup
    information for RIP-relative operands and relative branches.

    Args:
        data: Raw instruction bytes.
        offset: Starting offset within data.

    Returns:
        InstructionInfo with length and optional fixup metadata.

    Raises:
        ValueError: Unrecognized opcode or truncated data.
    """
    if offset >= len(data):
        raise ValueError("No data at offset")

    pos = offset
    end = len(data)
    has_rex_w = False
    has_66 = False

    # 1. Parse prefix bytes
    while pos < end:
        b = data[pos]
        if 0x40 <= b <= 0x4F:  # REX prefix
            has_rex_w = (b & 0x08) != 0  # REX.W bit
            pos += 1
        elif b == 0x66:  # Operand size override
            has_66 = True
            pos += 1
        elif b == 0x67:  # Address size override
            pos += 1
        elif b in (0xF0, 0xF2, 0xF3):  # LOCK, REPNE, REP
            pos += 1
        else:
            break

    if pos >= end:
        raise ValueError("Data ends in prefix bytes")

    # 2. Read opcode
    opcode = data[pos]
    pos += 1
    is_two_byte = False
    opcode2 = 0

    if opcode == 0x0F:
        if pos >= end:
            raise ValueError("Data ends after 0F prefix")
        opcode2 = data[pos]
        pos += 1
        is_two_byte = True

        if opcode2 not in OPCODE_0F_TABLE:
            raise ValueError(f"Unrecognized two-byte opcode: 0F {opcode2:02X}")
        has_modrm, imm_type = OPCODE_0F_TABLE[opcode2]
    else:
        if opcode not in OPCODE_TABLE:
            raise ValueError(f"Unrecognized opcode: {opcode:02X}")
        has_modrm, imm_type = OPCODE_TABLE[opcode]

    # 3. Parse ModRM if present
    disp_size = 0
    has_sib = False
    modrm_reg = 0
    fixup_offset = -1
    fixup_size = 0
    is_rip_memory = False

    if has_modrm:
        if pos >= end:
            raise ValueError("Data ends before ModRM byte")
        modrm = data[pos]
        pos += 1

        mod = (modrm >> 6) & 3
        modrm_reg = (modrm >> 3) & 7
        rm = modrm & 7

        if mod != 3:  # Not register-direct
            # RIP-relative: mod==0, rm==5
            if mod == 0 and rm == 5:
                # disp32 starts right after ModRM byte
                fixup_offset = pos - offset
                fixup_size = 4
                is_rip_memory = True
                disp_size = 4
            else:
                # SIB byte
                if rm == 4:
                    has_sib = True
                    if pos >= end:
                        raise ValueError("Data ends before SIB byte")
                    sib = data[pos]
                    pos += 1
                    sib_base = sib & 7

                    # mod==0 + SIB base==5 means [disp32 + index*scale] (absolute)
                    if mod == 0 and sib_base == 5:
                        disp_size = 4

                # Displacement
                if mod == 1:
                    disp_size = 1
                elif mod == 2:
                    disp_size = 4
                elif mod == 0 and rm == 4 and not has_sib:
                    pass  # Already handled above

        pos += disp_size

    # 4. Immediate size
    if imm_type == NONE:
        imm_size = 0
    elif imm_type == IMM8:
        imm_size = 1
    elif imm_type == IMM16:
        imm_size = 2
    elif imm_type == IMM32:
        imm_size = 4
    elif imm_type == IMM16_32:
        imm_size = 2 if has_66 else 4
    elif imm_type == IMM32_64:
        imm_size = 8 if has_rex_w else 4
    elif imm_type == SPECIAL_F6:
        imm_size = 1 if modrm_reg == 0 else 0  # TEST has imm8
    elif imm_type == SPECIAL_F7:
        imm_size = (2 if has_66 else 4) if modrm_reg == 0 else 0  # TEST has imm
    else:
        imm_size = 0

    # 5. Check for relative branch fixup (mutually exclusive with RIP-relative memory)
    if fixup_offset < 0 and imm_size > 0:
        if is_two_byte:
            if opcode2 in RELATIVE_OPCODES_2BYTE:
                fixup_offset = pos - offset
                fixup_size = imm_size
                is_rip_memory = False
        else:
            if opcode in RELATIVE_OPCODES_1BYTE:
                fixup_offset = pos - offset
                fixup_size = imm_size
                is_rip_memory = False

    pos += imm_size

    return InstructionInfo(
        offset=offset,
        length=pos - offset,
        fixup_offset=fixup_offset,
        fixup_size=fixup_size,
        is_rip_memory=is_rip_memory,
    )


def instruction_length(data: bytes, offset: int = 0) -> int:
    """Return byte length of the x64 instruction at data[offset:].

    Args:
        data: Raw instruction bytes.
        offset: Starting offset within data.

    Returns:
        Instruction length in bytes.

    Raises:
        ValueError: Unrecognized opcode.
        RIPRelativeError: Instruction uses RIP-relative addressing ([RIP+disp32]).
    """
    info = decode_instruction(data, offset)
    if info.is_rip_memory:
        raise RIPRelativeError(f"RIP-relative addressing at offset {offset}")
    return info.length


def decode_prologue(data: bytes, min_bytes: int) -> tuple[int, int]:
    """Decode instructions from start of data until total bytes >= min_bytes.

    Used to find a safe instruction boundary for JMP patching.

    Args:
        data: Raw bytes from function start.
        min_bytes: Minimum bytes needed (5 for rel32 JMP, 14 for abs64 JMP).

    Returns:
        (total_bytes, instruction_count) - total_bytes >= min_bytes.

    Raises:
        ValueError: Unrecognized opcode encountered before reaching min_bytes.
        RIPRelativeError: RIP-relative instruction in the region.
    """
    total_bytes, instructions = decode_prologue_ex(data, min_bytes)
    for insn in instructions:
        if insn.is_rip_memory:
            raise RIPRelativeError(f"RIP-relative addressing at offset {insn.offset}")
    return total_bytes, len(instructions)


def decode_prologue_ex(data: bytes, min_bytes: int) -> tuple[int, list[InstructionInfo]]:
    """Decode prologue instructions with relocation metadata.

    Unlike decode_prologue(), does NOT raise on RIP-relative instructions.
    Returns instruction details needed for relocation.

    Args:
        data: Raw bytes from function start.
        min_bytes: Minimum bytes needed for JMP patching.

    Returns:
        (total_bytes, instructions) where instructions is a list of InstructionInfo.

    Raises:
        ValueError: Unrecognized opcode before reaching min_bytes.
    """
    total = 0
    instructions = []
    while total < min_bytes:
        info = decode_instruction(data, total)
        instructions.append(info)
        total += info.length
    return total, instructions


def relocate_instructions(
    data: bytes,
    instructions: list[InstructionInfo],
    orig_addr: int,
    new_addr: int,
) -> bytes:
    """Relocate displaced instructions to execute at a new address.

    Adjusts RIP-relative memory operands and relative branch offsets so they
    still reference the same absolute targets from the new location.

    Args:
        data: Original instruction bytes (length = sum of instruction lengths).
        instructions: Decoded instruction metadata from decode_prologue_ex().
        orig_addr: Address where instructions originally lived.
        new_addr: Address where instructions will execute (trampoline stub).

    Returns:
        Relocated bytes, same length as data.

    Raises:
        RelocationOverflowError: If a new displacement doesn't fit in its field.
    """
    relocated = bytearray(data)

    for insn in instructions:
        if insn.fixup_offset < 0:
            continue  # no fixup needed

        # RIP at end of this instruction (where CPU evaluates the displacement)
        orig_rip = orig_addr + insn.offset + insn.length
        new_rip = new_addr + insn.offset + insn.length

        abs_fixup_pos = insn.offset + insn.fixup_offset  # position in byte stream

        if insn.fixup_size == 4:
            old_disp = struct.unpack_from("<i", data, abs_fixup_pos)[0]
            target = orig_rip + old_disp
            new_disp = target - new_rip

            if new_disp < -0x80000000 or new_disp > 0x7FFFFFFF:
                raise RelocationOverflowError(
                    f"Cannot relocate instruction at offset {insn.offset}: "
                    f"new displacement 0x{new_disp & 0xFFFFFFFFFFFFFFFF:X} overflows int32 "
                    f"(trampoline at 0x{new_addr:X} too far from original at 0x{orig_addr:X})"
                )

            struct.pack_into("<i", relocated, abs_fixup_pos, new_disp)

        elif insn.fixup_size == 1:
            old_disp = struct.unpack_from("<b", data, abs_fixup_pos)[0]
            target = orig_rip + old_disp
            new_disp = target - new_rip

            if new_disp < -128 or new_disp > 127:
                raise RelocationOverflowError(
                    f"Cannot relocate short branch at offset {insn.offset}: "
                    f"new displacement {new_disp} overflows int8 "
                    f"(trampoline at 0x{new_addr:X} too far from original at 0x{orig_addr:X})"
                )

            struct.pack_into("<b", relocated, abs_fixup_pos, new_disp)

    return bytes(relocated)
