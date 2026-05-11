"""Tests for RIP-relative instruction relocation (Phase 5b).

Covers decode_instruction(), decode_prologue_ex(), relocate_instructions(),
and backward compatibility of instruction_length() / decode_prologue().
"""

import struct

import pytest

from src.utils.disasm import (
    RelocationOverflowError,
    RIPRelativeError,
    decode_instruction,
    decode_prologue,
    decode_prologue_ex,
    instruction_length,
    relocate_instructions,
)

# ============================================================================
# TestDecodeInstruction
# ============================================================================


class TestDecodeInstruction:
    """Test decode_instruction() returns correct InstructionInfo fields."""

    def test_push_rbp_no_fixup(self):
        info = decode_instruction(b"\x55")
        assert info.length == 1
        assert info.fixup_offset == -1
        assert info.fixup_size == 0

    def test_sub_rsp_imm8_no_fixup(self):
        # 48 83 EC 20 = sub rsp, 0x20
        info = decode_instruction(b"\x48\x83\xec\x20")
        assert info.length == 4
        assert info.fixup_offset == -1
        assert info.fixup_size == 0

    def test_lea_rip_relative(self):
        # 48 8D 05 00 10 00 00 = lea rax, [rip+0x1000]
        info = decode_instruction(b"\x48\x8d\x05\x00\x10\x00\x00")
        assert info.length == 7
        assert info.fixup_offset == 3
        assert info.fixup_size == 4
        assert info.is_rip_memory is True

    def test_mov_rcx_rip_relative(self):
        # 48 8B 0D 00 20 00 00 = mov rcx, [rip+0x2000]
        info = decode_instruction(b"\x48\x8b\x0d\x00\x20\x00\x00")
        assert info.length == 7
        assert info.fixup_offset == 3
        assert info.fixup_size == 4
        assert info.is_rip_memory is True

    def test_cmp_rax_rip_relative(self):
        # 48 3B 05 78 56 00 00 = cmp rax, [rip+0x5678]
        info = decode_instruction(b"\x48\x3b\x05\x78\x56\x00\x00")
        assert info.length == 7
        assert info.fixup_offset == 3
        assert info.fixup_size == 4
        assert info.is_rip_memory is True

    def test_mov_dword_rip_with_imm(self):
        # C7 05 00 10 00 00 42 00 00 00 = mov dword [rip+0x1000], 0x42
        info = decode_instruction(b"\xc7\x05\x00\x10\x00\x00\x42\x00\x00\x00")
        assert info.length == 10
        assert info.fixup_offset == 2  # right after opcode + ModRM
        assert info.fixup_size == 4
        assert info.is_rip_memory is True

    def test_call_rel32(self):
        # E8 00 10 00 00 = call +0x1000
        info = decode_instruction(b"\xe8\x00\x10\x00\x00")
        assert info.length == 5
        assert info.fixup_offset == 1
        assert info.fixup_size == 4
        assert info.is_rip_memory is False

    def test_jmp_rel32(self):
        # E9 00 10 00 00 = jmp +0x1000
        info = decode_instruction(b"\xe9\x00\x10\x00\x00")
        assert info.length == 5
        assert info.fixup_offset == 1
        assert info.fixup_size == 4
        assert info.is_rip_memory is False

    def test_jmp_short(self):
        # EB 0A = jmp short +10
        info = decode_instruction(b"\xeb\x0a")
        assert info.length == 2
        assert info.fixup_offset == 1
        assert info.fixup_size == 1
        assert info.is_rip_memory is False

    def test_jz_short(self):
        # 74 0A = jz short +10
        info = decode_instruction(b"\x74\x0a")
        assert info.length == 2
        assert info.fixup_offset == 1
        assert info.fixup_size == 1
        assert info.is_rip_memory is False

    def test_jz_near_rel32(self):
        # 0F 84 00 10 00 00 = jz near +0x1000
        info = decode_instruction(b"\x0f\x84\x00\x10\x00\x00")
        assert info.length == 6
        assert info.fixup_offset == 2
        assert info.fixup_size == 4
        assert info.is_rip_memory is False

    def test_mov_eax_imm32_no_fixup(self):
        # B8 01 00 00 00 = mov eax, 1
        info = decode_instruction(b"\xb8\x01\x00\x00\x00")
        assert info.length == 5
        assert info.fixup_offset == -1
        assert info.fixup_size == 0

    def test_call_rip_relative_indirect(self):
        # FF 15 00 10 00 00 = call [rip+0x1000]
        info = decode_instruction(b"\xff\x15\x00\x10\x00\x00")
        assert info.length == 6
        assert info.fixup_offset == 2  # after opcode(FF) + ModRM(15)
        assert info.fixup_size == 4
        assert info.is_rip_memory is True

    def test_jmp_rip_relative_indirect(self):
        # FF 25 00 10 00 00 = jmp [rip+0x1000]
        info = decode_instruction(b"\xff\x25\x00\x10\x00\x00")
        assert info.length == 6
        assert info.fixup_offset == 2
        assert info.fixup_size == 4
        assert info.is_rip_memory is True

    def test_offset_parameter(self):
        # nop + lea rax, [rip+X]
        data = b"\x90\x48\x8d\x05\x00\x10\x00\x00"
        info = decode_instruction(data, offset=1)
        assert info.offset == 1
        assert info.length == 7
        assert info.fixup_offset == 3
        assert info.is_rip_memory is True

    def test_jne_near_rel32(self):
        # 0F 85 00 10 00 00 = jne near +0x1000
        info = decode_instruction(b"\x0f\x85\x00\x10\x00\x00")
        assert info.length == 6
        assert info.fixup_offset == 2
        assert info.fixup_size == 4
        assert info.is_rip_memory is False


# ============================================================================
# TestDecodePrologueEx
# ============================================================================


class TestDecodePrologueEx:
    def test_prologue_with_rip_relative_does_not_raise(self):
        # push rbp (1) + lea rax, [rip+X] (7) + sub rsp, 0x20 (4)
        data = b"\x55\x48\x8d\x05\x00\x10\x00\x00\x48\x83\xec\x20"
        total, instructions = decode_prologue_ex(data, min_bytes=5)
        assert total >= 5
        assert len(instructions) >= 2
        # The LEA should have fixup info
        lea = instructions[1]
        assert lea.fixup_offset == 3
        assert lea.is_rip_memory is True

    def test_prologue_without_rip_relative(self):
        # push rbp (1) + mov rbp, rsp (3) + sub rsp, 0x20 (4) = 8
        data = b"\x55\x48\x89\xe5\x48\x83\xec\x20"
        total, instructions = decode_prologue_ex(data, min_bytes=5)
        assert total == 8
        assert len(instructions) == 3
        for insn in instructions:
            assert insn.fixup_offset == -1

    def test_prologue_with_multiple_rip_relative(self):
        # lea rax, [rip+X] (7) + lea rcx, [rip+Y] (7) = 14
        data = b"\x48\x8d\x05\x00\x10\x00\x00\x48\x8d\x0d\x00\x20\x00\x00"
        total, instructions = decode_prologue_ex(data, min_bytes=5)
        assert total >= 7
        assert instructions[0].fixup_offset == 3
        assert instructions[0].is_rip_memory is True
        if len(instructions) > 1:
            assert instructions[1].fixup_offset == 3
            assert instructions[1].is_rip_memory is True

    def test_unrecognized_opcode_raises(self):
        with pytest.raises(ValueError, match="Unrecognized opcode"):
            decode_prologue_ex(b"\x0e", min_bytes=1)

    def test_returns_all_instructions(self):
        # push rbp (1) + mov rbp, rsp (3) + sub rsp, 0x20 (4) + mov [rsp+8], rbx (5)
        data = b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x5c\x24\x08"
        total, instructions = decode_prologue_ex(data, min_bytes=5)
        assert total == 8  # 1 + 3 + 4
        assert len(instructions) == 3
        assert instructions[0].length == 1
        assert instructions[1].length == 3
        assert instructions[2].length == 4


# ============================================================================
# TestRelocateInstructions
# ============================================================================


class TestRelocateInstructions:
    def test_single_rip_relative_lea(self):
        # 48 8D 05 00 10 00 00 = lea rax, [rip+0x1000]
        data = b"\x48\x8d\x05\x00\x10\x00\x00"
        orig_addr = 0x7FF600001000
        new_addr = 0x7FF600005000

        _, instructions = decode_prologue_ex(data, min_bytes=1)
        relocated = relocate_instructions(data, instructions, orig_addr, new_addr)

        # orig_rip = 0x7FF600001007, target = orig_rip + 0x1000 = 0x7FF600002007
        # new_rip = 0x7FF600005007, new_disp = 0x7FF600002007 - 0x7FF600005007 = -0x3000
        new_disp = struct.unpack_from("<i", relocated, 3)[0]
        assert new_disp == -0x3000

    def test_multiple_instructions_one_rip_relative(self):
        # push rbp (1) + lea rax, [rip+0x1000] (7) + sub rsp, 0x20 (4)
        data = b"\x55\x48\x8d\x05\x00\x10\x00\x00\x48\x83\xec\x20"
        orig_addr = 0x7FF600001000
        new_addr = 0x7FF600005000

        _, instructions = decode_prologue_ex(data, min_bytes=5)
        relocated = relocate_instructions(data, instructions, orig_addr, new_addr)

        # push rbp unchanged
        assert relocated[0] == 0x55
        # sub rsp, 0x20 unchanged
        assert relocated[8:12] == data[8:12]

        # LEA disp32 adjusted
        # LEA is at offset 1, length 7. orig_rip = orig_addr + 1 + 7 = orig_addr + 8
        # target = (orig_addr + 8) + 0x1000 = 0x7FF600002008
        # new_rip = new_addr + 8 = 0x7FF600005008
        # new_disp = 0x7FF600002008 - 0x7FF600005008 = -0x3000
        new_disp = struct.unpack_from("<i", relocated, 4)[0]  # offset 1 + fixup_offset 3 = 4
        assert new_disp == -0x3000

    def test_call_rel32_relocation(self):
        # E8 00 10 00 00 = call +0x1000
        data = b"\xe8\x00\x10\x00\x00"
        orig_addr = 0x7FF600001000
        new_addr = 0x7FF600002000

        _, instructions = decode_prologue_ex(data, min_bytes=1)
        relocated = relocate_instructions(data, instructions, orig_addr, new_addr)

        # orig_rip = orig_addr + 5 = 0x7FF600001005
        # target = orig_rip + 0x1000 = 0x7FF600002005
        # new_rip = new_addr + 5 = 0x7FF600002005
        # new_disp = target - new_rip = 0
        new_rel32 = struct.unpack_from("<i", relocated, 1)[0]
        assert new_rel32 == 0

    def test_no_fixups_needed(self):
        # push rbp; mov rbp, rsp; sub rsp, 0x20
        data = b"\x55\x48\x89\xe5\x48\x83\xec\x20"
        _, instructions = decode_prologue_ex(data, min_bytes=5)

        relocated = relocate_instructions(data, instructions, 0x1000, 0x5000)
        assert relocated == data  # unchanged

    def test_overflow_int32(self):
        # lea rax, [rip+0x7FFFFFF0]  -- near max positive disp
        data = b"\x48\x8d\x05" + struct.pack("<i", 0x7FFFFFF0)
        _, instructions = decode_prologue_ex(data, min_bytes=1)

        # Move trampoline far enough that new_disp overflows
        orig_addr = 0x100000000
        new_addr = 0x280000000  # delta = 0x180000000 > int32 max

        with pytest.raises(RelocationOverflowError, match="overflows int32"):
            relocate_instructions(data, instructions, orig_addr, new_addr)

    def test_overflow_int8_short_branch(self):
        # EB 7F = jmp short +127 (max positive)
        data = b"\xeb\x7f"
        _, instructions = decode_prologue_ex(data, min_bytes=1)

        # Moving 256 bytes away: new_disp = 127 - 256 = -129, overflows int8
        with pytest.raises(RelocationOverflowError, match="overflows int8"):
            relocate_instructions(data, instructions, 0x1000, 0x1100)

    def test_two_rip_relative_instructions(self):
        # lea rax, [rip+0x1000] (7) + mov rcx, [rip+0x2000] (7) = 14 total
        data = (
            b"\x48\x8d\x05\x00\x10\x00\x00"  # lea rax, [rip+0x1000]
            b"\x48\x8b\x0d\x00\x20\x00\x00"  # mov rcx, [rip+0x2000]
        )
        orig_addr = 0x7FF600001000
        new_addr = 0x7FF600005000

        # min_bytes=14 to force both instructions to be decoded
        _, instructions = decode_prologue_ex(data, min_bytes=14)
        assert len(instructions) == 2
        relocated = relocate_instructions(data, instructions, orig_addr, new_addr)

        # First LEA: orig_rip = orig_addr + 7 = 0x7FF600001007
        # target = orig_rip + 0x1000 = 0x7FF600002007
        # new_rip = new_addr + 7 = 0x7FF600005007
        # new_disp = 0x7FF600002007 - 0x7FF600005007 = -0x3000
        disp1 = struct.unpack_from("<i", relocated, 3)[0]
        assert disp1 == -0x3000

        # Second MOV: orig_rip = orig_addr + 14 = 0x7FF60000100E
        # target = orig_rip + 0x2000 = 0x7FF60000300E
        # new_rip = new_addr + 14 = 0x7FF60000500E
        # new_disp = 0x7FF60000300E - 0x7FF60000500E = -0x2000
        disp2 = struct.unpack_from("<i", relocated, 10)[0]  # offset 7 + fixup_offset 3 = 10
        assert disp2 == -0x2000

    def test_jmp_short_relocation_within_range(self):
        # EB 10 = jmp short +16
        data = b"\xeb\x10"
        orig_addr = 0x1000
        new_addr = 0x1008  # 8 bytes away, new_disp = 16 - 8 = 8

        _, instructions = decode_prologue_ex(data, min_bytes=1)
        relocated = relocate_instructions(data, instructions, orig_addr, new_addr)

        new_disp = struct.unpack_from("<b", relocated, 1)[0]
        assert new_disp == 8

    def test_jcc_near_relocation(self):
        # 0F 84 00 10 00 00 = jz near +0x1000
        data = b"\x0f\x84\x00\x10\x00\x00"
        orig_addr = 0x7FF600001000
        new_addr = 0x7FF600003000

        _, instructions = decode_prologue_ex(data, min_bytes=1)
        relocated = relocate_instructions(data, instructions, orig_addr, new_addr)

        # orig_rip = orig_addr + 6, target = orig_rip + 0x1000
        # new_rip = new_addr + 6, new_disp = target - new_rip = 0x1000 - 0x2000 = -0x1000
        new_disp = struct.unpack_from("<i", relocated, 2)[0]
        assert new_disp == -0x1000

    def test_same_address_no_change(self):
        # If orig_addr == new_addr, displacements don't change
        data = b"\x48\x8d\x05\x00\x10\x00\x00"
        _, instructions = decode_prologue_ex(data, min_bytes=1)
        relocated = relocate_instructions(data, instructions, 0x1000, 0x1000)
        assert relocated == data


# ============================================================================
# TestBackwardCompatibility
# ============================================================================


class TestBackwardCompatibility:
    """Verify instruction_length() and decode_prologue() behave identically to before."""

    def test_instruction_length_raises_on_rip_memory(self):
        # lea rax, [rip+X]
        with pytest.raises(RIPRelativeError):
            instruction_length(b"\x48\x8d\x05\x10\x20\x30\x40")

    def test_instruction_length_no_raise_on_call_rel32(self):
        # CALL rel32 is NOT a RIP-relative memory operand
        assert instruction_length(b"\xe8\x10\x20\x30\x40") == 5

    def test_instruction_length_no_raise_on_jmp_rel32(self):
        assert instruction_length(b"\xe9\x10\x20\x30\x40") == 5

    def test_instruction_length_no_raise_on_jmp_short(self):
        assert instruction_length(b"\xeb\x0a") == 2

    def test_instruction_length_no_raise_on_jcc_short(self):
        assert instruction_length(b"\x74\x0a") == 2

    def test_instruction_length_no_raise_on_jcc_near(self):
        assert instruction_length(b"\x0f\x84\x00\x10\x00\x00") == 6

    def test_decode_prologue_raises_on_rip_memory(self):
        # push rbp + lea rax, [rip+disp32]
        data = b"\x55\x48\x8d\x05\x10\x20\x30\x40"
        with pytest.raises(RIPRelativeError):
            decode_prologue(data, min_bytes=5)

    def test_decode_prologue_does_not_raise_on_call_in_prologue(self):
        # push rbp (1) + call rel32 (5) = 6 >= 5
        data = b"\x55\xe8\x10\x20\x30\x40"
        total, count = decode_prologue(data, min_bytes=5)
        assert total == 6
        assert count == 2

    def test_decode_prologue_returns_tuple(self):
        data = b"\x55\x48\x89\xe5\x48\x83\xec\x20"
        result = decode_prologue(data, min_bytes=5)
        assert isinstance(result, tuple)
        assert len(result) == 2
        total, count = result
        assert total == 8
        assert count == 3

    def test_push_rbp_length(self):
        assert instruction_length(b"\x55") == 1

    def test_sub_rsp_imm8_length(self):
        assert instruction_length(b"\x48\x83\xec\x20") == 4

    def test_mov_rip_relative_raises(self):
        with pytest.raises(RIPRelativeError):
            instruction_length(b"\x48\x8b\x05\x10\x20\x30\x40")
