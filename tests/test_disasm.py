"""Unit tests for x64 instruction length decoder."""

import pytest

from src.utils.disasm import RIPRelativeError, decode_prologue, instruction_length

# ============================================================================
# instruction_length - individual instructions
# ============================================================================


class TestSingleByteInstructions:
    def test_push_rbp(self):
        assert instruction_length(b"\x55") == 1

    def test_push_rbx(self):
        assert instruction_length(b"\x53") == 1

    def test_nop(self):
        assert instruction_length(b"\x90") == 1

    def test_int3(self):
        assert instruction_length(b"\xcc") == 1

    def test_ret(self):
        assert instruction_length(b"\xc3") == 1


class TestREXInstructions:
    def test_mov_rbp_rsp(self):
        # REX.W + mov r/m64, r64 (89 /r) with ModRM E5 (mod=3, reg=rsp, rm=rbp)
        assert instruction_length(b"\x48\x89\xe5") == 3

    def test_sub_rsp_imm8(self):
        # REX.W + sub r/m64, imm8 (83 /5) with ModRM EC, imm=0x20
        assert instruction_length(b"\x48\x83\xec\x20") == 4

    def test_sub_rsp_imm32(self):
        # REX.W + sub r/m64, imm32 (81 /5) with ModRM EC, imm=0x100
        assert instruction_length(b"\x48\x81\xec\x00\x01\x00\x00") == 7

    def test_mov_rax_imm64(self):
        # REX.W + mov r64, imm64 (B8+rd)
        data = b"\x48\xb8" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert instruction_length(data) == 10


class TestSIBInstructions:
    def test_mov_rsp_plus_disp8_rbx(self):
        # REX.W + mov [rsp+0x8], rbx -> 48 89 5C 24 08
        # ModRM 5C = mod=01, reg=rbx, rm=100(SIB); SIB 24 = base=rsp, index=none
        assert instruction_length(b"\x48\x89\x5c\x24\x08") == 5

    def test_mov_rsp_plus_disp8_rsi(self):
        # REX.W + mov [rsp+0x10], rsi -> 48 89 74 24 10
        assert instruction_length(b"\x48\x89\x74\x24\x10") == 5

    def test_lea_rax_rsp_plus_disp8(self):
        # REX.W + lea rax, [rsp+0x20] -> 48 8D 44 24 20
        assert instruction_length(b"\x48\x8d\x44\x24\x20") == 5


class TestALUInstructions:
    def test_xor_eax_eax(self):
        # xor r32, r/m32 (33 /r) with ModRM C0 (mod=3, reg=eax, rm=eax)
        assert instruction_length(b"\x33\xc0") == 2

    def test_mov_eax_imm32(self):
        # mov r32, imm32 (B8+rd)
        assert instruction_length(b"\xb8\x01\x00\x00\x00") == 5


class TestControlFlow:
    def test_call_rel32(self):
        assert instruction_length(b"\xe8\x10\x20\x30\x40") == 5

    def test_jmp_short(self):
        assert instruction_length(b"\xeb\x0a") == 2


class TestTwoByteOpcodes:
    def test_nop_dword_rax(self):
        # 0F 1F 00 = nop dword [rax], ModRM 00 = mod=0, rm=0 (no disp, no SIB)
        assert instruction_length(b"\x0f\x1f\x00") == 3

    def test_nop_dword_rax_rax_0(self):
        # 0F 1F 44 00 00 = nop [rax+rax*1+0], ModRM 44 = mod=1, rm=4(SIB), SIB=00, disp8=00
        assert instruction_length(b"\x0f\x1f\x44\x00\x00") == 5


# ============================================================================
# instruction_length - RIP-relative addressing
# ============================================================================


class TestRIPRelative:
    def test_lea_rip_relative(self):
        # REX.W + lea rax, [rip+disp32] -> 48 8D 05 xx xx xx xx
        # ModRM 05 = mod=0, rm=5 -> RIP-relative
        with pytest.raises(RIPRelativeError):
            instruction_length(b"\x48\x8d\x05\x10\x20\x30\x40")

    def test_mov_rip_relative(self):
        # REX.W + mov rax, [rip+disp32] -> 48 8B 05 xx xx xx xx
        with pytest.raises(RIPRelativeError):
            instruction_length(b"\x48\x8b\x05\x10\x20\x30\x40")


# ============================================================================
# instruction_length - prefixes
# ============================================================================


class TestPrefixes:
    def test_lock_prefix_consumed(self):
        # LOCK prefix (F0) is consumed, then the opcode is decoded normally.
        # LOCK + xor [rax], eax -> F0 31 00
        # F0 = LOCK, 31 = xor r/m, r (ModRM), 00 = mod=0 rm=0(rax)
        data = b"\xf0\x31\x00"
        assert instruction_length(data) == 3

    def test_lock_cmpxchg_unsupported(self):
        # LOCK + REX.WB + 0F B1 /r -> lock cmpxchg [r12], rdx
        # F0 49 0F B1 14 24
        # 0F B1 (cmpxchg) is not in the minimal opcode table
        data = b"\xf0\x49\x0f\xb1\x14\x24"
        with pytest.raises(ValueError, match="Unrecognized two-byte opcode: 0F B1"):
            instruction_length(data)

    def test_rep_movsb_unsupported(self):
        # F3 A4 = rep movsb
        # A4 (MOVSB) is not in the minimal opcode table
        with pytest.raises(ValueError, match="Unrecognized opcode: A4"):
            instruction_length(b"\xf3\xa4")

    def test_operand_size_override(self):
        # 66 prefix changes immediate size for some instructions
        # 66 + sub r/m16, imm16 (81 /5) -> 66 81 EC 00 01
        # ModRM EC = mod=3, reg=5, rm=4(esp) -- register direct, so no SIB
        data = b"\x66\x81\xec\x00\x01"
        assert instruction_length(data) == 5


# ============================================================================
# instruction_length - error cases
# ============================================================================


class TestErrors:
    def test_empty_data(self):
        with pytest.raises(ValueError):
            instruction_length(b"")

    def test_offset_past_end(self):
        with pytest.raises(ValueError, match="No data at offset"):
            instruction_length(b"\x90", offset=1)

    def test_offset_past_end_far(self):
        with pytest.raises(ValueError, match="No data at offset"):
            instruction_length(b"\x90", offset=100)

    def test_only_prefix_bytes(self):
        with pytest.raises(ValueError, match="Data ends in prefix bytes"):
            instruction_length(b"\x48")

    def test_unknown_opcode(self):
        # 0x0E (PUSH CS) is not in the table for x64
        with pytest.raises(ValueError, match="Unrecognized opcode"):
            instruction_length(b"\x0e")

    def test_unknown_two_byte_opcode(self):
        with pytest.raises(ValueError, match="Unrecognized two-byte opcode"):
            instruction_length(b"\x0f\x00")

    def test_data_ends_after_0f(self):
        with pytest.raises(ValueError, match="Data ends after 0F prefix"):
            instruction_length(b"\x0f")

    def test_data_ends_before_modrm(self):
        # 89 requires ModRM but data stops
        with pytest.raises(ValueError, match="Data ends before ModRM byte"):
            instruction_length(b"\x89")


# ============================================================================
# instruction_length - offset parameter
# ============================================================================


class TestOffset:
    def test_offset_skips_bytes(self):
        # Two instructions: nop (90) + ret (C3)
        data = b"\x90\xc3"
        assert instruction_length(data, offset=0) == 1
        assert instruction_length(data, offset=1) == 1

    def test_offset_into_rex_instruction(self):
        # Padding + REX.W mov rbp, rsp
        data = b"\xcc\xcc\x48\x89\xe5"
        assert instruction_length(data, offset=2) == 3


# ============================================================================
# decode_prologue
# ============================================================================


class TestDecodePrologue:
    """Test decode_prologue with a typical function prologue.

    push rbp           = 55           (1 byte)
    mov rbp, rsp       = 48 89 E5    (3 bytes) -> cumulative 4
    sub rsp, 0x20      = 48 83 EC 20 (4 bytes) -> cumulative 8
    mov [rsp+8], rbx   = 48 89 5C 24 08 (5 bytes) -> cumulative 13
    """

    PROLOGUE = b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x5c\x24\x08"

    def test_min_bytes_5(self):
        total, count = decode_prologue(self.PROLOGUE, min_bytes=5)
        # 1 + 3 = 4 < 5, so need third instruction: 1 + 3 + 4 = 8
        assert total == 8
        assert count == 3

    def test_min_bytes_14_with_extra(self):
        # Add a 5th instruction so we can reach 14: xor eax, eax (33 C0, 2 bytes)
        extended = self.PROLOGUE + b"\x33\xc0"
        total, count = decode_prologue(extended, min_bytes=14)
        # 1 + 3 + 4 + 5 + 2 = 15 >= 14
        assert total == 15
        assert count == 5

    def test_min_bytes_1(self):
        total, count = decode_prologue(self.PROLOGUE, min_bytes=1)
        # First instruction (push rbp) = 1 byte, 1 >= 1
        assert total == 1
        assert count == 1

    def test_min_bytes_exact_boundary(self):
        # push rbp (1) + mov rbp, rsp (3) = 4 bytes exactly
        total, count = decode_prologue(self.PROLOGUE, min_bytes=4)
        assert total == 4
        assert count == 2

    def test_rip_relative_in_prologue_raises(self):
        # push rbp + lea rax, [rip+disp32]
        data = b"\x55\x48\x8d\x05\x10\x20\x30\x40"
        with pytest.raises(RIPRelativeError):
            decode_prologue(data, min_bytes=5)

    def test_insufficient_data_raises(self):
        # Only 1 byte but need 5
        with pytest.raises(ValueError):
            decode_prologue(b"\x55", min_bytes=5)

    def test_min_bytes_14_exact_prologue_raises(self):
        # 13-byte prologue, need 14 -> runs out of instructions
        with pytest.raises(ValueError):
            decode_prologue(self.PROLOGUE, min_bytes=14)
