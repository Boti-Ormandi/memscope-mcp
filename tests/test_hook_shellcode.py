"""Tests for build_hook_trampoline shellcode generation.

Verifies generated trampoline bytes structurally WITHOUT executing them.
"""

import struct

import pytest

from src.utils.shellcode import RB_CONTROL_SIZE, build_hook_trampoline

# ---------- helpers ----------


def find_all(data: bytes, needle: bytes) -> list[int]:
    """Return all offsets where needle appears in data."""
    positions = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


# ---------- fixtures ----------

SAVED_BYTES = b"\x48\x89\x5c\x24\x08"  # mov [rsp+8], rbx  (typical 5-byte prologue)
RING_BUFFER = 0x0000_0200_0000_0000
CONTINUE_ADDR = 0x0000_7FF6_A001_0005
HOOK_ID = 42


def _build_pre_no_buffer(**overrides):
    defaults = dict(
        hook_id=HOOK_ID,
        ring_buffer_addr=RING_BUFFER,
        hook_type="pre",
        buffer_arg=-1,
        length_arg=-1,
        max_capture=0,
        saved_bytes=SAVED_BYTES,
        target_continue_addr=CONTINUE_ADDR,
    )
    defaults.update(overrides)
    code, _stub_offset = build_hook_trampoline(**defaults)
    return code


def _build_pre_with_buffer(**overrides):
    defaults = dict(
        hook_id=HOOK_ID,
        ring_buffer_addr=RING_BUFFER,
        hook_type="pre",
        buffer_arg=0,
        length_arg=1,
        max_capture=4096,
        saved_bytes=SAVED_BYTES,
        target_continue_addr=CONTINUE_ADDR,
    )
    defaults.update(overrides)
    code, _stub_offset = build_hook_trampoline(**defaults)
    return code


def _build_post_with_buffer(**overrides):
    defaults = dict(
        hook_id=HOOK_ID,
        ring_buffer_addr=RING_BUFFER,
        hook_type="post",
        buffer_arg=0,
        length_arg=-2,
        max_capture=4096,
        saved_bytes=SAVED_BYTES,
        target_continue_addr=CONTINUE_ADDR,
    )
    defaults.update(overrides)
    code, _stub_offset = build_hook_trampoline(**defaults)
    return code


# ============================================================
# 1. Pre-call, no buffer
# ============================================================


class TestPreCallNoBuffer:
    @pytest.fixture(autouse=True)
    def _build(self):
        self.code = _build_pre_no_buffer()

    def test_prologue_push_rbp(self):
        assert self.code[0:1] == b"\x55"  # push rbp

    def test_prologue_mov_rbp_rsp(self):
        assert self.code[1:4] == b"\x48\x89\xe5"  # mov rbp, rsp

    def test_prologue_sub_rsp(self):
        assert self.code[4:7] == b"\x48\x81\xec"  # sub rsp, imm32

    def test_callee_saved_rbx(self):
        # mov [rbp-0x30], rbx = 48 89 5D D0
        assert b"\x48\x89\x5d\xd0" in self.code

    def test_movabs_r12_ring_buffer(self):
        # 49 BC followed by 8-byte ring_buffer_addr
        marker = b"\x49\xbc" + struct.pack("<Q", RING_BUFFER)
        assert marker in self.code

    def test_lock_cmpxchg(self):
        assert b"\xf0\x49\x0f\xb1" in self.code

    def test_rdtsc(self):
        assert b"\x0f\x31" in self.code

    def test_call_rel32(self):
        # E8 xx xx xx xx -- at least one CALL rel32
        positions = find_all(self.code, b"\xe8")
        has_call = any(pos + 5 <= len(self.code) for pos in positions)
        assert has_call

    def test_ends_with_stub(self):
        # Tail: saved_bytes + FF 25 00 00 00 00 + uint64
        tail = SAVED_BYTES + b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", CONTINUE_ADDR)
        assert self.code.endswith(tail)

    def test_ret_before_stub(self):
        # C3 must appear before the stub at end
        stub_start = self.code.rfind(SAVED_BYTES)
        assert stub_start > 0
        # There should be a C3 right before the stub
        assert self.code[stub_start - 1 : stub_start] == b"\xc3"

    def test_no_rep_movsb(self):
        # No buffer => no rep movsb
        assert b"\xf3\xa4" not in self.code


# ============================================================
# 2. Pre-call, with buffer
# ============================================================


class TestPreCallWithBuffer:
    def test_rep_movsb_present(self):
        code = _build_pre_with_buffer()
        assert b"\xf3\xa4" in code


# ============================================================
# 3. Post-call, with buffer (length_arg=-2 = return value)
# ============================================================


class TestPostCallWithBuffer:
    @pytest.fixture(autouse=True)
    def _build(self):
        self.code = _build_post_with_buffer()

    def test_rep_movsb_present(self):
        assert b"\xf3\xa4" in self.code

    def test_buffer_copy_after_call(self):
        # The CALL to original stub is E8 rel32.  Find the call_insn by
        # looking for E8 that resolves to the stub.  Alternatively, just
        # check rep movsb comes after the CALL instruction area.
        #
        # The stub starts right after the epilogue's C3.  The CALL target
        # should point there.  But simpler: the rep movsb (F3 A4) must
        # come AFTER "49 89 c7" (mov r15, rax -- saving return value),
        # which is emitted right after the CALL returns.
        mov_r15_rax = b"\x49\x89\xc7"
        save_pos = self.code.find(mov_r15_rax)
        assert save_pos != -1

        rep_movsb_pos = self.code.find(b"\xf3\xa4")
        assert rep_movsb_pos > save_pos

    def test_test_r15d_r15d(self):
        # 45 85 FF -- test r15d, r15d (checking return value for length)
        assert b"\x45\x85\xff" in self.code


# ============================================================
# 4. Stub integrity
# ============================================================


class TestStubIntegrity:
    @pytest.mark.parametrize("builder", [_build_pre_no_buffer, _build_pre_with_buffer, _build_post_with_buffer])
    def test_saved_bytes_followed_by_jmp(self, builder):
        code = builder()
        idx = code.rfind(SAVED_BYTES)
        assert idx >= 0
        after = idx + len(SAVED_BYTES)
        # FF 25 00 00 00 00
        assert code[after : after + 6] == b"\xff\x25\x00\x00\x00\x00"
        # Followed by target_continue_addr as uint64 LE
        addr_bytes = code[after + 6 : after + 14]
        assert struct.unpack("<Q", addr_bytes)[0] == CONTINUE_ADDR


# ============================================================
# 5. Embedded constants
# ============================================================


class TestEmbeddedConstants:
    def test_hook_id_embedded(self):
        code = _build_pre_no_buffer()
        # mov dword [r13+0x0C], hook_id  =>  41 C7 45 0C <hook_id_le32>
        marker = b"\x41\xc7\x45\x0c" + struct.pack("<I", HOOK_ID)
        assert marker in code

    def test_ring_buffer_addr_embedded(self):
        code = _build_pre_no_buffer()
        # movabs r12, ring_buffer_addr  =>  49 BC <addr64>
        marker = b"\x49\xbc" + struct.pack("<Q", RING_BUFFER)
        assert marker in code

    def test_different_hook_id(self):
        code = _build_pre_no_buffer(hook_id=999)
        marker = b"\x41\xc7\x45\x0c" + struct.pack("<I", 999)
        assert marker in code

    def test_different_ring_buffer(self):
        alt_addr = 0x0000_0300_0000_0000
        code = _build_pre_no_buffer(ring_buffer_addr=alt_addr)
        marker = b"\x49\xbc" + struct.pack("<Q", alt_addr)
        assert marker in code


# ============================================================
# 6. Stack args
# ============================================================


class TestStackArgs:
    def test_reads_from_frame(self):
        code = _build_pre_no_buffer(stack_args=[4, 5])
        # arg4 frame_offset = 0x08 * (4+2) = 0x30 => [rbp+0x30]
        # 48 8B 45 30  (mov rax, [rbp+0x30])
        assert b"\x48\x8b\x45\x30" in code
        # arg5 frame_offset = 0x08 * (5+2) = 0x38 => [rbp+0x38]
        assert b"\x48\x8b\x45\x38" in code

    def test_flags_has_stack_count(self):
        code = _build_pre_no_buffer(stack_args=[4, 5])
        # flags_no_data = extra_args_count << 8 = 2 << 8 = 0x200
        # Written as: 41 C7 45 4C <flags_le32>
        flags_marker = b"\x41\xc7\x45\x4c" + struct.pack("<I", 2 << 8)
        assert flags_marker in code


# ============================================================
# 7. No stack args -- flags bits 8-11 = 0
# ============================================================


class TestNoStackArgs:
    def test_flags_no_extra(self):
        code = _build_pre_no_buffer(stack_args=[])
        # flags_no_data = 0 << 8 = 0
        # Written as: 41 C7 45 4C 00 00 00 00
        flags_marker = b"\x41\xc7\x45\x4c" + struct.pack("<I", 0)
        assert flags_marker in code


# ============================================================
# Module-level constant
# ============================================================


# ============================================================
# 8. Buffer deref (indirect buffer pointer via struct)
# ============================================================


def _build_pre_buffer_deref(**overrides):
    defaults = dict(
        hook_id=HOOK_ID,
        ring_buffer_addr=RING_BUFFER,
        hook_type="pre",
        buffer_arg=-1,
        length_arg=-1,
        max_capture=4096,
        saved_bytes=SAVED_BYTES,
        target_continue_addr=CONTINUE_ADDR,
        buffer_deref={"arg": 1, "offset": 8},  # 0-indexed: arg1 (RDX), struct+8
        length_deref={"arg": 1, "offset": 0, "size": 4},  # same struct, len at +0
    )
    defaults.update(overrides)
    code, _stub_offset = build_hook_trampoline(**defaults)
    return code


def _build_post_buffer_deref(**overrides):
    defaults = dict(
        hook_id=HOOK_ID,
        ring_buffer_addr=RING_BUFFER,
        hook_type="post",
        buffer_arg=-1,
        length_arg=-1,
        max_capture=4096,
        saved_bytes=SAVED_BYTES,
        target_continue_addr=CONTINUE_ADDR,
        buffer_deref={"arg": 1, "offset": 8},
        length_deref={"arg": 3, "offset": 0, "size": 4},  # different arg for length
    )
    defaults.update(overrides)
    code, _stub_offset = build_hook_trampoline(**defaults)
    return code


class TestBufferDerefPre:
    """Pre-call hook with buffer_deref: loads buffer pointer via struct dereference."""

    def test_has_rep_movsb(self):
        code = _build_pre_buffer_deref()
        assert b"\xf3\xa4" in code  # rep movsb

    def test_loads_struct_pointer_from_arg1(self):
        code = _build_pre_buffer_deref()
        # arg1 (0-indexed) offset = ARG_OFFSETS[1] = 0x10
        # mov rax, [rbp-0x10] => 48 8B 45 F0
        assert b"\x48\x8b\x45\xf0" in code

    def test_deref_buffer_pointer_at_offset_8(self):
        code = _build_pre_buffer_deref()
        # mov rsi, [rax+8] => 48 8B 70 08
        assert b"\x48\x8b\x70\x08" in code

    def test_deref_length_at_offset_0(self):
        code = _build_pre_buffer_deref()
        # mov eax, [rax] => 8B 00  (length_deref offset=0, size=4)
        assert b"\x8b\x00" in code

    def test_has_null_check_for_struct_pointer(self):
        code = _build_pre_buffer_deref()
        # test rax, rax => 48 85 C0
        assert b"\x48\x85\xc0" in code

    def test_has_null_check_for_buffer_pointer(self):
        code = _build_pre_buffer_deref()
        # test rsi, rsi => 48 85 F6
        assert b"\x48\x85\xf6" in code

    def test_stub_present(self):
        code = _build_pre_buffer_deref()
        # Stub ends with FF 25 00 00 00 00 + addr
        assert b"\xff\x25\x00\x00\x00\x00" in code


class TestBufferDerefPost:
    """Post-call hook with buffer_deref: loads buffer after call returns."""

    def test_has_rep_movsb(self):
        code = _build_post_buffer_deref()
        assert b"\xf3\xa4" in code

    def test_loads_length_from_arg3_deref(self):
        code = _build_post_buffer_deref()
        # arg3 (0-indexed) offset = ARG_OFFSETS[3] = 0x20
        # mov rax, [rbp-0x20] => 48 8B 45 E0
        assert b"\x48\x8b\x45\xe0" in code

    def test_deref_buffer_offset_8(self):
        code = _build_post_buffer_deref()
        # mov rsi, [rax+8] => 48 8B 70 08
        assert b"\x48\x8b\x70\x08" in code

    def test_saves_eax_to_r14d_before_struct_deref(self):
        code = _build_post_buffer_deref()
        # In post-call deref path, eax (length) is saved to r14d: 41 89 C6
        assert b"\x41\x89\xc6" in code

    def test_restores_eax_from_r14d(self):
        code = _build_post_buffer_deref()
        # Restored: mov eax, r14d => 44 89 F0
        assert b"\x44\x89\xf0" in code


class TestBufferDerefLargeOffset:
    """Buffer deref with offset >= 128 uses disp32 encoding."""

    def test_large_offset_uses_disp32(self):
        code = _build_pre_buffer_deref(buffer_deref={"arg": 0, "offset": 256})
        # mov rsi, [rax+256] => 48 8B B0 00 01 00 00
        marker = b"\x48\x8b\xb0" + struct.pack("<i", 256)
        assert marker in code


class TestModuleConstants:
    def test_rb_control_size(self):
        assert RB_CONTROL_SIZE == 0x100
