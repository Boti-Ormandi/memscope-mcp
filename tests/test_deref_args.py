"""Tests for deref_args feature in build_hook_trampoline shellcode generation.

Verifies generated trampoline bytes structurally WITHOUT executing them.
"""

from unittest.mock import patch

import pytest

from src.tools.hooking import HookManager, RingBufferConfig
from src.utils.shellcode import build_hook_trampoline

# ---------- fixtures ----------

SAVED_BYTES = b"\x48\x89\x5c\x24\x08"  # mov [rsp+8], rbx  (typical 5-byte prologue)
RING_BUFFER = 0x0000_0200_0000_0000
CONTINUE_ADDR = 0x0000_7FF6_A001_0005
HOOK_ID = 42

# Markers in the generated shellcode
RETURN_VALUE_WRITE = b"\x45\x89\x7d\x40"  # mov dword [r13+0x40], r15d
STATUS_COMPLETE = b"\x41\xc7\x45\x08\x02\x00\x00\x00"  # mov dword [r13+0x08], STATUS_COMPLETE


def _build_post(**overrides):
    defaults = dict(
        hook_id=HOOK_ID,
        ring_buffer_addr=RING_BUFFER,
        hook_type="post",
        buffer_arg=-1,
        length_arg=-1,
        max_capture=0,
        saved_bytes=SAVED_BYTES,
        target_continue_addr=CONTINUE_ADDR,
    )
    defaults.update(overrides)
    code, _stub_offset = build_hook_trampoline(**defaults)
    return code


def _deref_section(code: bytes) -> bytes:
    """Extract bytes between return value write and STATUS_COMPLETE mark."""
    ret_pos = code.find(RETURN_VALUE_WRITE)
    complete_pos = code.find(STATUS_COMPLETE, ret_pos)
    assert ret_pos != -1, "return value write not found"
    assert complete_pos != -1, "STATUS_COMPLETE not found"
    return code[ret_pos + len(RETURN_VALUE_WRITE) : complete_pos]


# ============================================================
# 1. Deref args shellcode structure
# ============================================================


class TestDerefArgsShellcode:
    def test_deref_4byte_read(self):
        """Post hook with deref_args={1: 4}: verify mov eax, [rax] in deref section."""
        code = _build_post(deref_args={1: 4})
        section = _deref_section(code)
        assert b"\x8b\x00" in section  # mov eax, [rax]

    def test_deref_8byte_read(self):
        """Post hook with deref_args={3: 8}: verify mov rax, [rax] in deref section."""
        code = _build_post(deref_args={3: 8})
        section = _deref_section(code)
        assert b"\x48\x8b\x00" in section  # mov rax, [rax]

    def test_deref_null_check(self):
        """Verify test rax, rax and jz present before each dereference."""
        code = _build_post(deref_args={1: 4})
        section = _deref_section(code)
        # test rax, rax
        assert b"\x48\x85\xc0" in section
        # jz (short jump)
        assert b"\x74" in section

    def test_deref_multiple(self):
        """deref_args={1: 4, 3: 8}: two null checks, one 4-byte and one 8-byte deref."""
        code = _build_post(deref_args={1: 4, 3: 8})
        section = _deref_section(code)

        # Two null checks
        null_check = b"\x48\x85\xc0"
        count = 0
        start = 0
        while True:
            idx = section.find(null_check, start)
            if idx == -1:
                break
            count += 1
            start = idx + 1
        assert count == 2

        # 4-byte read: mov eax, [rax]
        assert b"\x8b\x00" in section
        # 8-byte read: mov rax, [rax]
        assert b"\x48\x8b\x00" in section

    def test_deref_entry_write_offset(self):
        """deref_args={0: 4}: entry write targets [r13+0x20] for arg0."""
        code = _build_post(deref_args={0: 4})
        section = _deref_section(code)
        # mov [r13+0x20], rax
        assert b"\x49\x89\x45\x20" in section

    def test_deref_with_buffer_and_stack_args(self):
        """Post hook with buffer, stack args, and deref: all sections present in order."""
        code = _build_post(
            buffer_arg=0,
            length_arg=-2,
            max_capture=4096,
            stack_args=[4],
            deref_args={1: 4},
        )

        ret_pos = code.find(RETURN_VALUE_WRITE)
        complete_pos = code.find(STATUS_COMPLETE, ret_pos)
        assert ret_pos != -1
        assert complete_pos != -1

        # rep movsb (buffer capture) should be present after return value write
        rep_movsb = b"\xf3\xa4"
        rep_pos = code.find(rep_movsb, ret_pos)
        assert rep_pos != -1, "rep movsb not found after return value write"
        assert rep_pos < complete_pos, "rep movsb should be before COMPLETE mark"

        # Stack arg capture: mov rax, [rbp+0x30] for arg4 (0-indexed: frame_offset = 0x08 * (4+2) = 0x30)
        assert b"\x48\x8b\x45\x30" in code

        # Deref code: null check should appear after buffer capture, before COMPLETE
        section = code[rep_pos + len(rep_movsb) : complete_pos]
        assert b"\x48\x85\xc0" in section, "null check for deref should be after buffer capture"
        assert b"\x8b\x00" in section, "4-byte deref should be after buffer capture"

    def test_no_deref_args(self):
        """Post hook without deref_args: no deref code between return value write and COMPLETE."""
        code = _build_post()
        section = _deref_section(code)
        # No mov rax, [rbp-offset] patterns (48 8b 45 xx with negative offset) in this section
        # These would be the arg-loading instructions that deref emits
        idx = 0
        while idx < len(section):
            if section[idx : idx + 3] == b"\x48\x8b\x45":
                # Check if it's a negative offset (deref arg load)
                if idx + 3 < len(section):
                    offset_byte = section[idx + 3]
                    if offset_byte >= 0x80:  # signed negative
                        pytest.fail(
                            f"Found unexpected arg load (48 8b 45 {offset_byte:02x}) "
                            f"at offset {idx} in section between return value write and COMPLETE"
                        )
                idx += 1
            else:
                idx += 1


# ============================================================
# 2. Validation tests (install_hook in hooking.py)
# ============================================================


def make_hook_manager():
    hm = HookManager()
    hm.ring_buffer = RingBufferConfig(
        address=0x1000,
        entry_count=128,
        max_data_size=4096,
        entry_total_size=0x50 + 4096,
        total_size=0x100 + 128 * (0x50 + 4096),
    )
    return hm


class TestDerefArgsValidation:
    def test_deref_args_pre_hook_raises(self):
        """install_hook with hook_type='pre' and deref_args raises ValueError."""
        hm = make_hook_manager()
        with patch("src.tools.hooking.SESSION") as mock_session:
            mock_session.read_bytes.return_value = b"\x90" * 32
            with pytest.raises(ValueError, match="deref_args only valid with type='post'"):
                hm.install_hook(
                    target_addr=0x7FF600000000,
                    name="test",
                    hook_type="pre",
                    deref_args={1: 4},
                )

    def test_deref_args_invalid_key(self):
        """deref_args key outside 1-4 raises ValueError."""
        hm = make_hook_manager()
        with patch("src.tools.hooking.SESSION") as mock_session:
            mock_session.read_bytes.return_value = b"\x90" * 32
            with pytest.raises(ValueError, match="deref_args key must be 1-4"):
                hm.install_hook(
                    target_addr=0x7FF600000000,
                    name="test",
                    hook_type="post",
                    deref_args={0: 4},
                )
            with pytest.raises(ValueError, match="deref_args key must be 1-4"):
                hm.install_hook(
                    target_addr=0x7FF600000000,
                    name="test",
                    hook_type="post",
                    deref_args={5: 4},
                )

    def test_deref_args_invalid_size(self):
        """deref_args value not 4 or 8 raises ValueError."""
        hm = make_hook_manager()
        with patch("src.tools.hooking.SESSION") as mock_session:
            mock_session.read_bytes.return_value = b"\x90" * 32
            with pytest.raises(ValueError, match="deref_args read_size must be 4 or 8"):
                hm.install_hook(
                    target_addr=0x7FF600000000,
                    name="test",
                    hook_type="post",
                    deref_args={1: 2},
                )
            with pytest.raises(ValueError, match="deref_args read_size must be 4 or 8"):
                hm.install_hook(
                    target_addr=0x7FF600000000,
                    name="test",
                    hook_type="post",
                    deref_args={1: 16},
                )
