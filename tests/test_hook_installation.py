"""Tests for hook installation safeguards."""

import struct
from unittest.mock import MagicMock

import pytest

from memscope_mcp.tools.hooking import ENTRY_HEADER_SIZE, RB_CONTROL_SIZE, HookManager, RingBufferConfig


class TestAlreadyHookedDetection:
    """install_hook should refuse addresses that start with a JMP instruction."""

    def setup_method(self):
        self.session = MagicMock()
        self.mgr = HookManager(self.session)
        self.mgr.ring_buffer = RingBufferConfig(
            address=0x1000,
            entry_count=16,
            max_data_size=256,
            entry_total_size=ENTRY_HEADER_SIZE + 256,
            total_size=RB_CONTROL_SIZE + 16 * (ENTRY_HEADER_SIZE + 256),
        )

    def test_rejects_e9_jmp_prologue(self):
        """E9 xx xx xx xx = rel32 JMP, typical inline hook."""
        prologue = b"\xe9\x12\x34\x56\x78" + b"\x90" * 27
        self.session.read_bytes.side_effect = lambda addr, size: prologue

        with pytest.raises(RuntimeError, match="appears already hooked.*E9 rel32"):
            self.mgr.install_hook(0x7FF6A0010000, "test")

    def test_rejects_ff25_jmp_prologue(self):
        """FF 25 xx xx xx xx = abs indirect JMP, typical 14-byte hook."""
        prologue = b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", 0xDEAD) + b"\x90" * 18
        self.session.read_bytes.side_effect = lambda addr, size: prologue

        with pytest.raises(RuntimeError, match="appears already hooked.*FF25 abs"):
            self.mgr.install_hook(0x7FF6A0010000, "test")

    def test_allows_normal_prologue(self):
        """Normal prologues should pass the JMP check and continue into installation."""
        prologue = b"\x48\x89\x5c\x24\x08" + b"\x90" * 27
        self.session.read_bytes.side_effect = lambda addr, size: prologue
        self.session.allocate_near.side_effect = lambda *a, **kw: None
        self.session.allocate.side_effect = lambda *a, **kw: 0x2000
        self.session.virtual_protect.side_effect = lambda *a: 0x20
        self.session.write_bytes.side_effect = lambda *a: None
        self.session.suspend_process_threads.side_effect = lambda: []
        self.session.resume_process_threads.side_effect = lambda threads: None

        result = self.mgr.install_hook(0x7FF6A0010000, "test")
        assert result["hook_id"] == 1

    def test_duplicate_address_rejected(self):
        """Same target_addr should be rejected by the existing check."""
        prologue = b"\x48\x89\x5c\x24\x08" + b"\x90" * 27
        self.session.read_bytes.side_effect = lambda addr, size: prologue
        self.session.allocate_near.side_effect = lambda *a, **kw: None
        self.session.allocate.side_effect = lambda *a, **kw: 0x2000
        self.session.virtual_protect.side_effect = lambda *a: 0x20
        self.session.write_bytes.side_effect = lambda *a: None
        self.session.suspend_process_threads.side_effect = lambda: []
        self.session.resume_process_threads.side_effect = lambda threads: None

        self.mgr.install_hook(0x7FF6A0010000, "first")
        with pytest.raises(RuntimeError, match="already hooked"):
            self.mgr.install_hook(0x7FF6A0010000, "second")
