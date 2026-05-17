"""Tests for Phase 5c: thread suspension for safe 14-byte JMP patching.

Covers _safe_patch() logic, install/remove routing (14-byte vs 5-byte),
HookInfo fields, and backward compatibility of shellcode builder return type.
"""

import pytest

from memscope_mcp.session import SuspendedThread
from memscope_mcp.tools.hooking import PAGE_EXECUTE_READWRITE, HookInfo, HookManager
from memscope_mcp.utils.shellcode import build_hook_trampoline

# ============================================================================
# Helpers
# ============================================================================

SAVED_BYTES = b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x8d\x05\x00\x10\x00\x00"  # 15 bytes
TARGET_ADDR = 0x7FF600001000
TRAMPOLINE_ADDR = 0x7FF700000000
STUB_OFFSET = 500  # example stub offset within trampoline
STUB_ADDR = TRAMPOLINE_ADDR + STUB_OFFSET
OLD_PROT = 0x20  # PAGE_EXECUTE_READ


def make_thread(tid: int, handle: int) -> SuspendedThread:
    return SuspendedThread(tid=tid, handle=handle)


# ============================================================================
# TestSafePatch
# ============================================================================


class TestSafePatch:
    """Test HookManager._safe_patch() logic with mocked SESSION methods."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.mgr = HookManager()
        self.suspended_threads: list[SuspendedThread] = []
        self.rip_map: dict[int, int] = {}  # handle -> rip
        self.set_rip_calls: list[tuple[int, int]] = []
        self.write_calls: list[tuple[int, bytes]] = []
        self.protect_calls: list[tuple[int, int, int]] = []

        def mock_suspend():
            return list(self.suspended_threads)

        def mock_resume(threads):
            self.resumed_threads = threads

        def mock_get_rip(handle):
            if handle in self.rip_map:
                return self.rip_map[handle]
            raise OSError("GetThreadContext failed")

        def mock_set_rip(handle, new_rip):
            self.set_rip_calls.append((handle, new_rip))

        def mock_write(addr, data):
            self.write_calls.append((addr, data))

        def mock_protect(addr, size, prot):
            self.protect_calls.append((addr, size, prot))
            return OLD_PROT

        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.suspend_process_threads", mock_suspend)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.resume_process_threads", mock_resume)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.get_thread_rip", mock_get_rip)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.set_thread_rip", mock_set_rip)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.write_bytes", mock_write)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.virtual_protect", mock_protect)

    def test_no_threads_in_zone(self):
        """Threads outside danger zone are not adjusted."""
        self.suspended_threads = [make_thread(100, 0xA), make_thread(200, 0xB), make_thread(300, 0xC)]
        self.rip_map = {0xA: 0x9999, 0xB: 0x8888, 0xC: TARGET_ADDR + 20}  # all outside

        adjusted, prot = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        assert adjusted == 0
        assert prot == OLD_PROT
        assert len(self.set_rip_calls) == 0
        assert len(self.write_calls) == 1  # patch was written

    def test_thread_at_zone_start(self):
        """Thread with RIP == target_addr is redirected to stub_addr."""
        self.suspended_threads = [make_thread(100, 0xA)]
        self.rip_map = {0xA: TARGET_ADDR}

        adjusted, _ = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        assert adjusted == 1
        assert self.set_rip_calls == [(0xA, STUB_ADDR)]

    def test_thread_in_zone_middle(self):
        """Thread with RIP at offset 5 gets stub_addr + 5."""
        self.suspended_threads = [make_thread(100, 0xA)]
        self.rip_map = {0xA: TARGET_ADDR + 5}

        adjusted, _ = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        assert adjusted == 1
        assert self.set_rip_calls == [(0xA, STUB_ADDR + 5)]

    def test_thread_at_zone_boundary(self):
        """RIP == target + patch_size is NOT adjusted (exclusive upper bound)."""
        self.suspended_threads = [make_thread(100, 0xA), make_thread(200, 0xB)]
        self.rip_map = {0xA: TARGET_ADDR + 14, 0xB: TARGET_ADDR + 15}

        adjusted, _ = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        assert adjusted == 1
        assert self.set_rip_calls == [(0xA, STUB_ADDR + 14)]

    def test_multiple_threads_in_zone(self):
        """Multiple threads at different offsets are adjusted independently."""
        self.suspended_threads = [make_thread(100, 0xA), make_thread(200, 0xB)]
        self.rip_map = {0xA: TARGET_ADDR, 0xB: TARGET_ADDR + 7}

        adjusted, _ = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        assert adjusted == 2
        assert (0xA, STUB_ADDR) in self.set_rip_calls
        assert (0xB, STUB_ADDR + 7) in self.set_rip_calls

    def test_resumes_on_write_failure(self):
        """Threads are resumed even if write_bytes raises."""
        self.suspended_threads = [make_thread(100, 0xA)]
        self.rip_map = {0xA: 0x9999}

        def failing_write(addr, data):
            raise OSError("WriteProcessMemory failed")

        # Override write_bytes to fail
        import memscope_mcp.tools.hooking as hooking_mod

        original_write = hooking_mod.SESSION.write_bytes
        hooking_mod.SESSION.write_bytes = failing_write
        try:
            with pytest.raises(OSError, match="WriteProcessMemory"):
                self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        finally:
            hooking_mod.SESSION.write_bytes = original_write

        # Threads were resumed despite the error
        assert hasattr(self, "resumed_threads")
        assert len(self.resumed_threads) == 1

    def test_skips_thread_on_context_error(self):
        """Thread whose RIP can't be read is skipped, others checked normally."""
        self.suspended_threads = [make_thread(100, 0xA), make_thread(200, 0xB)]
        # 0xA not in rip_map -> get_thread_rip raises OSError
        self.rip_map = {0xB: TARGET_ADDR}

        adjusted, _ = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 15, 15, STUB_ADDR)
        assert adjusted == 1
        assert self.set_rip_calls == [(0xB, STUB_ADDR)]

    def test_returns_correct_protection(self):
        """Returns original page protection from VirtualProtectEx."""
        self.suspended_threads = []
        adjusted, prot = self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 5, 5, STUB_ADDR)
        assert adjusted == 0
        assert prot == OLD_PROT

    def test_protect_restore_sequence(self):
        """VirtualProtectEx called to set RWX then restore original."""
        self.suspended_threads = []
        self.mgr._safe_patch(TARGET_ADDR, b"\x90" * 5, 5, STUB_ADDR)
        assert len(self.protect_calls) == 2
        assert self.protect_calls[0] == (TARGET_ADDR, 5, PAGE_EXECUTE_READWRITE)
        assert self.protect_calls[1] == (TARGET_ADDR, 5, OLD_PROT)


# ============================================================================
# TestHookInfoFields
# ============================================================================


class TestHookInfoFields:
    """Verify HookInfo stores jmp_size and stub_offset."""

    def test_default_jmp_size(self):
        hook = HookInfo(
            hook_id=1,
            target_addr=0x1000,
            saved_bytes=b"\x55",
            saved_length=1,
            trampoline_addr=0x2000,
            trampoline_size=4096,
            original_protection=0x20,
            hook_type="pre",
            name="test",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=0,
        )
        assert hook.jmp_size == 5
        assert hook.stub_offset == 0

    def test_custom_jmp_size(self):
        hook = HookInfo(
            hook_id=1,
            target_addr=0x1000,
            saved_bytes=b"\x55",
            saved_length=1,
            trampoline_addr=0x2000,
            trampoline_size=4096,
            original_protection=0x20,
            hook_type="pre",
            name="test",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=0,
            jmp_size=14,
            stub_offset=500,
        )
        assert hook.jmp_size == 14
        assert hook.stub_offset == 500


# ============================================================================
# TestInstallRemoveRouting
# ============================================================================


class TestInstallRemoveRouting:
    """Test that install/remove chooses safe_patch vs direct write based on jmp_size."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.mgr = HookManager()
        self.safe_patch_calls: list[tuple] = []
        self.direct_write_calls: list[tuple] = []
        self.direct_protect_calls: list[tuple] = []

        # Track _safe_patch calls
        def tracking_safe_patch(mgr_self, target_addr, patch_bytes, patch_size, stub_addr):
            self.safe_patch_calls.append((target_addr, len(patch_bytes), patch_size, stub_addr))
            return 0, OLD_PROT

        monkeypatch.setattr(HookManager, "_safe_patch", tracking_safe_patch)

        # Mock SESSION methods
        self.memory = bytearray(65536)

        def mock_read_bytes(addr, size):
            # push rbp; mov rbp, rsp; sub rsp, 0x20; mov [rsp+8], rbx; mov [rsp+10], rsi; NOPs
            prologue = (
                b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x5c\x24\x08"
                b"\x48\x89\x74\x24\x10\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
            )
            return prologue[:size]

        def mock_write_bytes(addr, data):
            self.direct_write_calls.append((addr, data))

        def mock_virtual_protect(addr, size, prot):
            self.direct_protect_calls.append((addr, size, prot))
            return OLD_PROT

        def mock_allocate(size, executable=False):
            return 0x50000000

        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.read_bytes", mock_read_bytes)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.write_bytes", mock_write_bytes)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.virtual_protect", mock_virtual_protect)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate", mock_allocate)
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.free", lambda addr: True)

        # Set up ring buffer
        from memscope_mcp.tools.hooking import RingBufferConfig

        self.mgr.ring_buffer = RingBufferConfig(
            address=0x10000000,
            entry_count=16,
            max_data_size=256,
            entry_total_size=256 + 0x50,
            total_size=0x100 + 16 * (256 + 0x50),
        )

    def test_install_14byte_uses_safe_patch(self, monkeypatch):
        """When near alloc fails (jmp_size=14), _safe_patch is used."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: None)

        result = self.mgr.install_hook(TARGET_ADDR, "test_hook")
        assert result["jmp_size"] == 14
        assert len(self.safe_patch_calls) == 1
        assert self.safe_patch_calls[0][0] == TARGET_ADDR  # target_addr

    def test_install_5byte_uses_direct_write(self, monkeypatch):
        """When near alloc succeeds (jmp_size=5), direct write is used."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: 0x7FF600010000)

        result = self.mgr.install_hook(TARGET_ADDR, "test_hook")
        assert result["jmp_size"] == 5
        assert len(self.safe_patch_calls) == 0
        # Direct write should have happened (trampoline write + jmp patch)
        assert len(self.direct_write_calls) >= 2  # trampoline + jmp

    def test_remove_14byte_uses_safe_patch(self, monkeypatch):
        """Hook installed with jmp_size=14: remove_hook uses _safe_patch."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: None)

        self.mgr.install_hook(TARGET_ADDR, "test_hook")
        self.safe_patch_calls.clear()

        self.mgr.remove_hook(TARGET_ADDR)
        assert len(self.safe_patch_calls) == 1
        assert self.safe_patch_calls[0][0] == TARGET_ADDR

    def test_remove_5byte_uses_direct_write(self, monkeypatch):
        """Hook installed with jmp_size=5: remove_hook uses direct write."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: 0x7FF600010000)

        self.mgr.install_hook(TARGET_ADDR, "test_hook")
        self.safe_patch_calls.clear()
        self.direct_write_calls.clear()
        self.direct_protect_calls.clear()

        self.mgr.remove_hook(TARGET_ADDR)
        assert len(self.safe_patch_calls) == 0
        # Direct write: protect + write + protect
        assert any(prot == PAGE_EXECUTE_READWRITE for _, _, prot in self.direct_protect_calls)

    def test_hook_info_stores_jmp_size_14(self, monkeypatch):
        """HookInfo.jmp_size is 14 when near allocation fails."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: None)

        self.mgr.install_hook(TARGET_ADDR, "test_hook")
        hook = self.mgr.hooks[TARGET_ADDR]
        assert hook.jmp_size == 14

    def test_hook_info_stores_jmp_size_5(self, monkeypatch):
        """HookInfo.jmp_size is 5 when near allocation succeeds."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: 0x7FF600010000)

        self.mgr.install_hook(TARGET_ADDR, "test_hook")
        hook = self.mgr.hooks[TARGET_ADDR]
        assert hook.jmp_size == 5

    def test_hook_info_stores_stub_offset(self, monkeypatch):
        """HookInfo.stub_offset > 0 and matches shellcode builder output."""
        monkeypatch.setattr("memscope_mcp.tools.hooking.SESSION.allocate_near", lambda *a, **kw: 0x7FF600010000)

        self.mgr.install_hook(TARGET_ADDR, "test_hook")
        hook = self.mgr.hooks[TARGET_ADDR]
        assert hook.stub_offset > 0


# ============================================================================
# TestShellcodeReturnType
# ============================================================================


class TestShellcodeReturnType:
    """Verify build_hook_trampoline returns (bytes, int) tuple."""

    def test_returns_tuple(self):
        result = build_hook_trampoline(
            hook_id=1,
            ring_buffer_addr=0x200000000000,
            hook_type="pre",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=0,
            saved_bytes=b"\x55\x48\x89\xe5\x90",
            target_continue_addr=0x7FF600010005,
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        shellcode, stub_offset = result
        assert isinstance(shellcode, bytes)
        assert isinstance(stub_offset, int)

    def test_stub_offset_positive(self):
        """stub_offset is a positive value within the shellcode."""
        shellcode, stub_offset = build_hook_trampoline(
            hook_id=1,
            ring_buffer_addr=0x200000000000,
            hook_type="pre",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=0,
            saved_bytes=b"\x55\x48\x89\xe5\x90",
            target_continue_addr=0x7FF600010005,
        )
        assert stub_offset > 0
        assert stub_offset < len(shellcode)

    def test_stub_contains_saved_bytes(self):
        """The saved bytes appear at the stub_offset position."""
        saved = b"\x55\x48\x89\xe5\x90"
        shellcode, stub_offset = build_hook_trampoline(
            hook_id=1,
            ring_buffer_addr=0x200000000000,
            hook_type="pre",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=0,
            saved_bytes=saved,
            target_continue_addr=0x7FF600010005,
        )
        assert shellcode[stub_offset : stub_offset + len(saved)] == saved

    def test_ret_before_stub(self):
        """C3 (ret) appears right before the stub offset."""
        shellcode, stub_offset = build_hook_trampoline(
            hook_id=1,
            ring_buffer_addr=0x200000000000,
            hook_type="pre",
            buffer_arg=-1,
            length_arg=-1,
            max_capture=0,
            saved_bytes=b"\x55\x48\x89\xe5\x90",
            target_continue_addr=0x7FF600010005,
        )
        assert shellcode[stub_offset - 1] == 0xC3


# ============================================================================
# TestSessionThreadControlGuards
# ============================================================================


class TestSessionThreadControlGuards:
    """Test guard clauses on session thread control methods."""

    def test_suspend_raises_not_attached(self):
        from memscope_mcp.session import DebugSession

        session = DebugSession()
        with pytest.raises(RuntimeError, match="Not attached"):
            session.suspend_process_threads()

    def test_resume_empty_list(self):
        """resume_process_threads with empty list does nothing."""
        from memscope_mcp.session import DebugSession

        session = DebugSession()
        session.resume_process_threads([])  # should not raise
