"""Tests for PEB reading utilities."""

import ctypes
import os

import pytest

from src.utils.peb import (
    get_peb_address,
    read_process_environment,
    read_process_modules,
    read_process_peb,
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


def _find_explorer_pid():
    """Find explorer.exe PID, or None if not running."""
    import pymem.process

    for proc in pymem.process.list_processes():
        name = proc.szExeFile.decode() if isinstance(proc.szExeFile, bytes) else proc.szExeFile
        if name.lower() == "explorer.exe":
            return proc.th32ProcessID
    return None


# ===========================================================================
# Phase 1: PEB address and basic fields
# ===========================================================================


class TestGetPebAddress:
    """Test PEB address retrieval."""

    def test_self_process(self):
        """Can read PEB address of our own process."""
        pid = os.getpid()
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        assert handle != 0
        try:
            peb_addr = get_peb_address(handle)
            assert peb_addr is not None
            assert peb_addr > 0
            assert peb_addr < 0x7FFFFFFFFFFF
        finally:
            kernel32.CloseHandle(handle)

    def test_invalid_handle(self):
        """Returns None for invalid handle."""
        peb_addr = get_peb_address(0)
        assert peb_addr is None


class TestReadProcessPeb:
    """Test full PEB reading (Phase 1)."""

    def test_self_process_command_line(self):
        """Can read our own command line from PEB."""
        result = read_process_peb(os.getpid())
        assert result is not None
        assert "command_line" in result
        assert result["command_line"] is not None
        cmdline = result["command_line"].lower()
        assert "python" in cmdline or "pytest" in cmdline

    def test_self_process_current_directory(self):
        """Can read our own working directory from PEB."""
        result = read_process_peb(os.getpid())
        assert result is not None
        assert "current_directory" in result
        assert result["current_directory"] is not None
        assert os.path.sep in result["current_directory"] or "/" in result["current_directory"]

    def test_self_process_being_debugged(self):
        """Can read debugger flag from PEB."""
        result = read_process_peb(os.getpid())
        assert result is not None
        assert "being_debugged" in result
        assert isinstance(result["being_debugged"], bool)

    def test_self_process_image_path(self):
        """Can read image path from PEB."""
        result = read_process_peb(os.getpid())
        assert result is not None
        assert "image_path" in result
        assert result["image_path"] is not None
        assert "python" in result["image_path"].lower()

    def test_invalid_pid(self):
        """Returns None for invalid PID."""
        result = read_process_peb(99999999)
        assert result is None

    def test_pid_zero(self):
        """Returns None for PID 0 (System Idle Process)."""
        result = read_process_peb(0)
        assert result is None

    def test_explorer_process(self):
        """Can read PEB from explorer.exe."""
        explorer_pid = _find_explorer_pid()
        if explorer_pid is None:
            pytest.skip("explorer.exe not running")

        result = read_process_peb(explorer_pid)
        assert result is not None
        assert result["command_line"] is not None
        assert "explorer" in result["command_line"].lower()


# ===========================================================================
# Phase 2: Environment variables
# ===========================================================================


class TestReadProcessEnvironment:
    """Test environment block reading (Phase 2)."""

    def test_self_process_has_path(self):
        """Our own environment should have PATH."""
        env = read_process_environment(os.getpid())
        assert env is not None
        path_keys = [k for k in env if k.upper() == "PATH"]
        assert len(path_keys) > 0

    def test_self_process_matches_os_environ(self):
        """PEB-read env should match os.environ for key variables."""
        env = read_process_environment(os.getpid())
        assert env is not None
        for key in ["APPDATA", "USERPROFILE", "COMPUTERNAME"]:
            if key in os.environ:
                assert key in env
                assert env[key] == os.environ[key]

    def test_invalid_pid(self):
        """Returns None for invalid PID."""
        env = read_process_environment(99999999)
        assert env is None

    def test_explorer_has_environment(self):
        """External process should have a readable environment."""
        explorer_pid = _find_explorer_pid()
        if explorer_pid is None:
            pytest.skip("explorer.exe not running")

        env = read_process_environment(explorer_pid)
        if env is None:
            pytest.skip("access denied reading explorer.exe environment")
        assert len(env) > 0


# ===========================================================================
# Phase 3: Remote module enumeration
# ===========================================================================


class TestReadProcessModules:
    """Test module enumeration via PEB Ldr (Phase 3)."""

    def test_self_process_has_modules(self):
        """Our own process should have loaded modules."""
        modules = read_process_modules(os.getpid())
        assert modules is not None
        assert len(modules) > 0

    def test_self_process_has_python(self):
        """Our own module list should include python."""
        modules = read_process_modules(os.getpid())
        assert modules is not None
        names = [m["name"].lower() for m in modules]
        assert any("python" in n for n in names)

    def test_self_process_has_ntdll(self):
        """Every process should have ntdll.dll."""
        modules = read_process_modules(os.getpid())
        assert modules is not None
        names = [m["name"].lower() for m in modules]
        assert "ntdll.dll" in names

    def test_module_fields(self):
        """Each module should have name, base, size, path."""
        modules = read_process_modules(os.getpid())
        assert modules is not None
        for mod in modules:
            assert "name" in mod
            assert "base" in mod
            assert "size" in mod
            assert "path" in mod
            assert mod["base"] > 0
            assert mod["size"] > 0

    def test_explorer_modules(self):
        """Can read modules from explorer.exe."""
        explorer_pid = _find_explorer_pid()
        if explorer_pid is None:
            pytest.skip("explorer.exe not running")

        modules = read_process_modules(explorer_pid)
        assert modules is not None
        assert len(modules) > 0
        names = [m["name"].lower() for m in modules]
        assert "ntdll.dll" in names
        assert "explorer.exe" in names

    def test_invalid_pid(self):
        """Returns None for invalid PID."""
        modules = read_process_modules(99999999)
        assert modules is None

    def test_consistency_with_toolhelp(self):
        """PEB module list should roughly match CreateToolhelp32Snapshot results."""
        import pymem.process

        explorer_pid = _find_explorer_pid()
        if explorer_pid is None:
            pytest.skip("explorer.exe not running")

        peb_modules = read_process_modules(explorer_pid)
        assert peb_modules is not None

        toolhelp_names = set()
        for mod in pymem.process.enum_process_module(explorer_pid):
            name = mod.szModule.decode() if isinstance(mod.szModule, bytes) else mod.szModule
            toolhelp_names.add(name.lower())

        if not toolhelp_names:
            pytest.skip("toolhelp returned no modules for explorer.exe")

        peb_names = {m["name"].lower() for m in peb_modules}

        # At least 80% overlap
        overlap = peb_names & toolhelp_names
        assert len(overlap) > len(toolhelp_names) * 0.8
