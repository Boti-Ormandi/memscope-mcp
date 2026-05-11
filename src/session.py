"""Session state management for the memscope MCP server."""

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Optional

import pymem
import pymem.memory
import pymem.process
import pymem.ressources.structure as structs

# Windows API constants
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102

# Load kernel32
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# VirtualAllocEx
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

# VirtualFreeEx
kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

# CreateRemoteThread
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPDWORD,
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

# WaitForSingleObject
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

# CloseHandle
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# GetExitCodeProcess (for process liveness check)
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, wintypes.LPDWORD]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

STILL_ACTIVE = 259


@dataclass
class DebugSession:
    """Persistent state across MCP calls."""

    # Process handle
    pm: Optional[pymem.Pymem] = None
    target_process: str = ""
    pid: int = 0

    # Module cache (base addresses don't change during session)
    modules: dict[str, dict] = field(default_factory=dict)
    # Format: {"module.dll": {"base": 0x7FFE..., "size": 0x...}}

    def ensure_attached(self) -> bool:
        """Re-attach if process restarted. Returns True if connected."""
        if self.pm is None:
            return self._open_process()

        # Check if process is still alive (no memory read needed)
        if not self._is_process_alive():
            self.detach()
            return self._open_process()

        return True

    def _open_process(self) -> bool:
        """Open the target process and cache modules.

        Uses Pymem(pid_or_name) constructor so check_wow64() runs AFTER
        the process handle is opened (not against a null handle).
        """
        if not self.target_process and not self.pid:
            return False
        try:
            if self.pid:
                self.pm = pymem.Pymem(self.pid)
            else:
                self.pm = pymem.Pymem(self.target_process)
                self.pid = self.pm.process_id
            self._cache_modules()
            return True
        except Exception:
            self.pm = None
            return False

    def _is_process_alive(self) -> bool:
        """Check if the attached process is still running."""
        if self.pm is None or not self.pm.process_handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            result = kernel32.GetExitCodeProcess(self.pm.process_handle, ctypes.byref(exit_code))
            if not result:
                return False
            return exit_code.value == STILL_ACTIVE
        except Exception:
            return False

    def _cache_modules(self) -> None:
        """Cache all loaded module base addresses."""
        if self.pm is None:
            return

        self.modules.clear()
        for module in self.pm.list_modules():
            self.modules[module.name] = {
                "base": module.lpBaseOfDll,
                "size": module.SizeOfImage,
                "path": module.filename,
            }

    def get_module_base(self, module_name: str) -> Optional[int]:
        """Get base address for a module."""
        mod = self.modules.get(module_name)
        return mod["base"] if mod else None

    def get_module_size(self, module_name: str) -> Optional[int]:
        """Get size of a module."""
        mod = self.modules.get(module_name)
        return mod["size"] if mod else None

    def read_ptr(self, address: int) -> int:
        """Read a 64-bit pointer from memory."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        return self.pm.read_ulonglong(address)

    def read_int32(self, address: int) -> int:
        """Read a 32-bit signed integer."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        return self.pm.read_int(address)

    def read_uint32(self, address: int) -> int:
        """Read a 32-bit unsigned integer."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        return self.pm.read_uint(address)

    def read_float(self, address: int) -> float:
        """Read a 32-bit float."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        return self.pm.read_float(address)

    def read_double(self, address: int) -> float:
        """Read a 64-bit double."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        return self.pm.read_double(address)

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read raw bytes from memory."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        return self.pm.read_bytes(address, size)

    def read_string(self, address: int, max_length: int = 256) -> str:
        """Read a null-terminated C string."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        try:
            return self.pm.read_string(address, max_length)
        except Exception:
            return ""

    def is_valid_pointer(self, value: int) -> bool:
        """Check if a value looks like a valid user-mode pointer."""
        # Valid x64 user-mode range: 0x10000 to 0x7FFFFFFFFFFF
        return 0x10000 <= value <= 0x7FFFFFFFFFFF

    def is_memory_writable(self, address: int) -> bool:
        """Check if memory at address is writable (won't crash on write).

        Uses VirtualQueryEx to check page protection before writing.
        Returns False for PAGE_NOACCESS, PAGE_GUARD, or read-only pages.
        """
        if self.pm is None:
            return False

        try:
            mbi = pymem.memory.virtual_query(self.pm.process_handle, address)
        except Exception:
            return False

        # Must be committed memory (not reserved or free)
        if mbi.State != structs.MEMORY_STATE.MEM_COMMIT.value:
            return False

        # PAGE_GUARD triggers exception on first access - not safe
        if mbi.Protect & structs.MEMORY_PROTECTION.PAGE_GUARD.value:
            return False

        # Get base protection (strip modifier flags like PAGE_NOCACHE, PAGE_WRITECOMBINE)
        base_protect = mbi.Protect & 0xFF

        # Writable protections
        writable = {
            structs.MEMORY_PROTECTION.PAGE_READWRITE.value,  # 0x04
            structs.MEMORY_PROTECTION.PAGE_WRITECOPY.value,  # 0x08
            structs.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE.value,  # 0x40
            structs.MEMORY_PROTECTION.PAGE_EXECUTE_WRITECOPY.value,  # 0x80
        }

        return base_protect in writable

    # ========== Memory Write Functions ==========

    def write_byte(self, address: int, value: int) -> None:
        """Write a single byte to memory."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_bytes(address, bytes([value & 0xFF]), 1)

    def write_int32(self, address: int, value: int) -> None:
        """Write a 32-bit signed integer."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_int(address, value)

    def write_uint32(self, address: int, value: int) -> None:
        """Write a 32-bit unsigned integer."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_uint(address, value)

    def write_int64(self, address: int, value: int) -> None:
        """Write a 64-bit signed integer."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_longlong(address, value)

    def write_uint64(self, address: int, value: int) -> None:
        """Write a 64-bit unsigned integer (pointer)."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_ulonglong(address, value)

    def write_float(self, address: int, value: float) -> None:
        """Write a 32-bit float."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_float(address, value)

    def write_double(self, address: int, value: float) -> None:
        """Write a 64-bit double."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_double(address, value)

    def write_bytes(self, address: int, data: bytes) -> None:
        """Write raw bytes to memory."""
        if self.pm is None:
            raise RuntimeError("Not attached to process")
        self.pm.write_bytes(address, data, len(data))

    # ========== Memory Allocation ==========

    def allocate(self, size: int, executable: bool = False) -> int:
        """Allocate memory in target process.

        Args:
            size: Bytes to allocate
            executable: If True, memory is executable (for shellcode)

        Returns:
            Address of allocated memory

        Raises:
            RuntimeError: If not attached
            MemoryError: If allocation fails
        """
        if self.pm is None:
            raise RuntimeError("Not attached to process")

        protect = PAGE_EXECUTE_READWRITE if executable else PAGE_READWRITE
        addr = kernel32.VirtualAllocEx(self.pm.process_handle, None, size, MEM_COMMIT | MEM_RESERVE, protect)
        if not addr:
            err = ctypes.get_last_error()
            raise MemoryError(f"VirtualAllocEx failed: error {err}")
        return addr

    def free(self, address: int) -> bool:
        """Free allocated memory in target process.

        Args:
            address: Address returned by allocate()

        Returns:
            True if freed successfully
        """
        if self.pm is None:
            return False
        return bool(kernel32.VirtualFreeEx(self.pm.process_handle, address, 0, MEM_RELEASE))

    # ========== Remote Thread Execution ==========

    def create_remote_thread(self, start_address: int) -> int:
        """Create a thread in target process.

        Args:
            start_address: Address of code to execute

        Returns:
            Thread handle (must be closed with close_handle)

        Raises:
            RuntimeError: If not attached
            OSError: If thread creation fails
        """
        if self.pm is None:
            raise RuntimeError("Not attached to process")

        thread_id = wintypes.DWORD()
        handle = kernel32.CreateRemoteThread(
            self.pm.process_handle,
            None,  # security attributes
            0,  # stack size (default)
            start_address,
            None,  # parameter
            0,  # creation flags
            ctypes.byref(thread_id),
        )
        if not handle:
            err = ctypes.get_last_error()
            raise OSError(f"CreateRemoteThread failed: error {err}")
        return handle

    def wait_for_thread(self, handle: int, timeout_ms: int = 5000) -> bool:
        """Wait for thread to complete.

        Args:
            handle: Thread handle from create_remote_thread
            timeout_ms: Maximum wait time in milliseconds

        Returns:
            True if thread completed, False if timed out
        """
        result = kernel32.WaitForSingleObject(handle, timeout_ms)
        return result == WAIT_OBJECT_0

    def close_handle(self, handle: int) -> bool:
        """Close a Windows handle.

        Args:
            handle: Handle to close

        Returns:
            True if closed successfully
        """
        return bool(kernel32.CloseHandle(handle))

    def detach(self) -> None:
        """Detach from the process. Preserves target_process for reconnection."""
        if self.pm is not None:
            try:
                self.pm.close_process()
            except Exception:
                pass
            self.pm = None
        self.pid = 0
        self.modules.clear()


# Global session instance
SESSION = DebugSession()
