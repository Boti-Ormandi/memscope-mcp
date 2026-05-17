"""Session state management for the Headless CE MCP Server."""

import ctypes
import logging
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Callable, Optional

import pymem
import pymem.memory
import pymem.process
import pymem.ressources.structure as structs

logger = logging.getLogger(__name__)

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

# Thread access rights
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_ACCESS_FOR_PATCH = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT

# CONTEXT layout (x64)
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x01  # RIP, RSP, EFlags, SegCs, SegSs
CONTEXT_SIZE = 1232  # sizeof(CONTEXT) on x64
CONTEXT_FLAGS_OFFSET = 0x30  # offset of ContextFlags field
CONTEXT_RIP_OFFSET = 0xF8  # offset of Rip field

# Thread snapshot
TH32CS_SNAPTHREAD = 0x00000004

# VirtualProtectEx
kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


MEM_FREE = 0x10000

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t


# Thread enumeration
class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD

kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD

kernel32.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
kernel32.GetProcessIdOfThread.restype = wintypes.DWORD

kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.GetThreadContext.restype = wintypes.BOOL

kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.SetThreadContext.restype = wintypes.BOOL

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = wintypes.BOOL

kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = wintypes.BOOL


@dataclass
class SuspendedThread:
    """A thread suspended for safe memory patching."""

    tid: int
    handle: int


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

    # Lifecycle callbacks: {name: callback}
    _on_attach_callbacks: dict[str, Callable] = field(default_factory=dict)
    _on_detach_callbacks: dict[str, Callable] = field(default_factory=dict)

    # Track remote allocations for cleanup on detach
    _tracked_allocations: set[int] = field(default_factory=set)

    # ========== Lifecycle Callback Registration ==========

    def register_on_attach(self, name: str, callback: Callable[["DebugSession"], None]) -> None:
        """Register a callback invoked after successful process attach.

        Args:
            name: Unique identifier (used for logging and deregistration).
            callback: Called with (session) after attach succeeds.
        """
        self._on_attach_callbacks[name] = callback

    def register_on_detach(self, name: str, callback: Callable[["DebugSession", bool], None]) -> None:
        """Register a callback invoked before process handle is closed.

        Args:
            name: Unique identifier.
            callback: Called with (session, process_alive) before teardown.
        """
        self._on_detach_callbacks[name] = callback

    def _fire_attach(self) -> None:
        """Fire all attach callbacks. Failures are logged and isolated.

        Catches BaseException (not just Exception) so that KeyboardInterrupt
        during one callback doesn't skip remaining callbacks.
        """
        for name, cb in self._on_attach_callbacks.items():
            try:
                cb(self)
            except BaseException as e:
                logger.warning(f"Attach callback '{name}' failed: {type(e).__name__}: {e}")

    def _fire_detach(self, process_alive: bool) -> None:
        """Fire all detach callbacks. Failures are logged and isolated.

        Catches BaseException (not just Exception) so that KeyboardInterrupt
        during one callback doesn't skip remaining callbacks. This is critical
        for cleanup: all callbacks must run to restore hooks and free memory.
        """
        for name, cb in self._on_detach_callbacks.items():
            try:
                cb(self, process_alive)
            except BaseException as e:
                logger.warning(f"Detach callback '{name}' failed: {type(e).__name__}: {e}")

    # ========== Process Switching ==========

    def switch_process(self, process_name: str, pid: int = 0) -> bool:
        """Canonical process switch with lifecycle callbacks.

        Detaches from current process (firing detach callbacks),
        opens the new process, and fires attach callbacks on success.

        Args:
            process_name: Target process name (e.g. "Game.exe").
            pid: Optional PID for disambiguation.

        Returns:
            True if the new process was opened successfully.
        """
        self.detach()
        self.target_process = process_name
        self.pid = pid

        if not self._open_process():
            return False

        self._fire_attach()
        return True

    def ensure_attached(self) -> bool:
        """Re-attach if process restarted. Returns True if connected."""
        if self.pm is None:
            if not self._open_process():
                return False
            self._fire_attach()
            return True

        # Check if process is still alive (no memory read needed)
        if not self._is_process_alive():
            self.detach()
            if not self._open_process():
                return False
            self._fire_attach()
            return True

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

    def _find_module(self, module_name: str) -> Optional[dict]:
        """Case-insensitive module lookup."""
        mod = self.modules.get(module_name)
        if mod:
            return mod
        lower = module_name.lower()
        for name, info in self.modules.items():
            if name.lower() == lower:
                return info
        return None

    def get_module_base(self, module_name: str) -> Optional[int]:
        """Get base address for a module."""
        mod = self._find_module(module_name)
        return mod["base"] if mod else None

    def get_module_size(self, module_name: str) -> Optional[int]:
        """Get size of a module."""
        mod = self._find_module(module_name)
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

    def virtual_protect(self, address: int, size: int, new_protection: int) -> int:
        """Change memory protection in target process.

        Args:
            address: Target address.
            size: Region size in bytes.
            new_protection: New protection constant (PAGE_EXECUTE_READWRITE, etc.).

        Returns:
            Previous protection value.

        Raises:
            RuntimeError: If not attached or VirtualProtectEx fails.
        """
        if self.pm is None:
            raise RuntimeError("Not attached to process")

        old_protect = wintypes.DWORD()
        result = kernel32.VirtualProtectEx(
            self.pm.process_handle, address, size, new_protection, ctypes.byref(old_protect)
        )
        if not result:
            err = ctypes.get_last_error()
            raise RuntimeError(f"VirtualProtectEx failed: error {err}")
        return old_protect.value

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
        self._tracked_allocations.add(addr)
        return addr

    def allocate_near(self, target: int, size: int, executable: bool = True) -> int | None:
        """Allocate memory within +/-2GB of target address for 5-byte JMP reach.

        Scans free regions via VirtualQueryEx and attempts allocation.

        Args:
            target: Address to allocate near.
            size: Bytes to allocate.
            executable: If True, allocate RWX memory.

        Returns:
            Allocated address, or None if no suitable region found.
        """
        if self.pm is None:
            raise RuntimeError("Not attached to process")

        protect = PAGE_EXECUTE_READWRITE if executable else PAGE_READWRITE
        lo = max(target - 0x7FFF0000, 0x10000)
        hi = min(target + 0x7FFF0000, 0x7FFFFFFFFFFF)

        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)
        addr = lo

        while addr < hi:
            result = kernel32.VirtualQueryEx(self.pm.process_handle, addr, ctypes.byref(mbi), mbi_size)
            if result == 0:
                break

            region_base = mbi.BaseAddress or addr
            region_end = region_base + mbi.RegionSize

            if mbi.State == MEM_FREE and mbi.RegionSize >= size:
                # Try to allocate at the start of this free region
                alloc_addr = kernel32.VirtualAllocEx(
                    self.pm.process_handle, region_base, size, MEM_COMMIT | MEM_RESERVE, protect
                )
                if alloc_addr:
                    # Verify it's within range
                    offset = alloc_addr - target
                    if -0x7FFF0000 <= offset <= 0x7FFF0000:
                        self._tracked_allocations.add(alloc_addr)
                        return alloc_addr
                    # Out of range, free and continue
                    kernel32.VirtualFreeEx(self.pm.process_handle, alloc_addr, 0, MEM_RELEASE)

            addr = region_end

        return None

    def free(self, address: int) -> bool:
        """Free allocated memory in target process.

        Args:
            address: Address returned by allocate()

        Returns:
            True if freed successfully
        """
        self._tracked_allocations.discard(address)
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

    # ========== Thread Control (for safe patching) ==========

    def suspend_process_threads(self) -> list[SuspendedThread]:
        """Suspend all threads in the attached process.

        Enumerates threads via CreateToolhelp32Snapshot, opens each with
        suspend + context access, and calls SuspendThread.

        Threads that cannot be opened or suspended are logged and skipped.

        Returns:
            List of SuspendedThread with valid handles. Caller MUST call
            resume_process_threads() to resume and close handles.

        Raises:
            RuntimeError: If not attached to a process.
            OSError: If snapshot creation fails.
        """
        if self.pm is None:
            raise RuntimeError("Not attached to process")

        pid = self.pm.process_id
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot == -1 or snapshot == 0xFFFFFFFF:
            raise OSError(f"CreateToolhelp32Snapshot failed: error {ctypes.get_last_error()}")

        suspended: list[SuspendedThread] = []
        try:
            te = THREADENTRY32()
            te.dwSize = ctypes.sizeof(THREADENTRY32)

            if not kernel32.Thread32First(snapshot, ctypes.byref(te)):
                return suspended

            while True:
                if te.th32OwnerProcessID == pid:
                    handle = kernel32.OpenThread(THREAD_ACCESS_FOR_PATCH, False, te.th32ThreadID)
                    if handle:
                        # Verify thread still belongs to our process (defends against TID reuse)
                        owner = kernel32.GetProcessIdOfThread(handle)
                        if owner != pid:
                            kernel32.CloseHandle(handle)
                        elif kernel32.SuspendThread(handle) == 0xFFFFFFFF:
                            logger.warning(
                                f"SuspendThread failed for TID {te.th32ThreadID}: error {ctypes.get_last_error()}"
                            )
                            kernel32.CloseHandle(handle)
                        else:
                            suspended.append(SuspendedThread(tid=te.th32ThreadID, handle=handle))
                    else:
                        logger.debug(f"OpenThread failed for TID {te.th32ThreadID}: error {ctypes.get_last_error()}")

                if not kernel32.Thread32Next(snapshot, ctypes.byref(te)):
                    break
        finally:
            kernel32.CloseHandle(snapshot)

        return suspended

    def resume_process_threads(self, threads: list[SuspendedThread]) -> None:
        """Resume previously suspended threads and close handles.

        Best-effort: logs warnings on failures but does not raise.

        Args:
            threads: List from suspend_process_threads().
        """
        for t in threads:
            result = kernel32.ResumeThread(t.handle)
            if result == 0xFFFFFFFF:
                logger.warning(f"ResumeThread failed for TID {t.tid}: error {ctypes.get_last_error()}")
            kernel32.CloseHandle(t.handle)

    def get_thread_rip(self, handle: int) -> int:
        """Get instruction pointer (RIP) of a suspended thread.

        Args:
            handle: Thread handle with THREAD_GET_CONTEXT access.

        Returns:
            Current RIP value.

        Raises:
            OSError: If GetThreadContext fails.
        """
        # Allocate CONTEXT buffer with 16-byte alignment (required by Win32)
        buf = (ctypes.c_ubyte * (CONTEXT_SIZE + 16))()
        addr = ctypes.addressof(buf)
        aligned = (addr + 15) & ~15

        # Set ContextFlags = CONTEXT_CONTROL
        ctypes.c_uint32.from_address(aligned + CONTEXT_FLAGS_OFFSET).value = CONTEXT_CONTROL

        if not kernel32.GetThreadContext(handle, aligned):
            raise OSError(f"GetThreadContext failed: error {ctypes.get_last_error()}")

        return ctypes.c_uint64.from_address(aligned + CONTEXT_RIP_OFFSET).value

    def set_thread_rip(self, handle: int, new_rip: int) -> None:
        """Set instruction pointer (RIP) of a suspended thread.

        Gets the full CONTEXT_CONTROL context first (to preserve RSP, EFlags, etc.),
        modifies only RIP, then writes it back.

        Args:
            handle: Thread handle with THREAD_GET_CONTEXT | THREAD_SET_CONTEXT.
            new_rip: New instruction pointer value.

        Raises:
            OSError: If Get/SetThreadContext fails.
        """
        buf = (ctypes.c_ubyte * (CONTEXT_SIZE + 16))()
        addr = ctypes.addressof(buf)
        aligned = (addr + 15) & ~15

        ctypes.c_uint32.from_address(aligned + CONTEXT_FLAGS_OFFSET).value = CONTEXT_CONTROL

        if not kernel32.GetThreadContext(handle, aligned):
            raise OSError(f"GetThreadContext failed: error {ctypes.get_last_error()}")

        ctypes.c_uint64.from_address(aligned + CONTEXT_RIP_OFFSET).value = new_rip

        if not kernel32.SetThreadContext(handle, aligned):
            raise OSError(f"SetThreadContext failed: error {ctypes.get_last_error()}")

    def detach(self) -> None:
        """Detach from the process. Preserves target_process for reconnection.

        Cleanup order:
        1. Fire detach callbacks (extensions restore hooks, free their allocations)
        2. Free remaining tracked allocations (orphaned Lua alloc() calls etc.)
        3. Close the process handle
        """
        if self.pm is not None:
            alive = self._is_process_alive()
            self._fire_detach(alive)

            # Free orphaned allocations not cleaned up by callbacks.
            # Hook cleanup already freed its allocations via self.free(),
            # which removed them from the set. Only true orphans remain.
            if alive and self._tracked_allocations:
                orphaned = len(self._tracked_allocations)
                for addr in list(self._tracked_allocations):
                    try:
                        self.free(addr)
                    except BaseException:
                        pass
                if orphaned:
                    logger.info(f"Freed {orphaned} orphaned allocation(s) during detach")
            self._tracked_allocations.clear()

            try:
                self.pm.close_process()
            except Exception:
                pass
            self.pm = None

        # Always clear local state, even if pm was already None
        self._tracked_allocations.clear()
        self.pid = 0
        self.modules.clear()


# Global session instance
SESSION = DebugSession()
