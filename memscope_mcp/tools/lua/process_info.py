"""Process introspection functions for Lua engine.

Provides functions to enumerate processes, memory regions, threads, and services.
"""

import ctypes
from ctypes import wintypes
from typing import Callable, Optional

import pymem.memory
import pymem.process
import pymem.ressources.structure as structs

from ...session import SESSION
from ...utils.peb import read_process_environment, read_process_modules, read_process_peb

# Windows API constants
TH32CS_SNAPTHREAD = 0x00000004
THREAD_QUERY_INFORMATION = 0x0040


# Structures for thread enumeration
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


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# Thread enumeration
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = wintypes.BOOL

kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = wintypes.BOOL

kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# Process command line
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

# For reading PEB/command line
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Memory protection flags for readable output
PROTECTION_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

REGION_TYPE = {
    0x20000: "MEM_PRIVATE",
    0x40000: "MEM_MAPPED",
    0x1000000: "MEM_IMAGE",
}


def get_process_list(lua_table_fn: Callable, filter_str: Optional[str] = None, limit: int = 500):
    """List running processes.

    Args:
        lua_table_fn: Lua table constructor
        filter_str: Optional substring filter for process name
        limit: Maximum results

    Returns:
        Lua table of {pid, name, parent_pid, threads}
    """
    results = []
    for proc in pymem.process.list_processes():
        name = proc.szExeFile.decode() if isinstance(proc.szExeFile, bytes) else proc.szExeFile
        if filter_str and filter_str.lower() not in name.lower():
            continue
        results.append(
            {
                "pid": proc.th32ProcessID,
                "name": name,
                "parent_pid": proc.th32ParentProcessID,
                "threads": proc.cntThreads,
            }
        )
        if len(results) >= limit:
            break

    # Convert to Lua table
    t = lua_table_fn()
    for i, p in enumerate(results, 1):
        entry = lua_table_fn()
        entry["pid"] = p["pid"]
        entry["name"] = p["name"]
        entry["parent_pid"] = p["parent_pid"]
        entry["threads"] = p["threads"]
        t[i] = entry
    return t


def get_process_info(lua_table_fn: Callable, pid: Optional[int] = None):
    """Get detailed process information.

    Args:
        lua_table_fn: Lua table constructor
        pid: Process ID (uses attached process if None)

    Returns:
        Lua table with pid, name, path, parent_pid, or nil on error
    """
    target_pid = pid if pid else (SESSION.pid if SESSION.pm else 0)
    if not target_pid:
        return None

    result = lua_table_fn()
    result["pid"] = target_pid

    # Find process in list
    for proc in pymem.process.list_processes():
        if proc.th32ProcessID == target_pid:
            name = proc.szExeFile.decode() if isinstance(proc.szExeFile, bytes) else proc.szExeFile
            result["name"] = name
            result["parent_pid"] = proc.th32ParentProcessID
            result["threads"] = proc.cntThreads
            break

    # Get full image path
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, target_pid)
    if handle:
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                result["path"] = buf.value
        finally:
            kernel32.CloseHandle(handle)

    # Read PEB fields (command line, cwd, debugger flag)
    peb_data = read_process_peb(target_pid)
    if peb_data:
        if peb_data.get("command_line"):
            result["command_line"] = peb_data["command_line"]
        if peb_data.get("current_directory"):
            result["current_directory"] = peb_data["current_directory"]
        result["being_debugged"] = peb_data.get("being_debugged", False)

    return result


def get_memory_regions(lua_table_fn: Callable, filter_prot: Optional[str] = None, limit: int = 1000):
    """List memory regions of attached process.

    Args:
        lua_table_fn: Lua table constructor
        filter_prot: Filter by protection (e.g., "RWX", "RW", "R", "X")
        limit: Maximum results

    Returns:
        Lua table of {base, size, protection, type, state}
    """
    if SESSION.pm is None:
        return lua_table_fn()

    results = []
    address = 0
    max_addr = 0x7FFFFFFFFFFF  # User-mode limit

    while address < max_addr and len(results) < limit:
        try:
            mbi = pymem.memory.virtual_query(SESSION.pm.process_handle, address)
        except:
            break

        if mbi.RegionSize == 0:
            break

        # Skip free regions
        if mbi.State == structs.MEMORY_STATE.MEM_FREE.value:
            address += mbi.RegionSize
            continue

        # Get protection string
        base_prot = mbi.Protect & 0xFF
        prot_str = PROTECTION_FLAGS.get(base_prot, f"0x{base_prot:X}")

        # Get type string
        type_str = REGION_TYPE.get(mbi.Type, f"0x{mbi.Type:X}")

        # Get state string
        if mbi.State == structs.MEMORY_STATE.MEM_COMMIT.value:
            state_str = "COMMIT"
        elif mbi.State == structs.MEMORY_STATE.MEM_RESERVE.value:
            state_str = "RESERVE"
        else:
            state_str = f"0x{mbi.State:X}"

        # Filter by protection
        if filter_prot:
            fp = filter_prot.upper()
            is_read = base_prot in [0x02, 0x04, 0x08, 0x20, 0x40, 0x80]
            is_write = base_prot in [0x04, 0x08, 0x40, 0x80]
            is_exec = base_prot in [0x10, 0x20, 0x40, 0x80]

            match = True
            if "R" in fp and not is_read:
                match = False
            if "W" in fp and not is_write:
                match = False
            if "X" in fp and not is_exec:
                match = False

            if not match:
                address += mbi.RegionSize
                continue

        results.append(
            {
                "base": mbi.BaseAddress,
                "size": mbi.RegionSize,
                "protection": prot_str,
                "type": type_str,
                "state": state_str,
            }
        )

        address += mbi.RegionSize

    # Convert to Lua table
    t = lua_table_fn()
    for i, r in enumerate(results, 1):
        entry = lua_table_fn()
        entry["base"] = r["base"]
        entry["size"] = r["size"]
        entry["protection"] = r["protection"]
        entry["type"] = r["type"]
        entry["state"] = r["state"]
        t[i] = entry
    return t


def get_region_info(lua_table_fn: Callable, address: int):
    """Get info about memory region containing address.

    Args:
        lua_table_fn: Lua table constructor
        address: Address to query

    Returns:
        Lua table with base, size, protection, type, state, or nil
    """
    if SESSION.pm is None:
        return None

    try:
        addr = int(address)
        mbi = pymem.memory.virtual_query(SESSION.pm.process_handle, addr)
    except:
        return None

    base_prot = mbi.Protect & 0xFF
    prot_str = PROTECTION_FLAGS.get(base_prot, f"0x{base_prot:X}")
    type_str = REGION_TYPE.get(mbi.Type, f"0x{mbi.Type:X}")

    if mbi.State == structs.MEMORY_STATE.MEM_COMMIT.value:
        state_str = "COMMIT"
    elif mbi.State == structs.MEMORY_STATE.MEM_RESERVE.value:
        state_str = "RESERVE"
    elif mbi.State == structs.MEMORY_STATE.MEM_FREE.value:
        state_str = "FREE"
    else:
        state_str = f"0x{mbi.State:X}"

    result = lua_table_fn()
    result["base"] = mbi.BaseAddress
    result["size"] = mbi.RegionSize
    result["protection"] = prot_str
    result["type"] = type_str
    result["state"] = state_str
    result["is_readable"] = base_prot in [0x02, 0x04, 0x08, 0x20, 0x40, 0x80]
    result["is_writable"] = base_prot in [0x04, 0x08, 0x40, 0x80]
    result["is_executable"] = base_prot in [0x10, 0x20, 0x40, 0x80]

    return result


def get_threads(lua_table_fn: Callable, pid: Optional[int] = None):
    """List threads of a process.

    Args:
        lua_table_fn: Lua table constructor
        pid: Process ID (uses attached process if None)

    Returns:
        Lua table of {tid, owner_pid, priority}
    """
    target_pid = pid if pid else (SESSION.pid if SESSION.pm else 0)
    if not target_pid:
        return lua_table_fn()

    results = []

    # Create snapshot of threads
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == -1:
        return lua_table_fn()

    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)

        if kernel32.Thread32First(snapshot, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID == target_pid:
                    results.append(
                        {
                            "tid": te.th32ThreadID,
                            "owner_pid": te.th32OwnerProcessID,
                            "priority": te.tpBasePri,
                        }
                    )

                if not kernel32.Thread32Next(snapshot, ctypes.byref(te)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)

    # Convert to Lua table
    t = lua_table_fn()
    for i, th in enumerate(results, 1):
        entry = lua_table_fn()
        entry["tid"] = th["tid"]
        entry["owner_pid"] = th["owner_pid"]
        entry["priority"] = th["priority"]
        t[i] = entry
    return t


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    """SERVICE_STATUS_PROCESS structure."""

    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    """ENUM_SERVICE_STATUS_PROCESSW structure."""

    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


def get_services(lua_table_fn: Callable, pid: Optional[int] = None):
    """List services, optionally filtered by hosting process.

    Args:
        lua_table_fn: Lua table constructor
        pid: Filter to services in this PID (for svchost)

    Returns:
        Lua table of {name, display_name, pid, state}
    """
    SERVICE_STATE = {
        1: "STOPPED",
        2: "START_PENDING",
        3: "STOP_PENDING",
        4: "RUNNING",
        5: "CONTINUE_PENDING",
        6: "PAUSE_PENDING",
        7: "PAUSED",
    }

    SC_MANAGER_ENUMERATE_SERVICE = 0x0004
    SERVICE_WIN32 = 0x30
    SERVICE_STATE_ALL = 0x03

    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE

    advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    advapi32.CloseServiceHandle.restype = wintypes.BOOL

    advapi32.EnumServicesStatusExW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_byte),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPCWSTR,
    ]
    advapi32.EnumServicesStatusExW.restype = wintypes.BOOL

    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
    if not scm:
        return lua_table_fn()

    results = []

    try:
        bytes_needed = wintypes.DWORD()
        services_returned = wintypes.DWORD()
        resume_handle = wintypes.DWORD(0)

        # First call to get size
        advapi32.EnumServicesStatusExW(
            scm,
            0,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            0,
            ctypes.byref(bytes_needed),
            ctypes.byref(services_returned),
            ctypes.byref(resume_handle),
            None,
        )

        if bytes_needed.value == 0:
            return lua_table_fn()

        # Allocate buffer as array of structures
        buf_size = bytes_needed.value
        buf = (ctypes.c_byte * buf_size)()
        resume_handle = wintypes.DWORD(0)

        if advapi32.EnumServicesStatusExW(
            scm,
            0,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buf,
            buf_size,
            ctypes.byref(bytes_needed),
            ctypes.byref(services_returned),
            ctypes.byref(resume_handle),
            None,
        ):
            # Cast buffer to array of structures
            entry_array = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))

            for i in range(services_returned.value):
                entry = entry_array[i]
                ssp = entry.ServiceStatusProcess

                # Filter by PID if requested
                if pid and ssp.dwProcessId != pid:
                    continue

                results.append(
                    {
                        "name": entry.lpServiceName or "",
                        "display_name": entry.lpDisplayName or "",
                        "pid": ssp.dwProcessId,
                        "state": SERVICE_STATE.get(ssp.dwCurrentState, f"UNKNOWN({ssp.dwCurrentState})"),
                    }
                )
    finally:
        advapi32.CloseServiceHandle(scm)

    # Convert to Lua table
    t = lua_table_fn()
    for i, s in enumerate(results, 1):
        entry = lua_table_fn()
        entry["name"] = s["name"]
        entry["display_name"] = s["display_name"]
        entry["pid"] = s["pid"]
        entry["state"] = s["state"]
        t[i] = entry
    return t


def is_being_debugged(pid: Optional[int] = None) -> bool | None:
    """Check if a process has a debugger attached via PEB.

    Args:
        pid: Process ID. Uses attached process if None.

    Returns:
        True if debugger attached, False otherwise, None on error.
    """
    target_pid = pid if pid else (SESSION.pid if SESSION.pm else 0)
    if not target_pid:
        return None

    peb_data = read_process_peb(int(target_pid))
    if peb_data is None:
        return None
    return peb_data.get("being_debugged", False)


def get_environment(lua_table_fn: Callable, pid: Optional[int] = None):
    """Read environment variables from a process via PEB.

    Args:
        lua_table_fn: Lua table constructor.
        pid: Process ID. Uses attached process if None.

    Returns:
        Lua table of {KEY = "value", ...} or empty table on failure.
    """
    target_pid = pid if pid else (SESSION.pid if SESSION.pm else 0)
    if not target_pid:
        return lua_table_fn()

    env = read_process_environment(int(target_pid))
    if env is None:
        return lua_table_fn()

    t = lua_table_fn()
    for key, value in env.items():
        t[key] = value
    return t


def get_modules_remote(lua_table_fn: Callable, pid: Optional[int] = None):
    """Enumerate modules from a process without attaching, via PEB Ldr.

    Args:
        lua_table_fn: Lua table constructor.
        pid: Process ID. Uses attached process if None.

    Returns:
        Lua table of {name, base, size, path} entries, or empty table.
    """
    target_pid = pid if pid else (SESSION.pid if SESSION.pm else 0)
    if not target_pid:
        return lua_table_fn()

    modules = read_process_modules(int(target_pid))
    if modules is None:
        return lua_table_fn()

    t = lua_table_fn()
    for i, mod in enumerate(modules, 1):
        entry = lua_table_fn()
        entry["name"] = mod["name"]
        entry["base"] = mod["base"]
        entry["size"] = mod["size"]
        entry["path"] = mod["path"]
        t[i] = entry
    return t
