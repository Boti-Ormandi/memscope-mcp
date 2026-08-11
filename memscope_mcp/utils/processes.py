"""Windows process-introspection helpers shared across public surfaces."""

import ctypes
from collections.abc import Iterator
from ctypes import wintypes
from dataclasses import dataclass

import pymem.process

SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_WIN32 = 0x30
SERVICE_STATE_ALL = 0x03
SC_ENUM_PROCESS_INFO = 0
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

SERVICE_STATE_NAMES = {
    1: "STOPPED",
    2: "START_PENDING",
    3: "STOP_PENDING",
    4: "RUNNING",
    5: "CONTINUE_PENDING",
    6: "PAUSE_PENDING",
    7: "PAUSED",
}


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    """Base process enumeration result shared across public adapters."""

    pid: int
    name: str
    parent_pid: int
    threads: int


def enumerate_processes() -> Iterator[ProcessRecord]:
    """Yield immutable base process records in native enumeration order."""
    for proc in pymem.process.list_processes():
        name = proc.szExeFile.decode() if isinstance(proc.szExeFile, bytes) else proc.szExeFile
        yield ProcessRecord(
            pid=proc.th32ProcessID,
            name=name,
            parent_pid=proc.th32ParentProcessID,
            threads=proc.cntThreads,
        )


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def query_process_image_path(pid: int) -> str | None:
    """Return a process image path, or ``None`` when the native query fails."""
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        buffer = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value
    finally:
        kernel32.CloseHandle(handle)


@dataclass(frozen=True, slots=True)
class ServiceRecord:
    """Native service enumeration result with an untranslated state code."""

    name: str
    display_name: str
    pid: int
    state_code: int


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    """Windows SERVICE_STATUS_PROCESS structure."""

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
    """Windows ENUM_SERVICE_STATUS_PROCESSW structure."""

    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


def _advapi32():
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
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
    return advapi32


def enumerate_services() -> tuple[ServiceRecord, ...]:
    """Enumerate Windows services in SCM order, returning no services on native failure."""
    advapi32 = _advapi32()
    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
    if not scm:
        return ()

    try:
        bytes_needed = wintypes.DWORD()
        services_returned = wintypes.DWORD()
        resume_handle = wintypes.DWORD(0)

        advapi32.EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
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
            return ()

        buffer = (ctypes.c_byte * bytes_needed.value)()
        buffer_size = bytes_needed.value
        resume_handle = wintypes.DWORD(0)

        if not advapi32.EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buffer,
            buffer_size,
            ctypes.byref(bytes_needed),
            ctypes.byref(services_returned),
            ctypes.byref(resume_handle),
            None,
        ):
            return ()

        entries = ctypes.cast(buffer, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
        return tuple(
            ServiceRecord(
                name=entries[index].lpServiceName or "",
                display_name=entries[index].lpDisplayName or "",
                pid=entries[index].ServiceStatusProcess.dwProcessId,
                state_code=entries[index].ServiceStatusProcess.dwCurrentState,
            )
            for index in range(services_returned.value)
        )
    finally:
        advapi32.CloseServiceHandle(scm)
