"""PEB (Process Environment Block) reading utilities.

Read command line, environment variables, debugger flag, and loaded modules
from any process by PID. Pure ctypes, no pymem dependency, no session state.

Opens and closes its own process handle per call -- no leaked handles.
"""

import ctypes
from ctypes import wintypes

ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# ReadProcessMemory
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

# NtQueryInformationProcess
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_ulong),
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long  # NTSTATUS


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_long),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_ulonglong),
        ("InheritedFromUniqueProcessId", ctypes.c_ulonglong),
    ]


def get_peb_address(process_handle: int) -> int | None:
    """Get PEB base address via NtQueryInformationProcess.

    Args:
        process_handle: Handle with PROCESS_QUERY_INFORMATION access.

    Returns:
        PEB base address, or None on failure.
    """
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = ctypes.c_ulong()
    status = ntdll.NtQueryInformationProcess(
        process_handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
    )
    if status != 0:
        return None
    return pbi.PebBaseAddress


def _read_remote_memory(process_handle: int, address: int, size: int) -> bytes | None:
    """Read memory from a remote process.

    Args:
        process_handle: Handle with PROCESS_VM_READ access.
        address: Address to read from.
        size: Number of bytes to read.

    Returns:
        Bytes read, or None on failure.
    """
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read))
    if not ok or bytes_read.value == 0:
        return None
    return buf.raw[: bytes_read.value]


def _read_remote_pointer(process_handle: int, address: int) -> int | None:
    """Read a 64-bit pointer from remote process memory."""
    data = _read_remote_memory(process_handle, address, 8)
    if data is None or len(data) < 8:
        return None
    return int.from_bytes(data, "little")


def _read_remote_byte(process_handle: int, address: int) -> int | None:
    """Read a single byte from remote process memory."""
    data = _read_remote_memory(process_handle, address, 1)
    if data is None or len(data) < 1:
        return None
    return data[0]


def _read_remote_unicode_string(process_handle: int, address: int) -> str | None:
    """Read a UNICODE_STRING structure and its buffer from remote process.

    UNICODE_STRING layout (x64):
        +0x00: Length (uint16, byte count)
        +0x02: MaximumLength (uint16)
        +0x08: Buffer (ptr64)

    Args:
        process_handle: Handle with PROCESS_VM_READ.
        address: Address of the UNICODE_STRING structure.

    Returns:
        The string, or None on failure.
    """
    header = _read_remote_memory(process_handle, address, 0x10)
    if header is None or len(header) < 0x10:
        return None

    length = int.from_bytes(header[0:2], "little")
    buffer_ptr = int.from_bytes(header[8:16], "little")

    if length == 0 or buffer_ptr == 0:
        return None

    # Cap at 32KB to avoid reading garbage
    if length > 32768:
        length = 32768

    str_bytes = _read_remote_memory(process_handle, buffer_ptr, length)
    if str_bytes is None:
        return None

    try:
        return str_bytes.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------------------
# Phase 1: Command line, current directory, debugger flag
# ---------------------------------------------------------------------------


def read_process_peb(pid: int) -> dict | None:
    """Read key PEB fields from a process.

    Opens a handle, reads PEB, closes handle. No side effects.

    Args:
        pid: Process ID.

    Returns:
        Dict with command_line, current_directory, image_path, being_debugged.
        None if the process can't be opened or PEB can't be read.
    """
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None

    try:
        peb_addr = get_peb_address(handle)
        if peb_addr is None:
            return None

        result = {}

        # BeingDebugged: PEB+0x002
        debugged = _read_remote_byte(handle, peb_addr + 0x002)
        result["being_debugged"] = bool(debugged) if debugged is not None else False

        # ProcessParameters: PEB+0x020
        params_ptr = _read_remote_pointer(handle, peb_addr + 0x020)
        if params_ptr is None or params_ptr == 0:
            return result

        # CommandLine: ProcessParameters+0x070
        result["command_line"] = _read_remote_unicode_string(handle, params_ptr + 0x070)

        # CurrentDirectory.DosPath: ProcessParameters+0x038
        result["current_directory"] = _read_remote_unicode_string(handle, params_ptr + 0x038)

        # ImagePathName: ProcessParameters+0x060
        result["image_path"] = _read_remote_unicode_string(handle, params_ptr + 0x060)

        return result

    except Exception:
        return None
    finally:
        kernel32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# Phase 2: Environment variables
# ---------------------------------------------------------------------------


def read_process_environment(pid: int) -> dict[str, str] | None:
    """Read environment variables from a process.

    The environment block is at ProcessParameters+0x080. It's a contiguous
    region of null-terminated UTF-16LE strings: KEY1=VAL1\\0KEY2=VAL2\\0\\0

    Args:
        pid: Process ID.

    Returns:
        Dict of {name: value} pairs, or None on failure.
    """
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None

    try:
        peb_addr = get_peb_address(handle)
        if peb_addr is None:
            return None

        # ProcessParameters: PEB+0x020
        params_ptr = _read_remote_pointer(handle, peb_addr + 0x020)
        if params_ptr is None or params_ptr == 0:
            return None

        # Environment pointer: ProcessParameters+0x080
        env_ptr = _read_remote_pointer(handle, params_ptr + 0x080)
        if env_ptr is None or env_ptr == 0:
            return None

        # Read environment block in chunks until double-null terminator
        max_size = 65536
        chunk_size = 4096
        env_bytes = b""

        for offset in range(0, max_size, chunk_size):
            chunk = _read_remote_memory(handle, env_ptr + offset, chunk_size)
            if chunk is None:
                break
            env_bytes += chunk
            # Double-null in UTF-16LE = \x00\x00\x00\x00
            if b"\x00\x00\x00\x00" in chunk:
                break

        if not env_bytes:
            return None

        # Truncate at the double-null terminator to avoid decoding garbage after it
        term_pos = env_bytes.find(b"\x00\x00\x00\x00")
        if term_pos >= 0:
            # Align to UTF-16LE boundary (2 bytes) and include the terminator
            term_pos = term_pos - (term_pos % 2)
            env_bytes = env_bytes[: term_pos + 4]

        try:
            env_str = env_bytes.decode("utf-16-le")
        except UnicodeDecodeError:
            return None

        result = {}
        for entry in env_str.split("\x00"):
            if not entry:
                continue
            if "=" in entry:
                key, _, value = entry.partition("=")
                if key:  # skip Windows hidden entries like "=C:=C:\Windows"
                    result[key] = value

        return result

    except Exception:
        return None
    finally:
        kernel32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# Phase 3: Remote module enumeration
# ---------------------------------------------------------------------------


def read_process_modules(pid: int) -> list[dict] | None:
    """Enumerate loaded modules from a process via PEB Ldr.

    Walks InLoadOrderModuleList in PEB_LDR_DATA. Each entry is an
    LDR_DATA_TABLE_ENTRY with DllBase, SizeOfImage, and BaseDllName.

    Args:
        pid: Process ID.

    Returns:
        List of {name, base, size, path} dicts, or None on failure.
    """
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None

    try:
        peb_addr = get_peb_address(handle)
        if peb_addr is None:
            return None

        # Ldr: PEB+0x018
        ldr_ptr = _read_remote_pointer(handle, peb_addr + 0x018)
        if ldr_ptr is None or ldr_ptr == 0:
            return None

        # InLoadOrderModuleList: PEB_LDR_DATA+0x010
        list_head = ldr_ptr + 0x010
        first_entry = _read_remote_pointer(handle, list_head)
        if first_entry is None or first_entry == 0:
            return None

        modules = []
        current = first_entry
        max_modules = 1024

        while len(modules) < max_modules:
            if current == list_head:
                break

            # LDR_DATA_TABLE_ENTRY offsets (from InLoadOrderLinks at +0x000):
            #   +0x030: DllBase (ptr)
            #   +0x040: SizeOfImage (uint32)
            #   +0x048: FullDllName (UNICODE_STRING)
            #   +0x058: BaseDllName (UNICODE_STRING)

            dll_base = _read_remote_pointer(handle, current + 0x030)
            if dll_base is None or dll_base == 0:
                next_entry = _read_remote_pointer(handle, current)
                if next_entry is None or next_entry == 0 or next_entry == current:
                    break
                current = next_entry
                continue

            size_bytes = _read_remote_memory(handle, current + 0x040, 4)
            size_of_image = int.from_bytes(size_bytes, "little") if size_bytes and len(size_bytes) >= 4 else 0

            base_name = _read_remote_unicode_string(handle, current + 0x058)
            full_name = _read_remote_unicode_string(handle, current + 0x048)

            modules.append(
                {
                    "name": base_name or "unknown",
                    "base": dll_base,
                    "size": size_of_image,
                    "path": full_name or "",
                }
            )

            next_entry = _read_remote_pointer(handle, current)
            if next_entry is None or next_entry == 0 or next_entry == current:
                break
            current = next_entry

        return modules

    except Exception:
        return None
    finally:
        kernel32.CloseHandle(handle)
