"""memscope-mcp - Entry Point.

A minimal MCP server for low-level memory research and reverse engineering.
Designed for AI agents to explore memory structures dynamically.
"""

import logging
import time
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .extensions.bootstrap import bootstrap_extensions
from .instructions import build_instructions
from .session import SESSION
from .tools.lua.engine import LUA_ENGINE, execute_lua
from .tools.lua_scripts import (
    SCRIPTS_DIR,
    list_scripts,
    run_script,
)

# Import tool functions
from .tools.memory import smart_dump
from .tools.pointers import resolve_pointer_chain
from .tools.scanning import scan_aob
from .tools.types import read_typed, write_typed
from .utils.logger import LOGGER
from .utils.memory_utils import format_address
from .utils.peb import read_process_peb

logger = logging.getLogger(__name__)

# Bootstrap all extensions (core + plugins)
_extensions = bootstrap_extensions(LUA_ENGINE, SESSION)

# Build instructions from base + loaded extensions
_instructions = build_instructions(_extensions)

# Initialize MCP server with instructions
mcp = FastMCP(
    "memscope-mcp",
    instructions=f"""{_instructions}

---
Session log: {LOGGER._get_log_file()}""",
)


def _normalize_tool_result(result: Any) -> Any:
    """Normalize MCP wrapper failure dictionaries without masking exceptions."""
    if not isinstance(result, dict):
        return result

    is_failure = result.get("success") is False or "error" in result
    if not is_failure:
        return result

    normalized = dict(result)
    normalized["success"] = False

    if normalized.get("error") == "PROCESS_NOT_ATTACHED":
        normalized["error"] = "NOT_ATTACHED"
        normalized["source_error"] = "PROCESS_NOT_ATTACHED"
    elif "error" not in normalized or normalized["error"] is None:
        normalized["error"] = "ERROR"

    has_detail = "detail" in normalized and normalized["detail"] is not None
    has_error_detail = "error_detail" in normalized and normalized["error_detail"] is not None
    if has_detail and not has_error_detail:
        normalized["error_detail"] = normalized["detail"]
    elif has_error_detail and not has_detail:
        normalized["detail"] = normalized["error_detail"]
    elif not has_detail and not has_error_detail:
        detail = str(normalized["error"])
        normalized["detail"] = detail
        normalized["error_detail"] = detail

    return normalized


def _log(tool: str, args: dict, result: dict, start_time: float):
    """Log a tool call with timing."""
    normalized = _normalize_tool_result(result)
    duration_ms = (time.perf_counter() - start_time) * 1000
    LOGGER.log(tool, args, normalized, duration_ms)
    return normalized


# ============================================================================
# Process Management
# ============================================================================


def _enumerate_services() -> dict[int, list[dict]]:
    """Build pid -> services map. Returns {pid: [{name, state}, ...]}."""
    import ctypes
    from ctypes import wintypes

    pid_services = {}

    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

        SC_MANAGER_ENUMERATE_SERVICE = 0x0004
        SERVICE_WIN32 = 0x30
        SERVICE_STATE_ALL = 0x03

        class SERVICE_STATUS_PROCESS(ctypes.Structure):
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
            _fields_ = [
                ("lpServiceName", wintypes.LPWSTR),
                ("lpDisplayName", wintypes.LPWSTR),
                ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
            ]

        SERVICE_STATES = {
            1: "STOPPED",
            2: "START_PENDING",
            3: "STOP_PENDING",
            4: "RUNNING",
            5: "CONTINUE_PENDING",
            6: "PAUSE_PENDING",
            7: "PAUSED",
        }

        # Set up function signatures
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
        if scm:
            try:
                bytes_needed = wintypes.DWORD()
                services_returned = wintypes.DWORD()
                resume_handle = wintypes.DWORD(0)

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

                if bytes_needed.value > 0:
                    buf = (ctypes.c_byte * bytes_needed.value)()
                    resume_handle = wintypes.DWORD(0)

                    if advapi32.EnumServicesStatusExW(
                        scm,
                        0,
                        SERVICE_WIN32,
                        SERVICE_STATE_ALL,
                        buf,
                        bytes_needed.value,
                        ctypes.byref(bytes_needed),
                        ctypes.byref(services_returned),
                        ctypes.byref(resume_handle),
                        None,
                    ):
                        entry_array = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
                        for i in range(services_returned.value):
                            entry = entry_array[i]
                            ssp = entry.ServiceStatusProcess
                            svc_name = entry.lpServiceName or ""
                            svc_pid = ssp.dwProcessId
                            svc_state = SERVICE_STATES.get(ssp.dwCurrentState, "UNKNOWN")

                            if svc_pid not in pid_services:
                                pid_services[svc_pid] = []
                            pid_services[svc_pid].append({"name": svc_name, "state": svc_state})
            finally:
                advapi32.CloseServiceHandle(scm)
    except Exception:
        pass

    return pid_services


def _get_process_path(proc_pid: int) -> Optional[str]:
    """Get full path for a process."""
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, proc_pid)
        if handle:
            try:
                buf = ctypes.create_unicode_buffer(1024)
                size = wintypes.DWORD(1024)
                if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    return buf.value
            finally:
                kernel32.CloseHandle(handle)
    except Exception:
        pass
    return None


@mcp.tool()
def processes(
    filter: Optional[str] = None,
    pid: Optional[int] = None,
    parent: Optional[int] = None,
    service: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List running processes with smart filtering.

    Returns array of {pid, name, path, parent_pid, threads, command_line, services[]}.
    Services are auto-included for svchost processes.

    Filters (combine as needed):
      filter  - Substring match on process name
      pid     - Exact PID lookup (returns single process)
      parent  - Only processes with this parent PID
      service - Only processes hosting this service (e.g., "EventLog")

    Examples:
      processes(service="EventLog")     - Find which svchost hosts EventLog
      processes(filter="svchost")       - All svchosts with their services
      processes(pid=1820)               - Details for specific PID
      processes(parent=700)             - Children of services.exe"""
    import pymem.process

    _start = time.perf_counter()
    _log_args = {"filter": filter, "pid": pid, "parent": parent, "service": service, "limit": limit, "offset": offset}

    # Load services map if needed (service filter OR we'll need it for svchost)
    need_services = service is not None or (filter and "svchost" in filter.lower())
    pid_services = _enumerate_services() if need_services else {}

    # Enumerate processes
    result_list = []
    skipped = 0

    for proc in pymem.process.list_processes():
        name = proc.szExeFile.decode() if isinstance(proc.szExeFile, bytes) else proc.szExeFile
        proc_pid = proc.th32ProcessID
        parent_pid = proc.th32ParentProcessID

        # Apply filters
        if pid is not None and proc_pid != pid:
            continue
        if filter and filter.lower() not in name.lower():
            continue
        if parent is not None and parent_pid != parent:
            continue
        if service:
            proc_services = pid_services.get(proc_pid, [])
            if not any(s["name"].lower() == service.lower() for s in proc_services):
                continue

        # Apply offset
        if skipped < offset:
            skipped += 1
            continue

        # Build result entry
        entry = {
            "pid": proc_pid,
            "name": name,
            "parent_pid": parent_pid,
            "threads": proc.cntThreads,
        }

        # Include path and command line from PEB
        path = _get_process_path(proc_pid)
        if path:
            entry["path"] = path

        peb_data = read_process_peb(proc_pid)
        if peb_data and peb_data.get("command_line"):
            entry["command_line"] = peb_data["command_line"]

        # Include services for svchost processes
        if "svchost" in name.lower():
            if not pid_services:
                pid_services = _enumerate_services()  # Lazy load
            proc_services = pid_services.get(proc_pid, [])
            if proc_services:
                entry["services"] = proc_services

        result_list.append(entry)
        if len(result_list) >= limit:
            break

    return _log(
        "processes",
        _log_args,
        {
            "success": True,
            "processes": result_list,
            "count": len(result_list),
        },
        _start,
    )


@mcp.tool()
def attach(process_name: str, pid: Optional[int] = None) -> dict:
    """Attach to process and cache module bases.
    Returns pid, key_modules (base/size), saved_scripts list, scripts_dir, and log_file path.

    Use pid parameter when multiple processes share the same name (e.g., svchost.exe).
    Use processes() tool first to find the right PID.

    Examples: attach("Game.exe") or attach("svchost.exe", pid=1820)"""
    _start = time.perf_counter()

    _log_args = {"process_name": process_name}
    if pid:
        _log_args["pid"] = pid

    # Use canonical switch path (fires lifecycle callbacks)
    if not SESSION.switch_process(process_name, pid if pid else 0):
        LOGGER.clear_process()
        detail = f"Could not attach to PID {pid}" if pid else f"Could not attach to {process_name}. Is it running?"
        result = {"success": False, "error": "PROCESS_NOT_FOUND", "detail": detail}
        return _log("attach", _log_args, result, _start)

    LOGGER.set_process(process_name)

    # Return largest modules (most likely to be interesting)
    sorted_mods = sorted(SESSION.modules.items(), key=lambda x: x[1]["size"], reverse=True)
    modules_info = {}
    for name, info in sorted_mods[:10]:
        modules_info[name] = {"base": format_address(info["base"]), "size": info["size"]}

    # Get saved scripts info
    scripts_info = list_scripts()

    result = {
        "success": True,
        "pid": SESSION.pid,
        "process": process_name,
        "total_modules": len(SESSION.modules),
        "key_modules": modules_info,
        "saved_scripts": scripts_info.get("scripts", []),
        "scripts_dir": str(SCRIPTS_DIR / process_name),
        "log_file": str(LOGGER._get_log_file()),
    }
    return _log("attach", _log_args, result, _start)


@mcp.tool()
def modules(filter: Optional[str] = None, limit: int = 30) -> dict:
    """List loaded modules with base addresses, sizes, and paths.
    Use filter for substring match. Returns modules array."""
    _start = time.perf_counter()
    if SESSION.pm is None:
        return _log(
            "modules",
            {"filter": filter, "limit": limit},
            {"success": False, "error": "NOT_ATTACHED", "detail": "Call attach first"},
            _start,
        )

    mods = []
    for name, info in SESSION.modules.items():
        if filter and filter.lower() not in name.lower():
            continue
        mods.append(
            {"name": name, "base": format_address(info["base"]), "size": info["size"], "path": info.get("path", "")}
        )
        if len(mods) >= limit:
            break

    return _log(
        "modules",
        {"filter": filter, "limit": limit},
        {"success": True, "modules": mods, "total": len(SESSION.modules)},
        _start,
    )


# ============================================================================
# Memory Reading
# ============================================================================


@mcp.tool()
def read(address: str, type_name: str, count: int = 1) -> dict:
    """Read typed data from memory.
    Primitive types: int8/sbyte, uint8/byte, int16/short, uint16/ushort, char,
    int32/int, uint32/uint, int64/long, uint64/ulong, float/single,
    double, bool/boolean, ptr/pointer/intptr.
    Special types: cstring, bytes, bytes[N].
    Composite types: vector2/3/4, quaternion, color, color32, rect, bounds, matrix4x4.
    Use count > 1 for consecutive values; count controls length for bytes.
    Returns value or values array."""
    _start = time.perf_counter()
    result = read_typed(address, type_name, count)
    return _log("read", {"address": address, "type_name": type_name, "count": count}, result, _start)


# ============================================================================
# Memory Writing
# ============================================================================


@mcp.tool()
def write(address: str, value, type_name: str, verify: bool = False) -> dict:
    """Write typed data to memory. Use with caution.
    Types: primitives, composite types (vector3 as {x,y,z} dict), bytes, and bytes[N].
    Bytes values accept compact hex ("DEADBEEF"), spaced hex ("DE AD BE EF"), or [222, 173, 190, 239].
    bytes[N] requires exactly N bytes.
    Set verify=True to require a writable range check and byte-for-byte readback."""
    _start = time.perf_counter()
    result = write_typed(address, value, type_name, verify)
    return _log("write", {"address": address, "value": value, "type_name": type_name, "verify": verify}, result, _start)


# ============================================================================
# Memory Exploration
# ============================================================================


@mcp.tool()
def dump(
    address: str,
    size: int = 0x100,
    pointers_only: bool = False,
    start_offset: int = 0,
    non_null_only: bool = False,
    max_entries: int = 100,
    annotation_level: str = "normal",
) -> dict:
    """Smart memory dump with auto pointer detection.
    For exploring unknown structures. size is clamped to the remaining 4096-byte window.
    start_offset selects a byte offset within that window. annotation_level: minimal, normal, or full.
    Returns annotated entries showing likely pointers and values."""
    _start = time.perf_counter()
    _log_args = {
        "address": address,
        "size": size,
        "pointers_only": pointers_only,
        "start_offset": start_offset,
        "non_null_only": non_null_only,
        "max_entries": max_entries,
        "annotation_level": annotation_level,
    }
    result = smart_dump(
        address=address,
        size=size,
        start_offset=start_offset,
        pointers_only=pointers_only,
        non_null_only=non_null_only,
        max_entries=max_entries,
        annotation_level=annotation_level,
    )
    return _log("dump", _log_args, result, _start)


@mcp.tool()
def chain(base: str, offsets: list[int | str], read_final: str = "ptr") -> dict:
    """Follow pointer chain with standard RE semantics: add offset, then read.
    [[base+off0]+off1]... Offsets accept hex: ["0x148", "0x10"].
    Returns chain steps, final_address, and final_value."""
    _start = time.perf_counter()
    result = resolve_pointer_chain(base, offsets, read_final)
    return _log("chain", {"base": base, "offsets": offsets, "read_final": read_final}, result, _start)


@mcp.tool()
def scan(
    pattern: str,
    module: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    summary_only: bool = False,
    address_min: Optional[str] = None,
    address_max: Optional[str] = None,
    max_results: int = 5000,
    return_offset: bool = False,
    timeout_ms: int = 30000,
) -> dict:
    """Scan for byte pattern (AOB). Use ?? for wildcards.
    Faster with module specified. address_min/address_max bound the scan range.
    timeout_ms is clamped by the scanner to 100..30000 ms.
    Returns absolute matching addresses; return_offset=True adds module_offset."""
    _start = time.perf_counter()
    _log_args = {
        "pattern": pattern,
        "module": module,
        "limit": limit,
        "offset": offset,
        "summary_only": summary_only,
        "address_min": address_min,
        "address_max": address_max,
        "max_results": max_results,
        "return_offset": return_offset,
        "timeout_ms": timeout_ms,
    }
    result = scan_aob(**_log_args)
    return _log("scan", _log_args, result, _start)


# ============================================================================
# Lua Scripting
# ============================================================================


@mcp.tool()
def lua(script: str, timeout: Optional[float] = None) -> dict:
    """Execute Lua script for complex memory operations (loops, conditionals, multi-step).
    See server instructions for full list of available Lua functions.
    Args: script - Lua code. timeout - optional max seconds (default: 180 seconds).
    Returns: {success, results (dict), output (array of prints)}"""
    _start = time.perf_counter()
    result = execute_lua(script, timeout=timeout)
    return _log("lua", {"script": script, "timeout": timeout}, result, _start)


@mcp.tool()
def scripts(
    action: str, name: str = "", process: str = "", args: Optional[dict] = None, timeout: Optional[float] = None
) -> dict:
    """Lua script management. Scripts live under $MEMSCOPE_HOME/scripts/<process>/<name>.lua.

    Actions:
      list - Returns scripts with absolute paths. Use process='*' for all processes.
      run  - Execute by name. Pass args={} for script arguments. timeout=seconds optional.
             process='ProcessName.exe' selects the saved-script namespace only; it does not attach or switch.
             Without an attachment, pass process for detached execution. When attached, process must match.

    CREATE/EDIT: Use file tools on paths from 'list'. First line comment = description.
    Example: scripts(action='list') -> get scripts_dir, then Write to {scripts_dir}/<name>.lua
    """
    _start = time.perf_counter()
    _args = {"action": action, "name": name, "process": process, "args": args, "timeout": timeout}

    action = action.lower().strip()

    if action == "list":
        result = list_scripts(process if process else None)
    elif action == "run":
        if not name:
            result = {"success": False, "error": "MISSING_PARAM", "detail": "name required"}
        else:
            result = run_script(name, process if process else None, args, timeout=timeout)
    else:
        result = {
            "success": False,
            "error": "INVALID_ACTION",
            "detail": f"Unknown action '{action}'. Valid: list, run. Use file tools on 'list' paths to create/edit.",
        }

    return _log("scripts", _args, result, _start)


# ============================================================================
# Entry Point
# ============================================================================

_shutdown_done = False


def _shutdown():
    """Clean up hooks, free remote memory, and detach on server exit.

    Called from the main() finally block and registered with atexit as a backup.
    Idempotent -- safe to call multiple times (guarded by _shutdown_done).
    """
    global _shutdown_done
    if _shutdown_done:
        return
    _shutdown_done = True

    # Signal any running Lua script to abort at the next hook checkpoint.
    try:
        LUA_ENGINE.cancel()
    except BaseException:
        pass

    # Belt-and-suspenders: try hook cleanup directly first (in case detach
    # callbacks are not registered or SESSION.detach() fails early).
    try:
        from .tools.hooking import HOOK_MANAGER

        if HOOK_MANAGER.hooks or HOOK_MANAGER.ring_buffer:
            alive = SESSION.pm is not None and SESSION._is_process_alive()
            HOOK_MANAGER.cleanup(process_alive=alive)
    except BaseException:
        pass

    # Full detach fires remaining lifecycle callbacks and frees tracked allocations.
    try:
        if SESSION.pm is not None:
            SESSION.detach()
    except BaseException:
        pass


def main():
    """Run the MCP server."""
    import atexit
    import signal
    import sys

    if sys.platform == "win32":
        try:
            if hasattr(sys.stdin, "reconfigure"):
                sys.stdin.reconfigure(encoding="utf-8")
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    # Register cleanup for normal interpreter exit (backup for finally block).
    atexit.register(_shutdown)

    # Convert termination signals to SystemExit so finally/atexit run.
    def _signal_exit(sig, _frame):
        raise SystemExit(128 + sig)

    signal.signal(signal.SIGTERM, _signal_exit)
    if sys.platform == "win32" and hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _signal_exit)

    from .paths import MEMSCOPE_HOME as _MEMSCOPE_HOME

    print(f"[memscope] data dir: {_MEMSCOPE_HOME}", file=sys.stderr)

    try:
        mcp.run()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        _shutdown()


if __name__ == "__main__":
    main()
