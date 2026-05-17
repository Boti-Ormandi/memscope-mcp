"""Memory scanning tools: scan_aob and scan_references."""

import struct
import time
from dataclasses import dataclass
from typing import Any, Optional

import pymem.memory
import pymem.ressources.structure as structs

from ..session import SESSION
from ..utils.memory_utils import (
    format_address,
    get_module_for_address,
    parse_address,
)
from ..utils.pattern import match_pattern, parse_aob_pattern

# Scan limits
MAX_SCAN_RESULTS = 5000
SCAN_TIMEOUT_SECONDS = 30
SCAN_CHUNK_SIZE = 0x100000  # 1MB
USER_MODE_MAX_ADDRESS = 0x7FFFFFFFFFFF

# Protection constants. Keep these numeric to avoid coupling tests to pymem enum names.
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
MEM_COMMIT = structs.MEMORY_STATE.MEM_COMMIT.value


@dataclass
class ScanStats:
    """Runtime metadata collected during an AOB scan."""

    mode: str
    timeout_ms: int
    scanned_region_count: int = 0
    skipped_region_count: int = 0
    bytes_scanned: int = 0
    timeout_hit: bool = False
    read_error_count: int = 0
    result_count: int = 0
    limit_hit: bool = False
    duration_ms: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "scanned_region_count": self.scanned_region_count,
            "skipped_region_count": self.skipped_region_count,
            "bytes_scanned": self.bytes_scanned,
            "timeout_hit": self.timeout_hit,
            "result_count": self.result_count,
            "limit_hit": self.limit_hit,
            "read_error_count": self.read_error_count,
            "timeout_ms": self.timeout_ms,
            "duration_ms": self.duration_ms,
        }


def scan_aob(
    pattern: str,
    module: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    summary_only: bool = False,
    address_min: Optional[str] = None,
    address_max: Optional[str] = None,
    max_results: int = 5000,
    return_offset: bool = False,
    timeout_ms: int = SCAN_TIMEOUT_SECONDS * 1000,
) -> dict[str, Any]:
    """Scan memory for byte pattern (AOB scan).

    Unbounded scans keep the legacy module-only behavior. When address_min or
    address_max is supplied without a module, the scan walks committed readable
    memory regions from VirtualQueryEx, including MEM_PRIVATE heap pages.

    Args:
        pattern: Byte pattern with wildcards ("48 8B 05 ?? ?? ?? ??")
        module: Limit scan to specific module (faster)
        offset: Skip first N results (pagination)
        limit: Max results to return
        summary_only: Return counts only, no addresses
        address_min: Inclusive lower address bound
        address_max: Inclusive upper address bound
        max_results: Stop scanning after finding N total matches
        return_offset: Return module+offset instead of absolute address
        timeout_ms: Stop scanning after this many milliseconds

    Returns:
        {
            "pattern": str,
            "module": str or null,
            "data": [...],
            "scan_metadata": {...},
            "_pagination": {...}
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "error_detail": "Call attach_process first"}

    # Clamp paging limits. max_results is handled by scan_aob_addresses.
    limit = max(0, min(int(limit), 500))
    offset = max(0, int(offset))

    try:
        filter_min = parse_address(address_min) if address_min is not None else None
        filter_max = parse_address(address_max) if address_max is not None else None
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "error_detail": str(e)}

    raw_result = scan_aob_addresses(
        pattern,
        module=module,
        start_addr=filter_min,
        end_addr=filter_max,
        max_results=max_results,
        timeout_ms=timeout_ms,
    )
    if not raw_result["success"]:
        return raw_result

    all_matches = raw_result["matches"]

    # Apply pagination
    total = len(all_matches)
    paginated = all_matches[offset : offset + limit]

    # Format results
    if summary_only:
        data = []
    else:
        data = []
        for addr in paginated:
            entry = {"address": format_address(addr)}
            if return_offset:
                mod_info = get_module_for_address(addr)
                if mod_info:
                    entry["module_offset"] = f"{mod_info[0]}+0x{mod_info[1]:X}"
            data.append(entry)

    return {
        "success": True,
        "pattern": pattern,
        "module": module,
        "data": data,
        "scan_metadata": raw_result["metadata"],
        "_pagination": {"total": total, "offset": offset, "limit": limit, "has_more": offset + limit < total},
    }


def scan_aob_addresses(
    pattern: str,
    module: Optional[str] = None,
    start_addr: Optional[int] = None,
    end_addr: Optional[int] = None,
    max_results: int = 5000,
    timeout_ms: int = SCAN_TIMEOUT_SECONDS * 1000,
) -> dict[str, Any]:
    """Return raw AOB matches plus scan metadata.

    If no module and no bounds are provided, this scans loaded modules only.
    If bounds are provided without a module, this scans arbitrary committed
    readable VirtualQueryEx regions clipped to the requested interval.
    """
    try:
        parsed = parse_aob_pattern(pattern)
    except ValueError as e:
        return {"success": False, "error": "INVALID_PATTERN", "error_detail": str(e)}

    if parsed.length == 0:
        return {"success": False, "error": "INVALID_PATTERN", "error_detail": "Pattern is empty"}

    max_results = _clamp_max_results(max_results)
    timeout_ms = _normalize_timeout_ms(timeout_ms)
    timeout_seconds = timeout_ms / 1000.0
    start_time = time.time()

    stats = ScanStats(mode=_scan_mode(module, start_addr, end_addr), timeout_ms=timeout_ms)

    if max_results == 0 or (end_addr is not None and start_addr is not None and end_addr < start_addr):
        stats.duration_ms = int((time.time() - start_time) * 1000)
        return {"success": True, "matches": [], "metadata": stats.as_dict()}

    matches: list[int] = []

    if module:
        mod_info = SESSION.modules.get(module)
        if not mod_info:
            return {"success": False, "error": "MODULE_NOT_FOUND", "error_detail": f"Module '{module}' not found"}

        matches.extend(
            _scan_region(
                mod_info["base"],
                mod_info["size"],
                parsed,
                max_results,
                start_time,
                timeout_seconds,
                stats,
                start_addr,
                end_addr,
            )
        )
    elif start_addr is not None or end_addr is not None:
        scan_start = 0 if start_addr is None else max(0, start_addr)
        scan_end = USER_MODE_MAX_ADDRESS if end_addr is None else min(end_addr, USER_MODE_MAX_ADDRESS)
        for region_base, region_size in _iter_readable_regions(scan_start, scan_end, stats):
            if _timed_out(start_time, timeout_seconds, stats):
                break
            if len(matches) >= max_results:
                stats.limit_hit = True
                break

            region_matches = _scan_region(
                region_base,
                region_size,
                parsed,
                max_results - len(matches),
                start_time,
                timeout_seconds,
                stats,
            )
            matches.extend(region_matches)
    else:
        for _mod_name, mod_info in SESSION.modules.items():
            if _timed_out(start_time, timeout_seconds, stats):
                break
            if len(matches) >= max_results:
                stats.limit_hit = True
                break

            module_matches = _scan_region(
                mod_info["base"],
                mod_info["size"],
                parsed,
                max_results - len(matches),
                start_time,
                timeout_seconds,
                stats,
            )
            matches.extend(module_matches)

    stats.result_count = len(matches)
    stats.limit_hit = stats.limit_hit or len(matches) >= max_results
    stats.duration_ms = int((time.time() - start_time) * 1000)

    return {"success": True, "matches": matches, "metadata": stats.as_dict()}


def _scan_mode(module: Optional[str], start_addr: Optional[int], end_addr: Optional[int]) -> str:
    if module:
        return "module"
    if start_addr is not None or end_addr is not None:
        return "range"
    return "modules"


def _clamp_max_results(max_results: int) -> int:
    try:
        value = int(max_results)
    except (TypeError, ValueError):
        value = MAX_SCAN_RESULTS
    return max(0, min(value, MAX_SCAN_RESULTS))


def _normalize_timeout_ms(timeout_ms: int) -> int:
    try:
        value = int(timeout_ms)
    except (TypeError, ValueError):
        value = SCAN_TIMEOUT_SECONDS * 1000
    return max(100, min(value, SCAN_TIMEOUT_SECONDS * 1000))


def _timed_out(start_time: float, timeout_seconds: float, stats: ScanStats) -> bool:
    if time.time() - start_time > timeout_seconds:
        stats.timeout_hit = True
        return True
    return False


def _is_readable_committed(mbi) -> bool:
    if int(mbi.State) != MEM_COMMIT:
        return False
    if int(mbi.Protect) & PAGE_GUARD:
        return False
    base_protect = int(mbi.Protect) & 0xFF
    if base_protect == PAGE_NOACCESS:
        return False
    return base_protect in READABLE_PROTECTIONS


def _iter_readable_regions(start_addr: int, end_addr: int, stats: ScanStats):
    """Yield committed readable regions clipped to [start_addr, end_addr]."""
    if SESSION.pm is None:
        return

    address = max(0, start_addr)
    end_addr = min(end_addr, USER_MODE_MAX_ADDRESS)

    while address <= end_addr:
        try:
            mbi = pymem.memory.virtual_query(SESSION.pm.process_handle, address)
        except Exception:
            stats.skipped_region_count += 1
            break

        region_base = int(mbi.BaseAddress)
        region_size = int(mbi.RegionSize)
        if region_size <= 0:
            break

        region_end = region_base + region_size
        next_address = max(address + 0x1000, region_end)

        if region_end <= start_addr or region_base > end_addr:
            address = next_address
            continue

        clipped_base = max(region_base, start_addr)
        clipped_end = min(region_end, end_addr + 1)
        clipped_size = clipped_end - clipped_base

        if clipped_size <= 0:
            stats.skipped_region_count += 1
        elif not _is_readable_committed(mbi):
            stats.skipped_region_count += 1
        else:
            yield clipped_base, clipped_size

        address = next_address


def _scan_region(
    base: int,
    size: int,
    pattern,
    max_results: int,
    start_time: float,
    timeout_seconds: float,
    stats: ScanStats,
    filter_min: Optional[int] = None,
    filter_max: Optional[int] = None,
) -> list[int]:
    """Scan a single module or memory region for pattern matches."""
    scan_base, scan_size = _clip_region(base, size, filter_min, filter_max)
    if scan_size < pattern.length:
        stats.skipped_region_count += 1
        return []

    matches = []
    stats.scanned_region_count += 1

    chunk_size = max(SCAN_CHUNK_SIZE, pattern.length + 0x1000)
    overlap = max(0, pattern.length - 1)
    step = max(1, chunk_size - overlap)

    for chunk_start in range(0, scan_size, step):
        if _timed_out(start_time, timeout_seconds, stats):
            break
        if len(matches) >= max_results:
            stats.limit_hit = True
            break

        chunk_end = min(chunk_start + chunk_size, scan_size)
        read_size = chunk_end - chunk_start
        try:
            data = SESSION.read_bytes(scan_base + chunk_start, read_size)
        except Exception:
            stats.read_error_count += 1
            continue

        stats.bytes_scanned += len(data)
        chunk_matches = match_pattern(data, pattern, start=scan_base + chunk_start)

        for addr in chunk_matches:
            # Keep matches fully inside explicit bounds.
            if filter_min is not None and addr < filter_min:
                continue
            if filter_max is not None and addr + pattern.length - 1 > filter_max:
                continue

            matches.append(addr)
            if len(matches) >= max_results:
                stats.limit_hit = True
                break

    return matches


def _clip_region(
    base: int,
    size: int,
    filter_min: Optional[int],
    filter_max: Optional[int],
) -> tuple[int, int]:
    start = base
    end = base + size

    if filter_min is not None:
        start = max(start, filter_min)
    if filter_max is not None:
        end = min(end, filter_max + 1)

    if end <= start:
        return start, 0
    return start, end - start


def scan_references(
    target_address: str,
    scan_regions: Optional[list[str]] = None,
    alignment: int = 8,
    offset: int = 0,
    limit: int = 50,
    summary_only: bool = False,
    stop_after: int = 100,
) -> dict[str, Any]:
    """Find all pointers that reference target_address.

    Args:
        target_address: Address to find references to
        scan_regions: List of module names to scan (e.g., ["module.dll"]).
            If None or ["all"], scans all loaded modules.
        alignment: Only check aligned addresses (default 8)
        offset: Pagination offset
        limit: Max results per page
        summary_only: Return counts only
        stop_after: Stop after finding N refs

    Returns:
        {
            "target": "0x...",
            "data": [...],
            "_pagination": {...}
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "error_detail": "Call attach_process first"}

    if scan_regions is None:
        scan_regions = ["all"]

    try:
        target = parse_address(target_address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "error_detail": str(e)}

    # Convert target to bytes for searching
    target_bytes = struct.pack("<Q", target)

    all_refs = []
    start_time = time.time()

    # Determine which modules to scan
    if "all" in scan_regions:
        modules_to_scan = list(SESSION.modules.keys())
    else:
        modules_to_scan = [m for m in scan_regions if m in SESSION.modules]

    # Scan each module
    for mod_name in modules_to_scan:
        if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
            break
        if len(all_refs) >= stop_after:
            break

        mod_info = SESSION.modules.get(mod_name)
        if not mod_info:
            continue

        refs = _scan_for_pointer(
            mod_info["base"], mod_info["size"], target_bytes, alignment, stop_after - len(all_refs), start_time
        )

        for addr in refs:
            all_refs.append({"address": format_address(addr), "context": f"{mod_name}+0x{addr - mod_info['base']:X}"})

    # Apply pagination
    total = len(all_refs)
    paginated = all_refs[offset : offset + limit]

    return {
        "success": True,
        "target": format_address(target),
        "data": [] if summary_only else paginated,
        "_pagination": {"total": total, "offset": offset, "limit": limit, "has_more": offset + limit < total},
    }


def _scan_for_pointer(
    base: int, size: int, target_bytes: bytes, alignment: int, max_results: int, start_time: float
) -> list[int]:
    """Scan memory region for pointer value."""
    matches = []
    chunk_size = 0x100000  # 1MB

    for chunk_start in range(0, size, chunk_size):
        if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
            break
        if len(matches) >= max_results:
            break

        chunk_end = min(chunk_start + chunk_size, size)
        try:
            data = SESSION.read_bytes(base + chunk_start, chunk_end - chunk_start)
        except Exception:
            continue

        # Search for target bytes at aligned offsets
        for i in range(0, len(data) - 7, alignment):
            if data[i : i + 8] == target_bytes:
                matches.append(base + chunk_start + i)
                if len(matches) >= max_results:
                    break

    return matches
