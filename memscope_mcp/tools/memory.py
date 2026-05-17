"""Memory reading tools: read_memory and smart_dump."""

from typing import Any

from ..session import SESSION
from ..utils.heuristics import analyze_memory_region
from ..utils.memory_utils import (
    format_address,
    format_bytes,
    is_valid_pointer,
    parse_address,
    read_with_format,
)


def read_memory(address: str, size: int = 8, format: str = "hex") -> dict[str, Any]:
    """Read memory at address with automatic type conversion.

    Args:
        address: Hex string "0x1234" or decimal "12345" or "Module+0xOffset"
        size: Bytes to read (1, 2, 4, 8 for typed reads)
        format: "hex" | "int" | "uint" | "float" | "double" |
                "cstring" | "bytes"

    Returns:
        {
            "address": "0x...",
            "raw_bytes": "48 8B 05 ...",
            "value": <converted value>,
            "format": str
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "error_detail": "Call attach_process first"}

    try:
        addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "error_detail": str(e)}

    try:
        # Read raw bytes for display
        raw_bytes = SESSION.read_bytes(addr, size)

        # Get formatted value
        value = read_with_format(addr, size, format)

        # Convert bytes to displayable format if needed
        if isinstance(value, bytes):
            value = format_bytes(value)

        return {
            "success": True,
            "address": format_address(addr),
            "raw_bytes": format_bytes(raw_bytes),
            "value": value,
            "format": format,
        }

    except Exception as e:
        return {
            "success": False,
            "error": "ACCESS_VIOLATION",
            "error_detail": f"Cannot read memory at {format_address(addr)}: {str(e)}",
        }


def smart_dump(
    address: str,
    size: int = 0x100,
    start_offset: int = 0,
    pointers_only: bool = False,
    non_null_only: bool = False,
    max_entries: int = 100,
    annotation_level: str = "normal",
) -> dict[str, Any]:
    """Dump memory with automatic type detection and pointer resolution.

    Args:
        address: Starting address
        size: Bytes to dump (default 256, max 4096)
        start_offset: Begin dump from address + start_offset
        pointers_only: Only return entries that are valid pointers
        non_null_only: Skip null/zero entries
        max_entries: Cap entries regardless of size
        annotation_level: Detail level ("minimal" | "normal" | "full")

    Returns:
        {
            "address": "0x...",
            "size": int,
            "entries": [...],
            "pointers_found": ["0x...", ...],
            "_pagination": {...}
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "error_detail": "Call attach_process first"}

    # Clamp size
    size = min(size, 0x1000)  # Max 4096 bytes

    try:
        base_addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "error_detail": str(e)}

    actual_addr = base_addr + start_offset

    try:
        data = SESSION.read_bytes(actual_addr, size)
    except Exception as e:
        return {
            "success": False,
            "error": "ACCESS_VIOLATION",
            "error_detail": f"Cannot read memory at {format_address(actual_addr)}: {str(e)}",
        }

    # Analyze the memory region
    all_entries = analyze_memory_region(actual_addr, data, entry_size=8)

    # Apply filters
    filtered_entries = []
    pointers_found = []

    for entry in all_entries:
        # Extract raw value for filtering
        raw_hex = entry["raw"]
        try:
            raw_val = int(raw_hex, 16)
        except ValueError:
            raw_val = 0

        # Filter: non_null_only
        if non_null_only and raw_val == 0:
            continue

        # Filter: pointers_only
        if pointers_only:
            if not is_valid_pointer(raw_val):
                continue

        # Track pointers
        if is_valid_pointer(raw_val):
            pointers_found.append(format_address(raw_val))

        # Annotation level adjustments
        if annotation_level == "minimal":
            entry = {"offset": entry["offset"], "raw": entry["raw"], "type": entry["type"]}
        elif annotation_level == "full":
            entry["address"] = entry.get("address", format_address(actual_addr + int(entry["offset"][1:], 16)))

        filtered_entries.append(entry)

        if len(filtered_entries) >= max_entries:
            break

    # Calculate pagination info
    total_entries = len(data) // 8
    has_more = start_offset + size < 0x1000  # Could continue dumping

    return {
        "success": True,
        "address": format_address(base_addr),
        "dump_start": format_address(actual_addr),
        "size": size,
        "entries": filtered_entries,
        "pointers_found": pointers_found[:20],  # Limit pointer list
        "_pagination": {
            "total_size": size,
            "dumped_range": {"start": start_offset, "end": start_offset + size},
            "entries_returned": len(filtered_entries),
            "entries_total": total_entries,
            "has_more": has_more,
            "next_start_offset": start_offset + size if has_more else None,
        },
    }
