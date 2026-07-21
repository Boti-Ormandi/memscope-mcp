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
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "detail": "Call attach_process first"}

    try:
        addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "detail": str(e)}

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
            "detail": f"Cannot read memory at {format_address(addr)}: {str(e)}",
        }


_DUMP_WINDOW_SIZE = 0x1000
_DUMP_ENTRY_SIZE = 8
_DUMP_ANNOTATION_LEVELS = {"minimal", "normal", "full"}


def _invalid_dump_param(error: str, detail: str) -> dict[str, Any]:
    return {"success": False, "error": error, "detail": detail}


def _is_int_param(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


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
        size: Positive byte count, clamped to the remaining 4096-byte dump window
        start_offset: Begin dump from address + start_offset, in range 0..4095
        pointers_only: Only return entries that are valid pointers
        non_null_only: Skip null/zero entries
        max_entries: Positive cap on returned entries regardless of size
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
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "detail": "Call attach_process first"}

    if not _is_int_param(start_offset) or not 0 <= start_offset < _DUMP_WINDOW_SIZE:
        return _invalid_dump_param("INVALID_START_OFFSET", "start_offset must be an integer in range 0..4095")
    if not _is_int_param(size) or size <= 0:
        return _invalid_dump_param("INVALID_SIZE", "size must be a positive integer")
    if not _is_int_param(max_entries) or max_entries <= 0:
        return _invalid_dump_param("INVALID_MAX_ENTRIES", "max_entries must be a positive integer")
    if not isinstance(annotation_level, str):
        return _invalid_dump_param("INVALID_ANNOTATION_LEVEL", "annotation_level must be one of: minimal, normal, full")

    annotation_level = annotation_level.lower().strip()
    if annotation_level not in _DUMP_ANNOTATION_LEVELS:
        return _invalid_dump_param("INVALID_ANNOTATION_LEVEL", "annotation_level must be one of: minimal, normal, full")

    effective_size = min(size, _DUMP_WINDOW_SIZE - start_offset)

    try:
        base_addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "detail": str(e)}

    actual_addr = base_addr + start_offset

    try:
        data = SESSION.read_bytes(actual_addr, effective_size)
    except Exception as e:
        return {
            "success": False,
            "error": "ACCESS_VIOLATION",
            "detail": f"Cannot read memory at {format_address(actual_addr)}: {str(e)}",
        }

    bytes_read = len(data)
    all_entries = analyze_memory_region(
        actual_addr,
        data,
        entry_size=_DUMP_ENTRY_SIZE,
        include_confidence=annotation_level == "full",
    )

    filtered_entries = []
    pointers_found = []
    processed_entries = 0
    max_entries_reached = False

    for source_entry in all_entries:
        processed_entries += 1

        raw_hex = source_entry["raw"]
        try:
            raw_val = int(raw_hex, 16)
        except ValueError:
            raw_val = 0

        if non_null_only and raw_val == 0:
            continue

        if pointers_only and not is_valid_pointer(raw_val):
            continue

        if is_valid_pointer(raw_val):
            pointers_found.append(format_address(raw_val))

        entry = dict(source_entry)
        if annotation_level == "minimal":
            entry = {"offset": entry["offset"], "raw": entry["raw"], "type": entry["type"]}
        elif annotation_level == "full":
            entry.setdefault("address", format_address(actual_addr + int(entry["offset"][1:], 16)))

        filtered_entries.append(entry)

        if len(filtered_entries) >= max_entries:
            max_entries_reached = True
            break

    read_end_offset = start_offset + bytes_read
    if max_entries_reached:
        processed_end_offset = start_offset + processed_entries * _DUMP_ENTRY_SIZE
    else:
        processed_end_offset = read_end_offset

    has_more = processed_end_offset < _DUMP_WINDOW_SIZE

    return {
        "success": True,
        "address": format_address(base_addr),
        "dump_start": format_address(actual_addr),
        "size": bytes_read,
        "entries": filtered_entries,
        "pointers_found": pointers_found[:20],
        "_pagination": {
            "total_size": bytes_read,
            "dumped_range": {"start": start_offset, "end": processed_end_offset},
            "entries_returned": len(filtered_entries),
            "entries_total": len(all_entries),
            "entries_scanned": processed_entries,
            "has_more": has_more,
            "next_start_offset": processed_end_offset if has_more else None,
        },
    }
