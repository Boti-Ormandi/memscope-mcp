"""Pointer chain resolution tools."""

from typing import Any

from ..session import SESSION
from ..utils.memory_utils import (
    format_address,
    is_valid_pointer,
    parse_address,
    parse_offset,
    read_with_format,
)


def resolve_pointer_chain(base: str, offsets: list[int | str], read_final: str = "uint64") -> dict[str, Any]:
    """Follow a pointer chain: [[base+off0]+off1]+off2...

    Standard RE semantics: add offset first, then dereference.

    Args:
        base: Starting address or "module+offset" format
              e.g., "0x1CF300B7700" or "module.dll+0x1A208D8"
        offsets: List of offsets (int or hex string) ["0x148", "0x10"] or [328, 16]
        read_final: Format for final value ("ptr", "float", "cstring", etc)

    Returns:
        {
            "base": "0x...",
            "offsets": [0x148, 0x10],
            "chain": [
                {"step": 0, "address": "0x...", "read_value": "0x..."},
                ...
            ],
            "final_address": "0x...",
            "final_value": <value>,
            "success": bool,
            "error_at_step": int or null
        }
    """
    # Normalize offsets (accept hex strings like "0x148")
    offsets = [parse_offset(o) for o in offsets]

    if not SESSION.ensure_attached():
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "error_detail": "Call attach_process first"}

    try:
        current_addr = parse_address(base)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "error_detail": str(e)}

    chain = []
    current = current_addr
    final_read_addr = current_addr  # Track where we read from

    # Follow pointer chain: add offset first, then read (standard RE semantics)
    for step, offset in enumerate(offsets):
        read_addr = current + offset  # Add offset FIRST

        try:
            ptr_value = SESSION.read_ptr(read_addr)  # THEN read
        except Exception as e:
            chain.append(
                {
                    "step": step,
                    "address": format_address(read_addr),
                    "offset_applied": f"+0x{offset:X}",
                    "error": str(e),
                }
            )
            return {
                "success": False,
                "base": format_address(parse_address(base)),
                "offsets": offsets,
                "chain": chain,
                "final_address": None,
                "final_value": None,
                "error_at_step": step,
                "error": "ACCESS_VIOLATION",
                "error_detail": f"Step {step}: Cannot read at {format_address(read_addr)}",
            }

        chain.append(
            {
                "step": step,
                "address": format_address(read_addr),
                "offset_applied": f"+0x{offset:X}",
                "read_value": format_address(ptr_value),
            }
        )

        final_read_addr = read_addr  # Track for final_address

        # Validate pointer for intermediate steps (not the last one)
        is_last_step = step == len(offsets) - 1
        if not is_last_step and not is_valid_pointer(ptr_value):
            return {
                "success": False,
                "base": format_address(parse_address(base)),
                "offsets": offsets,
                "chain": chain,
                "final_address": None,
                "final_value": None,
                "error_at_step": step,
                "error": "INVALID_POINTER",
                "error_detail": f"Step {step}: Read value 0x{ptr_value:X} is not a valid pointer",
            }

        current = ptr_value  # Continue from read value

    # Format final value
    try:
        # For pointer types, use the last read value directly
        if read_final.lower() in ("ptr", "pointer", "uint64"):
            final_value = format_address(current)
        else:
            # Re-read with specified format
            final_value = read_with_format(final_read_addr, 8, read_final)
            if isinstance(final_value, bytes):
                final_value = " ".join(f"{b:02X}" for b in final_value)

        return {
            "success": True,
            "base": format_address(parse_address(base)),
            "offsets": offsets,
            "chain": chain,
            "final_address": format_address(final_read_addr),
            "final_value": final_value,
            "final_format": read_final,
            "error_at_step": None,
        }

    except Exception as e:
        return {
            "success": False,
            "base": format_address(parse_address(base)),
            "offsets": offsets,
            "chain": chain,
            "final_address": format_address(final_read_addr),
            "final_value": None,
            "error_at_step": len(offsets),
            "error": "ACCESS_VIOLATION",
            "error_detail": f"Cannot read final value at {format_address(final_read_addr)}: {str(e)}",
        }


def read_pointer(address: str) -> dict[str, Any]:
    """Read a single pointer and return info about what it points to.

    Args:
        address: Address to read pointer from

    Returns:
        {
            "address": "0x...",
            "value": "0x...",
            "is_valid": bool,
            "target_info": {...}
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "PROCESS_NOT_ATTACHED", "error_detail": "Call attach_process first"}

    try:
        addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "error_detail": str(e)}

    try:
        ptr_value = SESSION.read_ptr(addr)
        is_valid = is_valid_pointer(ptr_value)

        result = {
            "success": True,
            "address": format_address(addr),
            "value": format_address(ptr_value),
            "is_valid": is_valid,
        }

        if is_valid:
            # Try to get more info about target
            from .memory import smart_dump

            target_info = smart_dump(format_address(ptr_value), size=0x40, max_entries=8)
            if target_info.get("success"):
                result["target_preview"] = target_info.get("entries", [])[:4]

        return result

    except Exception as e:
        return {
            "success": False,
            "error": "ACCESS_VIOLATION",
            "error_detail": f"Cannot read at {format_address(addr)}: {str(e)}",
        }
