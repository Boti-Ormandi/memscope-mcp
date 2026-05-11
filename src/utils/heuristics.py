"""Type detection heuristics for smart_dump."""

import struct
from dataclasses import dataclass
from enum import Enum

from .memory_utils import (
    get_module_for_address,
    is_valid_pointer,
    safe_read_string,
)


class ValueType(Enum):
    """Detected value types."""

    NULL = "NULL"
    POINTER = "POINTER"
    STRING_PTR = "STRING_PTR"
    INT = "INT"
    FLOAT = "FLOAT"
    INLINE_STRING = "INLINE_STRING"
    UNKNOWN = "UNKNOWN"


@dataclass
class DetectedValue:
    """Result of type detection."""

    value_type: ValueType
    raw_value: int
    annotation: str
    confidence: float  # 0.0 to 1.0


def detect_value_type(raw_bytes: bytes, address: int) -> DetectedValue:
    """Detect the type of an 8-byte value.

    Args:
        raw_bytes: 8 bytes of data
        address: Address where the bytes came from (for context)

    Returns:
        DetectedValue with type and annotation
    """
    if len(raw_bytes) < 8:
        raw_bytes = raw_bytes + b"\x00" * (8 - len(raw_bytes))

    value = struct.unpack("<Q", raw_bytes)[0]

    if value == 0:
        return DetectedValue(value_type=ValueType.NULL, raw_value=0, annotation="NULL", confidence=1.0)

    if is_valid_pointer(value):
        annotation = _analyze_pointer(value)

        c_str = safe_read_string(value, 64)
        if c_str and len(c_str) > 2 and _is_printable(c_str):
            preview = c_str[:50] + "..." if len(c_str) > 50 else c_str
            return DetectedValue(
                value_type=ValueType.STRING_PTR, raw_value=value, annotation=f'-> "{preview}"', confidence=0.8
            )

        return DetectedValue(value_type=ValueType.POINTER, raw_value=value, annotation=annotation, confidence=0.85)

    if value < 0x10000:
        return DetectedValue(value_type=ValueType.INT, raw_value=value, annotation=str(value), confidence=0.7)

    # Examine lower 4 bytes for a plausible float value.
    float_val = struct.unpack("<f", raw_bytes[:4])[0]
    if _is_reasonable_float(float_val):
        return DetectedValue(value_type=ValueType.FLOAT, raw_value=value, annotation=f"{float_val:.4f}", confidence=0.6)

    if _looks_like_inline_string(raw_bytes):
        try:
            # Find null terminator or end
            null_idx = raw_bytes.find(b"\x00")
            if null_idx > 0:
                s = raw_bytes[:null_idx].decode("ascii")
            else:
                s = raw_bytes.decode("ascii")
            return DetectedValue(
                value_type=ValueType.INLINE_STRING, raw_value=value, annotation=f'"{s}"', confidence=0.7
            )
        except Exception:
            pass

    # Unknown
    return DetectedValue(value_type=ValueType.UNKNOWN, raw_value=value, annotation=f"0x{value:X}", confidence=0.0)


def _analyze_pointer(ptr: int) -> str:
    """Create annotation for a pointer value."""
    mod_info = get_module_for_address(ptr)
    if mod_info:
        name, offset = mod_info
        return f"-> {name}+0x{offset:X}"
    return f"-> 0x{ptr:X}"


def _is_printable(s: str) -> bool:
    """Check if string is mostly printable."""
    if not s:
        return False
    printable_count = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable_count / len(s) > 0.8


def _is_reasonable_float(f: float) -> bool:
    """Check if float value is reasonable (not NaN/Inf, in sensible range)."""
    import math

    if math.isnan(f) or math.isinf(f):
        return False
    return -1e10 < f < 1e10


def _looks_like_inline_string(data: bytes) -> bool:
    """Check if bytes look like inline ASCII string."""
    if len(data) < 2:
        return False

    # Must have mostly printable ASCII
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b == 0)
    return printable >= len(data) * 0.8


def analyze_memory_region(address: int, data: bytes, entry_size: int = 8) -> list[dict]:
    """Analyze a memory region and detect types for each entry.

    Args:
        address: Starting address
        data: Raw bytes
        entry_size: Size of each entry (default 8 for pointers)

    Returns:
        List of entry dictionaries with type info
    """
    entries = []
    offset = 0

    while offset + entry_size <= len(data):
        entry_bytes = data[offset : offset + entry_size]
        entry_addr = address + offset

        detected = detect_value_type(entry_bytes, entry_addr)

        entries.append(
            {
                "offset": f"+0x{offset:02X}",
                "address": f"0x{entry_addr:X}",
                "raw": f"0x{detected.raw_value:016X}",
                "type": detected.value_type.value,
                "annotation": detected.annotation,
            }
        )

        offset += entry_size

    return entries
