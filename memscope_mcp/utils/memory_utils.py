"""Memory reading utilities and validation helpers."""

import struct
from typing import Any, Optional, Union

from ..session import SESSION


def parse_offset(offset: Union[int, str]) -> int:
    """Parse offset from int or hex string. E.g., 0x148 or "0x148" or 328."""
    if isinstance(offset, int):
        return offset
    offset = offset.strip()
    if offset.startswith(("0x", "0X")):
        return int(offset, 16)
    return int(offset)


def parse_address(address: Union[str, int], *, session=None) -> int:
    """Parse address from string or int format.

    Supports:
        - Hex string: "0x1CF300B7700"
        - Decimal string: "12345"
        - Integer: 12345
        - Module+offset: "module.dll+0x1A208D8"
        - Hex+offset: "0x7FFC8E7D0000+0x1A23748"
    """
    if isinstance(address, int):
        return address

    address = address.strip()

    # Check for any expression with +
    if "+" in address:
        parts = address.split("+", 1)
        base_str = parts[0].strip()
        offset_str = parts[1].strip()

        # Parse offset (always numeric)
        offset = int(offset_str, 16) if offset_str.lower().startswith("0x") else int(offset_str)

        # Determine if base is a module name or hex address
        if base_str.lower().startswith("0x"):
            # Hex base address: 0x7FFC8E7D0000+0x1A23748
            base = int(base_str, 16)
        else:
            # Module name: module.dll+0x1A208D8
            lookup_session = SESSION if session is None else session
            base = lookup_session.get_module_base(base_str)
            if base is None:
                raise ValueError(f"Module not found: {base_str}")

        return base + offset

    # Hex or decimal
    if address.lower().startswith("0x"):
        return int(address, 16)

    try:
        return int(address)
    except ValueError:
        if session is None:
            raise
        base = session.get_module_base(address)
        if base is None:
            raise
        return base


def format_address(address: int) -> str:
    """Format address as hex string."""
    return f"0x{address:X}"


def format_bytes(data: bytes) -> str:
    """Format bytes as hex string with spaces."""
    return " ".join(f"{b:02X}" for b in data)


def read_with_format(address: int, size: int, fmt: str, *, session) -> Any:
    """Read memory and convert to specified format.

    Args:
        address: Memory address
        size: Bytes to read (for raw/hex)
        fmt: Format type

    Returns:
        Converted value
    """
    if session.pm is None:
        raise RuntimeError("Not attached to process")

    fmt = fmt.lower()

    if fmt == "int" or fmt == "int32":
        return session.read_int32(address)
    elif fmt == "uint" or fmt == "uint32":
        return session.read_uint32(address)
    elif fmt == "int64":
        return struct.unpack("<q", session.read_bytes(address, 8))[0]
    elif fmt == "uint64" or fmt == "pointer":
        return session.read_ptr(address)
    elif fmt == "float":
        return session.read_float(address)
    elif fmt == "double":
        return session.read_double(address)
    elif fmt == "cstring":
        return session.read_string(address, 256)
    elif fmt == "bytes" or fmt == "raw":
        return session.read_bytes(address, size)
    elif fmt == "hex":
        data = session.read_bytes(address, size)
        return format_bytes(data)
    else:
        # Default to raw bytes
        return session.read_bytes(address, size)


def is_valid_pointer(value: int) -> bool:
    """Check if a value looks like a valid user-mode pointer."""
    return 0x10000 <= value <= 0x7FFFFFFFFFFF


def get_module_for_address(address: int, *, session) -> Optional[tuple[str, int]]:
    """Find which module contains an address.

    Returns:
        Tuple of (module_name, offset) or None if not in any module
    """
    snapshot = session.module_snapshot
    if snapshot is None:
        return None
    for name, info in snapshot.to_legacy_dict().items():
        base = info["base"]
        size = info["size"]
        if base <= address < base + size:
            return (name, address - base)
    return None


def format_pointer_annotation(ptr: int, *, session) -> str:
    """Create annotation string for a pointer value."""
    mod_info = get_module_for_address(ptr, session=session)
    if mod_info:
        name, offset = mod_info
        return f"-> {name}+0x{offset:X}"
    return f"-> 0x{ptr:X}"


def safe_read_ptr(address: int, *, session) -> Optional[int]:
    """Safely read a pointer, returning None on error."""
    try:
        return session.read_ptr(address)
    except Exception:
        return None


def safe_read_bytes(address: int, size: int, *, session) -> Optional[bytes]:
    """Safely read bytes, returning None on error."""
    try:
        return session.read_bytes(address, size)
    except Exception:
        return None


def safe_read_string(address: int, max_len: int = 256, *, session) -> Optional[str]:
    """Safely read C string, returning None on error."""
    try:
        return session.read_string(address, max_len)
    except Exception:
        return None
