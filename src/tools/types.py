"""Typed memory reading and writing.

Supports primitives (int8-64, float, double, bool, ptr),
composite types (vector2/3/4, quaternion, color, rect, bounds, matrix4x4),
and null-terminated C strings.
"""

import struct
from typing import Any

from ..session import SESSION
from ..utils.memory_utils import format_address, parse_address

# =============================================================================
# Type Definitions - sizes and struct formats
# =============================================================================

# Primitive types: (size, struct_format, signed)
PRIMITIVES = {
    # Integers
    "int8": (1, "<b", True),
    "sbyte": (1, "<b", True),
    "uint8": (1, "<B", False),
    "byte": (1, "<B", False),
    "int16": (2, "<h", True),
    "short": (2, "<h", True),
    "uint16": (2, "<H", False),
    "ushort": (2, "<H", False),
    "char": (2, "<H", False),  # UTF-16 code unit
    "int32": (4, "<i", True),
    "int": (4, "<i", True),
    "uint32": (4, "<I", False),
    "uint": (4, "<I", False),
    "int64": (8, "<q", True),
    "long": (8, "<q", True),
    "uint64": (8, "<Q", False),
    "ulong": (8, "<Q", False),
    # Floats
    "float": (4, "<f", None),
    "single": (4, "<f", None),
    "double": (8, "<d", None),
    # Pointer
    "ptr": (8, "<Q", False),
    "pointer": (8, "<Q", False),
    "intptr": (8, "<Q", False),
    # Bool - 1 byte
    "bool": (1, "<B", None),
    "boolean": (1, "<B", None),
}

# Composite types: (size, component_count, component_format)
COMPOSITE_TYPES = {
    "vector2": (8, 2, "<ff"),
    "vector3": (12, 3, "<fff"),
    "vector4": (16, 4, "<ffff"),
    "quaternion": (16, 4, "<ffff"),
    "color": (16, 4, "<ffff"),  # RGBA floats 0-1
    "color32": (4, 4, "<BBBB"),  # RGBA bytes 0-255
    "rect": (16, 4, "<ffff"),  # x, y, width, height
    "bounds": (24, 6, "<ffffff"),  # center(3) + extents(3)
    "matrix4x4": (64, 16, "<16f"),  # Column-major
}


def read_typed(address: str, type_name: str, count: int = 1) -> dict[str, Any]:
    """Read typed data from memory.

    Args:
        address: Memory address (hex string, decimal, or "Module+0xOffset")
        type_name: Type to read. Supported types:

            Primitives:
                int8/sbyte, uint8/byte, int16/short, uint16/ushort, char,
                int32/int, uint32/uint, int64/long, uint64/ulong,
                float/single, double, ptr/pointer, bool

            Composite Types:
                vector2, vector3, vector4, quaternion,
                color, color32, rect, bounds, matrix4x4

            Strings:
                cstring - reads null-terminated C string

        count: Number of consecutive values to read (for arrays of primitives)

    Returns:
        {
            "success": bool,
            "address": "0x...",
            "type": str,
            "value": <typed value or list>,
            "size": int (bytes read)
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "NOT_ATTACHED"}

    try:
        addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "detail": str(e)}

    type_lower = type_name.lower().strip()

    try:
        # Handle primitives
        if type_lower in PRIMITIVES:
            return _read_primitive(addr, type_lower, count)

        # Handle composite types
        if type_lower in COMPOSITE_TYPES:
            return _read_composite_type(addr, type_lower, count)

        # Handle null-terminated C string
        if type_lower == "cstring":
            return _read_cstring(addr)

        # Handle raw bytes
        if type_lower == "bytes" or type_lower.startswith("bytes["):
            # Parse bytes[N] format
            if "[" in type_lower:
                size = int(type_lower.split("[")[1].rstrip("]"))
            else:
                size = count
            data = SESSION.read_bytes(addr, size)
            return {
                "success": True,
                "address": format_address(addr),
                "type": "bytes",
                "value": " ".join(f"{b:02X}" for b in data),
                "size": size,
            }

        return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}

    except Exception as e:
        return {"success": False, "error": "READ_ERROR", "address": format_address(addr), "detail": str(e)}


def _read_primitive(addr: int, type_name: str, count: int) -> dict:
    """Read primitive type(s)."""
    size, fmt, signed = PRIMITIVES[type_name]
    total_size = size * count

    data = SESSION.read_bytes(addr, total_size)

    if count == 1:
        value = struct.unpack(fmt, data)[0]
        # Format pointer as hex
        if type_name in ("ptr", "pointer", "intptr"):
            value = format_address(value)
        # Convert bool to Python bool
        elif type_name in ("bool", "boolean"):
            value = value != 0
    else:
        # Multiple values
        values = []
        for i in range(count):
            chunk = data[i * size : (i + 1) * size]
            v = struct.unpack(fmt, chunk)[0]
            if type_name in ("ptr", "pointer", "intptr"):
                v = format_address(v)
            elif type_name in ("bool", "boolean"):
                v = v != 0
            values.append(v)
        value = values

    return {"success": True, "address": format_address(addr), "type": type_name, "value": value, "size": total_size}


def _read_composite_type(addr: int, type_name: str, count: int) -> dict:
    """Read composite type(s)."""
    size, num_components, fmt = COMPOSITE_TYPES[type_name]
    total_size = size * count

    data = SESSION.read_bytes(addr, total_size)

    def parse_one(chunk: bytes) -> Any:
        components = struct.unpack(fmt, chunk)

        if type_name == "vector2":
            return {"x": round(components[0], 6), "y": round(components[1], 6)}
        elif type_name == "vector3":
            return {"x": round(components[0], 6), "y": round(components[1], 6), "z": round(components[2], 6)}
        elif type_name == "vector4":
            return {
                "x": round(components[0], 6),
                "y": round(components[1], 6),
                "z": round(components[2], 6),
                "w": round(components[3], 6),
            }
        elif type_name == "quaternion":
            return {
                "x": round(components[0], 6),
                "y": round(components[1], 6),
                "z": round(components[2], 6),
                "w": round(components[3], 6),
            }
        elif type_name == "color":
            return {
                "r": round(components[0], 4),
                "g": round(components[1], 4),
                "b": round(components[2], 4),
                "a": round(components[3], 4),
            }
        elif type_name == "color32":
            return {"r": components[0], "g": components[1], "b": components[2], "a": components[3]}
        elif type_name == "rect":
            return {
                "x": round(components[0], 4),
                "y": round(components[1], 4),
                "width": round(components[2], 4),
                "height": round(components[3], 4),
            }
        elif type_name == "bounds":
            return {
                "center": {"x": round(components[0], 4), "y": round(components[1], 4), "z": round(components[2], 4)},
                "extents": {"x": round(components[3], 4), "y": round(components[4], 4), "z": round(components[5], 4)},
            }
        elif type_name == "matrix4x4":
            # Column-major: m00,m10,m20,m30, m01,m11,m21,m31, ...
            return {"columns": [[round(components[i * 4 + j], 6) for j in range(4)] for i in range(4)]}
        return list(components)

    if count == 1:
        value = parse_one(data)
    else:
        value = [parse_one(data[i * size : (i + 1) * size]) for i in range(count)]

    return {"success": True, "address": format_address(addr), "type": type_name, "value": value, "size": total_size}


def _read_cstring(addr: int, max_length: int = 256) -> dict:
    """Read null-terminated C string."""
    # Read raw bytes and find null terminator manually
    raw = SESSION.read_bytes(addr, max_length)

    # Find null terminator
    null_pos = raw.find(b"\x00")
    if null_pos >= 0:
        raw = raw[:null_pos]

    # Decode as UTF-8 (falls back gracefully for ASCII)
    try:
        value = raw.decode("utf-8", errors="replace")
    except Exception:
        value = raw.decode("latin-1", errors="replace")

    return {
        "success": True,
        "address": format_address(addr),
        "type": "cstring",
        "value": value,
        "length": len(value),
        "size": len(value) + 1,  # +1 for null terminator
    }


def get_type_info(type_name: str) -> dict[str, Any]:
    """Get information about a type (size, alignment, etc.).

    Args:
        type_name: Type name to look up

    Returns:
        {"type": str, "size": int, "category": str, "components": ...}
    """
    type_lower = type_name.lower().strip()

    if type_lower in PRIMITIVES:
        size, fmt, signed = PRIMITIVES[type_lower]
        return {
            "success": True,
            "type": type_lower,
            "category": "primitive",
            "size": size,
            "signed": signed,
            "alignment": size,
        }

    if type_lower in COMPOSITE_TYPES:
        size, num_components, fmt = COMPOSITE_TYPES[type_lower]
        return {
            "success": True,
            "type": type_lower,
            "category": "composite",
            "size": size,
            "components": num_components,
            "alignment": 4,
        }

    if type_lower == "cstring":
        return {"success": True, "type": "cstring", "category": "native", "encoding": "null-terminated ASCII/UTF-8"}

    return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}


def write_typed(address: str, value: Any, type_name: str, validate: bool = False) -> dict[str, Any]:
    """Write typed data to memory.

    Args:
        address: Memory address (hex string, decimal, or "Module+0xOffset")
        value: Value to write. For composite types, pass dict: {x, y, z} or list/tuple
        type_name: Type to write. Supported:

            Primitives:
                int8/sbyte, uint8/byte, int16/short, uint16/ushort,
                int32/int, uint32/uint, int64/long, uint64/ulong,
                float/single, double, ptr/pointer, bool

            Composite Types:
                vector2, vector3, vector4, quaternion,
                color, color32, rect, bounds

        validate: If True, read the address first to ensure it's accessible

    Returns:
        {
            "success": bool,
            "address": "0x...",
            "type": str,
            "old_value": <value before write> (if validate=True),
            "new_value": <value written>,
            "size": int (bytes written)
        }
    """
    if not SESSION.ensure_attached():
        return {"success": False, "error": "NOT_ATTACHED"}

    try:
        addr = parse_address(address)
    except ValueError as e:
        return {"success": False, "error": "INVALID_ADDRESS", "detail": str(e)}

    type_lower = type_name.lower().strip()

    # Validate before write if requested
    old_value = None
    if validate:
        try:
            # Try to read the address first
            read_result = read_typed(address, type_name, 1)
            if read_result.get("success"):
                old_value = read_result.get("value")
        except:
            return {"success": False, "error": "VALIDATION_FAILED", "detail": "Cannot read address before write"}

    try:
        # Handle primitives
        if type_lower in PRIMITIVES:
            result = _write_primitive(addr, type_lower, value)
            if result["success"] and validate:
                result["old_value"] = old_value
            return result

        # Handle composite types
        if type_lower in COMPOSITE_TYPES:
            result = _write_composite_type(addr, type_lower, value)
            if result["success"] and validate:
                result["old_value"] = old_value
            return result

        return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}

    except Exception as e:
        return {"success": False, "error": "WRITE_ERROR", "address": format_address(addr), "detail": str(e)}


def _write_primitive(addr: int, type_name: str, value: Any) -> dict:
    """Write primitive type."""
    size, fmt, signed = PRIMITIVES[type_name]

    try:
        # Convert value to appropriate type
        if type_name in ("bool", "boolean"):
            val = 1 if value else 0
        elif type_name in ("float", "single", "double"):
            val = float(value)
        elif type_name in ("ptr", "pointer", "intptr"):
            # Handle hex string addresses
            if isinstance(value, str):
                val = parse_address(value)
            else:
                val = int(value)
        else:
            val = int(value)

        # Write using SESSION methods for common types (faster)
        if type_name in ("int32", "int"):
            SESSION.write_int32(addr, val)
        elif type_name in ("uint32", "uint"):
            SESSION.write_uint32(addr, val)
        elif type_name in ("int64", "long"):
            SESSION.write_int64(addr, val)
        elif type_name in ("uint64", "ulong", "ptr", "pointer", "intptr"):
            SESSION.write_uint64(addr, val)
        elif type_name in ("float", "single"):
            SESSION.write_float(addr, val)
        elif type_name in ("double",):
            SESSION.write_double(addr, val)
        elif type_name in ("byte", "uint8", "bool", "boolean"):
            SESSION.write_byte(addr, val)
        else:
            # Use struct packing for other types
            data = struct.pack(fmt, val)
            SESSION.write_bytes(addr, data)

        return {"success": True, "address": format_address(addr), "type": type_name, "new_value": value, "size": size}

    except struct.error as e:
        return {"success": False, "error": "VALUE_OUT_OF_RANGE", "type": type_name, "value": value, "detail": str(e)}


def _write_composite_type(addr: int, type_name: str, value: Any) -> dict:
    """Write composite type."""
    size, num_components, fmt = COMPOSITE_TYPES[type_name]

    # Convert value to component tuple
    try:
        if isinstance(value, dict):
            # Handle dict format: {x, y, z}
            if type_name in ("vector2",):
                components = (value["x"], value["y"])
            elif type_name in ("vector3",):
                components = (value["x"], value["y"], value["z"])
            elif type_name in ("vector4", "quaternion"):
                components = (value["x"], value["y"], value["z"], value["w"])
            elif type_name in ("color",):
                components = (value["r"], value["g"], value["b"], value["a"])
            elif type_name in ("color32",):
                components = (int(value["r"]), int(value["g"]), int(value["b"]), int(value["a"]))
            elif type_name in ("rect",):
                components = (value["x"], value["y"], value["width"], value["height"])
            elif type_name in ("bounds",):
                c = value["center"]
                e = value["extents"]
                components = (c["x"], c["y"], c["z"], e["x"], e["y"], e["z"])
            else:
                return {"success": False, "error": "UNSUPPORTED_COMPOSITE_TYPE", "type": type_name}
        elif isinstance(value, (list, tuple)):
            # Handle list/tuple format
            if len(value) != num_components:
                return {
                    "success": False,
                    "error": "COMPONENT_COUNT_MISMATCH",
                    "expected": num_components,
                    "got": len(value),
                }
            components = tuple(value)
        else:
            return {
                "success": False,
                "error": "INVALID_VALUE_FORMAT",
                "detail": "Composite types require dict {x,y,z} or list [x,y,z]",
            }

        # Pack and write
        data = struct.pack(fmt, *components)
        SESSION.write_bytes(addr, data)

        return {"success": True, "address": format_address(addr), "type": type_name, "new_value": value, "size": size}

    except (KeyError, struct.error) as e:
        return {"success": False, "error": "VALUE_FORMAT_ERROR", "type": type_name, "detail": str(e)}


def list_supported_types() -> dict[str, Any]:
    """List all supported types for read_typed.

    Returns:
        {"primitives": [...], "composite_types": [...], ...}
    """
    return {
        "success": True,
        "primitives": list(PRIMITIVES.keys()),
        "composite_types": list(COMPOSITE_TYPES.keys()),
        "native_types": ["cstring"],
        "special": ["bytes", "bytes[N]"],
    }
