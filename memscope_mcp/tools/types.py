"""Typed memory reading and writing.

Supports primitives (int8-64, float, double, bool, ptr),
composite types (vector2/3/4, quaternion, color, rect, bounds, matrix4x4),
null-terminated C strings, and raw byte reads.
"""

import struct
from typing import Any

from ..session import SESSION
from ..utils.memory_utils import format_address, format_bytes, parse_address

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

PRIMITIVE_ALIASES = {
    "int8": ["sbyte"],
    "uint8": ["byte"],
    "int16": ["short"],
    "uint16": ["ushort"],
    "int32": ["int"],
    "uint32": ["uint"],
    "int64": ["long"],
    "uint64": ["ulong"],
    "float": ["single"],
    "ptr": ["pointer", "intptr"],
    "bool": ["boolean"],
}

PRIMITIVE_CANONICAL_TYPES = {type_name: type_name for type_name in PRIMITIVES}
for _canonical, _aliases in PRIMITIVE_ALIASES.items():
    PRIMITIVE_CANONICAL_TYPES[_canonical] = _canonical
    for _alias in _aliases:
        PRIMITIVE_CANONICAL_TYPES[_alias] = _canonical

SPECIAL_READ_TYPES = ["bytes", "bytes[N]"]

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
                float/single, double, ptr/pointer/intptr, bool/boolean

            Composite Types:
                vector2, vector3, vector4, quaternion,
                color, color32, rect, bounds, matrix4x4

            Special Types:
                cstring - reads null-terminated C string
                bytes - reads count raw bytes as uppercase spaced hex
                bytes[N] - reads N raw bytes as uppercase spaced hex

        count: Number of consecutive values to read; controls byte count for bytes

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


def _parse_bytes_type_size(type_lower: str) -> int | None:
    if type_lower == "bytes":
        return None
    if not type_lower.startswith("bytes[") or not type_lower.endswith("]"):
        raise ValueError("not a bytes type")

    size_text = type_lower[6:-1].strip()
    if not size_text.isdecimal():
        raise ValueError("bytes[N] requires a non-negative integer size")
    return int(size_text)


def get_type_info(type_name: str) -> dict[str, Any]:
    """Get information about a type (size, alignment, etc.).

    Args:
        type_name: Type name to look up

    Returns:
        {"type": str, "size": int, "category": str, "components": ...}
    """
    type_lower = type_name.lower().strip()

    if type_lower in PRIMITIVES:
        size, _fmt, signed = PRIMITIVES[type_lower]
        canonical = PRIMITIVE_CANONICAL_TYPES[type_lower]
        info = {
            "success": True,
            "type": type_lower,
            "canonical_type": canonical,
            "aliases": PRIMITIVE_ALIASES.get(canonical, []).copy(),
            "category": "primitive",
            "size": size,
            "signed": signed,
            "alignment": size,
        }
        if type_lower == "char":
            info["encoding"] = "UTF-16 code unit"
        return info

    if type_lower in COMPOSITE_TYPES:
        size, num_components, _fmt = COMPOSITE_TYPES[type_lower]
        return {
            "success": True,
            "type": type_lower,
            "canonical_type": type_lower,
            "aliases": [],
            "category": "composite",
            "size": size,
            "components": num_components,
            "alignment": 4,
        }

    if type_lower == "cstring":
        return {
            "success": True,
            "type": "cstring",
            "canonical_type": "cstring",
            "aliases": [],
            "category": "native",
            "encoding": "null-terminated ASCII/UTF-8",
        }

    if type_lower == "bytes" or type_lower.startswith("bytes["):
        try:
            size = _parse_bytes_type_size(type_lower)
        except ValueError:
            return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}

        return {
            "success": True,
            "type": type_lower,
            "canonical_type": "bytes",
            "aliases": [],
            "category": "special",
            "size": size,
            "alignment": 1,
            "count_controls_size": size is None,
            "value_format": "uppercase spaced hex string",
        }

    return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}


def _coerce_primitive_value(type_name: str, value: Any) -> int | float:
    if type_name in ("bool", "boolean"):
        return 1 if value else 0
    if type_name in ("float", "single", "double"):
        return float(value)
    if type_name in ("ptr", "pointer", "intptr"):
        if isinstance(value, str):
            return parse_address(value)
        return int(value)
    return int(value)


def _pack_primitive_value(type_name: str, value: Any) -> dict[str, Any]:
    size, fmt, _signed = PRIMITIVES[type_name]
    val = _coerce_primitive_value(type_name, value)

    if type_name in ("byte", "uint8", "bool", "boolean"):
        return {"success": True, "data": bytes([int(val) & 0xFF]), "new_value": value, "size": size}

    try:
        data = struct.pack(fmt, val)
    except struct.error as e:
        return {"success": False, "error": "VALUE_OUT_OF_RANGE", "type": type_name, "value": value, "detail": str(e)}

    return {"success": True, "data": data, "new_value": value, "size": size}


def _get_composite_components(type_name: str, value: Any) -> tuple[Any, ...] | dict[str, Any]:
    _size, num_components, _fmt = COMPOSITE_TYPES[type_name]

    if isinstance(value, dict):
        if type_name in ("vector2",):
            return (value["x"], value["y"])
        if type_name in ("vector3",):
            return (value["x"], value["y"], value["z"])
        if type_name in ("vector4", "quaternion"):
            return (value["x"], value["y"], value["z"], value["w"])
        if type_name in ("color",):
            return (value["r"], value["g"], value["b"], value["a"])
        if type_name in ("color32",):
            return (int(value["r"]), int(value["g"]), int(value["b"]), int(value["a"]))
        if type_name in ("rect",):
            return (value["x"], value["y"], value["width"], value["height"])
        if type_name in ("bounds",):
            c = value["center"]
            e = value["extents"]
            return (c["x"], c["y"], c["z"], e["x"], e["y"], e["z"])
        return {"success": False, "error": "UNSUPPORTED_COMPOSITE_TYPE", "type": type_name}

    if isinstance(value, (list, tuple)):
        if len(value) != num_components:
            return {
                "success": False,
                "error": "COMPONENT_COUNT_MISMATCH",
                "expected": num_components,
                "got": len(value),
            }
        return tuple(value)

    return {
        "success": False,
        "error": "INVALID_VALUE_FORMAT",
        "detail": "Composite types require dict {x,y,z} or list [x,y,z]",
    }


def _pack_composite_value(type_name: str, value: Any) -> dict[str, Any]:
    size, _num_components, fmt = COMPOSITE_TYPES[type_name]

    try:
        components = _get_composite_components(type_name, value)
        if isinstance(components, dict):
            return components
        data = struct.pack(fmt, *components)
    except (KeyError, struct.error) as e:
        return {"success": False, "error": "VALUE_FORMAT_ERROR", "type": type_name, "detail": str(e)}

    return {"success": True, "data": data, "new_value": value, "size": size}


def _pack_write_value(type_name: str, value: Any) -> dict[str, Any]:
    if type_name in PRIMITIVES:
        return _pack_primitive_value(type_name, value)
    if type_name in COMPOSITE_TYPES:
        return _pack_composite_value(type_name, value)
    return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}


def _write_verified(addr: int, type_name: str, value: Any) -> dict[str, Any]:
    packed = _pack_write_value(type_name, value)
    if not packed.get("success"):
        return packed

    data = packed["data"]
    size = packed["size"]
    address = format_address(addr)

    try:
        writable = SESSION.is_memory_range_writable(addr, size)
    except Exception:
        writable = False
    if not writable:
        return {
            "success": False,
            "error": "MEMORY_NOT_WRITABLE",
            "address": address,
            "type": type_name,
            "size": size,
            "detail": "Target range is not writable",
        }

    try:
        old_data = SESSION.read_bytes(addr, size)
    except Exception as e:
        return {
            "success": False,
            "error": "VALIDATION_FAILED",
            "address": address,
            "type": type_name,
            "size": size,
            "detail": f"Cannot read target range before write: {e}",
        }

    try:
        SESSION.write_bytes(addr, data)
    except Exception as e:
        return {"success": False, "error": "WRITE_ERROR", "address": address, "type": type_name, "detail": str(e)}

    try:
        actual_data = SESSION.read_bytes(addr, size)
    except Exception as e:
        return {
            "success": False,
            "error": "VERIFY_READ_FAILED",
            "address": address,
            "type": type_name,
            "old_value": format_bytes(old_data),
            "new_value": value,
            "size": size,
            "detail": f"Cannot read target range after write: {e}",
        }

    if actual_data != data:
        return {
            "success": False,
            "error": "VERIFY_MISMATCH",
            "address": address,
            "type": type_name,
            "old_value": format_bytes(old_data),
            "new_value": value,
            "expected": format_bytes(data),
            "actual": format_bytes(actual_data),
            "size": size,
            "detail": "Readback did not match requested bytes",
        }

    return {
        "success": True,
        "address": address,
        "type": type_name,
        "old_value": format_bytes(old_data),
        "new_value": value,
        "size": size,
        "verified": True,
    }


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

        validate: If True, check the whole target range is writable, capture
            exact pre-write bytes, write, and byte-compare the readback

    Returns:
        {
            "success": bool,
            "address": "0x...",
            "type": str,
            "old_value": <pre-write bytes as hex> (if validate=True),
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

    try:
        if validate:
            return _write_verified(addr, type_lower, value)

        # Handle primitives
        if type_lower in PRIMITIVES:
            return _write_primitive(addr, type_lower, value)

        # Handle composite types
        if type_lower in COMPOSITE_TYPES:
            return _write_composite_type(addr, type_lower, value)

        return {"success": False, "error": "UNKNOWN_TYPE", "type": type_name}

    except Exception as e:
        return {"success": False, "error": "WRITE_ERROR", "address": format_address(addr), "detail": str(e)}


def _write_primitive(addr: int, type_name: str, value: Any) -> dict:
    """Write primitive type."""
    size, fmt, _signed = PRIMITIVES[type_name]

    try:
        val = _coerce_primitive_value(type_name, value)

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
    packed = _pack_composite_value(type_name, value)
    if not packed.get("success"):
        return packed

    SESSION.write_bytes(addr, packed["data"])
    return {
        "success": True,
        "address": format_address(addr),
        "type": type_name,
        "new_value": value,
        "size": packed["size"],
    }


def list_supported_types() -> dict[str, Any]:
    """List all supported types for read_typed.

    Returns:
        {"primitives": [...], "composite_types": [...], ...}
    """
    aliases = {alias: canonical for canonical, type_aliases in PRIMITIVE_ALIASES.items() for alias in type_aliases}
    primitive_aliases = {canonical: type_aliases.copy() for canonical, type_aliases in PRIMITIVE_ALIASES.items()}

    return {
        "success": True,
        "primitives": list(PRIMITIVES.keys()),
        "primitive_aliases": primitive_aliases,
        "aliases": aliases,
        "composite_types": list(COMPOSITE_TYPES.keys()),
        "native_types": ["cstring"],
        "special": SPECIAL_READ_TYPES.copy(),
        "special_types": SPECIAL_READ_TYPES.copy(),
    }
