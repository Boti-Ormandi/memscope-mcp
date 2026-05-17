"""Struct helper functions for Lua engine.

Generic struct reading: vectors, matrices, arbitrary field layouts.
Domain-specific helpers live in plugins.
"""

import struct
from typing import Any, Callable

from ...session import SESSION
from ...utils.memory_utils import is_valid_pointer


def read_vector3(address, table_factory: Callable[..., Any]):
    """Read Vector3 (12 bytes). Returns Lua table {x, y, z}."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 12)
        x, y, z = struct.unpack("<fff", data)
        return table_factory(x=x, y=y, z=z)
    except:
        return None


def read_vector4(address, table_factory: Callable[..., Any]):
    """Read Vector4/Quaternion (16 bytes). Returns Lua table {x, y, z, w}."""
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 16)
        x, y, z, w = struct.unpack("<ffff", data)
        return table_factory(x=x, y=y, z=z, w=w)
    except:
        return None


def read_matrix4x4(address, table_factory: Callable[..., Any]):
    """Read 4x4 matrix (64 bytes). Returns Lua table with position field.

    Matrix layout varies by engine. This assumes column-major (common in 3D engines).
    Position is typically in the 4th column (indices 12, 13, 14 for x, y, z).
    """
    try:
        addr = int(address)
        data = SESSION.read_bytes(addr, 64)
        floats = struct.unpack("<16f", data)

        # Column-major: position in 4th column (indices 12, 13, 14)
        pos_x = floats[12]
        pos_y = floats[13]
        pos_z = floats[14]

        result = table_factory()
        result["position"] = table_factory(x=pos_x, y=pos_y, z=pos_z)
        result["m00"] = floats[0]
        result["m10"] = floats[1]
        result["m20"] = floats[2]
        result["m30"] = floats[3]
        result["m01"] = floats[4]
        result["m11"] = floats[5]
        result["m21"] = floats[6]
        result["m31"] = floats[7]
        result["m02"] = floats[8]
        result["m12"] = floats[9]
        result["m22"] = floats[10]
        result["m32"] = floats[11]
        result["m03"] = floats[12]
        result["m13"] = floats[13]
        result["m23"] = floats[14]
        result["m33"] = floats[15]

        return result
    except:
        return None


def read_struct(
    address,
    fields_table,
    table_factory: Callable[..., Any],
    read_vector3_fn: Callable,
    read_vector4_fn: Callable,
    log_error: Callable[[str, Exception], None],
    output: list[str],
):
    """Read multiple fields from a struct in one call.

    Args:
        address: Base address of the struct
        fields_table: Lua table mapping field names to "type@offset" strings
        table_factory: Function to create Lua tables
        read_vector3_fn: Function to read vector3
        read_vector4_fn: Function to read vector4
        log_error: Error logging function
        output: Output list for messages

    Supported types:
        byte, bool, int16, uint16, int32, uint32, int64, uint64,
        float, double, ptr, pointer, cstring, vector3, vector4

    Example:
        local player = readStruct(playerAddr, {
            health = "float@0x100",
            maxHealth = "float@0x104",
            name = "cstring@0x10",
            position = "vector3@0x200",
            isAlive = "bool@0x108",
            level = "uint32@0x110"
        })
        print(player.health, player.name)

    Returns:
        Lua table with field values, or nil on error
    """
    try:
        base = int(address)
        if not is_valid_pointer(base):
            return None

        result = table_factory()

        # Type readers map
        readers = {
            "byte": lambda a: SESSION.read_bytes(a, 1)[0],
            "bool": lambda a: SESSION.read_bytes(a, 1)[0] != 0,
            "int16": lambda a: struct.unpack("<h", SESSION.read_bytes(a, 2))[0],
            "uint16": lambda a: struct.unpack("<H", SESSION.read_bytes(a, 2))[0],
            "int32": lambda a: SESSION.read_int32(a),
            "uint32": lambda a: struct.unpack("<I", SESSION.read_bytes(a, 4))[0],
            "int64": lambda a: struct.unpack("<q", SESSION.read_bytes(a, 8))[0],
            "uint64": lambda a: struct.unpack("<Q", SESSION.read_bytes(a, 8))[0],
            "float": lambda a: SESSION.read_float(a),
            "double": lambda a: SESSION.read_double(a),
            "ptr": lambda a: SESSION.read_ptr(a),
            "pointer": lambda a: SESSION.read_ptr(a),
            "cstring": lambda a: SESSION.read_string(a, 256),
            "vector3": lambda a: read_vector3_fn(a),
            "vector4": lambda a: read_vector4_fn(a),
        }

        # Iterate Lua table
        for field_name, field_spec in fields_table.items():
            try:
                spec = str(field_spec)
                if "@" not in spec:
                    continue

                type_name, offset_str = spec.split("@", 1)
                type_name = type_name.lower().strip()
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)

                reader = readers.get(type_name)
                if reader:
                    field_addr = base + offset
                    value = reader(field_addr)
                    result[field_name] = value
                else:
                    output.append(f"readStruct: unknown type '{type_name}' for field '{field_name}'")
            except Exception as field_err:
                log_error(f"readStruct.{field_name}", field_err)
                result[field_name] = None

        return result

    except Exception as e:
        log_error("readStruct", e)
        return None
