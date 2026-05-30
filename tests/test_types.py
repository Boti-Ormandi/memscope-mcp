"""Tests for type system metadata and definitions."""

import struct

import memscope_mcp.tools.types as types_module
from memscope_mcp.tools.types import COMPOSITE_TYPES, PRIMITIVES, get_type_info, list_supported_types, write_typed


class TestPrimitiveDefinitions:
    """Verify PRIMITIVES dict has consistent sizes and format strings."""

    def test_int8_size(self):
        assert PRIMITIVES["int8"][0] == 1
        assert PRIMITIVES["sbyte"][0] == 1

    def test_int16_size(self):
        assert PRIMITIVES["int16"][0] == 2
        assert PRIMITIVES["short"][0] == 2

    def test_int32_size(self):
        assert PRIMITIVES["int32"][0] == 4
        assert PRIMITIVES["int"][0] == 4

    def test_int64_size(self):
        assert PRIMITIVES["int64"][0] == 8
        assert PRIMITIVES["long"][0] == 8

    def test_float_size(self):
        assert PRIMITIVES["float"][0] == 4
        assert PRIMITIVES["single"][0] == 4

    def test_double_size(self):
        assert PRIMITIVES["double"][0] == 8

    def test_pointer_size(self):
        assert PRIMITIVES["ptr"][0] == 8
        assert PRIMITIVES["pointer"][0] == 8
        assert PRIMITIVES["intptr"][0] == 8

    def test_bool_size(self):
        assert PRIMITIVES["bool"][0] == 1

    def test_signed_flags(self):
        assert PRIMITIVES["int32"][2] is True
        assert PRIMITIVES["uint32"][2] is False
        assert PRIMITIVES["float"][2] is None  # N/A for floats
        assert PRIMITIVES["bool"][2] is None

    def test_all_aliases_match(self):
        """Aliases should have identical definitions."""
        assert PRIMITIVES["int8"] == PRIMITIVES["sbyte"]
        assert PRIMITIVES["uint8"] == PRIMITIVES["byte"]
        assert PRIMITIVES["int16"] == PRIMITIVES["short"]
        assert PRIMITIVES["uint16"] == PRIMITIVES["ushort"]
        assert PRIMITIVES["int32"] == PRIMITIVES["int"]
        assert PRIMITIVES["uint32"] == PRIMITIVES["uint"]
        assert PRIMITIVES["int64"] == PRIMITIVES["long"]
        assert PRIMITIVES["uint64"] == PRIMITIVES["ulong"]
        assert PRIMITIVES["float"] == PRIMITIVES["single"]
        assert PRIMITIVES["ptr"] == PRIMITIVES["pointer"]
        assert PRIMITIVES["bool"] == PRIMITIVES["boolean"]


class TestCompositeDefinitions:
    def test_vector2(self):
        size, components, fmt = COMPOSITE_TYPES["vector2"]
        assert size == 8  # 2 floats
        assert components == 2

    def test_vector3(self):
        size, components, fmt = COMPOSITE_TYPES["vector3"]
        assert size == 12  # 3 floats
        assert components == 3

    def test_vector4(self):
        size, components, fmt = COMPOSITE_TYPES["vector4"]
        assert size == 16
        assert components == 4

    def test_quaternion(self):
        size, components, fmt = COMPOSITE_TYPES["quaternion"]
        assert size == 16
        assert components == 4

    def test_color(self):
        size, components, fmt = COMPOSITE_TYPES["color"]
        assert size == 16
        assert components == 4

    def test_color32(self):
        size, components, fmt = COMPOSITE_TYPES["color32"]
        assert size == 4  # 4 bytes
        assert components == 4

    def test_bounds(self):
        size, components, fmt = COMPOSITE_TYPES["bounds"]
        assert size == 24  # 6 floats
        assert components == 6

    def test_matrix4x4(self):
        size, components, fmt = COMPOSITE_TYPES["matrix4x4"]
        assert size == 64  # 16 floats
        assert components == 16


class TestGetTypeInfo:
    def test_primitive(self):
        info = get_type_info("int32")
        assert info["success"] is True
        assert info["category"] == "primitive"
        assert info["size"] == 4
        assert info["signed"] is True
        assert info["alignment"] == 4

    def test_unsigned_primitive(self):
        info = get_type_info("uint64")
        assert info["success"] is True
        assert info["size"] == 8
        assert info["signed"] is False

    def test_composite(self):
        info = get_type_info("vector3")
        assert info["success"] is True
        assert info["category"] == "composite"
        assert info["size"] == 12
        assert info["components"] == 3

    def test_cstring(self):
        info = get_type_info("cstring")
        assert info["success"] is True
        assert info["category"] == "native"

    def test_unknown(self):
        info = get_type_info("nonexistent_type")
        assert info["success"] is False
        assert "UNKNOWN_TYPE" in info["error"]

    def test_case_insensitive(self):
        info = get_type_info("Vector3")
        assert info["success"] is True
        assert info["size"] == 12

    def test_whitespace_stripped(self):
        info = get_type_info("  float  ")
        assert info["success"] is True
        assert info["size"] == 4

    def test_primitive_alias_metadata(self):
        info = get_type_info("sbyte")
        assert info["success"] is True
        assert info["canonical_type"] == "int8"
        assert info["aliases"] == ["sbyte"]
        assert info["size"] == 1

    def test_pointer_alias_metadata(self):
        info = get_type_info("intptr")
        assert info["success"] is True
        assert info["canonical_type"] == "ptr"
        assert info["aliases"] == ["pointer", "intptr"]
        assert info["size"] == 8

    def test_char_metadata(self):
        info = get_type_info("char")
        assert info["success"] is True
        assert info["category"] == "primitive"
        assert info["size"] == 2
        assert info["encoding"] == "UTF-16 code unit"

    def test_bytes_metadata(self):
        info = get_type_info("bytes")
        assert info["success"] is True
        assert info["category"] == "special"
        assert info["canonical_type"] == "bytes"
        assert info["size"] is None
        assert info["count_controls_size"] is True

    def test_sized_bytes_metadata(self):
        info = get_type_info("bytes[16]")
        assert info["success"] is True
        assert info["category"] == "special"
        assert info["canonical_type"] == "bytes"
        assert info["size"] == 16
        assert info["count_controls_size"] is False

    def test_malformed_bytes_metadata_is_unknown_with_detail(self):
        cases = {
            "bytes[abc]": "bytes type must be 'bytes' or 'bytes[N]'",
            "bytes[]": "bytes type must be 'bytes' or 'bytes[N]'",
            "bytes[0]": "bytes[N] requires a positive integer size",
        }
        for type_name, detail in cases.items():
            info = get_type_info(type_name)
            assert info["success"] is False
            assert info["error"] == "UNKNOWN_TYPE"
            assert info["type"] == type_name
            assert info["detail"] == detail


class TestListSupportedTypes:
    def test_returns_all_categories(self):
        result = list_supported_types()
        assert result["success"] is True
        assert "primitives" in result
        assert "composite_types" in result
        assert "native_types" in result

    def test_primitives_populated(self):
        result = list_supported_types()
        assert "int32" in result["primitives"]
        assert "float" in result["primitives"]
        assert "ptr" in result["primitives"]

    def test_composites_populated(self):
        result = list_supported_types()
        assert "vector3" in result["composite_types"]
        assert "matrix4x4" in result["composite_types"]

    def test_cstring_in_native(self):
        result = list_supported_types()
        assert "cstring" in result["native_types"]

    def test_special_read_types_populated(self):
        result = list_supported_types()
        assert "bytes" in result["special"]
        assert "bytes[N]" in result["special"]
        assert result["special_types"] == result["special"]

    def test_aliases_are_discoverable(self):
        result = list_supported_types()
        assert result["aliases"]["sbyte"] == "int8"
        assert result["aliases"]["intptr"] == "ptr"
        assert result["primitive_aliases"]["ptr"] == ["pointer", "intptr"]


class FakeVerifiedWriteSession:
    def __init__(self, initial: bytes, *, writable: bool = True, readback: bytes | None = None):
        self.memory = bytearray(initial)
        self.writable = writable
        self.readback = readback
        self.range_checks = []
        self.reads = []
        self.writes = []
        self.read_count = 0

    def ensure_attached(self):
        return True

    def is_memory_range_writable(self, address: int, size: int):
        self.range_checks.append((address, size))
        return self.writable

    def read_bytes(self, address: int, size: int):
        self.reads.append((address, size))
        self.read_count += 1
        if self.read_count > 1 and self.readback is not None:
            return self.readback
        return bytes(self.memory[:size])

    def write_bytes(self, address: int, data: bytes):
        data = bytes(data)
        self.writes.append((address, data))
        self.memory[: len(data)] = data


class TestVerifiedWrites:
    def test_verified_primitive_write_checks_range_and_exact_readback(self, monkeypatch):
        fake = FakeVerifiedWriteSession(struct.pack("<i", 7))
        monkeypatch.setattr(types_module, "SESSION", fake)

        result = write_typed("0x1000", 42, "int32", validate=True)

        expected = struct.pack("<i", 42)
        assert result == {
            "success": True,
            "address": "0x1000",
            "type": "int32",
            "old_value": "07 00 00 00",
            "new_value": 42,
            "size": 4,
            "verified": True,
        }
        assert fake.range_checks == [(0x1000, 4)]
        assert fake.reads == [(0x1000, 4), (0x1000, 4)]
        assert fake.writes == [(0x1000, expected)]

    def test_verified_composite_write_uses_packed_byte_length(self, monkeypatch):
        fake = FakeVerifiedWriteSession(b"\x00" * 12)
        monkeypatch.setattr(types_module, "SESSION", fake)

        value = {"x": 1.25, "y": -2.5, "z": 3.75}
        result = write_typed("0x2000", value, "vector3", validate=True)

        expected = struct.pack("<fff", 1.25, -2.5, 3.75)
        assert result["success"] is True
        assert result["old_value"] == "00 00 00 00 00 00 00 00 00 00 00 00"
        assert result["new_value"] == value
        assert result["size"] == 12
        assert result["verified"] is True
        assert fake.range_checks == [(0x2000, 12)]
        assert fake.reads == [(0x2000, 12), (0x2000, 12)]
        assert fake.writes == [(0x2000, expected)]

    def test_verified_write_fails_without_writing_when_range_not_writable(self, monkeypatch):
        fake = FakeVerifiedWriteSession(struct.pack("<i", 7), writable=False)
        monkeypatch.setattr(types_module, "SESSION", fake)

        result = write_typed("0x3000", 42, "int32", validate=True)

        assert result["success"] is False
        assert result["error"] == "MEMORY_NOT_WRITABLE"
        assert result["address"] == "0x3000"
        assert result["size"] == 4
        assert fake.range_checks == [(0x3000, 4)]
        assert fake.reads == []
        assert fake.writes == []

    def test_verified_write_reports_expected_and_actual_on_readback_mismatch(self, monkeypatch):
        fake = FakeVerifiedWriteSession(struct.pack("<i", 7), readback=b"\x2b\x00\x00\x00")
        monkeypatch.setattr(types_module, "SESSION", fake)

        result = write_typed("0x4000", 42, "int32", validate=True)

        assert result["success"] is False
        assert result["error"] == "VERIFY_MISMATCH"
        assert result["expected"] == "2A 00 00 00"
        assert result["actual"] == "2B 00 00 00"
        assert result["old_value"] == "07 00 00 00"
        assert result["rollback"] == {"attempted": True, "success": True, "value": "07 00 00 00"}
        assert bytes(fake.memory[:4]) == struct.pack("<i", 7)
        assert fake.reads == [(0x4000, 4), (0x4000, 4)]
        assert fake.writes == [(0x4000, struct.pack("<i", 42)), (0x4000, struct.pack("<i", 7))]

    def test_verified_byte_writes_reject_out_of_range_values_before_write(self, monkeypatch):
        for type_name in ("byte", "uint8"):
            for value in (-1, 256, 300):
                fake = FakeVerifiedWriteSession(b"\x00")
                monkeypatch.setattr(types_module, "SESSION", fake)

                result = write_typed("0x5000", value, type_name, validate=True)

                assert result["success"] is False
                assert result["error"] == "VALUE_OUT_OF_RANGE"
                assert result["type"] == type_name
                assert result["value"] == value
                assert "0..255" in result["detail"]
                assert fake.range_checks == []
                assert fake.reads == []
                assert fake.writes == []
