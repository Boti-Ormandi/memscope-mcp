"""Tests for type system metadata and definitions."""

from src.tools.types import COMPOSITE_TYPES, PRIMITIVES, get_type_info, list_supported_types


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
