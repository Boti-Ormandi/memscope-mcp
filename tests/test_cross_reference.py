"""Tests for cross-reference search helpers in the netcap plugin.

searchPackets / searchPacketsForValue / _encode_search_value.
Pure unit tests -- no process attachment required.
"""

import struct

import pytest

from memscope_mcp._contrib.plugins.netcap import NetcapPlugin, _encode_search_value

# ==================== Helpers ====================


class LuaTable(dict):
    """Dict that returns None for missing keys, mirroring Lua table semantics."""

    def __missing__(self, key):
        return None


def make_table(*args, **kwargs):
    """Mock Lua table factory: 1-indexed sequential args + kwargs."""
    result = LuaTable()
    for i, val in enumerate(args, 1):
        result[i] = val
    result.update(kwargs)
    return result


class MockContext:
    engine = None
    session = None
    lua = None
    table_factory = None
    log_error = None


def make_plugin() -> NetcapPlugin:
    """Create a NetcapPlugin and register it with a mock context."""
    plugin = NetcapPlugin()
    ctx = MockContext()
    ctx.table_factory = make_table
    ctx.log_error = lambda *a: None
    plugin.register(ctx)
    return plugin


def make_packet(direction: str, socket: int, data: bytes | None, socket_hex: str | None = None) -> LuaTable:
    """Build a packet dict as readPackets returns."""
    if socket_hex is None:
        socket_hex = f"0x{socket:x}"
    return make_table(
        direction=direction,
        socket=socket,
        socket_hex=socket_hex,
        data=make_table(*data) if data is not None else None,
    )


def result_list(table) -> list:
    """Extract ordered values from a 1-indexed Lua table into a Python list."""
    items = []
    i = 1
    while True:
        v = table[i]
        if v is None:
            break
        items.append(v)
        i += 1
    return items


# ==================== searchPackets ====================


class TestSearchPackets:
    def test_pattern_found_in_one_packet(self):
        plugin = make_plugin()
        packets = make_table(make_packet("send", 0x1A4, b"hello HTTP world"))
        pat = make_table(*b"HTTP")
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 1
        assert results[0]["packet_index"] == 1
        assert results[0]["offset"] == 7  # 1-indexed: 'H' is at byte index 6 -> offset 7
        assert results[0]["direction"] == "send"

    def test_pattern_found_in_multiple_packets(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("send", 0x1A4, b"GET / HTTP/1.1"),
            make_packet("recv", 0x1A4, b"HTTP/1.1 200 OK"),
        )
        pat = make_table(*b"HTTP")
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 2
        assert results[0]["packet_index"] == 1
        assert results[1]["packet_index"] == 2

    def test_pattern_found_multiple_times_in_one_packet(self):
        plugin = make_plugin()
        data = b"AABABBA"
        packets = make_table(make_packet("recv", 0x200, data))
        pat = make_table(*b"AB")
        results = result_list(plugin._search_packets(packets, pat))
        # "AB" at index 1 (offset 2) and index 3 (offset 4)
        offsets = [r["offset"] for r in results]
        assert offsets == [2, 4]

    def test_pattern_not_found_returns_empty(self):
        plugin = make_plugin()
        packets = make_table(make_packet("send", 0x1A4, b"hello world"))
        pat = make_table(*b"ZZZZ")
        results = result_list(plugin._search_packets(packets, pat))
        assert results == []

    def test_packet_with_no_data_is_skipped(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("connect", 0x1A4, None),
            make_packet("send", 0x1A4, b"ABC"),
        )
        pat = make_table(*b"ABC")
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 1
        assert results[0]["packet_index"] == 2

    def test_empty_pattern_returns_empty(self):
        plugin = make_plugin()
        packets = make_table(make_packet("send", 0x1A4, b"hello"))
        pat = make_table()
        results = result_list(plugin._search_packets(packets, pat))
        assert results == []

    def test_single_byte_pattern_finds_all_occurrences(self):
        plugin = make_plugin()
        data = b"\xaa\xbb\xaa\xcc\xaa"
        packets = make_table(make_packet("recv", 0x1A4, data))
        pat = make_table(0xAA)
        results = result_list(plugin._search_packets(packets, pat))
        offsets = [r["offset"] for r in results]
        assert offsets == [1, 3, 5]

    def test_context_hex_includes_surrounding_bytes(self):
        plugin = make_plugin()
        # 8 leading bytes + "AB" + 8 trailing bytes
        data = bytes(range(8)) + b"AB" + bytes(range(8))
        packets = make_table(make_packet("send", 0x1A4, data))
        pat = make_table(*b"AB")
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 1
        ctx = results[0]["context_hex"]
        # context_hex should be non-empty and contain the pattern bytes
        assert "41 42" in ctx  # 'A'=0x41, 'B'=0x42

    def test_direction_and_socket_hex_are_preserved(self):
        plugin = make_plugin()
        packets = make_table(make_packet("recv", 0x1A4, b"XY", socket_hex="0x1a4"))
        pat = make_table(*b"XY")
        results = result_list(plugin._search_packets(packets, pat))
        assert results[0]["direction"] == "recv"
        assert results[0]["socket_hex"] == "0x1a4"

    def test_offset_is_one_indexed(self):
        plugin = make_plugin()
        packets = make_table(make_packet("send", 0x1A4, b"XAB"))
        pat = make_table(*b"AB")
        results = result_list(plugin._search_packets(packets, pat))
        # 'A' is at Python index 1 -> Lua 1-indexed offset 2
        assert results[0]["offset"] == 2

    def test_pattern_at_start_of_packet(self):
        plugin = make_plugin()
        packets = make_table(make_packet("send", 0x1A4, b"ABCxyz"))
        pat = make_table(*b"ABC")
        results = result_list(plugin._search_packets(packets, pat))
        assert results[0]["offset"] == 1

    def test_pattern_at_end_of_packet(self):
        plugin = make_plugin()
        packets = make_table(make_packet("send", 0x1A4, b"xyzABC"))
        pat = make_table(*b"ABC")
        results = result_list(plugin._search_packets(packets, pat))
        assert results[0]["offset"] == 4


# ==================== searchPacketsForValue ====================


class TestSearchPacketsForValue:
    def test_float_100(self):
        plugin = make_plugin()
        # IEEE 754 LE for 100.0f: {0x00, 0x00, 0xC8, 0x42}
        encoded = struct.pack("<f", 100.0)
        data = b"\x00\x01" + encoded + b"\xff"
        packets = make_table(make_packet("recv", 0x1A4, data))
        results = result_list(plugin._search_packets_for_value(packets, "float", 100.0))
        assert len(results) == 1
        assert results[0]["offset"] == 3  # after 2 leading bytes, 1-indexed

    def test_uint32_little_endian(self):
        plugin = make_plugin()
        encoded = struct.pack("<I", 0x12345678)  # {0x78, 0x56, 0x34, 0x12}
        data = b"\x00" + encoded
        packets = make_table(make_packet("send", 0x1A4, data))
        results = result_list(plugin._search_packets_for_value(packets, "uint32", 0x12345678))
        assert len(results) == 1
        assert results[0]["offset"] == 2

    def test_uint16be_443(self):
        plugin = make_plugin()
        encoded = struct.pack(">H", 443)  # {0x01, 0xBB}
        data = b"\xaa" + encoded + b"\xcc"
        packets = make_table(make_packet("send", 0x1A4, data))
        results = result_list(plugin._search_packets_for_value(packets, "uint16be", 443))
        assert len(results) == 1
        assert results[0]["offset"] == 2

    def test_int32_negative_one(self):
        plugin = make_plugin()
        encoded = struct.pack("<i", -1)  # {0xFF, 0xFF, 0xFF, 0xFF}
        data = encoded
        packets = make_table(make_packet("recv", 0x1A4, data))
        results = result_list(plugin._search_packets_for_value(packets, "int32", -1))
        assert len(results) == 1
        assert results[0]["offset"] == 1

    def test_unknown_type_raises_value_error(self):
        plugin = make_plugin()
        packets = make_table(make_packet("recv", 0x1A4, b"\x00" * 8))
        with pytest.raises(ValueError):
            plugin._search_packets_for_value(packets, "bogustype", 42)

    def test_value_not_found_returns_empty(self):
        plugin = make_plugin()
        data = b"\x00" * 16
        packets = make_table(make_packet("recv", 0x1A4, data))
        results = result_list(plugin._search_packets_for_value(packets, "uint32", 0xDEADBEEF))
        assert results == []


# ==================== _encode_search_value ====================


class TestEncodeSearchValue:
    def test_uint8(self):
        assert _encode_search_value("uint8", 255) == bytes([255])

    def test_int8(self):
        assert _encode_search_value("int8", -1) == bytes([0xFF])

    def test_uint16_little_endian(self):
        assert _encode_search_value("uint16", 0x0102) == bytes([0x02, 0x01])

    def test_int16_little_endian(self):
        assert _encode_search_value("int16", -2) == struct.pack("<h", -2)

    def test_uint32_little_endian(self):
        assert _encode_search_value("uint32", 0x12345678) == bytes([0x78, 0x56, 0x34, 0x12])

    def test_int32_little_endian(self):
        assert _encode_search_value("int32", -1) == bytes([0xFF, 0xFF, 0xFF, 0xFF])

    def test_uint64_little_endian(self):
        result = _encode_search_value("uint64", 0x0102030405060708)
        assert result == struct.pack("<Q", 0x0102030405060708)

    def test_int64_little_endian(self):
        result = _encode_search_value("int64", -1)
        assert result == bytes([0xFF] * 8)

    def test_float(self):
        assert _encode_search_value("float", 1.0) == struct.pack("<f", 1.0)

    def test_double(self):
        assert _encode_search_value("double", 3.14) == struct.pack("<d", 3.14)

    def test_uint16be(self):
        assert _encode_search_value("uint16be", 443) == bytes([0x01, 0xBB])

    def test_int16be(self):
        assert _encode_search_value("int16be", -256) == struct.pack(">h", -256)

    def test_uint32be(self):
        assert _encode_search_value("uint32be", 0x12345678) == bytes([0x12, 0x34, 0x56, 0x78])

    def test_int32be(self):
        assert _encode_search_value("int32be", -1) == bytes([0xFF, 0xFF, 0xFF, 0xFF])

    def test_unknown_type_returns_none(self):
        assert _encode_search_value("bogus", 0) is None

    def test_round_trip_float(self):
        plugin = make_plugin()
        val = 3.14
        encoded = _encode_search_value("float", val)
        data = b"\x00\x00" + encoded + b"\x00\x00"
        packets = make_table(make_packet("send", 0x1A4, data))
        pat = make_table(*encoded)
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 1
        assert results[0]["offset"] == 3

    def test_round_trip_uint32(self):
        plugin = make_plugin()
        val = 0xDEADBEEF
        encoded = _encode_search_value("uint32", val)
        data = b"\xaa\xbb" + encoded
        packets = make_table(make_packet("recv", 0x1A4, data))
        pat = make_table(*encoded)
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 1
        assert results[0]["offset"] == 3

    def test_round_trip_uint16be(self):
        plugin = make_plugin()
        val = 8080
        encoded = _encode_search_value("uint16be", val)
        data = encoded + b"\xff\xff"
        packets = make_table(make_packet("send", 0x1A4, data))
        pat = make_table(*encoded)
        results = result_list(plugin._search_packets(packets, pat))
        assert len(results) == 1
        assert results[0]["offset"] == 1
