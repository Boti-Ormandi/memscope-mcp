"""Tests for protocol framing helpers in the netcap plugin.

splitLengthPrefixed / splitDelimited / splitFixed.
Pure data tests -- no process attachment required.
"""

import struct

import pytest

from memscope_mcp._contrib.plugins.netcap import NetcapPlugin

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


def make_data_table(data: bytes) -> LuaTable:
    """Pack bytes into a 1-indexed Lua table."""
    return make_table(*data)


def make_lp_spec(
    *,
    length_offset=1,
    length_size=2,
    header_size=4,
    endian="little",
    includes_header=None,
) -> LuaTable:
    """Build a spec table for splitLengthPrefixed."""
    return make_table(
        length_offset=length_offset,
        length_size=length_size,
        header_size=header_size,
        endian=endian,
        includes_header=includes_header,
    )


def build_lp_message(payload: bytes, *, header_size=4, length_size=2, endian="little", includes_header=False) -> bytes:
    """Build a length-prefixed message with arbitrary header padding."""
    fmt_char = "<" if endian == "little" else ">"
    fmt_map = {1: "B", 2: "H", 4: "I"}
    fmt = fmt_char + fmt_map[length_size]
    if includes_header:
        length_val = header_size + len(payload)
    else:
        length_val = len(payload)
    length_bytes = struct.pack(fmt, length_val)
    # Header: length field at byte 0, rest zero-padded to header_size
    header = length_bytes + b"\x00" * (header_size - length_size)
    return header + payload


# ==================== splitLengthPrefixed ====================


class TestSplitLengthPrefixed:
    def test_two_complete_uint16le_messages(self):
        plugin = make_plugin()
        msg1 = build_lp_message(b"hello", header_size=4, length_size=2)
        msg2 = build_lp_message(b"world!", header_size=4, length_size=2)
        data = make_data_table(msg1 + msg2)
        spec = make_lp_spec(length_offset=1, length_size=2, header_size=4, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg1) + len(msg2)
        assert result["remainder"] == 0
        messages = result["messages"]
        assert messages[1] is not None
        assert messages[2] is not None
        assert messages[3] is None
        assert messages[1]["payload_length"] == len(b"hello")
        assert messages[2]["payload_length"] == len(b"world!")

    def test_one_complete_one_partial(self):
        plugin = make_plugin()
        msg1 = build_lp_message(b"full", header_size=4, length_size=2)
        # Partial: header present but payload missing
        partial = struct.pack("<H", 100) + b"\x00\x00"  # claims 100 bytes but none present
        data = make_data_table(msg1 + partial)
        spec = make_lp_spec(length_offset=1, length_size=2, header_size=4, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg1)
        assert result["remainder"] == len(partial)
        messages = result["messages"]
        assert messages[1] is not None
        assert messages[2] is None

    def test_big_endian_length_field(self):
        plugin = make_plugin()
        payload = b"bigendian"
        msg = build_lp_message(payload, header_size=4, length_size=2, endian="big")
        data = make_data_table(msg)
        spec = make_lp_spec(length_offset=1, length_size=2, header_size=4, endian="big")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg)
        assert result["remainder"] == 0
        assert result["messages"][1]["payload_length"] == len(payload)

    def test_uint32_length_field(self):
        plugin = make_plugin()
        payload = b"uint32payload"
        msg = build_lp_message(payload, header_size=8, length_size=4, endian="little")
        data = make_data_table(msg)
        spec = make_lp_spec(length_offset=1, length_size=4, header_size=8, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg)
        assert result["remainder"] == 0
        assert result["messages"][1]["payload_length"] == len(payload)

    def test_uint8_length_field(self):
        plugin = make_plugin()
        payload = b"byte"
        msg = build_lp_message(payload, header_size=2, length_size=1, endian="little")
        data = make_data_table(msg)
        spec = make_lp_spec(length_offset=1, length_size=1, header_size=2, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg)
        assert result["remainder"] == 0
        assert result["messages"][1]["payload_length"] == len(payload)

    def test_includes_header_true(self):
        plugin = make_plugin()
        payload = b"payload"
        header_size = 4
        # length = header + payload
        total = header_size + len(payload)
        header = struct.pack("<H", total) + b"\x00\x00"
        msg = header + payload
        data = make_data_table(msg)
        spec = make_lp_spec(
            length_offset=1,
            length_size=2,
            header_size=header_size,
            endian="little",
            includes_header=True,
        )
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg)
        assert result["remainder"] == 0
        assert result["messages"][1]["payload_length"] == len(payload)

    def test_empty_data_returns_zeros(self):
        plugin = make_plugin()
        data = make_data_table(b"")
        spec = make_lp_spec()
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == 0
        assert result["remainder"] == 0
        assert result["messages"][1] is None

    def test_header_only_zero_length_payload(self):
        plugin = make_plugin()
        # length field = 0 -> zero-byte payload
        header = struct.pack("<H", 0) + b"\x00\x00"
        data = make_data_table(header)
        spec = make_lp_spec(length_offset=1, length_size=2, header_size=4, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == 4
        assert result["remainder"] == 0
        msg = result["messages"][1]
        assert msg is not None
        assert msg["payload_length"] == 0

    def test_invalid_length_larger_than_buffer_stops_early(self):
        plugin = make_plugin()
        # First message is valid
        msg1 = build_lp_message(b"ok", header_size=4, length_size=2)
        # Second message claims more bytes than exist
        bad_header = struct.pack("<H", 9000) + b"\x00\x00"
        data = make_data_table(msg1 + bad_header)
        spec = make_lp_spec(length_offset=1, length_size=2, header_size=4, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg1)
        assert result["remainder"] == len(bad_header)
        assert result["messages"][1] is not None
        assert result["messages"][2] is None

    def test_16mb_sanity_cap_treated_as_end(self):
        plugin = make_plugin()
        # length field says 20MB -- exceeds 16MB cap
        oversized = 20 * 1024 * 1024
        header = struct.pack("<I", oversized) + b"\x00\x00\x00\x00"  # uint32 LE, 8-byte header
        data = make_data_table(header)
        spec = make_lp_spec(length_offset=1, length_size=4, header_size=8, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == 0
        assert result["remainder"] == len(header)
        assert result["messages"][1] is None

    def test_length_offset_not_at_start_of_header(self):
        plugin = make_plugin()
        payload = b"offset_test"
        # Header layout: [padding_byte][length_uint16_LE][padding_byte] = 4 bytes
        length_val = len(payload)
        header = b"\xaa" + struct.pack("<H", length_val) + b"\xbb"
        msg = header + payload
        data = make_data_table(msg)
        # length_offset=2 (1-indexed), so field starts at byte index 1
        spec = make_lp_spec(length_offset=2, length_size=2, header_size=4, endian="little")
        result = plugin._split_length_prefixed(data, spec)
        assert result["consumed"] == len(msg)
        assert result["remainder"] == 0
        assert result["messages"][1]["payload_length"] == len(payload)

    def test_validation_length_size_3_raises(self):
        plugin = make_plugin()
        data = make_data_table(b"\x00" * 8)
        spec = make_lp_spec(length_size=3, header_size=4)
        with pytest.raises(ValueError):
            plugin._split_length_prefixed(data, spec)

    def test_validation_header_size_too_small_raises(self):
        plugin = make_plugin()
        data = make_data_table(b"\x00" * 8)
        # length_offset=1 (->0), length_size=4, so header_size must be >= 4; give 3
        spec = make_lp_spec(length_offset=1, length_size=4, header_size=3)
        with pytest.raises(ValueError):
            plugin._split_length_prefixed(data, spec)


# ==================== splitDelimited ====================


class TestSplitDelimited:
    def test_crlf_two_segments(self):
        plugin = make_plugin()
        raw = b"line1\r\nline2\r\n"
        data = make_data_table(raw)
        delim = make_table(0x0D, 0x0A)
        result = plugin._split_delimited(data, delim)
        assert result["remainder"] == 0
        assert result["consumed"] == len(raw)
        assert result["segments"][1]["length"] == len(b"line1")
        assert result["segments"][2]["length"] == len(b"line2")
        assert result["segments"][3] is None

    def test_multiple_consecutive_delimiters_produce_empty_segments(self):
        plugin = make_plugin()
        raw = b"a\r\n\r\nb"  # empty segment between the two CRLFs
        data = make_data_table(raw)
        delim = make_table(0x0D, 0x0A)
        result = plugin._split_delimited(data, delim)
        segs = result["segments"]
        # "a", "", "b" is not returned -- only segments before a delimiter count
        # "a" at index 1, "" at index 2, no more delimiters after "b"
        assert segs[1]["length"] == 1  # "a"
        assert segs[2]["length"] == 0  # empty between the two CRLFs

    def test_no_delimiter_found_empty_segments(self):
        plugin = make_plugin()
        raw = b"nodelmessage"
        data = make_data_table(raw)
        delim = make_table(0x0D, 0x0A)
        result = plugin._split_delimited(data, delim)
        assert result["consumed"] == 0
        assert result["remainder"] == len(raw)
        assert result["segments"][1] is None

    def test_delimiter_at_end_no_remainder(self):
        plugin = make_plugin()
        raw = b"hello\x00"
        data = make_data_table(raw)
        delim = make_table(0x00)
        result = plugin._split_delimited(data, delim)
        assert result["remainder"] == 0
        assert result["consumed"] == len(raw)
        assert result["segments"][1]["length"] == len(b"hello")

    def test_single_byte_delimiter(self):
        plugin = make_plugin()
        raw = b"foo|bar|baz"
        data = make_data_table(raw)
        delim = make_table(ord("|"))
        result = plugin._split_delimited(data, delim)
        assert result["segments"][1]["length"] == 3  # "foo"
        assert result["segments"][2]["length"] == 3  # "bar"
        assert result["segments"][3] is None  # "baz" has no trailing delimiter
        assert result["remainder"] == 3

    def test_multi_byte_delimiter(self):
        plugin = make_plugin()
        sep = b"\xde\xad\xbe\xef"
        raw = b"first" + sep + b"second" + sep
        data = make_data_table(raw)
        delim = make_table(*sep)
        result = plugin._split_delimited(data, delim)
        assert result["consumed"] == len(raw)
        assert result["remainder"] == 0
        assert result["segments"][1]["length"] == 5
        assert result["segments"][2]["length"] == 6

    def test_empty_data_returns_empty(self):
        plugin = make_plugin()
        data = make_data_table(b"")
        delim = make_table(0x0D, 0x0A)
        result = plugin._split_delimited(data, delim)
        assert result["consumed"] == 0
        assert result["remainder"] == 0
        assert result["segments"][1] is None

    def test_empty_delimiter_raises(self):
        plugin = make_plugin()
        data = make_data_table(b"hello")
        delim = make_table()  # empty
        with pytest.raises(ValueError):
            plugin._split_delimited(data, delim)


# ==================== splitFixed ====================


class TestSplitFixed:
    def test_10_bytes_by_3_three_messages_remainder_1(self):
        plugin = make_plugin()
        data = make_data_table(b"A" * 10)
        result = plugin._split_fixed(data, 3)
        assert result["consumed"] == 9
        assert result["remainder"] == 1
        assert result["messages"][1] is not None
        assert result["messages"][2] is not None
        assert result["messages"][3] is not None
        assert result["messages"][4] is None

    def test_exact_multiple_zero_remainder(self):
        plugin = make_plugin()
        data = make_data_table(b"B" * 12)
        result = plugin._split_fixed(data, 4)
        assert result["consumed"] == 12
        assert result["remainder"] == 0
        assert result["messages"][3] is not None
        assert result["messages"][4] is None

    def test_less_than_one_message_zero_messages(self):
        plugin = make_plugin()
        data = make_data_table(b"XX")
        result = plugin._split_fixed(data, 5)
        assert result["consumed"] == 0
        assert result["remainder"] == 2
        assert result["messages"][1] is None

    def test_size_zero_raises(self):
        plugin = make_plugin()
        data = make_data_table(b"hello")
        with pytest.raises(ValueError):
            plugin._split_fixed(data, 0)

    def test_message_data_contents_correct(self):
        plugin = make_plugin()
        raw = b"abcdef"
        data = make_data_table(raw)
        result = plugin._split_fixed(data, 3)
        msg1 = result["messages"][1]
        msg2 = result["messages"][2]
        assert bytes(msg1["data"][i] for i in range(1, 4)) == b"abc"
        assert bytes(msg2["data"][i] for i in range(1, 4)) == b"def"

    def test_offsets_are_1_indexed(self):
        plugin = make_plugin()
        data = make_data_table(b"XXYYZZ")
        result = plugin._split_fixed(data, 2)
        assert result["messages"][1]["offset"] == 1
        assert result["messages"][2]["offset"] == 3
        assert result["messages"][3]["offset"] == 5
