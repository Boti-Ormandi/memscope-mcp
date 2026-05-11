"""Tests for stream assembly helpers in the netcap plugin.

feedPackets / getStream / consumeStream / listStreams / clearStream.
Pure unit tests -- no process attachment required.
"""

import struct
from dataclasses import dataclass
from typing import Any

from contrib.plugins.netcap import NetcapPlugin

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


@dataclass
class MockContext:
    engine: Any = None
    session: Any = None
    lua: Any = None
    table_factory: Any = None
    log_error: Any = None


def make_plugin() -> NetcapPlugin:
    """Create a NetcapPlugin and register it with a mock context."""
    plugin = NetcapPlugin()
    ctx = MockContext(table_factory=make_table, log_error=lambda *a: None)
    plugin.register(ctx)
    return plugin


def make_packet(direction: str, socket: int, data: bytes | None) -> dict:
    """Build a packet dict as feedPackets expects (mirrors readPackets output)."""
    return make_table(
        direction=direction,
        socket=socket,
        data=make_table(*data) if data is not None else None,
    )


# ==================== feedPackets ====================


class TestFeedPackets:
    def test_send_packets_accumulate_in_order(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("send", 0x1A4, b"hello"),
            make_packet("send", 0x1A4, b" world"),
        )
        result = plugin._feed_packets(packets)
        assert result["bytes_added"] == 11
        assert result["sockets_updated"] == 1
        stream = plugin._streams[0x1A4]
        assert bytes(stream.send_buffer) == b"hello world"

    def test_recv_packets_accumulate_in_order(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("recv", 0x1A4, b"foo"),
            make_packet("recv", 0x1A4, b"bar"),
        )
        plugin._feed_packets(packets)
        stream = plugin._streams[0x1A4]
        assert bytes(stream.recv_buffer) == b"foobar"

    def test_mixed_send_recv_go_to_correct_buffers(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("send", 0x1A4, b"out"),
            make_packet("recv", 0x1A4, b"in"),
        )
        plugin._feed_packets(packets)
        stream = plugin._streams[0x1A4]
        assert bytes(stream.send_buffer) == b"out"
        assert bytes(stream.recv_buffer) == b"in"

    def test_packets_without_data_are_skipped(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("connect", 0x1A4, None),
            make_packet("close", 0x1A4, None),
        )
        result = plugin._feed_packets(packets)
        assert result["bytes_added"] == 0
        assert result["sockets_updated"] == 0
        assert 0x1A4 not in plugin._streams

    def test_empty_packet_list_returns_zeros(self):
        plugin = make_plugin()
        result = plugin._feed_packets(make_table())
        assert result["sockets_updated"] == 0
        assert result["bytes_added"] == 0

    def test_packets_from_two_sockets_create_separate_streams(self):
        plugin = make_plugin()
        packets = make_table(
            make_packet("recv", 0x1A4, b"alpha"),
            make_packet("recv", 0x200, b"beta"),
        )
        plugin._feed_packets(packets)
        assert 0x1A4 in plugin._streams
        assert 0x200 in plugin._streams
        assert bytes(plugin._streams[0x1A4].recv_buffer) == b"alpha"
        assert bytes(plugin._streams[0x200].recv_buffer) == b"beta"

    def test_max_stream_size_enforced_oldest_bytes_truncated(self):
        plugin = make_plugin()
        plugin._max_stream_size = 10
        # Feed 15 bytes total; only the last 10 should remain
        packets = make_table(
            make_packet("recv", 0x1A4, b"AAAAA"),  # 5 bytes
            make_packet("recv", 0x1A4, b"BBBBBBBBBB"),  # 10 bytes -- triggers trim
        )
        plugin._feed_packets(packets)
        stream = plugin._streams[0x1A4]
        assert len(stream.recv_buffer) == 10
        assert bytes(stream.recv_buffer) == b"BBBBBBBBBB"

    def test_total_fed_counts_bytes_including_truncated(self):
        plugin = make_plugin()
        plugin._max_stream_size = 5
        packets = make_table(
            make_packet("send", 0x1A4, b"hello"),
            make_packet("send", 0x1A4, b"world"),
        )
        plugin._feed_packets(packets)
        stream = plugin._streams[0x1A4]
        # Both chunks were fed, so total = 10 even though buffer is capped at 5
        assert stream.send_total == 10
        assert len(stream.send_buffer) == 5


# ==================== getStream ====================


class TestGetStream:
    def test_get_recv_stream_returns_correct_data(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"hello")))
        result = plugin._get_stream("0x1A4", "recv")
        assert result is not None
        assert result["length"] == 5
        assert bytes(result["data"][i] for i in range(1, 6)) == b"hello"

    def test_get_send_stream_returns_correct_data(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("send", 0x1A4, b"send_data")))
        result = plugin._get_stream("0x1A4", "send")
        assert result is not None
        assert result["length"] == 9

    def test_get_stream_unknown_socket_returns_none(self):
        plugin = make_plugin()
        result = plugin._get_stream("0xDEAD", "recv")
        assert result is None

    def test_get_stream_default_direction_is_recv(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"default_recv")))
        plugin._feed_packets(make_table(make_packet("send", 0x1A4, b"other_send")))
        result = plugin._get_stream("0x1A4")
        assert result["length"] == 12  # recv buffer length

    def test_get_stream_empty_direction_returns_zero_length(self):
        plugin = make_plugin()
        # Feed only recv; send buffer should be empty
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"data")))
        result = plugin._get_stream("0x1A4", "send")
        assert result is not None
        assert result["length"] == 0
        assert result["total_fed"] == 0

    def test_get_stream_total_fed_reflects_all_bytes(self):
        plugin = make_plugin()
        plugin._max_stream_size = 5
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"hello world")))
        result = plugin._get_stream("0x1A4", "recv")
        assert result["total_fed"] == 11
        assert result["length"] == 5  # capped


# ==================== consumeStream ====================


class TestConsumeStream:
    def test_consume_n_bytes_removes_from_front(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"hello world")))
        consumed = plugin._consume_stream("0x1A4", "recv", 5)
        assert consumed == 5
        assert bytes(plugin._streams[0x1A4].recv_buffer) == b" world"

    def test_consume_more_than_buffer_clears_and_returns_actual(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"hi")))
        consumed = plugin._consume_stream("0x1A4", "recv", 100)
        assert consumed == 2
        assert len(plugin._streams[0x1A4].recv_buffer) == 0

    def test_consume_unknown_socket_returns_zero(self):
        plugin = make_plugin()
        result = plugin._consume_stream("0xDEAD", "recv", 10)
        assert result == 0

    def test_consume_zero_bytes_leaves_buffer_unchanged(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"intact")))
        consumed = plugin._consume_stream("0x1A4", "recv", 0)
        assert consumed == 0
        assert bytes(plugin._streams[0x1A4].recv_buffer) == b"intact"

    def test_consume_send_direction(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("send", 0x1A4, b"outgoing")))
        consumed = plugin._consume_stream("0x1A4", "send", 3)
        assert consumed == 3
        assert bytes(plugin._streams[0x1A4].send_buffer) == b"going"

    def test_get_stream_reflects_shorter_buffer_after_consume(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"abcdef")))
        plugin._consume_stream("0x1A4", "recv", 3)
        result = plugin._get_stream("0x1A4", "recv")
        assert result["length"] == 3
        assert bytes(result["data"][i] for i in range(1, 4)) == b"def"


# ==================== listStreams ====================


class TestListStreams:
    def test_empty_returns_empty_table(self):
        plugin = make_plugin()
        result = plugin._list_streams()
        # make_table() with no args returns {} -- check no socket keys present
        assert not any(k.startswith("0x") for k in result)

    def test_multiple_sockets_show_correct_sizes_and_totals(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("send", 0x1A4, b"send1")))
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"recv1recv1")))
        plugin._feed_packets(make_table(make_packet("recv", 0x200, b"other")))
        result = plugin._list_streams()
        entry_1a4 = result["0x1a4"]
        assert entry_1a4["send_length"] == 5
        assert entry_1a4["recv_length"] == 10
        assert entry_1a4["send_total"] == 5
        assert entry_1a4["recv_total"] == 10
        entry_200 = result["0x200"]
        assert entry_200["recv_length"] == 5
        assert entry_200["send_length"] == 0


# ==================== clearStream ====================


class TestClearStream:
    def test_clear_specific_socket_removes_only_that_socket(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"data")))
        plugin._feed_packets(make_table(make_packet("recv", 0x200, b"keep")))
        result = plugin._clear_stream("0x1A4")
        assert result is True
        assert 0x1A4 not in plugin._streams
        assert 0x200 in plugin._streams

    def test_clear_all_with_none_empties_all_streams(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"a")))
        plugin._feed_packets(make_table(make_packet("recv", 0x200, b"b")))
        result = plugin._clear_stream(None)
        assert result is True
        assert len(plugin._streams) == 0

    def test_clear_nonexistent_socket_does_not_raise(self):
        plugin = make_plugin()
        result = plugin._clear_stream("0xDEAD")
        assert result is True

    def test_clear_leaves_other_sockets_unaffected(self):
        plugin = make_plugin()
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, b"one")))
        plugin._feed_packets(make_table(make_packet("recv", 0x200, b"two")))
        plugin._feed_packets(make_table(make_packet("recv", 0x300, b"three")))
        plugin._clear_stream("0x200")
        assert 0x1A4 in plugin._streams
        assert 0x200 not in plugin._streams
        assert 0x300 in plugin._streams


# ==================== Round-trip integration ====================


class TestRoundTrip:
    def test_feed_get_split_consume_get_remainder(self):
        """feedPackets -> getStream -> splitLengthPrefixed -> consumeStream -> getStream."""
        plugin = make_plugin()

        # Build two length-prefixed messages: 4-byte little-endian length header + payload
        def make_lp_msg(payload: bytes) -> bytes:
            return struct.pack("<I", len(payload)) + payload

        msg1 = make_lp_msg(b"hello")
        msg2 = make_lp_msg(b"world!")
        partial = struct.pack("<I", 99)  # header only, no payload -- incomplete

        raw = msg1 + msg2 + partial
        plugin._feed_packets(make_table(make_packet("recv", 0x1A4, raw)))

        # Get the stream
        stream_result = plugin._get_stream("0x1A4", "recv")
        assert stream_result["length"] == len(raw)

        # Split using length-prefixed framing
        spec = make_table(
            length_offset=1,
            length_size=4,
            header_size=4,
            endian="little",
            includes_header=False,
        )
        split = plugin._split_length_prefixed(stream_result["data"], spec)
        assert split["consumed"] == len(msg1) + len(msg2)
        assert split["remainder"] == len(partial)

        # Consume the parsed bytes
        consumed = plugin._consume_stream("0x1A4", "recv", split["consumed"])
        assert consumed == len(msg1) + len(msg2)

        # Only the partial header should remain
        remainder_stream = plugin._get_stream("0x1A4", "recv")
        assert remainder_stream["length"] == len(partial)
