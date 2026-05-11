"""Tests for filterPackets in the network capture plugin."""

from dataclasses import dataclass
from typing import Any

from contrib.plugins.netcap import NetcapPlugin

# ==================== Helpers ====================


class LuaTable(dict):
    """Dict subclass that returns None for missing keys (like Lua tables)."""

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


def make_packet(direction="send", socket=0x1A4, size=100, hook_name="send", data=None):
    """Build a mock packet as a Lua table dict."""
    pkt = {
        "direction": direction,
        "socket": socket,
        "socket_hex": hex(socket),
        "timestamp": 12345,
        "sequence": 1,
        "size": size,
        "captured": len(data) if data else 0,
        "result": size,
        "caller": "0x7FFE1234",
        "hook_name": hook_name,
    }
    if data:
        pkt["data"] = make_table(*data)
    return pkt


def make_packets(*pkts):
    """Build a 1-indexed Lua table of packets."""
    return make_table(*pkts)


def make_criteria(direction=None, socket=None, min_size=None, max_size=None, hook_name=None, contains=None):
    """Build a criteria dict with all keys present."""
    return {
        "direction": direction,
        "socket": socket,
        "min_size": min_size,
        "max_size": max_size,
        "hook_name": hook_name,
        "contains": contains,
    }


def result_to_list(result):
    """Extract sequential 1-indexed entries from a result table into a list."""
    items = []
    i = 1
    while True:
        val = result.get(i)
        if val is None:
            break
        items.append(val)
        i += 1
    return items


# ==================== Tests ====================


class TestFilterPackets:
    def setup_method(self):
        self.plugin = make_plugin()

    def test_filter_by_direction(self):
        packets = make_packets(
            make_packet(direction="send"),
            make_packet(direction="recv"),
            make_packet(direction="send"),
        )
        criteria = make_criteria(direction="send")
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 2
        assert all(p["direction"] == "send" for p in items)

    def test_filter_by_socket(self):
        packets = make_packets(
            make_packet(socket=0x1A4),
            make_packet(socket=0x2B8),
            make_packet(socket=0x3CC),
        )
        criteria = make_criteria(socket=0x1A4)
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 1
        assert items[0]["socket"] == 0x1A4

    def test_filter_by_min_size(self):
        packets = make_packets(
            make_packet(size=100),
            make_packet(size=250),
            make_packet(size=500),
        )
        criteria = make_criteria(min_size=200)
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 2
        assert items[0]["size"] == 250
        assert items[1]["size"] == 500

    def test_filter_by_max_size(self):
        packets = make_packets(
            make_packet(size=100),
            make_packet(size=250),
            make_packet(size=500),
        )
        criteria = make_criteria(max_size=200)
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 1
        assert items[0]["size"] == 100

    def test_filter_by_hook_name(self):
        packets = make_packets(
            make_packet(hook_name="send"),
            make_packet(hook_name="recv"),
            make_packet(hook_name="WSASend"),
        )
        criteria = make_criteria(hook_name="WSASend")
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 1
        assert items[0]["hook_name"] == "WSASend"

    def test_filter_by_contains(self):
        get_bytes = [0x47, 0x45, 0x54, 0x20]  # "GET "
        packets = make_packets(
            make_packet(data=get_bytes),
            make_packet(data=[0x50, 0x4F, 0x53, 0x54]),  # "POST"
            make_packet(data=[0x01, 0x02, 0x03]),
        )
        criteria = make_criteria(contains=make_table(0x47, 0x45, 0x54, 0x20))
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 1
        assert items[0]["data"] == make_table(*get_bytes)

    def test_combined_filters(self):
        packets = make_packets(
            make_packet(direction="send", size=50),
            make_packet(direction="send", size=150),
            make_packet(direction="recv", size=200),
            make_packet(direction="send", size=100),
        )
        criteria = make_criteria(direction="send", min_size=100)
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 2
        assert all(p["direction"] == "send" and p["size"] >= 100 for p in items)

    def test_empty_criteria(self):
        packets = make_packets(
            make_packet(size=100),
            make_packet(size=200),
            make_packet(size=300),
        )
        criteria = make_criteria()  # all None
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 3

    def test_no_matches(self):
        packets = make_packets(
            make_packet(direction="send"),
            make_packet(direction="send"),
        )
        criteria = make_criteria(direction="recv")
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 0

    def test_empty_input(self):
        packets = make_table()  # empty
        criteria = make_criteria(direction="send")
        result = self.plugin._filter_packets(packets, criteria)
        items = result_to_list(result)
        assert len(items) == 0

    def test_no_criteria(self):
        packets = make_packets(
            make_packet(size=100),
            make_packet(size=200),
        )
        result = self.plugin._filter_packets(packets, None)
        assert result is packets  # returned unchanged
