"""Semantic parity tests for the netcap Lua buffer-search helpers."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

import pytest
from lupa import LuaRuntime

from memscope_mcp._contrib.plugins.netcap import NetcapPlugin, _lua_table_to_list


def make_table(*args, **kwargs):
    """Create a 1-indexed dictionary with optional named fields."""
    result = {index: value for index, value in enumerate(args, 1)}
    result.update(kwargs)
    return result


@dataclass
class MockContext:
    engine: Any = None
    session: Any = None
    lua: Any = None
    table_factory: Any = None
    log_error: Any = None


def make_plugin(table_factory=make_table) -> NetcapPlugin:
    plugin = NetcapPlugin()
    plugin.register(MockContext(table_factory=table_factory, log_error=lambda *args: None))
    return plugin


def legacy_find(data, pattern) -> int | None:
    data_list = _lua_table_to_list(data)
    pat_list = _lua_table_to_list(pattern)
    pat_len = len(pat_list)
    for index in range(len(data_list) - pat_len + 1):
        if data_list[index : index + pat_len] == pat_list:
            return index + 1
    return None


def legacy_contains(data, pattern) -> bool:
    return legacy_find(data, pattern) is not None


def legacy_find_all(data, pattern) -> list[int]:
    data_list = _lua_table_to_list(data)
    pat_list = _lua_table_to_list(pattern)
    pat_len = len(pat_list)
    return [
        index + 1 for index in range(len(data_list) - pat_len + 1) if data_list[index : index + pat_len] == pat_list
    ]


def result_list(table) -> list[int]:
    return _lua_table_to_list(table)


def assert_parity(plugin: NetcapPlugin, data, pattern) -> None:
    assert plugin._buffer_find(data, pattern) == legacy_find(data, pattern)
    assert plugin._buffer_contains(data, pattern) is legacy_contains(data, pattern)
    assert result_list(plugin._buffer_find_all(data, pattern)) == legacy_find_all(data, pattern)


@pytest.mark.parametrize(
    ("data_values", "pattern_values"),
    [
        ([1, 2, 3, 2, 3], [2, 3]),
        ([65, 65, 65, 65], [65, 65]),
        ([], []),
        ([1, 2, 3], []),
        ([], [1]),
        ([1], [1, 2]),
        (["65", 66.9, True], [65, 66, 1]),
        ([300, -1, 65536], [300, -1, 65536]),
        ([300], [44]),
    ],
)
def test_python_tables_preserve_legacy_semantics(data_values, pattern_values):
    plugin = make_plugin()
    assert_parity(plugin, make_table(*data_values), make_table(*pattern_values))


def test_find_uses_offset_zero_shortcut_without_masking_later_values():
    plugin = make_plugin()
    data = make_table(300, -1, *([0] * 70), 65536)
    pattern = make_table(300, -1)

    assert plugin._buffer_find(data, pattern) == 1
    assert plugin._buffer_contains(data, pattern) is True


def test_large_out_of_range_values_use_exact_fallback():
    plugin = make_plugin()
    data_values = [0] * 68 + [300, -1]
    data = make_table(*data_values)
    pattern = make_table(300, -1)

    assert plugin._buffer_find(data, pattern) == 69
    assert plugin._buffer_contains(data, pattern) is True
    assert result_list(plugin._buffer_find_all(data, pattern)) == [69]
    assert plugin._buffer_find(data, make_table(44, 255)) is None


def test_find_all_preserves_overlaps_above_short_input_cutoff():
    plugin = make_plugin()
    data = make_table(*([65] * 70))
    pattern = make_table(65, 65)

    assert result_list(plugin._buffer_find_all(data, pattern)) == list(range(1, 70))


@pytest.mark.parametrize("size", [0, 3, 64, 65, 130])
def test_empty_pattern_matches_every_boundary(size):
    plugin = make_plugin()
    data = make_table(*([7] * size))
    pattern = make_table()

    assert plugin._buffer_find(data, pattern) == 1
    assert plugin._buffer_contains(data, pattern) is True
    assert result_list(plugin._buffer_find_all(data, pattern)) == list(range(1, size + 2))


def test_first_hole_truncates_and_non_sequence_keys_are_ignored():
    plugin = make_plugin()
    data = {0: 9, 1: 1, 3: 3, "named": 4}

    assert_parity(plugin, data, make_table(3))
    assert plugin._buffer_find(data, make_table(1)) == 1
    assert plugin._buffer_find(data, make_table(9)) is None


class TracingTable:
    def __init__(self, name: str, values: dict[int, object], events: list[tuple[str, int]]) -> None:
        self.name = name
        self.values = values
        self.events = events

    def __getitem__(self, index: int):
        self.events.append((self.name, index))
        if index not in self.values:
            raise KeyError(index)
        return self.values[index]


@pytest.mark.parametrize("method_name", ["_buffer_find", "_buffer_contains", "_buffer_find_all"])
def test_data_conversion_precedes_pattern_conversion(method_name):
    plugin = make_plugin()
    events: list[tuple[str, int]] = []
    data = TracingTable("data", {1: "not-an-integer"}, events)
    pattern = TracingTable("pattern", {1: 1}, events)

    with pytest.raises(ValueError):
        getattr(plugin, method_name)(data, pattern)

    assert events == [("data", 1)]


def test_pattern_conversion_starts_after_data_conversion_finishes():
    plugin = make_plugin()
    events: list[tuple[str, int]] = []
    data = TracingTable("data", {1: 10, 2: 20}, events)
    pattern = TracingTable("pattern", {1: "not-an-integer"}, events)

    with pytest.raises(ValueError):
        plugin._buffer_find(data, pattern)

    assert events == [("data", 1), ("data", 2), ("data", 3), ("pattern", 1)]


def test_conversion_stops_at_first_missing_index():
    plugin = make_plugin()
    events: list[tuple[str, int]] = []
    data = TracingTable("data", {1: 10, 3: 30}, events)
    pattern = TracingTable("pattern", {1: 30}, events)

    assert plugin._buffer_find(data, pattern) is None
    assert ("data", 3) not in events
    assert events[:2] == [("data", 1), ("data", 2)]


def test_deterministic_python_differential_parity():
    plugin = make_plugin()
    rng = random.Random(0xB00F)
    values = list(range(256)) + [-1, 256, 300, 65536]

    for _ in range(500):
        data_size = rng.randrange(0, 161)
        pattern_size = rng.randrange(0, 25)
        data_values = [rng.choice(values) for _ in range(data_size)]
        pattern_values = [rng.choice(values) for _ in range(pattern_size)]
        data = make_table(*data_values)
        pattern = make_table(*pattern_values)

        if data_size > 2 and rng.randrange(5) == 0:
            hole = rng.randrange(1, data_size + 1)
            data.pop(hole)
            data[data_size + 2] = rng.choice(values)
        if pattern_size > 2 and rng.randrange(5) == 0:
            hole = rng.randrange(1, pattern_size + 1)
            pattern.pop(hole)
            pattern[pattern_size + 2] = rng.choice(values)

        assert_parity(plugin, data, pattern)


def register_real_lua_functions(lua: LuaRuntime) -> NetcapPlugin:
    plugin = NetcapPlugin()
    functions = plugin.register(MockContext(lua=lua, table_factory=lua.table, log_error=lambda *args: None))
    globals_table = lua.globals()
    for name in ("bufferFind", "bufferContains", "bufferFindAll"):
        globals_table[name] = functions[name]
    return plugin


def test_real_lua_exposure_preserves_offsets_overlaps_and_empty_patterns():
    lua = LuaRuntime(unpack_returned_tuples=True)
    register_real_lua_functions(lua)

    assert lua.execute("return bufferFind({65, 65, 65, 65}, {65, 65})") == 1
    assert lua.execute("return bufferContains({1, 2, 3}, {2, 3})") is True
    assert lua.execute("return bufferFind({1, 2, 3}, {9})") is None

    overlaps = lua.execute("return bufferFindAll({65, 65, 65, 65}, {65, 65})")
    assert result_list(overlaps) == [1, 2, 3]

    empty = lua.execute("return bufferFindAll({1, 2, 3}, {})")
    assert result_list(empty) == [1, 2, 3, 4]


def test_real_lua_holes_coercion_and_out_of_range_fallback():
    lua = LuaRuntime(unpack_returned_tuples=True)
    register_real_lua_functions(lua)

    assert lua.execute("return bufferFind({[1] = 1, [3] = 3}, {3})") is None
    assert lua.execute("return bufferFind({'65', 66.9, true}, {65, 66, 1})") == 1
    assert lua.execute("return bufferFind({300, -1, 7}, {300, -1})") == 1
    assert lua.execute("return bufferFind({300}, {44})") is None

    with pytest.raises(ValueError):
        lua.execute("return bufferFind({1, 'not-an-integer'}, {1})")


def test_deterministic_real_lua_differential_parity():
    lua = LuaRuntime(unpack_returned_tuples=True)
    plugin = register_real_lua_functions(lua)
    find = lua.eval("function(data, pattern) return bufferFind(data, pattern) end")
    contains = lua.eval("function(data, pattern) return bufferContains(data, pattern) end")
    find_all = lua.eval("function(data, pattern) return bufferFindAll(data, pattern) end")
    rng = random.Random(0x51A0)

    for _ in range(150):
        data_values = [rng.randrange(256) for _ in range(rng.randrange(0, 129))]
        pattern_values = [rng.randrange(256) for _ in range(rng.randrange(0, 17))]
        data = lua.table_from(data_values)
        pattern = lua.table_from(pattern_values)

        assert find(data, pattern) == legacy_find(data, pattern)
        assert contains(data, pattern) is legacy_contains(data, pattern)
        assert result_list(find_all(data, pattern)) == legacy_find_all(data, pattern)
        assert plugin._buffer_find(data, pattern) == legacy_find(data, pattern)
