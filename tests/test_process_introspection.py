"""Focused parity tests for shared Windows process introspection."""

from types import SimpleNamespace

import pytest

import memscope_mcp.server as server
from memscope_mcp.extensions.core import process as process_extension
from memscope_mcp.tools.lua import process_info
from memscope_mcp.utils import logger as logger_utils
from memscope_mcp.utils import processes as process_utils
from memscope_mcp.utils.processes import ProcessRecord, ServiceRecord


def _record(
    name: str,
    display_name: str,
    pid: int,
    state_code: int,
) -> ServiceRecord:
    return ServiceRecord(name=name, display_name=display_name, pid=pid, state_code=state_code)


def _process_record(
    pid: int,
    name: str,
    parent_pid: int = 0,
    threads: int = 1,
) -> ProcessRecord:
    return ProcessRecord(pid=pid, name=name, parent_pid=parent_pid, threads=threads)


def _fake_session(pid: int = 0, pm=None):
    return SimpleNamespace(pid=pid, pm=pm)


def _attach_extension(session, log_error=lambda *_args: None):
    extension = process_extension.ProcessExtension()
    extension._session = session
    extension._table = dict
    extension._log_error = log_error
    return extension


def _raw_process(
    pid: int,
    name: bytes | str,
    parent_pid: int = 0,
    threads: int = 1,
):
    return SimpleNamespace(
        th32ProcessID=pid,
        szExeFile=name,
        th32ParentProcessID=parent_pid,
        cntThreads=threads,
    )


def _stub_mcp_enrichment(monkeypatch):
    monkeypatch.setattr(server, "_get_process_path", lambda _pid: None)
    monkeypatch.setattr(server, "read_process_peb", lambda _pid: None)
    monkeypatch.setattr(server, "_log", lambda _tool, _args, result, _start: result)


def test_known_service_states_are_translated_by_both_adapters(monkeypatch):
    records = tuple(
        _record(f"svc{state_code}", f"Service {state_code}", 1000 + state_code, state_code)
        for state_code in process_utils.SERVICE_STATE_NAMES
    )
    monkeypatch.setattr(process_utils, "enumerate_services", lambda: records)

    mcp_services = server._enumerate_services()
    lua_services = process_info.get_services(dict)

    for index, record in enumerate(records, 1):
        expected_state = process_utils.SERVICE_STATE_NAMES[record.state_code]
        assert mcp_services[record.pid] == [{"name": record.name, "state": expected_state}]
        assert lua_services[index]["state"] == expected_state


def test_mcp_adapter_groups_by_pid_preserves_order_and_surface_fields(monkeypatch):
    records = (
        _record("alpha", "Alpha Service", 4242, 4),
        _record("beta", "Beta Service", 4242, 1),
        _record("gamma", "Gamma Service", 99, 7),
    )
    monkeypatch.setattr(process_utils, "enumerate_services", lambda: records)

    result = server._enumerate_services()

    assert result == {
        4242: [
            {"name": "alpha", "state": "RUNNING"},
            {"name": "beta", "state": "STOPPED"},
        ],
        99: [{"name": "gamma", "state": "PAUSED"}],
    }
    assert all(set(service) == {"name", "state"} for services in result.values() for service in services)


def test_lua_adapter_preserves_fields_and_pid_filtering(monkeypatch):
    records = (
        _record("alpha", "Alpha Service", 4242, 4),
        _record("beta", "Beta Service", 99, 1),
        _record("gamma", "Gamma Service", 4242, 7),
    )
    monkeypatch.setattr(process_utils, "enumerate_services", lambda: records)

    result = process_info.get_services(dict, pid=4242)

    assert result == {
        1: {"name": "alpha", "display_name": "Alpha Service", "pid": 4242, "state": "RUNNING"},
        2: {"name": "gamma", "display_name": "Gamma Service", "pid": 4242, "state": "PAUSED"},
    }
    assert all(set(service) == {"name", "display_name", "pid", "state"} for service in result.values())


def test_unknown_state_keeps_surface_specific_fallback(monkeypatch):
    records = (_record("mystery", "Mystery Service", 123, 99),)
    monkeypatch.setattr(process_utils, "enumerate_services", lambda: records)

    assert server._enumerate_services()[123][0]["state"] == "UNKNOWN"
    assert process_info.get_services(dict)[1]["state"] == "UNKNOWN(99)"


def test_both_adapters_use_same_shared_enumeration_seam(monkeypatch):
    records = (_record("shared", "Shared Service", 321, 4),)
    calls = []

    def fake_enumerate_services():
        calls.append(True)
        return records

    monkeypatch.setattr(process_utils, "enumerate_services", fake_enumerate_services)

    assert server._enumerate_services()[321][0]["name"] == "shared"
    assert process_info.get_services(dict)[1]["name"] == "shared"
    assert len(calls) == 2


def test_duplicate_service_entries_are_not_collapsed(monkeypatch):
    duplicate = _record("duplicate", "Duplicate Service", 777, 4)
    monkeypatch.setattr(process_utils, "enumerate_services", lambda: (duplicate, duplicate))

    mcp_services = server._enumerate_services()
    lua_services = process_info.get_services(dict)

    assert mcp_services[777] == [
        {"name": "duplicate", "state": "RUNNING"},
        {"name": "duplicate", "state": "RUNNING"},
    ]
    assert lua_services == {
        1: {"name": "duplicate", "display_name": "Duplicate Service", "pid": 777, "state": "RUNNING"},
        2: {"name": "duplicate", "display_name": "Duplicate Service", "pid": 777, "state": "RUNNING"},
    }


def test_shared_process_record_mapping_preserves_existing_name_rule(monkeypatch):
    source = (
        _raw_process(10, b"alpha.exe", parent_pid=1, threads=7),
        _raw_process(11, "beta.exe", parent_pid=2, threads=8),
    )
    monkeypatch.setattr(process_utils.pymem.process, "list_processes", lambda: iter(source))

    records = list(process_utils.enumerate_processes())

    assert records == [
        _process_record(10, "alpha.exe", parent_pid=1, threads=7),
        _process_record(11, "beta.exe", parent_pid=2, threads=8),
    ]
    assert not hasattr(records[0], "__dict__")
    with pytest.raises(AttributeError):
        setattr(records[0], "pid", 99)


def test_shared_process_enumeration_preserves_order_and_duplicates(monkeypatch):
    source = (
        _raw_process(20, b"duplicate.exe", parent_pid=4, threads=2),
        _raw_process(21, b"middle.exe", parent_pid=4, threads=3),
        _raw_process(20, b"duplicate.exe", parent_pid=4, threads=2),
    )
    monkeypatch.setattr(process_utils.pymem.process, "list_processes", lambda: iter(source))

    records = list(process_utils.enumerate_processes())

    assert [(record.pid, record.name) for record in records] == [
        (20, "duplicate.exe"),
        (21, "middle.exe"),
        (20, "duplicate.exe"),
    ]
    assert records[0] is not records[2]


def test_shared_process_enumeration_is_lazy(monkeypatch):
    events = []

    def source():
        events.append("first")
        yield _raw_process(30, b"first.exe", parent_pid=3, threads=4)
        events.append("sentinel")
        raise AssertionError("later source entry should not be consumed")

    def list_processes():
        events.append("factory")
        return source()

    monkeypatch.setattr(process_utils.pymem.process, "list_processes", list_processes)

    records = process_utils.enumerate_processes()
    assert events == []
    assert next(records) == _process_record(30, "first.exe", parent_pid=3, threads=4)
    assert events == ["factory", "first"]


def test_shared_process_enumeration_propagates_source_failures(monkeypatch):
    def source():
        raise RuntimeError("enumeration failed")
        yield

    monkeypatch.setattr(process_utils.pymem.process, "list_processes", source)

    with pytest.raises(RuntimeError, match="enumeration failed"):
        next(process_utils.enumerate_processes())


def test_process_extension_numeric_attach_uses_shared_process_seam(monkeypatch):
    records = (
        _process_record(4241, "other.exe"),
        _process_record(4242, "target.exe"),
    )
    switch_calls = []
    log_processes = []

    def switch_process(process_name, pid):
        switch_calls.append((process_name, pid))
        return True

    session = SimpleNamespace(pid=4242, module_snapshot=None, switch_process=switch_process)
    extension = _attach_extension(session)
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter(records))

    def fail_direct_enumeration():
        raise AssertionError("ProcessExtension bypassed the shared process seam")

    monkeypatch.setattr(process_utils.pymem.process, "list_processes", fail_direct_enumeration)
    monkeypatch.setattr(logger_utils.LOGGER, "set_process", log_processes.append)

    result = extension._attach(4242.75)

    assert switch_calls == [("target.exe", 4242)]
    assert log_processes == ["target.exe"]
    assert result == {"pid": 4242, "name": "target.exe", "module_count": 0}


def test_process_extension_numeric_attach_stops_after_first_matching_record(monkeypatch):
    def records():
        yield _process_record(90, "other.exe")
        yield _process_record(91, "first.exe")
        raise AssertionError("attach-by-PID lookup should stop after the first match")

    switch_calls = []

    def switch_process(process_name, pid):
        switch_calls.append((process_name, pid))
        return True

    session = SimpleNamespace(pid=91, module_snapshot=None, switch_process=switch_process)
    extension = _attach_extension(session)
    monkeypatch.setattr(process_utils, "enumerate_processes", records)
    monkeypatch.setattr(logger_utils.LOGGER, "set_process", lambda _name: None)

    result = extension._attach(91)

    assert switch_calls == [("first.exe", 91)]
    assert result == {"pid": 91, "name": "first.exe", "module_count": 0}


def test_process_extension_numeric_attach_missing_pid_does_not_switch(monkeypatch):
    switch_calls = []

    def switch_process(process_name, pid):
        switch_calls.append((process_name, pid))
        return True

    session = SimpleNamespace(pid=0, module_snapshot=None, switch_process=switch_process)
    extension = _attach_extension(session)
    monkeypatch.setattr(
        process_utils,
        "enumerate_processes",
        lambda: iter((_process_record(100, "other.exe"),)),
    )
    monkeypatch.setattr(
        logger_utils.LOGGER,
        "set_process",
        lambda _name: pytest.fail("missing PID should not update logger process"),
    )

    assert extension._attach(101) is None
    assert switch_calls == []


def test_shared_image_path_query_uses_limited_information_and_closes_handle(monkeypatch):
    expected_path = "C:\\Program Files\\例\\shared.exe"
    calls = []

    class FakeKernel32:
        def OpenProcess(self, access, inherit_handle, pid):
            calls.append(("open", access, inherit_handle, pid))
            return 0x1234

        def QueryFullProcessImageNameW(self, handle, flags, buffer, size_ptr):
            calls.append(("query", handle, flags, size_ptr._obj.value))
            buffer.value = expected_path
            return True

        def CloseHandle(self, handle):
            calls.append(("close", handle))
            return True

    monkeypatch.setattr(process_utils, "_kernel32", lambda: FakeKernel32())

    result = process_utils.query_process_image_path(4242)

    assert result == expected_path
    assert calls == [
        ("open", 0x1000, False, 4242),
        ("query", 0x1234, 0, 1024),
        ("close", 0x1234),
    ]
    assert process_utils.PROCESS_QUERY_LIMITED_INFORMATION == 0x1000


def test_shared_image_path_query_open_failure_returns_none_without_query_or_close(monkeypatch):
    calls = []

    class FakeKernel32:
        def OpenProcess(self, access, inherit_handle, pid):
            calls.append(("open", access, inherit_handle, pid))
            return 0

        def QueryFullProcessImageNameW(self, *_args):
            raise AssertionError("query should not run without a handle")

        def CloseHandle(self, _handle):
            raise AssertionError("close should not run without a handle")

    monkeypatch.setattr(process_utils, "_kernel32", lambda: FakeKernel32())

    assert process_utils.query_process_image_path(31337) is None
    assert calls == [("open", 0x1000, False, 31337)]


def test_shared_image_path_query_native_query_failure_still_closes_handle(monkeypatch):
    calls = []

    class FakeKernel32:
        def OpenProcess(self, *_args):
            return 77

        def QueryFullProcessImageNameW(self, handle, flags, _buffer, _size_ptr):
            calls.append(("query", handle, flags))
            return False

        def CloseHandle(self, handle):
            calls.append(("close", handle))
            return True

    monkeypatch.setattr(process_utils, "_kernel32", lambda: FakeKernel32())

    assert process_utils.query_process_image_path(99) is None
    assert calls == [("query", 77, 0), ("close", 77)]


def test_shared_image_path_query_unexpected_exception_closes_handle_and_propagates(monkeypatch):
    calls = []

    class FakeKernel32:
        def OpenProcess(self, *_args):
            return 88

        def QueryFullProcessImageNameW(self, *_args):
            raise RuntimeError("query exploded")

        def CloseHandle(self, handle):
            calls.append(handle)
            return True

    monkeypatch.setattr(process_utils, "_kernel32", lambda: FakeKernel32())

    with pytest.raises(RuntimeError, match="query exploded"):
        process_utils.query_process_image_path(123)

    assert calls == [88]


def test_mcp_process_path_wrapper_delegates_and_preserves_result(monkeypatch):
    calls = []

    def fake_query(pid):
        calls.append(pid)
        return "C:\\shared\\mcp.exe"

    monkeypatch.setattr(process_utils, "query_process_image_path", fake_query)

    assert server._get_process_path(5150) == "C:\\shared\\mcp.exe"
    assert calls == [5150]


def test_mcp_process_path_wrapper_swallows_unexpected_shared_exception(monkeypatch):
    def fail_query(_pid):
        raise RuntimeError("unexpected shared failure")

    monkeypatch.setattr(process_utils, "query_process_image_path", fail_query)

    assert server._get_process_path(5151) is None


def test_lua_process_info_delegates_shared_image_path_query(monkeypatch):
    record = _process_record(600, "lua.exe", parent_pid=12, threads=3)
    calls = []
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter((record,)))

    def fake_query(pid):
        calls.append(pid)
        return "C:\\shared\\lua.exe"

    monkeypatch.setattr(process_utils, "query_process_image_path", fake_query)
    monkeypatch.setattr(process_info, "read_process_peb", lambda _pid: None)

    result = process_info.get_process_info(dict, pid=600, session=_fake_session())

    assert result["path"] == "C:\\shared\\lua.exe"
    assert calls == [600]


def test_lua_process_info_image_path_failure_omits_path_and_continues_peb(monkeypatch):
    record = _process_record(601, "lua-none.exe", parent_pid=13, threads=4)
    peb_calls = []
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter((record,)))
    monkeypatch.setattr(process_utils, "query_process_image_path", lambda _pid: None)

    def fake_peb(pid):
        peb_calls.append(pid)
        return {"command_line": "lua-none --flag", "being_debugged": False}

    monkeypatch.setattr(process_info, "read_process_peb", fake_peb)

    result = process_info.get_process_info(dict, pid=601, session=_fake_session())

    assert "path" not in result
    assert result["command_line"] == "lua-none --flag"
    assert peb_calls == [601]


def test_lua_process_info_shared_image_path_exception_still_propagates(monkeypatch):
    record = _process_record(602, "lua-error.exe")
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter((record,)))

    def fail_query(_pid):
        raise RuntimeError("lua path failure")

    monkeypatch.setattr(process_utils, "query_process_image_path", fail_query)
    monkeypatch.setattr(
        process_info,
        "read_process_peb",
        lambda _pid: pytest.fail("PEB lookup should not run after an unexpected image-path exception"),
    )

    with pytest.raises(RuntimeError, match="lua path failure"):
        process_info.get_process_info(dict, pid=602, session=_fake_session())


def test_lua_process_info_uses_injected_session_pid_and_explicit_pid_wins(monkeypatch):
    attached_pid = 7001
    explicit_pid = 7002
    records = (
        _process_record(attached_pid, "attached.exe", parent_pid=1, threads=2),
        _process_record(explicit_pid, "explicit.exe", parent_pid=3, threads=4),
    )
    path_calls = []
    peb_calls = []
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter(records))

    def fake_query(pid):
        path_calls.append(pid)
        return None

    def fake_peb(pid):
        peb_calls.append(pid)
        return None

    monkeypatch.setattr(process_utils, "query_process_image_path", fake_query)
    monkeypatch.setattr(process_info, "read_process_peb", fake_peb)
    session = _fake_session(pid=attached_pid, pm=object())

    attached = process_info.get_process_info(dict, session=session)
    explicit = process_info.get_process_info(dict, pid=explicit_pid, session=session)

    assert attached["pid"] == attached_pid
    assert attached["name"] == "attached.exe"
    assert explicit["pid"] == explicit_pid
    assert explicit["name"] == "explicit.exe"
    assert path_calls == [attached_pid, explicit_pid]
    assert peb_calls == [attached_pid, explicit_pid]


def test_lua_region_info_uses_injected_process_handle_and_preserves_detached_results(monkeypatch):
    process_handle = object()
    calls = []
    mbi = SimpleNamespace(
        Protect=0x04,
        Type=0x20000,
        State=process_info.structs.MEMORY_STATE.MEM_COMMIT.value,
        BaseAddress=0x1000,
        RegionSize=0x2000,
    )

    def fake_virtual_query(handle, address):
        calls.append((handle, address))
        return mbi

    monkeypatch.setattr(process_info.pymem.memory, "virtual_query", fake_virtual_query)
    session = _fake_session(pid=7003, pm=SimpleNamespace(process_handle=process_handle))

    result = process_info.get_region_info(dict, 0x1234, session=session)

    assert calls[0][0] is process_handle
    assert calls[0][1] == 0x1234
    assert result["base"] == 0x1000
    assert result["size"] == 0x2000
    assert result["protection"] == "PAGE_READWRITE"
    assert result["type"] == "MEM_PRIVATE"
    assert result["state"] == "COMMIT"

    detached_session = _fake_session()
    assert process_info.get_region_info(dict, 0x1234, session=detached_session) is None
    assert process_info.get_memory_regions(dict, session=detached_session) == {}


def test_mcp_processes_consumes_shared_process_seam(monkeypatch):
    record = _process_record(40, "shared.exe", parent_pid=5, threads=6)
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter((record,)))

    def fail_direct_enumeration():
        raise AssertionError("MCP bypassed the shared process seam")

    monkeypatch.setattr(process_utils.pymem.process, "list_processes", fail_direct_enumeration)
    _stub_mcp_enrichment(monkeypatch)

    result = server.processes(limit=1)

    assert result == {
        "success": True,
        "processes": [{"pid": 40, "name": "shared.exe", "parent_pid": 5, "threads": 6}],
        "count": 1,
    }


def test_mcp_process_filters_offset_limit_and_order_remain_adapter_owned(monkeypatch):
    records = (
        _process_record(1, "Alpha.exe", parent_pid=10),
        _process_record(2, "beta.exe", parent_pid=10),
        _process_record(3, "alpha-child.exe", parent_pid=20),
        _process_record(4, "ALPHA-helper.exe", parent_pid=10),
    )
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter(records))
    _stub_mcp_enrichment(monkeypatch)

    filtered = server.processes(filter="alpha", parent=10, offset=1, limit=1)
    by_pid = server.processes(pid=2)

    assert [entry["pid"] for entry in filtered["processes"]] == [4]
    assert [entry["pid"] for entry in by_pid["processes"]] == [2]

    def stop_after_first():
        yield records[0]
        raise AssertionError("MCP limit should stop shared enumeration")

    monkeypatch.setattr(process_utils, "enumerate_processes", stop_after_first)
    assert [entry["pid"] for entry in server.processes(limit=1)["processes"]] == [1]


def test_mcp_process_enrichment_runs_only_for_emitted_entries(monkeypatch):
    records = (
        _process_record(50, "match-one.exe", parent_pid=7, threads=2),
        _process_record(51, "match-two.exe", parent_pid=7, threads=3),
        _process_record(52, "match-three.exe", parent_pid=7, threads=4),
    )
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter(records))
    monkeypatch.setattr(server, "_log", lambda _tool, _args, result, _start: result)
    path_calls = []
    peb_calls = []

    def fake_path(pid):
        path_calls.append(pid)
        return f"C:\\processes\\{pid}.exe"

    def fake_peb(pid):
        peb_calls.append(pid)
        return {"command_line": f"process-{pid} --flag"}

    monkeypatch.setattr(server, "_get_process_path", fake_path)
    monkeypatch.setattr(server, "read_process_peb", fake_peb)

    result = server.processes(filter="MATCH", offset=1, limit=1)

    assert result["processes"] == [
        {
            "pid": 51,
            "name": "match-two.exe",
            "parent_pid": 7,
            "threads": 3,
            "path": "C:\\processes\\51.exe",
            "command_line": "process-51 --flag",
        }
    ]
    assert path_calls == [51]
    assert peb_calls == [51]


def test_mcp_service_loading_and_joining_remain_adapter_owned(monkeypatch):
    service_map = {70: [{"name": "EventLog", "state": "RUNNING"}]}
    events = []

    def fake_services():
        events.append("services")
        return service_map

    def fake_processes():
        events.append("process")
        yield _process_record(70, "svchost.exe", parent_pid=1, threads=9)

    monkeypatch.setattr(server, "_enumerate_services", fake_services)
    monkeypatch.setattr(process_utils, "enumerate_processes", fake_processes)
    _stub_mcp_enrichment(monkeypatch)

    by_service = server.processes(service="eventlog", limit=1)
    assert events == ["services", "process"]
    assert by_service["processes"][0]["services"] == service_map[70]

    events.clear()
    by_name = server.processes(filter="SVCHOST", limit=1)
    assert events == ["services", "process"]
    assert by_name["processes"][0]["services"] == service_map[70]

    events.clear()
    lazy = server.processes(limit=1)
    assert events == ["process", "services"]
    assert lazy["processes"][0]["services"] == service_map[70]


def test_lua_process_list_uses_shared_seam_with_filter_limit_and_order(monkeypatch):
    def records():
        yield _process_record(80, "other.exe", parent_pid=1, threads=2)
        yield _process_record(81, "Alpha.exe", parent_pid=2, threads=3)
        yield _process_record(82, "alpha-helper.exe", parent_pid=3, threads=4)
        raise AssertionError("Lua limit should stop shared enumeration")

    monkeypatch.setattr(process_utils, "enumerate_processes", records)

    result = process_info.get_process_list(dict, filter_str="ALPHA", limit=2)

    assert result == {
        1: {"pid": 81, "name": "Alpha.exe", "parent_pid": 2, "threads": 3},
        2: {"pid": 82, "name": "alpha-helper.exe", "parent_pid": 3, "threads": 4},
    }
    assert list(result) == [1, 2]
    assert all(set(entry) == {"pid", "name", "parent_pid", "threads"} for entry in result.values())


def test_lua_process_info_uses_first_matching_shared_record(monkeypatch):
    records = (
        _process_record(90, "other.exe", parent_pid=1, threads=2),
        _process_record(91, "first.exe", parent_pid=3, threads=4),
        _process_record(91, "second.exe", parent_pid=5, threads=6),
    )
    monkeypatch.setattr(process_utils, "enumerate_processes", lambda: iter(records))
    monkeypatch.setattr(process_utils, "query_process_image_path", lambda _pid: None)
    monkeypatch.setattr(
        process_info,
        "read_process_peb",
        lambda pid: {
            "command_line": f"process-{pid}",
            "current_directory": "C:\\work",
            "being_debugged": True,
        },
    )

    result = process_info.get_process_info(dict, pid=91, session=_fake_session())

    assert result == {
        "pid": 91,
        "name": "first.exe",
        "parent_pid": 3,
        "threads": 4,
        "command_line": "process-91",
        "current_directory": "C:\\work",
        "being_debugged": True,
    }


def test_lua_process_info_absent_base_record_keeps_downstream_probes(monkeypatch):
    monkeypatch.setattr(
        process_utils,
        "enumerate_processes",
        lambda: iter((_process_record(100, "other.exe"),)),
    )
    monkeypatch.setattr(process_utils, "query_process_image_path", lambda _pid: None)
    monkeypatch.setattr(
        process_info,
        "read_process_peb",
        lambda pid: {
            "command_line": f"process-{pid}",
            "current_directory": "C:\\missing-base",
            "being_debugged": False,
        },
    )

    result = process_info.get_process_info(dict, pid=101, session=_fake_session())

    assert result == {
        "pid": 101,
        "command_line": "process-101",
        "current_directory": "C:\\missing-base",
        "being_debugged": False,
    }


def test_process_adapters_enumerate_independently_without_shared_cache(monkeypatch):
    calls = 0

    def list_processes():
        nonlocal calls
        calls += 1
        call = calls
        return iter((_raw_process(110 + call, f"call-{call}.exe", threads=call),))

    monkeypatch.setattr(process_utils.pymem.process, "list_processes", list_processes)
    _stub_mcp_enrichment(monkeypatch)

    mcp_result = server.processes(limit=1)
    lua_result = process_info.get_process_list(dict, limit=1)

    assert calls == 2
    assert mcp_result["processes"][0]["name"] == "call-1.exe"
    assert lua_result[1]["name"] == "call-2.exe"
