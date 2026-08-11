import inspect
from types import SimpleNamespace

from memscope_mcp.extensions.base import ExtensionContext

EXECUTION_HELPERS = (
    "execute_code_lua",
    "execute_code_ex_lua",
    "call_sequence_lua",
    "call_sequence_results_lua",
    "alloc_lua",
    "free_memory_lua",
)


def _register_execution_extension(session):
    from memscope_mcp.extensions.core.execution import ExecutionExtension
    from memscope_mcp.tools.lua.code_execution import LuaExecutionGuard

    engine = SimpleNamespace(
        _log_error=lambda *_args: None,
        _output=[],
        _execution_guard=LuaExecutionGuard(),
    )
    extension = ExecutionExtension()
    functions = extension.register(
        ExtensionContext(
            engine=engine,
            session=session,
            table_factory=dict,
            log_error=engine._log_error,
        )
    )
    return extension, functions


def test_code_execution_helpers_require_keyword_only_session():
    from memscope_mcp.tools.lua import code_execution

    for helper_name in EXECUTION_HELPERS:
        parameter = inspect.signature(getattr(code_execution, helper_name)).parameters["session"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty


def test_execution_extension_forwards_registered_session(monkeypatch):
    import memscope_mcp.extensions.core.execution as execution_extension

    calls = {}

    def spy(helper_name):
        def capture(*args, **kwargs):
            calls.setdefault(helper_name, []).append((args, kwargs))
            return helper_name

        return capture

    for helper_name in EXECUTION_HELPERS:
        monkeypatch.setattr(execution_extension, helper_name, spy(helper_name))

    session = object()
    extension, functions = _register_execution_extension(session)

    assert extension._session is session
    assert functions["executeCode"](0x20000, 1, 2) == "execute_code_lua"
    assert functions["executeCodeEx"](0, 1000, 0x20000, 3) == "execute_code_ex_lua"
    assert functions["callSequence"]({1: {"address": 0x20000, "args": {}}}) == "call_sequence_lua"
    assert functions["callSequenceResults"]({1: {"address": 0x20000, "args": {}}}) == "call_sequence_results_lua"
    assert functions["alloc"]("text") == "alloc_lua"
    assert functions["freeMemory"](0x250000000) == "free_memory_lua"

    for helper_name in EXECUTION_HELPERS:
        _, kwargs = calls[helper_name][0]
        assert set(kwargs) == {"session"}
        assert kwargs["session"] is session

    assert functions["call"] is functions["executeCode"]
    assert functions["allocateMemory"] is functions["alloc"]
    assert functions["allocString"] is functions["alloc"]


class _FakeExecutionSession:
    def __init__(self):
        self.calls = []

    def get_module_base(self, module_name):
        self.calls.append(("get_module_base", module_name))
        return 0x180000000

    def allocate(self, size, *, executable):
        self.calls.append(("allocate", size, executable))
        return 0x250000000


def test_module_qualified_execution_uses_registered_session(monkeypatch):
    import memscope_mcp.tools.execute as execute_tools
    from memscope_mcp.session import SESSION

    def hostile_global(*_args, **_kwargs):
        raise AssertionError("global SESSION must not be consulted")

    monkeypatch.setattr(SESSION, "get_module_base", hostile_global)

    calls = []

    def fake_execute_code(address, args, timeout_ms=5000, *, session):
        assert session is fake_session
        calls.append(("execute_code", address, args, timeout_ms))
        return {"success": True, "result": "0x123"}

    def fake_execute_code_ex(flags, timeout_ms, address, *args, session):
        assert session is fake_session
        calls.append(("execute_code_ex", flags, timeout_ms, address, args))
        return {"success": True, "result": "0x456"}

    monkeypatch.setattr(execute_tools, "execute_code", fake_execute_code)
    monkeypatch.setattr(execute_tools, "execute_code_ex", fake_execute_code_ex)

    fake_session = _FakeExecutionSession()
    _, functions = _register_execution_extension(fake_session)

    assert functions["executeCode"]("target.dll+0x20", 7) == 0x123
    assert functions["executeCodeEx"](0, 1200, "target.dll+0x30", 9) == 0x456
    assert fake_session.calls == [
        ("get_module_base", "target.dll"),
        ("get_module_base", "target.dll"),
    ]
    assert calls == [
        ("execute_code", 0x180000020, [7], 5000),
        ("execute_code_ex", 0, 1200, 0x180000030, (9,)),
    ]


def test_raw_alloc_uses_registered_session(monkeypatch):
    from memscope_mcp.session import SESSION

    def hostile_global(*_args, **_kwargs):
        raise AssertionError("global SESSION must not be consulted")

    monkeypatch.setattr(SESSION, "allocate", hostile_global)

    session = _FakeExecutionSession()
    _, functions = _register_execution_extension(session)

    assert functions["alloc"](64) == 0x250000000
    assert session.calls == [("allocate", 64, False)]


def test_execute_tools_require_explicit_keyword_only_session():
    from memscope_mcp.tools import execute

    targets = (
        execute.execute_code,
        execute.execute_code_ex,
        execute.call_sequence,
        execute.alloc_string,
        execute.free_alloc,
        execute.CallContext.__init__,
    )
    for target in targets:
        parameter = inspect.signature(target).parameters["session"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty


def test_lua_helpers_forward_identical_session_to_execute_tools(monkeypatch):
    from memscope_mcp.tools import execute as execute_tools
    from memscope_mcp.tools.lua.code_execution import (
        alloc_lua,
        call_sequence_lua,
        call_sequence_results_lua,
        free_memory_lua,
    )

    fake_session = object()
    forwarded = []

    def fake_call_sequence(calls, timeout_ms=5000, *, session):
        assert session is fake_session
        forwarded.append(("call_sequence", calls, timeout_ms, session))
        return {
            "success": True,
            "result": "0x222",
            "call_results": ["0x222"],
            "calls_executed": 1,
        }

    def fake_alloc_string(value, wide=False, *, session):
        assert session is fake_session
        forwarded.append(("alloc_string", value, wide, session))
        return {"success": True, "address": "0x250000000", "size": 5}

    def fake_free_alloc(address, *, session):
        assert session is fake_session
        forwarded.append(("free_alloc", address, session))
        return {"success": True}

    monkeypatch.setattr(execute_tools, "call_sequence", fake_call_sequence)
    monkeypatch.setattr(execute_tools, "alloc_string", fake_alloc_string)
    monkeypatch.setattr(execute_tools, "free_alloc", fake_free_alloc)

    calls_table = {1: {"address": "0x1000", "args": {}}}
    output = []
    errors = []

    def log_error(*args):
        errors.append(args)

    assert call_sequence_lua(calls_table, 1234, output, log_error, session=fake_session) == 0x222
    results = call_sequence_results_lua(calls_table, 2345, dict, output, log_error, session=fake_session)
    assert results["result"] == 0x222
    assert results["call_results"] == {1: 0x222}
    assert results["calls_executed"] == 1
    assert alloc_lua("text", False, output, session=fake_session) == 0x250000000
    assert free_memory_lua(0x250000000, log_error, session=fake_session) is True

    assert [entry[0] for entry in forwarded] == [
        "call_sequence",
        "call_sequence",
        "alloc_string",
        "free_alloc",
    ]
    assert all(entry[-1] is fake_session for entry in forwarded)
    assert output == []
    assert errors == []


class _CleanupSession:
    def __init__(self):
        self.calls = []

    def allocate(self, size, executable=False):
        self.calls.append(("allocate", size, executable))
        return 0x1000

    def write_bytes(self, address, data):
        self.calls.append(("write_bytes", address, bytes(data)))

    def free(self, address):
        self.calls.append(("free", address))
        return True

    def close_handle(self, handle):
        self.calls.append(("close_handle", handle))
        return True


def test_call_context_cleanup_uses_creator_session_for_every_resource():
    from memscope_mcp.tools.execute import CallContext

    fake_session = _CleanupSession()
    ctx = CallContext(session=fake_session)
    string_addr = ctx.alloc_string("text")
    ctx.shellcode_addr = 0x2000
    ctx.result_addr = 0x3000
    ctx.output_buffer_addr = 0x4000
    ctx.thread_handle = 0x5000

    ctx.cleanup()

    assert string_addr == 0x1000
    assert fake_session.calls == [
        ("allocate", 5, False),
        ("write_bytes", 0x1000, b"text\x00"),
        ("free", 0x1000),
        ("free", 0x2000),
        ("free", 0x3000),
        ("free", 0x4000),
        ("close_handle", 0x5000),
    ]


class _NativeSession:
    def __init__(self, result_values):
        self.pm = object()
        self.calls = []
        self.result_values = list(result_values)
        self.next_alloc = 0x250000000
        self.memory = {}
        self.alloc_meta = {}
        self.result_addr = None

    def get_module_base(self, module_name):
        self.calls.append(("get_module_base", module_name))
        return 0x180000000

    def is_valid_pointer(self, address):
        self.calls.append(("is_valid_pointer", address))
        return True

    def allocate(self, size, executable=False):
        address = self.next_alloc
        self.next_alloc += max(size, 1) + 0x100
        self.calls.append(("allocate", address, size, executable))
        self.alloc_meta[address] = (size, executable)
        self.memory[address] = b"\x00" * size
        return address

    def write_bytes(self, address, data):
        payload = bytes(data)
        self.calls.append(("write_bytes", address, payload))
        self.memory[address] = payload
        size, executable = self.alloc_meta.get(address, (len(payload), False))
        if not executable and payload == b"\x00" * size and size == len(self.result_values) * 8:
            self.result_addr = address

    def create_remote_thread(self, address):
        self.calls.append(("create_remote_thread", address))
        if self.result_addr is None:
            raise AssertionError("result buffer was not identified")
        import struct

        self.memory[self.result_addr] = struct.pack("<" + "Q" * len(self.result_values), *self.result_values)
        return 0xABC

    def wait_for_thread(self, handle, timeout_ms):
        self.calls.append(("wait_for_thread", handle, timeout_ms))
        return True

    def read_bytes(self, address, size):
        self.calls.append(("read_bytes", address, size))
        return self.memory[address][:size]

    def free(self, address):
        self.calls.append(("free", address))
        return True

    def close_handle(self, handle):
        self.calls.append(("close_handle", handle))
        return True


def _make_global_hostile(monkeypatch):
    from memscope_mcp.session import SESSION

    def hostile_global(*_args, **_kwargs):
        raise AssertionError("global application session must not be consulted")

    for name in (
        "get_module_base",
        "is_valid_pointer",
        "allocate",
        "write_bytes",
        "create_remote_thread",
        "wait_for_thread",
        "read_bytes",
        "free",
        "close_handle",
    ):
        monkeypatch.setattr(SESSION, name, hostile_global)


def test_internal_execute_code_module_address_stays_on_explicit_session(monkeypatch):
    from memscope_mcp.tools.execute import execute_code

    _make_global_hostile(monkeypatch)
    fake_session = _NativeSession([0x123])

    result = execute_code(
        "target.dll+0x20",
        [7],
        output_arg=0,
        output_size=4,
        session=fake_session,
    )

    assert result == {"success": True, "result": "0x123", "output_data": "00000000"}
    assert ("get_module_base", "target.dll") in fake_session.calls
    assert ("is_valid_pointer", 0x180000020) in fake_session.calls
    assert sum(call[0] == "create_remote_thread" for call in fake_session.calls) == 1
    assert sum(call[0] == "read_bytes" for call in fake_session.calls) == 2
    assert sum(call[0] == "free" for call in fake_session.calls) == 3
    assert ("close_handle", 0xABC) in fake_session.calls


def test_execute_code_ex_forwards_identical_session(monkeypatch):
    import memscope_mcp.tools.execute as execute_tools

    fake_session = object()
    forwarded = []

    def fake_execute_code(func_addr, args, timeout_ms=5000, *, session):
        forwarded.append((func_addr, args, timeout_ms, session))
        return {"success": True, "result": "0x456"}

    monkeypatch.setattr(execute_tools, "execute_code", fake_execute_code)

    result = execute_tools.execute_code_ex(0, None, 0x1000, 1, 2, session=fake_session)

    assert result == {"success": True, "result": "0x456"}
    assert forwarded == [(0x1000, [1, 2], 5000, fake_session)]


def test_call_sequence_uses_one_explicit_session_context_and_thread(monkeypatch):
    from memscope_mcp.tools.execute import call_sequence

    _make_global_hostile(monkeypatch)
    fake_session = _NativeSession([0x111, 0x222])

    result = call_sequence(
        [
            {"address": "target.dll+0x10", "args": ["text"]},
            {"address": 0x2000, "args": [{"result": 1}]},
        ],
        timeout_ms=4321,
        session=fake_session,
    )

    assert result["success"] is True
    assert result["result"] == "0x222"
    assert result["call_results"] == ["0x111", "0x222"]
    assert result["calls_executed"] == 2
    assert result["_string_allocs"] == ["call0.arg0='text' -> 0x250000000"]
    assert ("get_module_base", "target.dll") in fake_session.calls
    assert sum(call[0] == "create_remote_thread" for call in fake_session.calls) == 1
    assert ("wait_for_thread", 0xABC, 4321) in fake_session.calls
    assert sum(call[0] == "read_bytes" for call in fake_session.calls) == 1
    assert sum(call[0] == "free" for call in fake_session.calls) == 3
    assert ("close_handle", 0xABC) in fake_session.calls
