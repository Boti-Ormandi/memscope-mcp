"""Tests for Lua engine edge cases and built-in functions."""

import threading
import time

import pytest

from memscope_mcp.tools.lua.code_execution import parse_lua_arg
from memscope_mcp.tools.lua.engine import LUA_ENGINE, MemscopeLuaEngine


class TestLuaArgParsing:
    def test_negative_int_becomes_uint64(self):
        assert parse_lua_arg(-1) == 0xFFFFFFFFFFFFFFFF


class TestLuaErrors:
    def test_syntax_error(self):
        result = LUA_ENGINE.execute("this is not valid lua !!!")
        assert result["success"] is False
        assert "error" in result

    def test_runtime_error(self):
        result = LUA_ENGINE.execute('error("intentional error")')
        assert result["success"] is False
        assert "intentional error" in result.get("detail", "")

    def test_nil_variable_access(self):
        result = LUA_ENGINE.execute("local x = nil; addResult('val', x)")
        assert result["success"] is True
        # nil values may or may not appear in results depending on implementation

    def test_division_by_zero(self):
        result = LUA_ENGINE.execute("addResult('val', 1/0)")
        assert result["success"] is True
        # Lua returns inf for 1/0

    def test_empty_script(self):
        result = LUA_ENGINE.execute("")
        assert result["success"] is True
        assert result["results"] == {} or result["results"] is not None


class TestLuaToHex:
    def test_small_value(self):
        result = LUA_ENGINE.execute('addResult("hex", toHex(255))')
        assert result["success"] is True
        assert result["results"]["hex"] == "0xFF"

    def test_zero(self):
        result = LUA_ENGINE.execute('addResult("hex", toHex(0))')
        assert result["success"] is True
        assert result["results"]["hex"] == "0x0"

    def test_large_value(self):
        result = LUA_ENGINE.execute('addResult("hex", toHex(addr("0x7FFC8E7D0000")))')
        assert result["success"] is True
        assert result["results"]["hex"] == "0x7FFC8E7D0000"

    def test_negative_lua_int_formats_as_unsigned(self):
        result = LUA_ENGINE.execute('addResult("hex", toHex(addr("0xFFFFFFFFFFFFFFFF")))')
        assert result["success"] is True
        assert result["results"]["hex"] == "0xFFFFFFFFFFFFFFFF"


class TestLuaCodeExecution:
    def test_execute_code_ex_rejects_nonzero_flags(self):
        result = LUA_ENGINE.execute("""
            local r = executeCodeEx(1, 5000, 0x1000)
            addResult("is_nil", r == nil)
        """)
        assert result["success"] is True
        assert result["results"]["is_nil"] is True
        assert any("INVALID_FLAGS" in line for line in result["output"])

    def test_execute_code_guard_blocks_large_loop(self, monkeypatch):
        calls = []

        def fake_execute_code(addr, args, timeout_ms=5000, *, session):
            calls.append((addr, args, timeout_ms))
            return {"success": True, "result": "0x1"}

        monkeypatch.setattr("memscope_mcp.tools.execute.execute_code", fake_execute_code)

        result = LUA_ENGINE.execute("""
            local blocked = 0
            for i = 1, 101 do
                local r = executeCode(0x1000)
                if r == nil then blocked = blocked + 1 end
            end
            addResult("blocked", blocked)
        """)

        assert result["success"] is True
        assert result["results"]["blocked"] == 1
        assert len(calls) == 100
        assert any("more than 25" in line for line in result["output"])
        assert any("blocked" in line for line in result["output"])

    def test_unsafe_execute_override_is_script_local(self, monkeypatch):
        calls = []

        def fake_execute_code(addr, args, timeout_ms=5000, *, session):
            calls.append((addr, args, timeout_ms))
            return {"success": True, "result": "0x1"}

        monkeypatch.setattr("memscope_mcp.tools.execute.execute_code", fake_execute_code)

        override = LUA_ENGINE.execute("""
            allowUnsafeCodeExecution(true)
            local blocked = 0
            for i = 1, 101 do
                if executeCode(0x1000) == nil then blocked = blocked + 1 end
            end
            addResult("blocked", blocked)
        """)
        assert override["success"] is True
        assert override["results"]["blocked"] == 0

        guarded = LUA_ENGINE.execute("""
            local blocked = 0
            for i = 1, 101 do
                if executeCode(0x1000) == nil then blocked = blocked + 1 end
            end
            addResult("blocked", blocked)
        """)
        assert guarded["success"] is True
        assert guarded["results"]["blocked"] == 1

    def test_call_sequence_results_returns_per_call_values(self, monkeypatch):
        def fake_call_sequence(calls, timeout_ms=5000, *, session):
            assert timeout_ms == 1234
            assert calls == [
                {"address": "0x1000", "args": []},
                {"address": "0x2000", "args": [{"result": 1}]},
            ]
            return {
                "success": True,
                "result": "0x222",
                "call_results": ["0x111", "0x222"],
                "calls_executed": 2,
            }

        monkeypatch.setattr("memscope_mcp.tools.execute.call_sequence", fake_call_sequence)

        result = LUA_ENGINE.execute("""
            local r = callSequenceResults({
                {address=0x1000, args={}},
                {address=0x2000, args={{result=1}}}
            }, 1234)
            addResult("result", r.result)
            addResult("first", r.call_results[1])
            addResult("second", r.call_results[2])
            addResult("calls_executed", r.calls_executed)
        """)

        assert result["success"] is True
        assert result["results"]["result"] == 0x222
        assert result["results"]["first"] == 0x111
        assert result["results"]["second"] == 0x222
        assert result["results"]["calls_executed"] == 2


class TestLuaAddr:
    def test_basic(self):
        result = LUA_ENGINE.execute('addResult("val", addr("0x1000"))')
        assert result["success"] is True

    def test_large_address(self):
        result = LUA_ENGINE.execute('addResult("hex", toHex(addr("0x1F58E12ECF0")))')
        assert result["success"] is True
        assert result["results"]["hex"] == "0x1F58E12ECF0"

    def test_roundtrip(self):
        """addr() -> toHex() should preserve the original value."""
        result = LUA_ENGINE.execute("""
            local addresses = {"0xDEADBEEF", "0x7FFC8E7D0000", "0x180000000"}
            for i, a in ipairs(addresses) do
                addResult("rt_" .. i, toHex(addr(a)))
            end
        """)
        assert result["success"] is True
        assert result["results"]["rt_1"] == "0xDEADBEEF"
        assert result["results"]["rt_2"] == "0x7FFC8E7D0000"
        assert result["results"]["rt_3"] == "0x180000000"

    def test_invalid_returns_nil(self):
        result = LUA_ENGINE.execute("""
            local val = addr("not_hex")
            addResult("is_nil", val == nil)
        """)
        assert result["success"] is True
        assert result["results"]["is_nil"] is True


class TestLuaBitwise:
    def test_band(self):
        result = LUA_ENGINE.execute("addResult('val', band(0xFF, 0x0F))")
        assert result["success"] is True
        assert result["results"]["val"] == 0x0F

    def test_bor(self):
        result = LUA_ENGINE.execute("addResult('val', bor(0xF0, 0x0F))")
        assert result["success"] is True
        assert result["results"]["val"] == 0xFF

    def test_bxor(self):
        result = LUA_ENGINE.execute("addResult('val', bxor(0xFF, 0x0F))")
        assert result["success"] is True
        assert result["results"]["val"] == 0xF0

    def test_bnot(self):
        result = LUA_ENGINE.execute("addResult('val', bnot(0xFF))")
        assert result["success"] is True
        assert result["results"]["val"] == 0xFFFFFF00

    def test_lshift(self):
        result = LUA_ENGINE.execute("addResult('val', lshift(1, 8))")
        assert result["success"] is True
        assert result["results"]["val"] == 256

    def test_rshift(self):
        result = LUA_ENGINE.execute("addResult('val', rshift(256, 4))")
        assert result["success"] is True
        assert result["results"]["val"] == 16

    def test_bextract_single_bit(self):
        result = LUA_ENGINE.execute("addResult('val', bextract(0xFF, 3))")
        assert result["success"] is True
        assert result["results"]["val"] == 1

    def test_bextract_field(self):
        result = LUA_ENGINE.execute("addResult('val', bextract(0xAB, 4, 4))")
        assert result["success"] is True
        assert result["results"]["val"] == 0xA


class TestLuaPrint:
    def test_multiple_args(self):
        result = LUA_ENGINE.execute('print("a", "b", "c")')
        assert result["success"] is True
        assert len(result["output"]) == 1
        assert "a" in result["output"][0]
        assert "b" in result["output"][0]
        assert "c" in result["output"][0]

    def test_numbers(self):
        result = LUA_ENGINE.execute("print(42, 3.14)")
        assert result["success"] is True
        assert "42" in result["output"][0]

    def test_nil(self):
        result = LUA_ENGINE.execute("print(nil)")
        assert result["success"] is True
        assert "nil" in result["output"][0]


class TestLuaAddResult:
    def test_string_value(self):
        result = LUA_ENGINE.execute('addResult("key", "value")')
        assert result["results"]["key"] == "value"

    def test_number_value(self):
        result = LUA_ENGINE.execute('addResult("key", 42)')
        assert result["results"]["key"] == 42

    def test_boolean_value(self):
        result = LUA_ENGINE.execute('addResult("key", true)')
        assert result["results"]["key"] is True

    def test_multiple_results(self):
        result = LUA_ENGINE.execute("""
            addResult("a", 1)
            addResult("b", 2)
            addResult("c", 3)
        """)
        assert result["results"]["a"] == 1
        assert result["results"]["b"] == 2
        assert result["results"]["c"] == 3

    def test_overwrite_key(self):
        result = LUA_ENGINE.execute("""
            addResult("key", "first")
            addResult("key", "second")
        """)
        assert result["results"]["key"] == "second"


class TestLuaIsNilAndOrZero:
    def test_isNil_true(self):
        result = LUA_ENGINE.execute("addResult('val', isNil(nil))")
        assert result["results"]["val"] is True

    def test_isNil_false(self):
        result = LUA_ENGINE.execute("addResult('val', isNil(42))")
        assert result["results"]["val"] is False

    def test_orZero_nil(self):
        result = LUA_ENGINE.execute("addResult('val', orZero(nil))")
        assert result["results"]["val"] == 0

    def test_orZero_value(self):
        result = LUA_ENGINE.execute("addResult('val', orZero(42))")
        assert result["results"]["val"] == 42

    def test_orEmpty_nil(self):
        result = LUA_ENGINE.execute('addResult("val", orEmpty(nil))')
        assert result["results"]["val"] == ""

    def test_orEmpty_value(self):
        result = LUA_ENGINE.execute('addResult("val", orEmpty("hello"))')
        assert result["results"]["val"] == "hello"


class TestLuaExecutionOwnership:
    def test_fresh_unbound_engine_supports_direct_registration_and_execution(self):
        engine = MemscopeLuaEngine()

        assert engine.bound_session is None
        engine.register_functions("direct", {"directValue": lambda: 42})
        result = engine.execute("return directValue()")

        assert result["success"] is True
        assert result["results"]["return"] == 42
        assert engine.bound_session is None

    def test_mutable_runtime_is_serialized_across_threads(self):
        engine = MemscopeLuaEngine()
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()
        results = []

        def block():
            first_entered.set()
            assert release_first.wait(2)

        def mark():
            second_entered.set()
            return 7

        engine.register_functions("test", {"block": block, "mark": mark})
        first = threading.Thread(target=lambda: results.append(engine.execute("block(); return 1")))
        second = threading.Thread(target=lambda: results.append(engine.execute("return mark()")))

        first.start()
        assert first_entered.wait(2)
        second.start()
        time.sleep(0.05)
        assert not second_entered.is_set()
        release_first.set()
        first.join(2)
        second.join(2)

        assert second_entered.is_set()
        assert len(results) == 2
        assert all(result["success"] for result in results)

    def test_engine_owned_interrupt_is_stable_and_cancels_registered_work(self):
        engine = MemscopeLuaEngine()
        interrupt = engine.execution_interrupt
        started = threading.Event()
        result = []

        def cooperative_work():
            started.set()
            while True:
                interrupt.check()
                time.sleep(0.001)

        engine.register_functions("test", {"cooperativeWork": cooperative_work})
        worker = threading.Thread(target=lambda: result.append(engine.execute("cooperativeWork()")))
        worker.start()
        assert started.wait(2)
        assert interrupt.deadline_ns is not None
        engine.cancel()
        worker.join(2)

        assert not worker.is_alive()
        assert result[0]["success"] is False
        assert result[0]["error"] == "CANCELLED"
        assert engine.execution_interrupt is interrupt
        assert interrupt.deadline_ns is None

    def test_same_thread_nested_execute_rejects_without_deadlock(self):
        engine = MemscopeLuaEngine()
        nested_errors = []
        results = []

        def nested_execute():
            outer_token = engine._operation_token
            try:
                engine.execute("return 2")
            except RuntimeError as exc:
                nested_errors.append(str(exc))
            assert engine._operation_token is outer_token
            assert engine._operation_kind.name == "EXECUTE"
            return 7

        engine.register_functions("test", {"nestedExecute": nested_execute})
        worker = threading.Thread(target=lambda: results.append(engine.execute("return nestedExecute()")))
        worker.start()
        worker.join(2)

        assert not worker.is_alive()
        assert nested_errors == ["Nested Lua engine execution is not allowed"]
        assert results == [{"success": True, "results": {"return": 7}, "output": []}]
        assert engine.execute("return 8")["results"]["return"] == 8
        assert engine._operation_token is None
        assert engine._operation_kind is None

    def test_public_registration_rejects_during_blocked_execution(self):
        engine = MemscopeLuaEngine()
        entered = threading.Event()
        release = threading.Event()
        results = []

        def block():
            entered.set()
            assert release.wait(3)

        engine.register_functions("test", {"block": block})
        worker = threading.Thread(target=lambda: results.append(engine.execute("block(); return 1")))
        worker.start()
        assert entered.wait(2)

        with pytest.raises(RuntimeError, match="operation is active"):
            engine.register_functions("foreign", {"foreignName": lambda: 2})

        release.set()
        worker.join(2)
        assert not worker.is_alive()
        assert results[0]["success"] is True
        absence = engine.execute("return foreignName == nil")
        assert absence["success"] is True
        assert absence["results"]["return"] is True

    def test_table_factory_rejects_foreign_thread_during_execution(self):
        engine = MemscopeLuaEngine()
        factory = engine.table_factory
        entered = threading.Event()
        release = threading.Event()
        results = []

        def block_and_make():
            entered.set()
            assert release.wait(3)
            return factory(value=5)

        engine.register_functions("test", {"blockAndMake": block_and_make})
        worker = threading.Thread(target=lambda: results.append(engine.execute("return blockAndMake()")))
        worker.start()
        assert entered.wait(2)

        with pytest.raises(RuntimeError, match="engine-owned operation"):
            factory()

        release.set()
        worker.join(2)
        assert not worker.is_alive()
        assert results[0]["success"] is True
        assert results[0]["results"]["return"] == {"value": 5}

    @pytest.mark.parametrize(
        "script",
        [
            "return function() return 1 end",
            "return coroutine.create(function() return 1 end)",
            "return io.stdout",
            "return {nested = function() return 1 end}",
        ],
        ids=["function", "thread", "userdata", "nested-function"],
    )
    def test_executable_lua_handles_do_not_escape_results(self, script):
        engine = MemscopeLuaEngine()

        result = engine.execute(script)

        assert result["success"] is False
        assert result["error"] == "EXECUTION_ERROR"
        assert "cannot leave the engine" in result["detail"]
        assert not any(callable(value) for value in result.values())

    def test_raw_lua_runtime_is_not_public(self):
        engine = MemscopeLuaEngine()

        assert not hasattr(engine, "lua")
        with pytest.raises(RuntimeError, match="engine-owned operation"):
            engine.table_factory()


class TestPublicRegistrationFailureBoundaries:
    def test_global_publication_failure_after_prior_name_quarantines(self):
        engine = MemscopeLuaEngine()
        runtime = engine._lua
        lua_globals = runtime.globals()

        class FailingGlobals:
            def __setitem__(self, name, value):
                if name == "secondIncoming":
                    raise KeyboardInterrupt("global publication interrupted")
                lua_globals[name] = value

        class RuntimeProxy:
            @staticmethod
            def globals():
                return FailingGlobals()

        engine._lua = RuntimeProxy()

        with pytest.raises(KeyboardInterrupt, match="global publication interrupted"):
            engine.register_functions(
                "partial",
                {"firstIncoming": lambda: 1, "secondIncoming": lambda: 2},
            )

        assert lua_globals["firstIncoming"]() == 1
        assert engine._operation_token is None
        assert engine._operation_kind is None
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.register_functions("late", {"lateName": lambda: 3})

    def test_registry_publication_failure_after_globals_quarantines(self):
        engine = MemscopeLuaEngine()
        lua_globals = engine._lua.globals()

        class FailingRegistry(dict):
            def __setitem__(self, name, owner):
                if name == "secondIncoming":
                    raise SystemExit("registry publication interrupted")
                super().__setitem__(name, owner)

        engine._function_registry = FailingRegistry()

        with pytest.raises(SystemExit, match="registry publication interrupted"):
            engine.register_functions(
                "partial",
                {"firstIncoming": lambda: 1, "secondIncoming": lambda: 2},
            )

        assert lua_globals["firstIncoming"]() == 1
        assert lua_globals["secondIncoming"]() == 2
        assert engine._function_registry == {"firstIncoming": "partial"}
        assert engine._operation_token is None
        assert engine._operation_kind is None
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.register_functions("late", {"lateName": lambda: 3})

    def test_validation_failure_before_reservation_leaves_engine_usable(self):
        engine = MemscopeLuaEngine()

        with pytest.raises(TypeError, match="must be callable"):
            engine.register_functions("invalid", {"badName": object()})

        assert engine._operation_token is None
        assert engine._operation_kind is None
        engine.register_functions("valid", {"validName": lambda: 7})
        assert engine.execute("return validName()")["results"]["return"] == 7

    def test_interrupt_after_mapping_commit_does_not_quarantine(self, monkeypatch):
        engine = MemscopeLuaEngine()
        real_clear = engine._clear_operation_locked

        def clear_then_interrupt():
            real_clear()
            raise KeyboardInterrupt("after mapping commit")

        monkeypatch.setattr(engine, "_clear_operation_locked", clear_then_interrupt)
        with pytest.raises(KeyboardInterrupt, match="after mapping commit"):
            engine.register_functions("committed", {"committedName": lambda: 9})
        monkeypatch.setattr(engine, "_clear_operation_locked", real_clear)

        assert engine._operation_token is None
        assert engine._function_registry == {"committedName": "committed"}
        assert engine.execute("return committedName()")["results"]["return"] == 9
