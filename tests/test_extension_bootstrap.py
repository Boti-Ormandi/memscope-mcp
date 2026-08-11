"""Tests for the extension bootstrap system.

Verifies that core extensions register through the bootstrap path,
function names are present, ordering is stable, and collisions are caught.
"""

import threading
from types import SimpleNamespace

import pytest

from memscope_mcp.attachment import ModuleSnapshot, build_module_records
from memscope_mcp.extensions.base import LuaExtension
from memscope_mcp.extensions.bootstrap import bootstrap_extensions
from memscope_mcp.extensions.core import CORE_EXTENSIONS
from memscope_mcp.session import DebugSession
from memscope_mcp.tools.hooking import HookManager
from memscope_mcp.tools.lua.engine import LUA_ENGINE, MemscopeLuaEngine


def _lua_results(engine: MemscopeLuaEngine, script: str) -> dict:
    result = engine.execute(script)
    assert result["success"] is True, result
    return result["results"]


def _module_snapshot() -> ModuleSnapshot:
    module = SimpleNamespace(
        name="legacy.dll",
        lpBaseOfDll=0x12340000,
        SizeOfImage=0x1000,
        filename=r"C:\Target\legacy.dll",
    )
    return ModuleSnapshot.create(build_module_records([module]), generation=1)


class TestCoreExtensions:
    """Core extension loading and registration."""

    def test_core_extension_count(self):
        """Seven core extensions are defined."""
        assert len(CORE_EXTENSIONS) == 7

    def test_core_extension_names(self):
        """Core extensions have expected names."""
        names = [cls().name for cls in CORE_EXTENSIONS]
        assert names == ["general", "memory", "module_scan", "execution", "hooking", "process", "network"]

    def test_core_extensions_all_have_instructions(self):
        """Every core extension provides non-empty instructions."""
        for cls in CORE_EXTENSIONS:
            ext = cls()
            assert ext.instructions, f"{ext.name} has no instructions"


class TestBootstrapRegistration:
    """Verify bootstrap populates the engine correctly."""

    def test_representative_lua_functions_present(self):
        """Key Lua globals are available after bootstrap."""
        results = _lua_results(
            LUA_ENGINE,
            """
            addResult("addr", addr ~= nil)
            addResult("readInteger", readInteger ~= nil)
            addResult("AOBScan", AOBScan ~= nil)
            addResult("AOBScanModule", AOBScanModule == nil)
            addResult("executeCode", executeCode ~= nil)
            addResult("getProcessList", getProcessList ~= nil)
            """,
        )
        assert all(results.values())

    def test_aliases_registered(self):
        """Execution aliases are present."""
        results = _lua_results(
            LUA_ENGINE,
            """
            addResult("call", call ~= nil)
            addResult("free", free ~= nil)
            addResult("allocateMemory", allocateMemory ~= nil)
            """,
        )
        assert all(results.values())

    def test_function_registry_tracks_owners(self):
        """Engine tracks which extension owns each function."""
        reg = LUA_ENGINE._function_registry
        assert reg.get("addr") == "general"
        assert reg.get("readInteger") == "memory"
        assert reg.get("AOBScan") == "module_scan"
        assert reg.get("executeCode") == "execution"
        assert reg.get("getProcessList") == "process"

    def test_registration_order_is_stable(self):
        """The first five owners in the registry match CORE_EXTENSIONS order."""
        seen_owners = []
        for owner in LUA_ENGINE._function_registry.values():
            if owner not in seen_owners:
                seen_owners.append(owner)
        expected = ["general", "memory", "module_scan", "execution", "hooking", "process"]
        assert seen_owners[:6] == expected

    def test_module_scan_registered_helpers_use_ctx_session(self, monkeypatch):
        import memscope_mcp.utils.pe as pe
        from memscope_mcp.extensions.base import ExtensionContext
        from memscope_mcp.extensions.core.module_scan import ModuleScanExtension
        from memscope_mcp.session import SESSION, DebugSession

        custom_module = SimpleNamespace(
            name="custom.dll",
            lpBaseOfDll=0x700000,
            SizeOfImage=0x2000,
            filename=r"C:\\Custom\\custom.dll",
        )
        custom_snapshot = ModuleSnapshot.create(build_module_records([custom_module]), generation=2)
        monkeypatch.setattr(SESSION, "_module_snapshot", _module_snapshot())

        session = DebugSession()
        session._module_snapshot = custom_snapshot
        resolved = {}

        def fake_resolve_export(module_name, function_name, *, session):
            resolved["module_name"] = module_name
            resolved["function_name"] = function_name
            resolved["session"] = session
            return 0xCAFEBABE

        monkeypatch.setattr(pe, "resolve_export", fake_resolve_export)

        extension = ModuleScanExtension()
        functions = extension.register(
            ExtensionContext(
                engine=None,
                session=session,
                table_factory=dict,
                log_error=lambda *_args: None,
            )
        )

        modules = functions["getModules"]()
        assert modules[1]["name"] == "custom.dll"
        assert modules[1]["base"] == 0x700000

        module = functions["getModuleFromAddress"](0x700040)
        assert module == {"name": "custom.dll", "base": 0x700000, "offset": 0x40}
        assert functions["formatAddress"](0x700040) == "custom.dll+0x40"
        assert functions["resolveExport"]("custom.dll", "Example") == 0xCAFEBABE
        assert resolved == {
            "module_name": "custom.dll",
            "function_name": "Example",
            "session": session,
        }
        assert resolved["session"] is session

    def test_process_registration_forwards_ctx_session_only_where_required(self, monkeypatch):
        import memscope_mcp.extensions.core.process as process_extension
        from memscope_mcp.extensions.base import ExtensionContext

        calls = {}

        def spy(name):
            def capture(*args, **kwargs):
                calls[name] = (args, kwargs)
                return name

            return capture

        helper_names = (
            "get_process_info",
            "is_being_debugged",
            "get_environment",
            "get_modules_remote",
            "get_memory_regions",
            "get_region_info",
            "get_threads",
            "get_process_list",
            "get_services",
        )
        for helper_name in helper_names:
            monkeypatch.setattr(process_extension, helper_name, spy(helper_name))

        session = object()
        extension = process_extension.ProcessExtension()
        functions = extension.register(
            ExtensionContext(
                engine=None,
                session=session,
                table_factory=dict,
                log_error=lambda *_args: None,
            )
        )

        assert functions["getProcessInfo"](11) == "get_process_info"
        assert functions["isBeingDebugged"](22) == "is_being_debugged"
        assert functions["getEnvironment"](33) == "get_environment"
        assert functions["getModulesRemote"](44) == "get_modules_remote"
        assert functions["getMemoryRegions"]("RW", 7) == "get_memory_regions"
        assert functions["getRegionInfo"](0x1234) == "get_region_info"
        assert functions["getThreads"](55) == "get_threads"
        assert functions["getProcessList"]("needle", 6) == "get_process_list"
        assert functions["getServices"](66) == "get_services"

        expected_args = {
            "get_process_info": (dict, 11),
            "is_being_debugged": (22,),
            "get_environment": (dict, 33),
            "get_modules_remote": (dict, 44),
            "get_memory_regions": (dict, "RW", 7),
            "get_region_info": (dict, 0x1234),
            "get_threads": (dict, 55),
        }
        for helper_name, args in expected_args.items():
            actual_args, kwargs = calls[helper_name]
            assert actual_args == args
            assert set(kwargs) == {"session"}
            assert kwargs["session"] is session

        assert calls["get_process_list"] == ((dict, "needle", 6), {})
        assert calls["get_services"] == ((dict, 66), {})


class TestCollisionDetection:
    """Function mappings preflight completely before registry mutation."""

    def test_duplicate_raises_valueerror(self):
        """Registering the same function name twice without allow_overwrite raises."""
        engine = MemscopeLuaEngine()
        engine.register_functions("ext_a", {"myFunc": lambda: 1})
        with pytest.raises(ValueError) as exc_info:
            engine.register_functions("ext_b", {"myFunc": lambda: 2})
        assert "ext_a" in str(exc_info.value)
        assert "ext_b" in str(exc_info.value)
        assert "myFunc" in str(exc_info.value)

    def test_collision_rejects_full_mapping_before_new_name_mutation(self):
        engine = MemscopeLuaEngine()

        def original():
            return 1

        engine.register_functions("ext_a", {"myFunc": original, "unrelated": lambda: 3})

        with pytest.raises(ValueError, match="myFunc"):
            engine.register_functions(
                "ext_b",
                {"newNameBeforeCollision": lambda: 2, "myFunc": lambda: 4},
            )

        results = _lua_results(
            engine,
            """
            return {
                new_absent = newNameBeforeCollision == nil,
                my_func = myFunc(),
                unrelated = unrelated(),
            }
            """,
        )
        assert results["return"] == {"new_absent": True, "my_func": 1, "unrelated": 3}
        assert engine._function_registry == {"myFunc": "ext_a", "unrelated": "ext_a"}

    def test_allow_overwrite_transfers_incoming_names_and_preserves_unrelated(self):
        engine = MemscopeLuaEngine()
        engine.register_functions(
            "ext_a",
            {"myFunc": lambda: 1, "transferred": lambda: 2, "unrelated": lambda: 3},
        )

        engine.register_functions(
            "ext_b",
            {"newName": lambda: 4, "myFunc": lambda: 5, "transferred": lambda: 6},
            allow_overwrite=True,
        )

        results = _lua_results(
            engine,
            """
            return {
                new = newName(),
                my_func = myFunc(),
                transferred = transferred(),
                unrelated = unrelated(),
            }
            """,
        )
        assert results["return"] == {"new": 4, "my_func": 5, "transferred": 6, "unrelated": 3}
        assert engine._function_registry == {
            "myFunc": "ext_b",
            "transferred": "ext_b",
            "unrelated": "ext_a",
            "newName": "ext_b",
        }


class TestPluginIsolation:
    """Plugin failures don't corrupt the registry."""

    def test_plugin_can_read_public_modules_mapping(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod
        from memscope_mcp.plugins import PluginBase
        from memscope_mcp.session import DebugSession

        engine = MemscopeLuaEngine()
        session = DebugSession()
        session._module_snapshot = _module_snapshot()

        class ReaderPlugin(PluginBase):
            name = "reader"
            description = "Synthetic compatibility reader"
            instructions = "Synthetic compatibility reader"

            def register(self, ctx):
                return {"readLegacyModuleBase": lambda name: ctx.session.modules[str(name)]["base"]}

        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [ReaderPlugin()])
        extensions = bootstrap_extensions(engine, session)

        assert "reader" in [extension.name for extension in extensions]
        assert _lua_results(engine, 'return readLegacyModuleBase("legacy.dll")')["return"] == 0x12340000

    def test_plugin_modules_mutation_does_not_write_through(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod
        from memscope_mcp.plugins import PluginBase
        from memscope_mcp.session import DebugSession

        engine = MemscopeLuaEngine()
        session = DebugSession()
        snapshot = _module_snapshot()
        session._module_snapshot = snapshot
        expected = snapshot.to_legacy_dict()

        class MutatingPlugin(PluginBase):
            name = "mutating_reader"
            description = "Synthetic compatibility mutation reader"
            instructions = "Synthetic compatibility mutation reader"

            def register(self, ctx):
                def mutate_legacy_modules():
                    modules = ctx.session.modules
                    modules["legacy.dll"]["base"] = 0xDEADBEEF
                    modules["legacy.dll"]["size"] = 0x2000
                    modules["inserted.dll"] = {"base": 0x2000, "size": 0x80, "path": "inserted.dll"}
                    del modules["legacy.dll"]
                    return modules["inserted.dll"]["base"]

                return {
                    "mutateLegacyModules": mutate_legacy_modules,
                    "readLegacyModuleBase": lambda: ctx.session.modules["legacy.dll"]["base"],
                }

        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [MutatingPlugin()])
        bootstrap_extensions(engine, session)

        results = _lua_results(
            engine,
            """
            addResult("mutated", mutateLegacyModules())
            addResult("original", readLegacyModuleBase())
            """,
        )
        assert results == {"mutated": 0x2000, "original": 0x12340000}
        assert session.modules == expected
        assert session._module_snapshot is snapshot
        assert snapshot.to_legacy_dict() == expected

    def test_plugin_collision_skips_complete_mapping_and_lifecycle(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class CoreProvider(LuaExtension):
            name = "core_provider"

            def register(self, ctx):
                return {"sharedName": lambda: "core"}

        class CollidingPlugin(LuaExtension):
            name = "colliding_plugin"

            def register(self, ctx):
                return {
                    "pluginNameBeforeCollision": lambda: "plugin",
                    "sharedName": lambda: "plugin",
                }

            def on_process_attached(self, session):
                raise AssertionError("rejected plugin lifecycle must not be installed")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (CoreProvider,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [CollidingPlugin()])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        extensions = bootstrap_extensions(engine, session)

        assert [extension.name for extension in extensions] == ["core_provider"]
        results = _lua_results(
            engine,
            "return {plugin_absent = pluginNameBeforeCollision == nil, shared = sharedName()}",
        )
        assert results["return"] == {"plugin_absent": True, "shared": "core"}
        assert engine._function_registry == {"sharedName": "core_provider"}
        assert "colliding_plugin" not in session._on_attach_callbacks

    def test_bad_plugin_does_not_block_core(self):
        """A failing plugin doesn't prevent core extensions from loading."""
        from memscope_mcp.session import DebugSession

        engine = MemscopeLuaEngine()
        session = DebugSession()

        class BadPlugin(LuaExtension):
            name = "bad"
            description = "Intentionally broken"

            def register(self, ctx):
                raise RuntimeError("I broke")

        # Monkey-patch load_plugins to return our bad plugin
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        original_load = bootstrap_mod.load_plugins

        def mock_load():
            return [BadPlugin()]

        bootstrap_mod.load_plugins = mock_load
        try:
            extensions = bootstrap_extensions(engine, session)
            # Core extensions should all be present
            core_names = [e.name for e in extensions if e.name != "bad"]
            assert "general" in core_names
            assert "memory" in core_names
        finally:
            bootstrap_mod.load_plugins = original_load


class TestExtensionContract:
    """LuaExtension interface behaves correctly."""

    def test_default_lifecycle_is_noop(self):
        """Default on_process_attached/detaching don't raise."""

        class MinimalExt(LuaExtension):
            name = "minimal"

            def register(self, ctx):
                return {}

        ext = MinimalExt()
        ext.on_process_attached(None)
        ext.on_process_detaching(None, True)
        ext.on_process_detaching(None, False)

    def test_default_description_and_instructions(self):
        """Default description and instructions are empty strings."""

        class MinimalExt(LuaExtension):
            name = "minimal"

            def register(self, ctx):
                return {}

        ext = MinimalExt()
        assert ext.description == ""
        assert ext.instructions == ""


class TestHookManagerComposition:
    """Bootstrap owns one session-bound HookManager per composition domain."""

    def test_provisional_session_is_hidden_and_callbacks_wait_for_ready(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class OwnershipProbe(LuaExtension):
            name = "ownership_probe"

            def register(self, ctx):
                assert ctx.engine.bound_session is None
                assert ctx.session._on_attach_callbacks == {}
                with pytest.raises(RuntimeError, match="bootstrapping"):
                    ctx.engine.execute("return 1")
                return {"boundSessionPid": lambda: ctx.session.pid}

            def on_process_attached(self, session):
                return None

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (OwnershipProbe,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession(pid=123)

        assert engine.bound_session is None

        extensions = bootstrap_extensions(engine, session)

        assert engine.bound_session is session
        assert [extension.name for extension in extensions] == ["ownership_probe"]
        assert list(session._on_attach_callbacks) == ["ownership_probe"]
        assert _lua_results(engine, "return boundSessionPid()")["return"] == 123

    def test_ready_engine_rebootstrap_rejects_before_registry_or_callback_mutation(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session_a = DebugSession()
        session_b = DebugSession()
        bootstrap_extensions(engine, session_a)
        registry_before = dict(engine._function_registry)
        attach_a_before = dict(session_a._on_attach_callbacks)
        detach_a_before = dict(session_a._on_detach_callbacks)

        for attempted_session in (session_a, session_b):
            with pytest.raises(RuntimeError, match="already ready"):
                bootstrap_extensions(engine, attempted_session, hook_manager=HookManager(attempted_session))

        with pytest.raises(RuntimeError, match="registration is closed"):
            engine.register_functions("late", {"lateName": lambda: None})

        assert engine.bound_session is session_a
        assert engine._function_registry == registry_before
        assert _lua_results(engine, "return lateName == nil")["return"] is True
        assert session_a._on_attach_callbacks == attach_a_before
        assert session_a._on_detach_callbacks == detach_a_before
        assert session_b._on_attach_callbacks == {}
        assert session_b._on_detach_callbacks == {}
        assert session_b._lua_composition_engine is None

    def test_core_failure_terminally_quarantines_engine(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class PartialCore(LuaExtension):
            name = "partial"

            def register(self, ctx):
                return {"partialFunction": lambda: 1}

        class BrokenCore(LuaExtension):
            name = "broken"

            def register(self, ctx):
                raise RuntimeError("hard failure")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (PartialCore, BrokenCore))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        with pytest.raises(RuntimeError, match="Core extension 'broken' failed to register: hard failure"):
            bootstrap_extensions(engine, session)

        assert engine.bound_session is None
        assert not hasattr(engine, "lua")
        assert engine._function_registry == {}
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return partialFunction()")
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.register_functions("late", {"lateName": lambda: None})

    def test_failed_engine_same_and_cross_session_rebootstrap_reject_before_mutation(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class BrokenCore(LuaExtension):
            name = "broken"

            def register(self, ctx):
                raise RuntimeError("hard failure")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (BrokenCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session_a = DebugSession()
        session_b = DebugSession()
        with pytest.raises(RuntimeError, match="hard failure"):
            bootstrap_extensions(engine, session_a)
        registry_before = dict(engine._function_registry)
        callbacks_before = (
            dict(session_a._on_attach_callbacks),
            dict(session_a._on_detach_callbacks),
        )

        for attempted_session in (session_a, session_b):
            with pytest.raises(RuntimeError, match="failed.*quarantined"):
                bootstrap_extensions(engine, attempted_session, hook_manager=HookManager(attempted_session))

        assert engine._function_registry == registry_before
        assert session_a._on_attach_callbacks == callbacks_before[0]
        assert session_a._on_detach_callbacks == callbacks_before[1]
        assert session_b._on_attach_callbacks == {}
        assert session_b._on_detach_callbacks == {}
        assert session_b._lua_composition_engine is None

    def test_failed_claimed_session_cannot_be_reused_by_another_engine(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class BrokenCore(LuaExtension):
            name = "broken"

            def register(self, ctx):
                raise RuntimeError("hard failure")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (BrokenCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        failed_engine = MemscopeLuaEngine()
        session = DebugSession()
        with pytest.raises(RuntimeError, match="hard failure"):
            bootstrap_extensions(failed_engine, session)

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
        replacement_engine = MemscopeLuaEngine()
        with pytest.raises(ValueError, match="already claimed by a different"):
            bootstrap_extensions(replacement_engine, session)

        assert session._lua_composition_engine is failed_engine
        assert replacement_engine.bound_session is None
        assert replacement_engine._function_registry == {}
        assert replacement_engine._operation_token is None
        assert replacement_engine._operation_kind is None
        assert replacement_engine._operation_thread_id is None
        assert replacement_engine._bootstrap_token is None
        assert replacement_engine.execute("return 7")["results"]["return"] == 7

    def test_lifecycle_install_failure_quarantines_composition(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class LifecycleCore(LuaExtension):
            name = "lifecycle"

            def register(self, ctx):
                return {"registeredBeforeLifecycle": lambda: 1}

            def on_process_attached(self, session):
                return None

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (LifecycleCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        monkeypatch.setattr(
            session,
            "_commit_lua_composition_callback_batch",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("lifecycle commit failed")),
        )

        with pytest.raises(RuntimeError, match="lifecycle commit failed"):
            bootstrap_extensions(engine, session)

        assert engine.bound_session is None
        assert engine._function_registry == {}
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")

    def test_two_argument_bootstraps_create_distinct_bound_managers(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        session_a = DebugSession()
        session_b = DebugSession()

        extensions_a = bootstrap_extensions(MemscopeLuaEngine(), session_a)
        extensions_b = bootstrap_extensions(MemscopeLuaEngine(), session_b)
        hooking_a = next(ext for ext in extensions_a if ext.name == "hooking")
        hooking_b = next(ext for ext in extensions_b if ext.name == "hooking")

        assert hooking_a._hook_manager is not hooking_b._hook_manager
        assert hooking_a._hook_manager.session is session_a
        assert hooking_b._hook_manager.session is session_b
        assert hooking_a._session is session_a
        assert hooking_b._session is session_b

    def test_explicit_mismatched_manager_fails_before_registration(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        session_a = DebugSession()
        session_b = DebugSession()
        manager_a = HookManager(session_a)
        engine = MemscopeLuaEngine()

        with pytest.raises(ValueError, match="HookManager/session ownership mismatch"):
            bootstrap_extensions(engine, session_b, hook_manager=manager_a)

        assert session_b._lua_composition_engine is None
        assert engine.bound_session is None
        assert engine.execute("return 9")["results"]["return"] == 9

    def test_core_hooking_and_real_netcap_share_exact_manager(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod
        from memscope_mcp._contrib.plugins.netcap import NetcapPlugin

        session = DebugSession()
        manager = HookManager(session)
        netcap = NetcapPlugin()
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [netcap])

        extensions = bootstrap_extensions(MemscopeLuaEngine(), session, hook_manager=manager)
        hooking = next(ext for ext in extensions if ext.name == "hooking")
        registered_netcap = next(ext for ext in extensions if ext.name == "netcap")

        assert registered_netcap is netcap
        assert hooking._hook_manager is netcap._hook_manager is manager
        assert hooking._session is netcap._session is session
        assert manager.session is session

    def test_core_hooking_and_plugin_receive_same_manager_identity(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class CapturingPlugin(LuaExtension):
            name = "capture_manager"
            description = "Synthetic manager identity probe"

            def register(self, ctx):
                self.session = ctx.session
                self.hook_manager = ctx.hook_manager
                return {}

        session = DebugSession()
        manager = HookManager(session)
        plugin = CapturingPlugin()
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [plugin])

        extensions = bootstrap_extensions(MemscopeLuaEngine(), session, hook_manager=manager)
        hooking = next(ext for ext in extensions if ext.name == "hooking")
        registered_plugin = next(ext for ext in extensions if ext.name == "capture_manager")

        assert hooking._hook_manager is manager
        assert registered_plugin is plugin
        assert plugin.hook_manager is manager
        assert plugin.session is session
        assert manager.session is session


class _SyntheticBootstrapAbort(BaseException):
    pass


class TestBootstrapOperationHardening:
    def test_lua_callback_reentrant_bootstrap_rejects_without_claim_or_partial(self):
        engine = MemscopeLuaEngine()
        session = DebugSession()
        observed = []
        results = []

        def attempt_bootstrap():
            outer_token = engine._operation_token
            try:
                bootstrap_extensions(engine, session)
            except RuntimeError as exc:
                observed.append(str(exc))
            assert engine._operation_token is outer_token
            assert engine._operation_kind.name == "EXECUTE"
            return 11

        engine.register_functions("direct", {"attemptBootstrap": attempt_bootstrap})
        worker = threading.Thread(target=lambda: results.append(engine.execute("return attemptBootstrap()")))
        worker.start()
        worker.join(2)

        assert not worker.is_alive()
        assert results == [{"success": True, "results": {"return": 11}, "output": []}]
        assert observed and "operation is active" in observed[0]
        assert session._lua_composition_engine_identity() is None
        assert engine.bound_session is None
        assert engine._function_registry == {"attemptBootstrap": "direct"}
        assert _lua_results(engine, "return addr == nil")["return"] is True

    def test_other_thread_bootstrap_during_blocked_execution_rejects_immediately(self):
        engine = MemscopeLuaEngine()
        session = DebugSession()
        entered = threading.Event()
        release = threading.Event()
        execution_results = []
        bootstrap_errors = []

        def block():
            entered.set()
            assert release.wait(3)

        def attempt_bootstrap():
            try:
                bootstrap_extensions(engine, session)
            except BaseException as exc:
                bootstrap_errors.append(exc)

        engine.register_functions("direct", {"block": block})
        execution = threading.Thread(target=lambda: execution_results.append(engine.execute("block(); return 3")))
        execution.start()
        assert entered.wait(2)

        attempt = threading.Thread(target=attempt_bootstrap)
        attempt.start()
        attempt.join(0.5)
        queued = attempt.is_alive()
        release.set()
        execution.join(2)
        attempt.join(2)

        assert not queued
        assert not execution.is_alive()
        assert not attempt.is_alive()
        assert execution_results[0]["success"] is True
        assert len(bootstrap_errors) == 1
        assert isinstance(bootstrap_errors[0], RuntimeError)
        assert "operation is active" in str(bootstrap_errors[0])
        assert session._lua_composition_engine_identity() is None

    def test_execute_and_public_registration_reject_during_blocked_bootstrap(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        entered = threading.Event()
        release = threading.Event()

        class BlockingCore(LuaExtension):
            name = "blocking"

            def register(self, ctx):
                entered.set()
                assert release.wait(3)
                return {"bootstrapOwned": lambda: 9}

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (BlockingCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        bootstrap_errors = []
        execute_errors = []
        register_errors = []

        def run_bootstrap():
            try:
                bootstrap_extensions(engine, session)
            except BaseException as exc:
                bootstrap_errors.append(exc)

        def try_execute():
            try:
                engine.execute("return 1")
            except BaseException as exc:
                execute_errors.append(exc)

        def try_register():
            try:
                engine.register_functions("foreign", {"foreignInjected": lambda: 1})
            except BaseException as exc:
                register_errors.append(exc)

        bootstrap_thread = threading.Thread(target=run_bootstrap)
        bootstrap_thread.start()
        assert entered.wait(2)
        execute_thread = threading.Thread(target=try_execute)
        register_thread = threading.Thread(target=try_register)
        execute_thread.start()
        register_thread.start()
        execute_thread.join(0.5)
        register_thread.join(0.5)
        execute_queued = execute_thread.is_alive()
        register_queued = register_thread.is_alive()
        release.set()
        bootstrap_thread.join(2)
        execute_thread.join(2)
        register_thread.join(2)

        assert not execute_queued
        assert not register_queued
        assert not bootstrap_thread.is_alive()
        assert bootstrap_errors == []
        assert len(execute_errors) == len(register_errors) == 1
        assert "bootstrapping" in str(execute_errors[0])
        assert "bootstrapping" in str(register_errors[0])
        observed = _lua_results(
            engine,
            "return {owned = bootstrapOwned(), foreign_absent = foreignInjected == nil}",
        )["return"]
        assert observed == {"owned": 9, "foreign_absent": True}

    @pytest.mark.parametrize(
        "error_type",
        [RuntimeError, KeyboardInterrupt, SystemExit],
        ids=["exception", "keyboard-interrupt", "system-exit"],
    )
    def test_begin_return_then_raise_quarantines_and_releases_exact_lease(
        self,
        monkeypatch,
        error_type,
    ):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        real_begin = engine._begin_bootstrap

        def begin_then_raise(candidate_session, token):
            real_begin(candidate_session, token)
            raise error_type("interrupted after begin")

        monkeypatch.setattr(engine, "_begin_bootstrap", begin_then_raise)

        with pytest.raises(error_type, match="interrupted after begin"):
            bootstrap_extensions(engine, session)

        assert session._lua_composition_engine_identity() is engine
        assert engine.bound_session is None
        assert engine._operation_token is None
        assert engine._operation_kind is None
        assert engine._operation_thread_id is None
        assert engine._bootstrap_token is None
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.register_functions("late", {"lateName": lambda: 1})
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            bootstrap_extensions(engine, session)
        assert engine._operation_token is None
        assert engine._operation_kind is None


class TestBootstrapFailureClassification:
    def test_plugin_public_registration_then_exception_is_fully_skipped(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class Core(LuaExtension):
            name = "core"

            def register(self, ctx):
                return {"coreValue": lambda: 1}

        class InjectingPlugin(LuaExtension):
            name = "injecting"

            def register(self, ctx):
                with pytest.raises(RuntimeError, match="bootstrapping"):
                    ctx.engine.register_functions("injected", {"injectedName": lambda: 2})
                raise RuntimeError("plugin failed after injection attempt")

            def on_process_attached(self, session):
                raise AssertionError("skipped plugin lifecycle ran")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (Core,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [InjectingPlugin()])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        extensions = bootstrap_extensions(engine, session)

        assert [type(extension) for extension in extensions] == [Core]
        observed = _lua_results(
            engine,
            "return {core = coreValue(), injected_absent = injectedName == nil}",
        )["return"]
        assert observed == {"core": 1, "injected_absent": True}
        assert "injecting" not in session._on_attach_callbacks

    def test_plugin_lifecycle_inspection_exception_skips_mapping_and_callback(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class Core(LuaExtension):
            name = "core"

            def register(self, ctx):
                return {"coreValue": lambda: 1}

        class BadLifecyclePlugin(LuaExtension):
            name = "bad_lifecycle"

            def register(self, ctx):
                return {"badLifecycleValue": lambda: 2}

            @property
            def on_process_attached(self):
                raise RuntimeError("lifecycle inspection failed")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (Core,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [BadLifecyclePlugin()])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        bootstrap_extensions(engine, session)

        assert _lua_results(engine, "return badLifecycleValue == nil")["return"] is True
        assert "bad_lifecycle" not in session._on_attach_callbacks

    @pytest.mark.parametrize(
        "error",
        [
            KeyboardInterrupt("plugin interrupt"),
            SystemExit("plugin exit"),
            _SyntheticBootstrapAbort("plugin base exception"),
        ],
        ids=["keyboard-interrupt", "system-exit", "custom-base-exception"],
    )
    def test_plugin_baseexception_quarantines(self, monkeypatch, error):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class Core(LuaExtension):
            name = "core"

            def register(self, ctx):
                return {"coreStaged": lambda: 1}

        class FatalPlugin(LuaExtension):
            name = "fatal"

            def register(self, ctx):
                raise error

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (Core,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [FatalPlugin()])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        with pytest.raises(type(error)):
            bootstrap_extensions(engine, session)

        assert session._lua_composition_engine_identity() is engine
        assert engine.bound_session is None
        assert engine._function_registry == {}
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")

    def test_core_baseexception_quarantines_without_wrapping(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class FatalCore(LuaExtension):
            name = "fatal_core"

            def register(self, ctx):
                raise KeyboardInterrupt("core interrupt")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (FatalCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        with pytest.raises(KeyboardInterrupt, match="core interrupt"):
            bootstrap_extensions(engine, session)

        assert session._lua_composition_engine_identity() is engine
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")

    def test_plugin_name_is_not_reaccessed_after_acceptance(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class Core(LuaExtension):
            name = "core"

            def register(self, ctx):
                return {}

        class OneShotNamePlugin(LuaExtension):
            def __init__(self):
                self.name_reads = 0

            @property
            def name(self):
                self.name_reads += 1
                if self.name_reads > 1:
                    raise RuntimeError("name was read after acceptance")
                return "one_shot"

            def register(self, ctx):
                return {"oneShotValue": lambda: 4}

        plugin = OneShotNamePlugin()
        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (Core,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [plugin])

        extensions = bootstrap_extensions(MemscopeLuaEngine(), DebugSession())

        assert extensions[-1] is plugin
        assert plugin.name_reads == 1


class TestSessionClaimReconciliation:
    def test_claim_exception_before_mutation_returns_engine_to_clean_unbound(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        def fail_before_mutation(_candidate):
            raise RuntimeError("claim failed before mutation")

        monkeypatch.setattr(session, "_claim_lua_composition_engine", fail_before_mutation)

        with pytest.raises(RuntimeError, match="before mutation"):
            bootstrap_extensions(engine, session)

        assert session._lua_composition_engine_identity() is None
        assert engine.bound_session is None
        assert engine._operation_token is None
        assert engine._operation_kind is None
        assert engine._operation_thread_id is None
        assert engine._bootstrap_token is None
        assert engine.execute("return 7")["results"]["return"] == 7
        engine.register_functions("direct", {"directAfterClaimFailure": lambda: 8})
        assert engine.execute("return directAfterClaimFailure()")["results"]["return"] == 8

    @pytest.mark.parametrize(
        "error_type",
        [RuntimeError, KeyboardInterrupt, SystemExit, _SyntheticBootstrapAbort],
        ids=["exception", "keyboard-interrupt", "system-exit", "custom-base-exception"],
    )
    def test_claim_mutation_then_raise_quarantines_and_retains_claim(self, monkeypatch, error_type):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        error = error_type("claim failed after mutation")

        def mutate_then_fail(candidate):
            with session._lua_composition_claim_lock:
                session._lua_composition_engine = candidate
            raise error

        monkeypatch.setattr(session, "_claim_lua_composition_engine", mutate_then_fail)

        with pytest.raises(error_type):
            bootstrap_extensions(engine, session)

        assert session._lua_composition_engine_identity() is engine
        assert engine.bound_session is None
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")


class TestLifecyclePublicationHardening:
    def test_two_extension_batch_is_inert_until_ready_and_preserves_generic(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        calls = []

        class First(LuaExtension):
            name = "first"

            def register(self, ctx):
                return {"firstValue": lambda: 1}

            def on_process_attached(self, session):
                calls.append("first")

        class Second(LuaExtension):
            name = "second"

            def register(self, ctx):
                return {"secondValue": lambda: 2}

            def on_process_attached(self, session):
                calls.append("second")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (First, Second))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        session.register_on_attach("generic", lambda _session: calls.append("generic"))
        original_commit = session._commit_lua_composition_callback_batch
        observations = []

        def inspect_batch(attach_candidate, detach_candidate):
            observations.append(
                (
                    engine.bound_session,
                    tuple(session._on_attach_callbacks),
                    tuple(attach_candidate),
                    tuple(detach_candidate),
                )
            )
            attach_candidate["first"](session)
            attach_candidate["second"](session)
            original_commit(attach_candidate, detach_candidate)

        monkeypatch.setattr(session, "_commit_lua_composition_callback_batch", inspect_batch)

        bootstrap_extensions(engine, session)

        assert observations == [(None, ("generic",), ("generic", "first", "second"), ())]
        assert calls == []
        assert engine.bound_session is session
        session._fire_attach()
        assert calls == ["generic", "first", "second"]

    def test_lifecycle_candidate_collision_preserves_prior_record_and_quarantines(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        class ExistingCore(LuaExtension):
            name = "existing"

            def register(self, ctx):
                return {"candidateValue": lambda: 1}

            def on_process_attached(self, session):
                raise AssertionError("colliding composition callback ran")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (ExistingCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()

        def prior(_session):
            return None

        session.register_on_attach("existing", prior)
        callbacks_before = session._on_attach_callbacks

        with pytest.raises(RuntimeError, match="already registered"):
            bootstrap_extensions(engine, session)

        assert session._on_attach_callbacks is callbacks_before
        assert session._on_attach_callbacks == {"existing": prior}
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")

    def test_interrupted_callback_commit_leaves_provisional_wrapper_inert(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        calls = []

        class LifecycleCore(LuaExtension):
            name = "composition"

            def register(self, ctx):
                return {"compositionValue": lambda: 1}

            def on_process_attached(self, session):
                calls.append("composition")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (LifecycleCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        session.register_on_attach("generic", lambda _session: calls.append("generic"))

        def partial_commit(attach_candidate, _detach_candidate):
            session._on_attach_callbacks = attach_candidate
            raise RuntimeError("interrupted callback commit")

        monkeypatch.setattr(session, "_commit_lua_composition_callback_batch", partial_commit)

        with pytest.raises(RuntimeError, match="interrupted callback commit"):
            bootstrap_extensions(engine, session)

        assert tuple(session._on_attach_callbacks) == ("generic", "composition")
        session._fire_attach()
        assert calls == ["generic"]
        assert engine._function_registry == {}
        with pytest.raises(RuntimeError, match="failed.*quarantined"):
            engine.execute("return 1")

    def test_callback_can_register_callback_for_next_snapshot(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        calls = []

        class RegistrarCore(LuaExtension):
            name = "registrar"

            def register(self, ctx):
                return {}

            def on_process_attached(self, session):
                calls.append("registrar")
                session.register_on_attach("late", lambda _session: calls.append("late"))

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (RegistrarCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        session = DebugSession()
        bootstrap_extensions(engine, session)

        session._fire_attach()
        assert calls == ["registrar"]
        session._fire_attach()
        assert calls == ["registrar", "registrar", "late"]
        with pytest.raises(RuntimeError, match="cannot be replaced"):
            session.register_on_attach("registrar", lambda _session: None)


class TestGuardedRuntimeCapabilities:
    def test_context_has_no_lua_and_table_factory_is_operation_scoped(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        captured = {}

        class TableCore(LuaExtension):
            name = "tables"

            def register(self, ctx):
                assert not hasattr(ctx, "lua")
                captured["factory"] = ctx.table_factory
                bootstrap_table = ctx.table_factory(answer=42)
                return {
                    "bootstrapTable": lambda: bootstrap_table,
                    "runtimeTable": lambda: ctx.table_factory(value=7),
                }

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (TableCore,))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()
        bootstrap_extensions(engine, DebugSession())

        assert not hasattr(engine, "lua")
        observed = _lua_results(
            engine,
            "return {bootstrap = bootstrapTable(), runtime = runtimeTable()}",
        )["return"]
        assert observed == {"bootstrap": {"answer": 42}, "runtime": {"value": 7}}
        with pytest.raises(RuntimeError, match="engine-owned operation"):
            captured["factory"]()

    def test_captured_table_factory_rejects_after_bootstrap_failure(self, monkeypatch):
        import memscope_mcp.extensions.bootstrap as bootstrap_mod

        captured = {}

        class CaptureCore(LuaExtension):
            name = "capture"

            def register(self, ctx):
                captured["factory"] = ctx.table_factory
                return {"staged": lambda: 1}

        class BrokenCore(LuaExtension):
            name = "broken"

            def register(self, ctx):
                raise RuntimeError("hard failure")

        monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (CaptureCore, BrokenCore))
        monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [])
        engine = MemscopeLuaEngine()

        with pytest.raises(RuntimeError, match="hard failure"):
            bootstrap_extensions(engine, DebugSession())

        with pytest.raises(RuntimeError, match="quarantined"):
            captured["factory"]()
