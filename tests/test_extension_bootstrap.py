"""Tests for the extension bootstrap system.

Verifies that core extensions register through the bootstrap path,
function names are present, ordering is stable, and collisions are caught.
"""

from memscope_mcp.extensions.base import LuaExtension
from memscope_mcp.extensions.bootstrap import bootstrap_extensions
from memscope_mcp.extensions.core import CORE_EXTENSIONS
from memscope_mcp.tools.lua.engine import LUA_ENGINE, MemscopeLuaEngine


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
        g = LUA_ENGINE.lua.globals()
        # One from each extension
        assert g["addr"] is not None, "addr (general)"
        assert g["readInteger"] is not None, "readInteger (memory)"
        assert g["AOBScanModule"] is not None, "AOBScanModule (module_scan)"
        assert g["executeCode"] is not None, "executeCode (execution)"
        assert g["getProcessList"] is not None, "getProcessList (process)"

    def test_aliases_registered(self):
        """Execution aliases are present."""
        g = LUA_ENGINE.lua.globals()
        assert g["call"] is not None
        assert g["free"] is not None
        assert g["allocateMemory"] is not None

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


class TestCollisionDetection:
    """Duplicate function name registration raises."""

    def test_duplicate_raises_valueerror(self):
        """Registering the same function name twice without allow_overwrite raises."""
        engine = MemscopeLuaEngine()
        engine.register_functions("ext_a", {"myFunc": lambda: 1})
        try:
            engine.register_functions("ext_b", {"myFunc": lambda: 2})
            assert False, "Expected ValueError"
        except ValueError as e:
            assert "ext_a" in str(e)
            assert "ext_b" in str(e)
            assert "myFunc" in str(e)

    def test_allow_overwrite_succeeds(self):
        """allow_overwrite=True permits re-registration."""
        engine = MemscopeLuaEngine()
        engine.register_functions("ext_a", {"myFunc": lambda: 1})
        engine.register_functions("ext_b", {"myFunc": lambda: 2}, allow_overwrite=True)
        assert engine._function_registry["myFunc"] == "ext_b"


class TestPluginIsolation:
    """Plugin failures don't corrupt the registry."""

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
