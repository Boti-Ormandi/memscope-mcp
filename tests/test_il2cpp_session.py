"""Session ownership coverage for the IL2CPP contrib plugin."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from memscope_mcp._contrib.plugins.il2cpp import IL2CppPlugin
from memscope_mcp.extensions.base import ExtensionContext


def _register(session):
    plugin = IL2CppPlugin()
    functions = plugin.register(
        ExtensionContext(
            engine=SimpleNamespace(),
            session=session,
            table_factory=dict,
            log_error=lambda _name, _exc: None,
        )
    )
    return plugin, functions


def test_il2cpp_plugin_reads_only_from_registered_session():
    session_a = MagicMock(name="session_a")
    session_b = MagicMock(name="session_b")
    session_a.read_int32.return_value = 1
    session_a.read_bytes.return_value = "A".encode("utf-16-le")
    session_b.read_int32.return_value = 1
    session_b.read_bytes.return_value = "B".encode("utf-16-le")

    plugin_a, functions_a = _register(session_a)
    plugin_b, functions_b = _register(session_b)

    assert plugin_a._session is session_a
    assert plugin_b._session is session_b
    assert functions_a["readIL2CppString"](0x1000) == "A"
    assert functions_b["readIL2CppString"](0x2000) == "B"
    session_a.read_int32.assert_called_once_with(0x1010)
    session_a.read_bytes.assert_called_once_with(0x1014, 2)
    session_b.read_int32.assert_called_once_with(0x2010)
    session_b.read_bytes.assert_called_once_with(0x2014, 2)
