"""Plugin migration, diagnostic, and deterministic activation regressions."""

from __future__ import annotations

import copy
import json
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import memscope_mcp.extensions.bootstrap as bootstrap_mod
import memscope_mcp.plugins.diagnostics as diagnostics
from memscope_mcp.extensions.bootstrap import bootstrap_extensions
from memscope_mcp.plugins import _get_plugin_metadata, load_plugins
from memscope_mcp.session import DebugSession
from memscope_mcp.tools.lua.engine import MemscopeLuaEngine

EXPECTED_CONTEXT_FIELDS = ["ctx.session", "ctx.table_factory", "ctx.hook_manager"]
EXPECTED_GUIDANCE = "https://memscope.esrc.dev/plugins/upgrading/"
PLUGIN_FILENAME_CASES = (
    ("plugin.py", True),
    ("élan-插件.py", True),
    ("플러그인.py", True),
    ("", False),
    (".", False),
    ("..", False),
    ("C:secret.py", False),
    ("D:", False),
    ("a:b.py", False),
    ("nested/example.py", False),
    (r"nested\example.py", False),
)


def _plugin_source(name: str, register_body: str, *, class_name: str = "ExamplePlugin") -> str:
    body = "\n".join(f"        {line}" for line in register_body.splitlines())
    return f"""from memscope_mcp.extensions.base import ExtensionContext
from memscope_mcp.plugins import PluginBase

class {class_name}(PluginBase):
    name = {name!r}
    description = "temporary test plugin"
    instructions = "temporary test plugin"

    def register(self, ctx: ExtensionContext):
{body}
"""


def _write_plugin(root: Path, filename: str, name: str, register_body: str) -> Path:
    path = root / filename
    path.write_text(_plugin_source(name, register_body), encoding="utf-8")
    return path


@pytest.fixture
def captured_diagnostics(monkeypatch):
    records: list[dict[str, object]] = []

    def capture(record):
        records.append(copy.deepcopy(record))

    monkeypatch.setattr(diagnostics, "_write_stderr_record", capture)
    monkeypatch.setattr(diagnostics, "_write_session_log_record", capture)
    return records


def _assert_diagnostic_pair(records, *, code: str, filename: str, declared_name: str | None):
    assert [record["channel"] for record in records] == ["stderr", "session_log"]
    assert len({record["channel"] for record in records}) == 2
    for record in records:
        assert diagnostics.validate_plugin_diagnostic(record) == record
        assert set(record) == {"schema", "severity", "code", "plugin", "cause", "guidance", "channel"}
        assert record["schema"] == "memscope-plugin-diagnostic/v1"
        assert record["severity"] == "warning"
        assert record["code"] == code
        assert record["plugin"] == {"filename": filename, "declared_name": declared_name}
        assert record["guidance"] == {
            "url": EXPECTED_GUIDANCE,
            "required_context_fields": EXPECTED_CONTEXT_FIELDS,
        }


def _valid_record() -> dict[str, object]:
    return {
        "schema": "memscope-plugin-diagnostic/v1",
        "severity": "warning",
        "code": "PLUGIN_LOAD_FAILED",
        "plugin": {"filename": "example.py", "declared_name": "example"},
        "cause": {"type": "RuntimeError", "message": "safe failure"},
        "guidance": {
            "url": EXPECTED_GUIDANCE,
            "required_context_fields": list(EXPECTED_CONTEXT_FIELDS),
        },
        "channel": "stderr",
    }


def test_supported_plugin_imports_preserve_guarded_context_contract():
    import memscope_mcp.extensions.base as extension_base
    import memscope_mcp.plugins as plugins_module
    import memscope_mcp.tools.hooking as hooking_module
    from memscope_mcp.extensions.base import ExtensionContext
    from memscope_mcp.plugins import PluginBase

    assert issubclass(PluginBase, extension_base.LuaExtension)
    assert ExtensionContext is extension_base.ExtensionContext
    assert not hasattr(ExtensionContext, "lua")
    assert not hasattr(hooking_module, "HOOK_MANAGER")
    assert not hasattr(extension_base, "SESSION")
    assert not hasattr(plugins_module, "SESSION")
    assert diagnostics.REQUIRED_CONTEXT_FIELDS == tuple(EXPECTED_CONTEXT_FIELDS)


def test_packaged_schema_pins_exact_strict_contract():
    schema = json.loads(
        files("memscope_mcp.schemas").joinpath("plugin-diagnostic-v1.schema.json").read_text(encoding="utf-8")
    )

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["schema", "severity", "code", "plugin", "cause", "guidance", "channel"]
    assert schema["properties"]["schema"] == {"const": "memscope-plugin-diagnostic/v1"}
    assert schema["properties"]["severity"] == {"const": "warning"}
    assert schema["properties"]["code"]["enum"] == ["PLUGIN_LOAD_FAILED", "PLUGIN_CONTEXT_INCOMPATIBLE"]
    assert schema["properties"]["channel"]["enum"] == ["stderr", "session_log"]
    Draft202012Validator.check_schema(schema)
    for nested in ("plugin", "cause", "guidance"):
        assert schema["properties"][nested]["additionalProperties"] is False
    assert schema["properties"]["guidance"]["properties"]["url"] == {"const": EXPECTED_GUIDANCE}
    assert schema["properties"]["guidance"]["properties"]["required_context_fields"] == {
        "const": EXPECTED_CONTEXT_FIELDS
    }


@pytest.mark.parametrize(("filename", "expected"), PLUGIN_FILENAME_CASES)
def test_runtime_and_packaged_schema_apply_identical_platform_stable_filename_rules(filename, expected):
    schema = json.loads(
        files("memscope_mcp.schemas").joinpath("plugin-diagnostic-v1.schema.json").read_text(encoding="utf-8")
    )
    record = _valid_record()
    record["plugin"]["filename"] = filename

    try:
        diagnostics.validate_plugin_diagnostic(record)
    except ValidationError:
        runtime_valid = False
    else:
        runtime_valid = True
    schema_valid = Draft202012Validator(schema).is_valid(record)

    assert runtime_valid == schema_valid == expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: record.pop("code"),
        lambda record: record.update(extra=True),
        lambda record: record.update(schema=1),
        lambda record: record.update(severity="error"),
        lambda record: record.update(code="OTHER"),
        lambda record: record["plugin"].update(extra=True),
        lambda record: record["plugin"].update(filename=3),
        lambda record: record["plugin"].update(filename="nested/example.py"),
        lambda record: record["plugin"].update(filename="."),
        lambda record: record["plugin"].update(filename=".."),
        lambda record: record["plugin"].pop("declared_name"),
        lambda record: record["cause"].update(extra=True),
        lambda record: record["cause"].update(message=4),
        lambda record: record["guidance"].update(extra=True),
        lambda record: record["guidance"].update(url="https://example.invalid/"),
        lambda record: record["guidance"].update(required_context_fields=list(reversed(EXPECTED_CONTEXT_FIELDS))),
        lambda record: record.update(channel="log"),
    ],
)
def test_runtime_schema_rejects_missing_extra_wrong_type_and_wrong_constants(mutate):
    record = _valid_record()
    mutate(record)

    with pytest.raises(ValidationError):
        diagnostics.validate_plugin_diagnostic(record)


def test_emission_is_one_line_utf8_json_with_escaping_and_fixed_channel_order(monkeypatch):
    lines: list[str] = []
    monkeypatch.setattr(
        diagnostics.sys,
        "stderr",
        type(
            "Sink",
            (),
            {
                "write": lambda self, text: lines.append(text),
                "flush": lambda self: None,
            },
        )(),
    )
    logged: list[dict[str, object]] = []
    monkeypatch.setattr(diagnostics, "_write_session_log_record", lambda record: logged.append(copy.deepcopy(record)))

    diagnostics.emit_plugin_failure(
        filename="unicode.py",
        declared_name='é"clair\nnext',
        exc=RuntimeError("plugin-controlled details"),
    )

    assert len(lines) == 1
    assert lines[0].endswith("\n")
    assert len(lines[0].splitlines()) == 1
    assert "é" in lines[0]
    stderr_record = json.loads(lines[0])
    assert stderr_record["plugin"]["declared_name"] == 'é"clair\nnext'
    assert stderr_record["cause"]["message"] == diagnostics._REDACTED_CAUSE_MESSAGE
    assert stderr_record["channel"] == "stderr"
    assert [stderr_record["channel"], logged[0]["channel"]] == ["stderr", "session_log"]


def test_emission_replaces_invalid_utf8_and_unicode_line_separators(captured_diagnostics):
    diagnostics.emit_plugin_failure(
        filename="unicode.py",
        declared_name="bad\ud800\u2028name",
        exc=RuntimeError("bad\ud800\u2029message"),
    )

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="unicode.py",
        declared_name="bad? name",
    )
    for record in captured_diagnostics:
        line = diagnostics.serialize_plugin_diagnostic(record)
        assert "\ud800" not in line
        assert "\u2028" not in line
        assert "\u2029" not in line
        line.encode("utf-8")


def test_session_log_sink_appends_one_raw_json_event_to_temporary_home(tmp_path, monkeypatch):
    import memscope_mcp.paths as paths
    import memscope_mcp.utils.logger as logger_module

    monkeypatch.setattr(paths, "LOGS_DIR", tmp_path / "logs")
    fresh_logger = logger_module.MCPLogger()
    monkeypatch.setattr(logger_module, "LOGGER", fresh_logger)
    record = _valid_record()
    record["channel"] = "session_log"

    diagnostics._write_session_log_record(record)

    lines = fresh_logger._get_log_file().read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == record


def test_unknown_failure_message_is_bounded_and_sanitizes_paths_and_secrets(tmp_path, captured_diagnostics):
    source = tmp_path / "bad.py"
    secret = "ghp_1234567890abcdefghijklmnop"
    bearer = "sk-live-1234567890abcdefghijklmnop"
    relative_path = r"..\private\credentials.json"
    exc = RuntimeError(
        f'Authorization: Bearer {bearer}; token="top-secret" secret={secret}; '
        f"failed at {source}, C:\\Private Folder\\target.py, C:private.py, private.py, and {relative_path}; "
        + "x"
        * 1000
    )

    diagnostics.emit_plugin_failure(
        filename=source.name,
        declared_name="bad",
        exc=exc,
        source_path=source,
    )

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="bad.py",
        declared_name="bad",
    )
    for record in captured_diagnostics:
        message = record["cause"]["message"]
        assert str(tmp_path) not in message
        assert "C:\\Private" not in message
        assert "top-secret" not in message
        assert secret not in message
        assert bearer not in message
        assert relative_path not in message
        assert "C:private.py" not in message
        assert "private.py" not in message
        assert message == diagnostics._REDACTED_CAUSE_MESSAGE
        assert len(message) <= 512


def test_hostile_exception_rendering_and_oversized_name_cannot_break_diagnostic_isolation(captured_diagnostics):
    class HostileError(RuntimeError):
        def __str__(self):
            raise RuntimeError("rendering failed")

    diagnostics.emit_plugin_failure(
        filename="hostile.py",
        declared_name="n" * 1000,
        exc=HostileError(),
    )

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="hostile.py",
        declared_name="n" * 255,
    )
    assert {record["cause"]["message"] for record in captured_diagnostics} == {diagnostics._REDACTED_CAUSE_MESSAGE}
    assert {record["cause"]["type"] for record in captured_diagnostics} == {"Exception"}


def test_hostile_str_subclass_plugin_name_cannot_promote_registration_failure(
    monkeypatch,
    captured_diagnostics,
):
    from memscope_mcp.extensions.base import LuaExtension

    class HostileName(str):
        def encode(self, *_args, **_kwargs):
            raise RuntimeError("hostile encode")

    class BadPlugin(LuaExtension):
        name = HostileName("bad")

        def register(self, ctx):
            raise RuntimeError("ordinary plugin failure")

    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: [BadPlugin()])
    engine = MemscopeLuaEngine()
    session = DebugSession()

    assert bootstrap_extensions(engine, session) == []
    assert engine.bound_session is session
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="test_plugin_migration.py",
        declared_name="bad",
    )


def test_public_constant_aliases_cannot_mutate_emitted_schema_contract(monkeypatch, captured_diagnostics):
    monkeypatch.setattr(diagnostics, "SCHEMA_NAME", "evil")
    monkeypatch.setattr(diagnostics, "GUIDANCE_URL", "https://example.invalid/")
    monkeypatch.setattr(diagnostics, "REQUIRED_CONTEXT_FIELDS", ["evil"])

    diagnostics.emit_plugin_failure(
        filename="example.py",
        declared_name="example",
        exc=RuntimeError("ordinary failure"),
    )

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="example.py",
        declared_name="example",
    )


def test_metadata_recursion_is_isolated_and_later_sorted_plugin_still_loads(tmp_path, captured_diagnostics):
    (tmp_path / "10-malformed.py").write_text(
        "value = " + "+".join("1" for _ in range(5000)),
        encoding="utf-8",
    )
    _write_plugin(tmp_path, "20-valid.py", "valid", "return {}")

    plugins = load_plugins(tmp_path)

    assert [plugin.name for plugin in plugins] == ["valid"]
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="10-malformed.py",
        declared_name=None,
    )


def test_import_time_removed_hook_manager_import_is_narrowly_classified(tmp_path, captured_diagnostics):
    path = tmp_path / "10-stale.py"
    path.write_text(
        """from memscope_mcp.tools.hooking import HOOK_MANAGER
from memscope_mcp.plugins import PluginBase

class StalePlugin(PluginBase):
    name = "stale"
    description = "stale"
    instructions = "stale"
    def register(self, ctx):
        return {}
""",
        encoding="utf-8",
    )

    assert load_plugins(tmp_path) == []

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_CONTEXT_INCOMPATIBLE",
        filename="10-stale.py",
        declared_name="stale",
    )
    assert {record["cause"]["message"] for record in captured_diagnostics} == {diagnostics._RECOGNIZED_CONTEXT_MESSAGE}


def test_import_time_stale_plugin_does_not_corrupt_core_composition(
    tmp_path,
    monkeypatch,
    captured_diagnostics,
):
    from memscope_mcp.extensions.base import LuaExtension

    (tmp_path / "10-stale.py").write_text(
        "from memscope_mcp.tools.hooking import HOOK_MANAGER\n",
        encoding="utf-8",
    )

    class CoreProbe(LuaExtension):
        name = "core_probe"

        def register(self, ctx):
            return {"coreProbe": lambda: 7}

    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", (CoreProbe,))
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: load_plugins(tmp_path))
    engine = MemscopeLuaEngine()
    session = DebugSession()

    extensions = bootstrap_extensions(engine, session)

    assert [extension.name for extension in extensions] == ["core_probe"]
    assert engine.bound_session is session
    assert engine.execute("return coreProbe()")["results"]["return"] == 7
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_CONTEXT_INCOMPATIBLE",
        filename="10-stale.py",
        declared_name=None,
    )


def test_user_thrown_import_error_with_matching_words_is_not_structurally_classified(tmp_path, captured_diagnostics):
    path = tmp_path / "10-user-thrown.py"
    path.write_text(
        """raise ImportError(
    "cannot import name 'HOOK_MANAGER' from 'memscope_mcp.tools.hooking'",
    name="memscope_mcp.tools.hooking",
)
from memscope_mcp.plugins import PluginBase
class UserThrown(PluginBase):
    name = "user_thrown"
    description = "user thrown"
    instructions = "user thrown"
    def register(self, ctx):
        return {}
""",
        encoding="utf-8",
    )

    assert load_plugins(tmp_path) == []

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="10-user-thrown.py",
        declared_name="user_thrown",
    )


@pytest.mark.parametrize(
    "register_body",
    [
        "return ctx.lua.table()",
        "return ctx.engine.lua.table()",
        "return ExtensionContext.lua.table()",
        "from memscope_mcp.tools.lua.engine import MemscopeLuaEngine\nreturn MemscopeLuaEngine.lua",
        "import memscope_mcp.tools.hooking as hooking\nreturn hooking.HOOK_MANAGER",
    ],
    ids=["context-instance", "engine-instance", "context-class", "engine-class", "hooking-module"],
)
def test_registration_time_removed_context_access_is_isolated_and_classified(
    tmp_path,
    monkeypatch,
    captured_diagnostics,
    register_body,
):
    _write_plugin(tmp_path, "10-stale.py", "stale", register_body)
    plugins = load_plugins(tmp_path)
    assert len(plugins) == 1
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: plugins)
    engine = MemscopeLuaEngine()
    session = DebugSession()

    extensions = bootstrap_extensions(engine, session)

    assert extensions == []
    assert engine.bound_session is session
    assert engine._function_registry == {}
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_CONTEXT_INCOMPATIBLE",
        filename="10-stale.py",
        declared_name="stale",
    )


def test_user_thrown_attribute_error_with_stale_words_remains_generic(tmp_path, monkeypatch, captured_diagnostics):
    _write_plugin(
        tmp_path,
        "10-generic.py",
        "generic",
        'raise AttributeError("ctx.lua ExtensionContext.lua HOOK_MANAGER")',
    )
    plugins = load_plugins(tmp_path)
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: plugins)

    engine = MemscopeLuaEngine()
    session = DebugSession()
    assert bootstrap_extensions(engine, session) == []
    assert engine.bound_session is session

    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="10-generic.py",
        declared_name="generic",
    )


def test_sorted_activated_directory_is_only_runtime_root_and_skips_private_and_nested(tmp_path, captured_diagnostics):
    activated = tmp_path / "activated"
    bundled = tmp_path / "bundled-catalog"
    nested = activated / "nested"
    activated.mkdir()
    bundled.mkdir()
    nested.mkdir()
    _write_plugin(activated, "20-second.py", "second", "return {}")
    _write_plugin(activated, "10-first.py", "first", "return {}")
    _write_plugin(activated, "_ignored.py", "ignored", 'raise RuntimeError("must not import")')
    _write_plugin(nested, "00-nested.py", "nested", 'raise RuntimeError("must not import")')
    _write_plugin(bundled, "00-bundled.py", "bundled", 'raise RuntimeError("must not import")')

    plugins = load_plugins(activated)

    assert [plugin.name for plugin in plugins] == ["first", "second"]
    assert [_get_plugin_metadata(plugins, plugin).filename for plugin in plugins] == ["10-first.py", "20-second.py"]
    assert captured_diagnostics == []


def test_earlier_filename_wins_declared_extension_name_collision(tmp_path, monkeypatch, captured_diagnostics):
    _write_plugin(tmp_path, "10-first.py", "duplicate", 'return {"firstValue": lambda: 1}')
    _write_plugin(tmp_path, "20-second.py", "duplicate", 'return {"secondValue": lambda: 2}')
    plugins = load_plugins(tmp_path)
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: plugins)
    engine = MemscopeLuaEngine()

    extensions = bootstrap_extensions(engine, DebugSession())

    assert [_get_plugin_metadata(plugins, extension).filename for extension in extensions] == ["10-first.py"]
    result = engine.execute("return {first = firstValue(), second_absent = secondValue == nil}")
    assert result["results"]["return"] == {"first": 1, "second_absent": True}
    assert engine._function_registry == {"firstValue": "duplicate"}
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="20-second.py",
        declared_name="duplicate",
    )


def test_earlier_filename_wins_function_mapping_collision(tmp_path, monkeypatch, captured_diagnostics):
    _write_plugin(tmp_path, "10-first.py", "first", 'return {"sharedValue": lambda: 1}')
    _write_plugin(
        tmp_path,
        "20-second.py",
        "second",
        'return {"secondOnly": lambda: 2, "sharedValue": lambda: 3}',
    )
    plugins = load_plugins(tmp_path)
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: plugins)
    engine = MemscopeLuaEngine()

    extensions = bootstrap_extensions(engine, DebugSession())

    assert [extension.name for extension in extensions] == ["first"]
    result = engine.execute("return {shared = sharedValue(), second_absent = secondOnly == nil}")
    assert result["results"]["return"] == {"shared": 1, "second_absent": True}
    assert engine._function_registry == {"sharedValue": "first"}
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="20-second.py",
        declared_name="second",
    )


def test_existing_lifecycle_name_collision_skips_plugin_without_replacing_callback(
    tmp_path,
    monkeypatch,
    captured_diagnostics,
):
    source = _plugin_source("reserved", "return {}")
    source = source.replace(
        "    def register(self, ctx: ExtensionContext):\n        return {}\n",
        "    def register(self, ctx: ExtensionContext):\n        return {}\n"
        "\n    def on_process_attached(self, session):\n        raise AssertionError('must remain isolated')\n",
    )
    (tmp_path / "10-reserved.py").write_text(source, encoding="utf-8")
    plugins = load_plugins(tmp_path)
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: plugins)
    session = DebugSession()
    calls: list[str] = []
    session.register_on_attach("reserved", lambda _session: calls.append("existing"))

    assert bootstrap_extensions(MemscopeLuaEngine(), session) == []
    session._fire_attach()

    assert calls == ["existing"]
    _assert_diagnostic_pair(
        captured_diagnostics,
        code="PLUGIN_LOAD_FAILED",
        filename="10-reserved.py",
        declared_name="reserved",
    )


@pytest.mark.parametrize("failed_sink", ["stderr", "session_log"])
def test_diagnostic_sink_failure_does_not_promote_plugin_failure(
    tmp_path,
    monkeypatch,
    captured_diagnostics,
    failed_sink,
):
    _write_plugin(tmp_path, "10-bad.py", "bad", 'raise RuntimeError("ordinary failure")')
    plugins = load_plugins(tmp_path)
    assert len(plugins) == 1
    captured_diagnostics.clear()

    def fail(_record):
        raise OSError("sink unavailable")

    monkeypatch.setattr(diagnostics, f"_write_{failed_sink}_record", fail)
    monkeypatch.setattr(bootstrap_mod, "CORE_EXTENSIONS", ())
    monkeypatch.setattr(bootstrap_mod, "load_plugins", lambda: plugins)
    engine = MemscopeLuaEngine()
    session = DebugSession()

    assert bootstrap_extensions(engine, session) == []
    assert engine.bound_session is session
    assert [record["channel"] for record in captured_diagnostics] == [
        "session_log" if failed_sink == "stderr" else "stderr"
    ]
