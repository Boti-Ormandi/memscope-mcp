"""Strict structured diagnostics for isolated user-plugin failures."""

from __future__ import annotations

import dis
import json
import sys
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..extensions.base import ExtensionContext

_SCHEMA_NAME = "memscope-plugin-diagnostic/v1"
_GUIDANCE_URL = "https://memscope.esrc.dev/plugins/upgrading/"
_REQUIRED_CONTEXT_FIELDS = ("ctx.session", "ctx.table_factory", "ctx.hook_manager")
SCHEMA_NAME = _SCHEMA_NAME
GUIDANCE_URL = _GUIDANCE_URL
REQUIRED_CONTEXT_FIELDS = _REQUIRED_CONTEXT_FIELDS

_MAX_CAUSE_TYPE_CHARS = 128
_MAX_CAUSE_MESSAGE_CHARS = 512
_RECOGNIZED_CONTEXT_MESSAGE = (
    "Plugin uses a removed Lua runtime or hook-manager global; migrate to the required ExtensionContext fields."
)
_REDACTED_CAUSE_MESSAGE = "Plugin failure details are not included; inspect the activated plugin locally."
_SAFE_CAUSE_TYPES = frozenset(
    {
        "AttributeError",
        "Exception",
        "FileNotFoundError",
        "ImportError",
        "ModuleNotFoundError",
        "OSError",
        "PermissionError",
        "RecursionError",
        "RuntimeError",
        "SyntaxError",
        "TypeError",
        "ValueError",
    }
)


class _StrictDiagnosticModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PluginIdentity(_StrictDiagnosticModel):
    filename: str = Field(min_length=1, max_length=255)
    declared_name: str | None = Field(min_length=1, max_length=255)

    @field_validator("filename")
    @classmethod
    def _require_basename(cls, value: str) -> str:
        if value in {".", ".."} or any(separator in value for separator in ("/", "\\", ":")):
            raise ValueError("plugin filename must be a basename")
        return value


class PluginCause(_StrictDiagnosticModel):
    type: str = Field(min_length=1, max_length=_MAX_CAUSE_TYPE_CHARS)
    message: str = Field(min_length=1, max_length=_MAX_CAUSE_MESSAGE_CHARS)


class PluginGuidance(_StrictDiagnosticModel):
    url: Literal["https://memscope.esrc.dev/plugins/upgrading/"]
    required_context_fields: list[str]

    @model_validator(mode="after")
    def _require_exact_context_fields(self) -> PluginGuidance:
        if tuple(self.required_context_fields) != _REQUIRED_CONTEXT_FIELDS:
            raise ValueError("required_context_fields must match the supported ordered context contract")
        return self


class PluginDiagnostic(_StrictDiagnosticModel):
    schema_name: Literal["memscope-plugin-diagnostic/v1"] = Field(alias="schema")
    severity: Literal["warning"]
    code: Literal["PLUGIN_LOAD_FAILED", "PLUGIN_CONTEXT_INCOMPATIBLE"]
    plugin: PluginIdentity
    cause: PluginCause
    guidance: PluginGuidance
    channel: Literal["stderr", "session_log"]


def validate_plugin_diagnostic(value: object) -> dict[str, object]:
    """Strictly validate and normalize one diagnostic record."""

    return PluginDiagnostic.model_validate(value).model_dump(mode="json", by_alias=True)


def serialize_plugin_diagnostic(value: object) -> str:
    """Return one compact UTF-8-safe JSON record with no physical newline."""

    record = validate_plugin_diagnostic(value)
    return json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def classify_plugin_failure(exc: Exception) -> Literal["PLUGIN_LOAD_FAILED", "PLUGIN_CONTEXT_INCOMPATIBLE"]:
    """Classify only structural failures from removed plugin context APIs."""

    try:
        if isinstance(exc, AttributeError):
            if exc.name == "lua" and _is_removed_lua_owner(exc.obj):
                return "PLUGIN_CONTEXT_INCOMPATIBLE"
            if exc.name == "HOOK_MANAGER" and _is_hooking_module(exc.obj):
                return "PLUGIN_CONTEXT_INCOMPATIBLE"

        if (
            isinstance(exc, ImportError)
            and exc.name == "memscope_mcp.tools.hooking"
            and _missing_import_symbol(exc) == "HOOK_MANAGER"
        ):
            return "PLUGIN_CONTEXT_INCOMPATIBLE"
    except Exception:
        pass

    return "PLUGIN_LOAD_FAILED"


def emit_plugin_failure(
    *,
    filename: str,
    declared_name: str | None,
    exc: Exception,
    source_path: Path | None = None,
) -> None:
    """Attempt one record on stderr and then one in the session log."""

    code = classify_plugin_failure(exc)
    cause_message = (
        _RECOGNIZED_CONTEXT_MESSAGE
        if code == "PLUGIN_CONTEXT_INCOMPATIBLE"
        else sanitize_cause_message(exc, source_path=source_path)
    )
    common = {
        "schema": _SCHEMA_NAME,
        "severity": "warning",
        "code": code,
        "plugin": {
            "filename": _safe_filename(filename),
            "declared_name": _safe_declared_name(declared_name),
        },
        "cause": {
            "type": _safe_cause_type(exc),
            "message": cause_message,
        },
        "guidance": {
            "url": _GUIDANCE_URL,
            "required_context_fields": list(_REQUIRED_CONTEXT_FIELDS),
        },
    }

    for channel, sink in (
        ("stderr", _write_stderr_record),
        ("session_log", _write_session_log_record),
    ):
        try:
            sink(validate_plugin_diagnostic({**common, "channel": channel}))
        except Exception:
            pass


def sanitize_cause_message(exc: Exception, *, source_path: Path | None = None) -> str:
    """Return a bounded message that cannot disclose plugin-controlled text."""

    del exc, source_path
    return _REDACTED_CAUSE_MESSAGE


def _is_removed_lua_owner(value: object) -> bool:
    if value is ExtensionContext or isinstance(value, ExtensionContext):
        return True

    try:
        from ..tools.lua.engine import MemscopeLuaEngine
    except Exception:
        return False
    return value is MemscopeLuaEngine or isinstance(value, MemscopeLuaEngine)


def _is_hooking_module(value: object) -> bool:
    if not isinstance(value, types.ModuleType) or value.__name__ != "memscope_mcp.tools.hooking":
        return False
    try:
        from ..tools import hooking
    except Exception:
        return False
    return value is hooking


def _missing_import_symbol(exc: ImportError) -> str | None:
    traceback = exc.__traceback__
    while traceback is not None:
        instruction = next(
            (item for item in dis.get_instructions(traceback.tb_frame.f_code) if item.offset == traceback.tb_lasti),
            None,
        )
        if instruction is not None and instruction.opname == "IMPORT_FROM":
            return instruction.argval if isinstance(instruction.argval, str) else None
        traceback = traceback.tb_next
    return None


def _safe_filename(filename: str) -> str:
    if not isinstance(filename, str):
        return "unknown.py"
    name = Path(_clean_utf8(filename)).name
    if not name or name in {".", ".."}:
        return "unknown.py"
    return name[:255]


def _safe_declared_name(value: object) -> str | None:
    if not isinstance(value, str) or str.__len__(value) == 0:
        return None
    return _clean_utf8(value)[:255]


def _clean_utf8(value: str) -> str:
    encoded = str.encode(value, "utf-8", errors="replace")
    return bytes.decode(encoded, "utf-8").replace("\u2028", " ").replace("\u2029", " ")


def _safe_cause_type(exc: Exception) -> str:
    try:
        name = _clean_utf8(type(exc).__name__)
        if name in _SAFE_CAUSE_TYPES and len(name) <= _MAX_CAUSE_TYPE_CHARS:
            return name
    except Exception:
        pass
    return "Exception"


def _write_stderr_record(record: Mapping[str, object]) -> None:
    line = (serialize_plugin_diagnostic(record) + "\n").encode("utf-8")
    buffer = getattr(sys.stderr, "buffer", None)
    if buffer is not None:
        buffer.write(line)
        buffer.flush()
        return
    sys.stderr.write(line.decode("utf-8"))
    sys.stderr.flush()


def _write_session_log_record(record: Mapping[str, object]) -> None:
    from ..utils.logger import LOGGER

    LOGGER._append_raw_event(validate_plugin_diagnostic(record))
