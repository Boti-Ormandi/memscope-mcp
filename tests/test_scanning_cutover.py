"""Static clean-break assertions for the registered scanning surfaces."""

from pathlib import Path

from memscope_mcp.extensions.core.module_scan import ModuleScanExtension
from memscope_mcp.tools.lua.engine import LUA_ENGINE

ROOT = Path(__file__).parents[1]
PRODUCTION = ROOT / "memscope_mcp"

REMOVED_RUNTIME_TERMS = {
    "AOBScanModule",
    "scan_aob_addresses",
    "scan_references",
    "summary_only",
    "return_offset",
    "error_detail",
    "source_error",
    "scanning_helpers",
    "utils.pattern",
}


def _production_text() -> str:
    parts = []
    for path in sorted(PRODUCTION.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def test_removed_scanner_modules_are_deleted():
    assert not (PRODUCTION / "tools" / "scanning.py").exists()
    assert not (PRODUCTION / "tools" / "lua" / "scanning_helpers.py").exists()
    assert not (PRODUCTION / "utils" / "pattern.py").exists()


def test_removed_runtime_terms_do_not_survive_in_production_python():
    production = _production_text()

    for term in REMOVED_RUNTIME_TERMS:
        assert term not in production


def test_core_scan_instructions_teach_only_named_scan_options():
    instructions = ModuleScanExtension.instructions

    assert "AOBScan(pattern, options?)" in instructions
    assert "AOBScanMany(patterns, options?)" in instructions
    assert "scanString(text, options?)" in instructions
    assert "scanPointer(target, options?)" in instructions
    assert "Expected failures return `nil, error_table`" in instructions
    assert "AOBScanModule" not in instructions
    assert "start?, end?, limit?" not in instructions


def test_lua_registry_has_only_the_four_scan_helpers():
    globals_table = LUA_ENGINE.lua.globals()

    assert globals_table["AOBScan"] is not None
    assert globals_table["AOBScanMany"] is not None
    assert globals_table["scanString"] is not None
    assert globals_table["scanPointer"] is not None
    assert globals_table["AOBScanModule"] is None
