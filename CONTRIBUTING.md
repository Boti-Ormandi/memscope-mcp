# Contributing to memscope-mcp

Small focused PRs welcome. For anything large or speculative, open an issue first.

## Development setup

Windows x64 + Python 3.10+ are required. The `pymem` dependency is unconditional and Windows-only; the package will not install on macOS or Linux.

```bash
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
cd memscope-mcp
pip install -e ".[dev]"
pre-commit install
pytest
```

Pre-commit runs `ruff check --fix` and `ruff format` on every commit. CI runs the same checks plus the full pytest suite on Python 3.10 through 3.13.

## Project layout

The top-level [README](README.md#architecture) has the full tree. The pieces you'll actually touch:

- [`src/server.py`](src/server.py) — `@mcp.tool()` wrappers (one per MCP tool)
- [`src/tools/`](src/tools/) — tool implementations (`memory.py`, `scanning.py`, `pointers.py`, `types.py`, `execute.py`, `lua_scripts.py`)
- [`src/tools/lua/`](src/tools/lua/) — Lua engine (`engine.py`) plus nine themed function modules: `memory_read`, `memory_write`, `process_info`, `scanning_helpers`, `struct_helpers`, `modules`, `code_execution`, `comparisons`, `utilities`
- [`src/instructions/base.py`](src/instructions/base.py) — AI-facing Lua reference (token-priced, kept terse)
- [`docs/lua-reference.md`](docs/lua-reference.md) — human-facing Lua reference (complete)
- [`contrib/plugins/`](contrib/plugins/) — checked-in plugins users can activate by copying into `plugins/`
- [`tests/`](tests/) — pytest suite, smoke + unit

## Adding an MCP tool

1. Implement in `src/tools/<your_tool>.py`. Follow patterns in `types.py` or `scanning.py`.
2. Wrap with `@mcp.tool()` in `src/server.py`. Call `_log()` so the tool call lands in session logs.
3. Keep the docstring terse — it becomes AI-facing context and costs tokens. List parameters, types, and return shape.
4. Update `tests/test_smoke.py`: add the tool name to `test_tool_names` and bump `test_tool_count`. This test pins the 10-tool surface; forgetting it makes the smoke test fail immediately.
5. Add the tool to the README tool table.

## Adding a Lua function

1. Pick the module by category:
   - Reads → `memory_read.py`, writes → `memory_write.py`
   - AOB / xref scans → `scanning_helpers.py`
   - Vector / matrix / declarative struct reads → `struct_helpers.py`
   - Module-name and address resolution → `modules.py`
   - Remote calls and allocation → `code_execution.py`
   - Pre-attach introspection (processes, threads, regions, services) → `process_info.py`
   - 64-bit safe comparisons → `comparisons.py`
   - Bitwise, formatting, `addr()`, result helpers → `utilities.py`
2. Register the function in `MemscopeLuaEngine._register_functions` in `src/tools/lua/engine.py`.
3. Document it in both `src/instructions/base.py` (AI-facing, terse) and `docs/lua-reference.md` (human-facing, complete).
4. Conventions: return `nil` on failure (don't raise), accept addresses as int or hex string (use `parse_address`), and use `engine.lua.table(...)` to build Lua-side return tables.

## Adding a plugin

Plugins live in `plugins/` (gitignored for user-curated) and ship in `contrib/plugins/` (checked in, activate by copying). The interface, authoring guidelines, and a minimal example are in [`plugins/README.md`](plugins/README.md). The reference IL2CPP plugin in [`contrib/plugins/il2cpp.py`](contrib/plugins/il2cpp.py) is a real-world example.

## Code style

Enforced by [ruff](https://docs.astral.sh/ruff/). Configuration in `pyproject.toml`:

- Line length 120
- Rules: E, F, W, I (pycodestyle, pyflakes, isort)
- E722 (bare `except`) is allowed: it's deliberate in memory-read paths where any failure means "return nil"
- Type hints on public function signatures
- Docstrings with Args/Returns on public functions

## Testing

The smoke suite (`tests/test_smoke.py`) is the gating invariant: it asserts the 10-tool surface, that the Lua engine initializes, that the plugin loader runs, and that the instructions builder produces output. Most regressions show up here first.

Unit tests live next to features (`test_types.py`, `test_scanning.py`, `test_lua_engine.py`, etc.). Run a focused subset with `pytest -k <pattern>`.

There's no live-process integration test — pymem can't attach to anything useful in a clean GitHub Actions runner, so verifying tool behavior against a real target stays manual.

## PR checklist

- `ruff check` and `ruff format --check` pass
- `pytest` passes locally on Windows
- README tool table updated if you added or removed an MCP tool
- New Lua functions documented in both `src/instructions/base.py` and `docs/lua-reference.md`
- One logical change per commit; PR description explains the what and the why

## License

By contributing, you agree your contributions will be licensed under the MIT License.
