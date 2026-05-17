# Contributing to memscope-mcp

Small focused PRs welcome. For anything large or speculative, open an issue first.

## Development setup

Windows x64 + Python 3.10+ are required. The `pymem` dependency is Windows-only and is skipped via an environment marker on other platforms; the package installs on macOS and Linux but `import memscope_mcp` raises `RuntimeError` there.

```bash
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
cd memscope-mcp
pip install -e ".[dev]"
pre-commit install
pytest
```

Pre-commit runs `ruff check --fix` and `ruff format` on every commit. CI runs the same checks plus the full pytest suite on Python 3.10 through 3.13.

### Dev workflow note: MEMSCOPE_HOME

By default, logs and saved Lua scripts land in `~/.memscope-mcp/`. If you want
artefacts to land next to the cloned repository instead, set `MEMSCOPE_HOME=$PWD`
in your shell before starting the server.

## Project layout

The top-level [README](README.md#architecture) has the full tree. The pieces you'll actually touch:

- [`memscope_mcp/server.py`](memscope_mcp/server.py) -- `@mcp.tool()` wrappers (one per MCP tool)
- [`memscope_mcp/tools/`](memscope_mcp/tools/) -- tool implementations (`memory.py`, `scanning.py`, `pointers.py`, `types.py`, `execute.py`, `hooking.py`, `lua_scripts.py`)
- [`memscope_mcp/tools/lua/`](memscope_mcp/tools/lua/) -- Lua engine (`engine.py`) plus themed function modules: `memory_read`, `memory_write`, `process_info`, `scanning_helpers`, `struct_helpers`, `modules`, `code_execution`, `comparisons`, `utilities`, `hooking`, `network`
- [`memscope_mcp/extensions/`](memscope_mcp/extensions/) -- `LuaExtension` ABC + bootstrap + the seven core extensions under `core/`
- [`memscope_mcp/utils/`](memscope_mcp/utils/) -- address parsing, heuristics, x64 shellcode (`shellcode.py`), instruction decoder + relocator (`disasm.py`), PE export resolver (`pe.py`), PEB reader (`peb.py`)
- [`memscope_mcp/instructions/base.py`](memscope_mcp/instructions/base.py) -- AI-facing Lua reference (token-priced, kept terse)
- [`docs/lua-reference.md`](docs/lua-reference.md) -- human-facing Lua reference (complete)
- [`docs/hooking.md`](docs/hooking.md) and [`docs/peb.md`](docs/peb.md) -- design docs for the hooking and PEB-introspection layers
- [`memscope_mcp/_contrib/plugins/`](memscope_mcp/_contrib/plugins/) -- bundled reference plugins (il2cpp, netcap)
- [`tests/`](tests/) -- pytest suite, smoke + unit + extension/hook/netcap/PEB coverage

## Adding an MCP tool

1. Implement in `memscope_mcp/tools/<your_tool>.py`. Follow patterns in `types.py` or `scanning.py`.
2. Wrap with `@mcp.tool()` in `memscope_mcp/server.py`. Call `_log()` so the tool call lands in session logs.
3. Keep the docstring terse — it becomes AI-facing context and costs tokens. List parameters, types, and return shape.
4. Update `tests/test_smoke.py`: add the tool name to `test_tool_names` and bump `test_tool_count`. This test pins the 10-tool surface; forgetting it makes the smoke test fail immediately.
5. Add the tool to the README tool table.

## Adding a Lua function

Lua functions live inside extensions. Pick the right extension first.

1. Pick the extension by category:
   - Reads -> `core/memory.py` (which dispatches to `tools/lua/memory_read.py`)
   - Writes -> `core/memory.py` (`tools/lua/memory_write.py`)
   - AOB / xref scans, module/address resolution -> `core/module_scan.py` (`tools/lua/scanning_helpers.py`, `tools/lua/modules.py`)
   - Vector / matrix / declarative struct reads, comparisons, bitwise, formatting -> `core/general.py` (`tools/lua/struct_helpers.py`, `tools/lua/comparisons.py`, `tools/lua/utilities.py`)
   - Remote calls and allocation -> `core/execution.py` (`tools/lua/code_execution.py`)
   - Pre-attach / PEB introspection -> `core/process.py` (`tools/lua/process_info.py`)
   - Hooking primitives -> `core/hooking.py` (`tools/lua/hooking.py`)
   - Network helpers -> `core/network.py` (`tools/lua/network.py`)
2. Add the function to the relevant `tools/lua/*.py` module (or directly to the extension if it is tightly scoped).
3. Add the Lua-name -> Python-callable mapping to the dict returned by the extension's `register(ctx)`.
4. Update the extension's `instructions` string with a one-line AI-facing description (token-priced, terse).
5. Document the function in [`docs/lua-reference.md`](docs/lua-reference.md) under the matching category and in [`memscope_mcp/instructions/base.py`](memscope_mcp/instructions/base.py) if a shared-guidance bullet is appropriate.
6. Conventions: return `nil` on failure (don't raise), accept addresses as int or hex string (use `parse_address`), and use `ctx.table_factory(...)` to build Lua-side return tables.

## Adding an extension

A core extension is appropriate when the functionality is generic enough to be useful on any target -- memory, scanning, hooking, process introspection. A user plugin (under `plugins/`) is the right shape when the functionality is target-specific.

1. Create `memscope_mcp/extensions/core/<your_ext>.py`. Subclass `LuaExtension` from `memscope_mcp/extensions/base.py`. Implement `name`, `description`, `instructions`, and `register(ctx)`. Override `on_process_attached` / `on_process_detaching` if the extension holds process-bound state (allocations, hooks).
2. Register the class in `memscope_mcp/extensions/core/__init__.py` -- import it and add it to `CORE_EXTENSIONS` in the right position (`General` first, the rest in the order the AI is likely to encounter them).
3. Hold cross-call state on the extension instance, not on `SESSION`.
4. If the extension introduces a new conceptual surface, write a short `docs/<topic>.md` design doc (see [`docs/hooking.md`](docs/hooking.md) and [`docs/peb.md`](docs/peb.md) for shape and tone) and link it from the README's Implementation Notes.
5. Add a test file under `tests/test_<your_ext>.py` covering the registration path and any non-trivial logic. `tests/test_extension_bootstrap.py` already pins ordering and the basic contract.

## Adding a plugin

The bundled reference plugins live under `memscope_mcp/_contrib/plugins/` and ship in the wheel. Users install them to `$MEMSCOPE_HOME/plugins/` (default `~/.memscope-mcp/plugins/`) via `memscope-mcp install-plugin <name>`; the loader picks up any `.py` file placed there. Reference plugins:

- [`memscope_mcp/_contrib/plugins/il2cpp.py`](memscope_mcp/_contrib/plugins/il2cpp.py) -- Unity IL2CPP runtime helpers; template for managed-runtime object walking.
- [`memscope_mcp/_contrib/plugins/netcap.py`](memscope_mcp/_contrib/plugins/netcap.py) -- Winsock capture and analysis built on the generic hooking layer; template for API-hooking + protocol parsing.

## Code style

Enforced by [ruff](https://docs.astral.sh/ruff/). Configuration in `pyproject.toml`:

- Line length 120
- Rules: E, F, W, I (pycodestyle, pyflakes, isort)
- E722 (bare `except`) is allowed: it's deliberate in memory-read paths where any failure means "return nil"
- Type hints on public function signatures
- Docstrings with Args/Returns on public functions

## Testing

The smoke suite (`tests/test_smoke.py`) is the gating invariant: it asserts the 10-tool surface, that the Lua engine initializes, that the plugin loader runs, and that the instructions builder produces output. Most regressions show up here first.

Unit tests live next to features (`test_types.py`, `test_scanning.py`, `test_lua_engine.py`, etc.). Hooking and netcap have dedicated coverage in `test_disasm.py`, `test_relocation.py`, `test_hook_shellcode.py`, `test_ring_buffer.py`, `test_pe_exports.py`, `test_thread_suspension.py`, `test_netcap_plugin.py`, `test_netcap_lifecycle.py`, `test_netcap_udp.py`, `test_netcap_wsa.py`, `test_stream_assembly.py`, `test_protocol_framing.py`, `test_filter_packets.py`, `test_header_only.py`, `test_deref_args.py`, `test_phase5_hardening.py`, `test_cross_reference.py`, `test_session_recording.py`. The extension bootstrap is pinned by `test_extension_bootstrap.py`. PEB reading is covered by `test_peb.py` (self-process tests run in CI; explorer.exe-dependent tests skip gracefully when explorer is not running). Run a focused subset with `pytest -k <pattern>`.

`tests/conftest.py` imports `memscope_mcp.server` once at collection time so the extension bootstrap runs before any test resolves a Lua function. If a new test needs the Lua surface initialized, it relies on this import side-effect -- nothing else is required.

There's no live-process integration test -- pymem can't attach to anything useful in a clean GitHub Actions runner, so verifying tool behavior against a real target stays manual.

## PR checklist

- `ruff check` and `ruff format --check` pass
- `pytest` passes locally on Windows
- README tool table updated if you added or removed an MCP tool
- New Lua functions documented in the relevant extension's `instructions` string and in `docs/lua-reference.md`
- New conceptual surface (a new extension category, a new design pattern) gets a short `docs/<topic>.md`
- One logical change per commit; PR description explains the what and the why

## License

By contributing, you agree your contributions will be licensed under the MIT License.
