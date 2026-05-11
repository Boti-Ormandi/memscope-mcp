# memscope-mcp

Windows-only MCP server for low-level memory research and reverse engineering. Python 3.10+, 10 MCP tools, embedded Lua 5.4 engine, generic inline hooking with shared ring buffer, PEB introspection without attaching.

See @README.md for the project overview, @CONTRIBUTING.md for the contribution flow, @docs/hooking.md and @docs/peb.md for the two non-trivial subsystems, @docs/lua-reference.md for the full Lua surface, @plugins/README.md for the plugin interface.

## Commands

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ contrib/ tests/
ruff format --check src/ contrib/ tests/
```

Pre-commit hooks run ruff on every commit. Config lives in `pyproject.toml` (line length 120).

## Project structure

```
src/
  server.py          # MCP tool definitions (thin wrappers), entry point
  session.py         # Attach/detach, memory primitives, threads, VirtualProtect,
                     #   allocate_near, suspend/resume, lifecycle callbacks
  extensions/        # LuaExtension ABC + bootstrap
    base.py          # LuaExtension, ExtensionContext
    bootstrap.py     # Core extension + user plugin registration
    core/            # Always-loaded: general, memory, module_scan, execution,
                     #   hooking, process, network
  tools/
    server-side tool implementations + `hooking.py` (HookManager)
    lua/             # Lua-callable function modules
  utils/
    shellcode.py     # x64 codegen (native calls + hook trampolines)
    disasm.py        # Table-driven x64 length decoder + RIP-relative relocation
    pe.py            # PE export resolution (resolveExport)
    peb.py           # PEB reader: cmdline, env, debugger, remote modules
  plugins/           # PluginBase (LuaExtension specialization) + loader
  instructions/      # AI context builder (base + extensions + plugins)
contrib/plugins/     # Reference plugins (il2cpp, netcap)
plugins/             # Active plugins (gitignored, user copies from contrib/)
scripts/             # Saved Lua scripts per process (gitignored)
logs/                # Session logs in JSONL (gitignored)
docs/                # hooking.md, peb.md, lua-reference.md
tests/               # pytest suite
```

## Architecture rules

- **Generic core, plugins for domains.** No domain-specific code in `src/`. Game/engine helpers go in `contrib/plugins/`; users activate by copying to `plugins/`.
- **One contract, two activation paths.** Core features and plugins both implement `LuaExtension` (`src/extensions/base.py`). Core extensions are always loaded and registration failure is hard; plugins are user-curated, loaded only when their file is in `plugins/`, and isolated on failure.
- **10 MCP tools, locked.** Everything new goes through Lua. `tests/test_smoke.py::test_tool_count` pins the count. Adding an MCP tool requires explicit justification.
- **Lua for complexity.** Simple typed reads use MCP tools. Loops, conditionals, multi-step chains go in Lua.
- **Scripts persist, addresses don't.** ASLR invalidates addresses every restart. Save the finder, not the address.
- **AI context is expensive.** `src/instructions/base.py` is always loaded; per-extension `instructions` fragments are appended in registration order. Keep both terse.

## Hooking and PEB invariants

- Hooks require an attached process. PEB reads do not.
- Hook installation prefers a +-2 GiB trampoline allocation so a 5-byte `JMP rel32` patch suffices. Falls back to a 14-byte `JMP [RIP+0]` with thread-suspension + IP redirect when near allocation fails.
- The shared ring buffer is allocated lazily by `createRingBuffer`. `destroyRingBuffer` refuses while hooks are still installed.
- Hook removal restores the saved prologue but defers trampoline free until `cleanup()` (called from `on_process_detaching` and from server shutdown). A thread may still be inside the trampoline at the moment of unhook.
- `_safe_patch` in `HookManager` is the only writer for 14-byte patches; it suspends every thread, redirects RIPs in the danger zone, writes, and resumes. Do not patch 14 bytes outside this path.
- The PEB reader (`src/utils/peb.py`) opens and closes its own handle per call. No state, no leaks.
- PEB reads truncate silently: environment block 64 KiB, module list 1024 entries, individual wide strings 32 KiB.

## Code conventions

- Delete unused code; no dead functions.
- `bare except` is deliberate in memory-read paths (any failure means "return nil"); ruff E722 is suppressed.
- Lua functions return `nil` on failure rather than raising.
- Addresses accept ints, hex strings (`"0x7FF6A0010000"`), and module+offset (`"module.dll+0x123"`). Use `parse_address` from `src/utils/memory_utils.py`.
- Lua-side return tables are built with `ctx.table_factory(...)` inside extensions, or `engine.lua.table()` outside.

## Key files

- `src/server.py` -- MCP tool definitions, shutdown handler with hook cleanup
- `src/extensions/bootstrap.py` -- the registration spine
- `src/extensions/core/__init__.py` -- `CORE_EXTENSIONS` ordering
- `src/tools/hooking.py` -- HookManager (ring buffer + install/remove/cleanup)
- `src/tools/lua/engine.py` -- `MemscopeLuaEngine`, per-execution state
- `tests/test_smoke.py` -- the pinned 10-tool surface; first regression catcher
- `tests/test_extension_bootstrap.py` -- pins extension ordering and registration contract
- `tests/conftest.py` -- imports `src.server` so bootstrap runs before any test collects

## Gotchas

- Windows-only (pymem wraps Win32). Tests run on Windows GitHub Actions runners; nothing here works on Linux/macOS.
- Module bases cached on `attach` -- the auto-reconnect path re-caches transparently on transient restart.
- Large Lua hex literals (>32-bit) cause parse errors. The engine preprocessor rewrites them, but explicit `addr("0x...")` is safer in user-edited scripts.
- All MCP tool calls log to `logs/sessions/<timestamp>.jsonl`. Useful for diagnosing what the agent actually called.
- The netcap plugin (`contrib/plugins/netcap.py`) is *not* a core extension. It is the reference plugin built on the hooking primitives. Don't import it from `src/`.
