---
title: "Contribute"
description: "Set up a Windows development environment and contribute focused changes."
---

Contributions target Windows reverse engineers, live-process researchers, native Windows users, and MCP integrators. Keep changes focused, document the user-facing contract, and open an issue before a large or speculative change.

## Development setup

Use a Windows x64 checkout with 64-bit Python 3.10 or newer. The `pymem` dependency is Windows-specific. Create a virtual environment if the project workflow uses one, then install the editable package with development dependencies:

```powershell
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
Set-Location memscope-mcp
python -m pip install -e ".[dev]"
pre-commit install
```

Run the focused gates from the repository root:

```powershell
pytest tests/ -v
ruff check memscope_mcp/ tests/ benchmarks/
ruff format --check memscope_mcp/ tests/ benchmarks/
```

Pre-commit runs the configured Ruff checks and formatting. CI runs the same style checks and the test suite on the supported Python versions.

### Use a disposable data root

Point `MEMSCOPE_HOME` outside the checkout so logs, scripts, plugins, and recordings stay out of the repository:

```powershell
$env:MEMSCOPE_HOME = Join-Path $env:TEMP "memscope-mcp-dev-home"
New-Item -ItemType Directory -Force $env:MEMSCOPE_HOME | Out-Null
memscope-mcp paths
```

Use a fresh temporary root for tests that exercise plugin activation or Netcap recording. Remove the temporary root only after confirming it contains no data you need.

## Repository layout

- [`memscope_mcp/server.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/server.py) — the 11 MCP tool registrations and stdio entry point.
- [`memscope_mcp/boundary.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/boundary.py) — strict scan-model MCP boundary.
- [`memscope_mcp/session.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/session.py) — process attachment, module snapshots, leases, lifecycle, and target memory primitives.
- [`memscope_mcp/scanning/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/scanning) — strict scan contracts and bounded execution internals.
- [`memscope_mcp/tools/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/tools) — typed memory, dumps, pointer chains, Lua execution, scripts, and hooks.
- [`memscope_mcp/extensions/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/extensions) — `LuaExtension`, bootstrap, and the seven core extensions.
- [`memscope_mcp/_contrib/plugins/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/_contrib/plugins) — bundled reference plugin sources.
- [`docs/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/docs) — evergreen human-facing product content and reference material.
- [`tests/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/tests) — unit, smoke, extension, hook, scan, and plugin coverage.

The complete navigation and source-of-truth boundaries are in [`docs/architecture.md`](/concepts/architecture/) and [`docs/site-routes.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/site-routes.md).

## Adding an MCP tool

The public MCP surface is intentionally exactly 11 tools. A new tool changes that contract and requires an explicit product decision. For an accepted tool change:

1. Implement the behavior under `memscope_mcp/tools/` or the strict scan boundary.
2. Register the wrapper in [`memscope_mcp/server.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/server.py) and keep the business function synchronous unless the boundary requires otherwise.
3. Keep the tool description and result envelope precise.
4. Update smoke coverage for the tool name and count.
5. Update [`README.md`](/) and [`docs/reference/mcp-tools.md`](/reference/mcp-tools/).
6. Add task-first and reference documentation without creating a second conflicting full contract.

## Adding Lua functions or a core extension

Lua functions belong to the appropriate core extension. Use the registration contract in [`docs/reference/plugin-api.md`](/reference/plugin-api/) and the full [Lua reference](/reference/lua/). Keep state on the extension instance or the session-owned object that owns it; do not introduce module-level session or hook-manager globals.

A core extension normally requires:

1. a `LuaExtension` implementation under `memscope_mcp/extensions/core/`;
2. registration in `CORE_EXTENSIONS` with deliberate ordering;
3. focused tests under `tests/`;
4. a concise AI-facing instruction fragment; and
5. human documentation linked from the relevant guide or reference page.

## Adding a plugin

Plugins are activated Python files, not automatically loaded package modules. Subclass `PluginBase`, implement `name`, `description`, `instructions`, and `register(ctx)`, and use the supported context fields `ctx.session`, `ctx.table_factory`, and `ctx.hook_manager`. Keep plugin state on the instance and use lifecycle callbacks for process-bound resources.

Start with:

- [Plugin authoring](/plugins/authoring/)
- [Plugin lifecycle](/plugins/lifecycle-and-contract/)
- [Plugin API reference](/reference/plugin-api/)
- [Netcap](/plugins/netcap/) as a filesystem and hook example
- [IL2CPP](/plugins/il2cpp/) as a session-bound structure-reader example

Add tests for activation ordering, failure isolation, context ownership, lifecycle cleanup, and every durable file behavior. Use a disposable `MEMSCOPE_HOME`; never activate a test plugin from the repository's real data location.

## Documentation and compatibility

Write in present tense and describe current behavior only. Keep the exact 11-tool surface, `openProcess`, `DebugSession.modules`, plugin activation boundary, scan contract, and Netcap recording rules aligned with source and tests. Use relative links for repository content and keep canonical site routes aligned with [`docs/site-routes.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/site-routes.md).

Retained compatibility facts belong in [`docs/support/compatibility.md`](/support/compatibility/). Version-specific change notes belong in the project release materials, not in evergreen README or reference pages.

## Testing expectations

The smoke suite checks imports, the 11-tool registration, Lua initialization, plugin loading, and instruction construction. Focused tests cover typed memory, scan contracts, lifecycle, hooks, PEB reads, plugins, and Netcap. Run the narrowest affected tests first, then the full suite on Windows before requesting review.

Before requesting review, run the appropriate full Windows test suite and report any scoped failures with their causes.

## Release mechanics

Maintainers review source, tests, documentation, dependency metadata, and generated distribution checks as one change. They verify a clean tree, run the required gates, prepare release notes separately from evergreen docs, and use the project's authenticated publication process. Contributors do not add credentials, publication configuration, release bodies, or package/site administration to a feature change.

## License

By contributing, you agree that your contributions are licensed under the MIT License.

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/CONTRIBUTING.md)
