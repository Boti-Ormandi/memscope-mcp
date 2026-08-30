---
title: "Contribute"
description: "Set up Windows development and run the Python and site checks."
---

Use Windows x64, 64-bit Python 3.10 or newer, and Node.js 22.12 or newer. See [`CONTRIBUTING.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/CONTRIBUTING.md) for the full contributor instructions.

## Python setup and checks

```powershell
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
Set-Location memscope-mcp
python -m pip install -e ".[dev]"
ruff check
ruff format --check
pytest tests/ -v
```

Use a separate runtime data root:

```powershell
$env:MEMSCOPE_HOME = Join-Path $env:TEMP ("memscope-mcp-dev-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $env:MEMSCOPE_HOME | Out-Null
memscope-mcp paths
```

Logs, saved scripts, activated plugin files, and recordings persist under that root. Activated plugin files execute as Python when a server starts with the same root.

## Site setup and checks

```powershell
Set-Location site
npm ci
npx playwright install chromium
npm run check
```

The site check builds and installs the current Python wheel, compares its exact 11-tool contract with `site/tools.json`, checks generated Markdown, typechecks/builds Astro, and runs static plus browser/accessibility tests.

After changing the MCP tool interface, regenerate the installed-wheel snapshot and tool reference:

```powershell
npm run tools:snapshot:update
npm run check
```

## Documentation files

- Write end-user procedures and reference content in `site/src/content/docs/**`.
- Update `site/tools.json` through `npm run tools:snapshot:update`; it generates the MCP tool page.
- Keep `README.md` as a short introduction for repository visitors.
- Keep root `docs/**` for implementation notes and the documentation URL map.
- Keep vulnerability-reporting instructions in `SECURITY.md`.
- Record version-specific history in [GitHub Releases](https://github.com/Boti-Ormandi/memscope-mcp/releases).

When a documentation URL changes, update [the URL map](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/site-routes.md), navigation, site checks, and route/link tests together.

## Source areas

- [`memscope_mcp/server.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/server.py) — MCP registration and stdio entry.
- [`memscope_mcp/scanning/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/scanning) — strict scan contracts and execution.
- [`memscope_mcp/extensions/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/extensions) — core Lua composition.
- [`memscope_mcp/_contrib/plugins/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/memscope_mcp/_contrib/plugins) — bundled plugin sources.
- [`tests/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/tests) — Python behavioral coverage.
- [`site/`](https://github.com/Boti-Ormandi/memscope-mcp/tree/main/site) — documentation source, build, and tests.
