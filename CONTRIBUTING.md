# Contributing to memscope-mcp

Keep changes focused and document end-user behavior in the Astro/Starlight site under `site/src/content/docs/`. Open an issue before a large or speculative change.

## Development setup

Use Windows x64 with 64-bit Python 3.10 or newer. Install the editable package and development dependencies:

```powershell
git clone https://github.com/Boti-Ormandi/memscope-mcp.git
Set-Location memscope-mcp
python -m pip install -e ".[dev]"
pre-commit install
```

Point runtime data outside the checkout:

```powershell
$env:MEMSCOPE_HOME = Join-Path $env:TEMP ("memscope-mcp-dev-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $env:MEMSCOPE_HOME | Out-Null
memscope-mcp paths
```

Activated files under `$MEMSCOPE_HOME\plugins` execute as Python when the server starts. Logs, scripts, plugins, and recordings persist under the selected root.

## Python checks

Run the narrowest affected tests first, then the full repository checks:

```powershell
ruff check
ruff format --check
pytest tests/ -v
```

The test matrix covers Python 3.10 through 3.14 on Windows. Interface, compatibility, and serialized-format changes require focused tests and matching documentation.

## Documentation site

The site requires Node.js 22.12 or newer. CI and local checks install the versions recorded in `site/package-lock.json`:

```powershell
Set-Location site
npm ci
npx playwright install chromium
npm run check
```

`npm run check` performs the installed-wheel tool snapshot comparison, type checking, a production build, static contract tests, and Playwright browser/accessibility tests. The wheel check builds the current tree, installs that wheel into a temporary virtual environment, loads its exact 11-tool registration, and compares names, descriptions, input schemas, and output schemas with `site/tools.json`.

After changing the runtime tool contract, regenerate the installed-wheel snapshot and tool reference:

```powershell
npm run tools:snapshot:update
npm run check
```

The update command replaces the tool array in `site/tools.json` from an installed built wheel and renders `site/src/content/docs/reference/mcp-tools/index.md`. Do not hand-edit generated tool sections.

## Documentation files

- Write end-user procedures and reference content in `site/src/content/docs/**`.
- Update `site/tools.json` through `npm run tools:snapshot:update`; it generates the MCP tool reference.
- Keep `README.md` as a concise repository introduction.
- Keep root `docs/**` for implementation notes and the documentation URL map, not end-user procedures.
- Keep vulnerability-reporting instructions in `SECURITY.md`.
- Record version-specific history in [GitHub Releases](https://github.com/Boti-Ormandi/memscope-mcp/releases).

When a documentation URL changes, update `docs/site-routes.md`, navigation, site checks, and route/link tests together.

## Plugins

Plugins subclass `PluginBase`, register a complete Lua mapping through `ExtensionContext`, keep process-bound state on the plugin instance, and release target resources during detach. See [plugin authoring](https://memscope.esrc.dev/plugins/authoring/), [lifecycle](https://memscope.esrc.dev/plugins/lifecycle-and-contract/), and the [API reference](https://memscope.esrc.dev/reference/plugin-api/).

## Release checks

Pull requests and main-branch updates must pass the Python lint/tests and the site checks. The release workflow repeats the Windows Python matrix before building distribution artifacts; the site workflow runs separately for pull requests and main-branch updates.

## License

Contributions are licensed under the [MIT License](LICENSE).
