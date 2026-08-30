# memscope-mcp

memscope-mcp is a Windows x64 process-memory MCP server for reverse engineering and live-process research. It exposes an 11-tool stdio surface over process discovery, attachment, typed memory access, scanning, Lua automation, saved scripts, inline hooks, and opt-in Python plugins.

The documentation is available at **[memscope.esrc.dev](https://memscope.esrc.dev/)**. Start with:

- [Install memscope-mcp](https://memscope.esrc.dev/get-started/install/)
- [Configure VS Code on Windows](https://memscope.esrc.dev/get-started/configure-client/)
- [Perform the first read](https://memscope.esrc.dev/get-started/first-session/)
- [Browse the generated MCP tool reference](https://memscope.esrc.dev/reference/mcp-tools/)

The server uses the Windows permissions granted to its process. Writes modify target memory. Lua can call native target functions and install hooks. Activated plugins load as Python at server startup. Session logs, saved scripts, and optional recordings persist under `MEMSCOPE_HOME`.

## Repository files

- [Contributing](CONTRIBUTING.md) — development setup, tests, documentation maintenance, and release checks.
- [Security policy](SECURITY.md) — intended selected-target behavior and private reporting for unintended defects.
- [Documentation site](site/) — Astro/Starlight content, build instructions, and the generated MCP tool reference.
- [Documentation URL map](docs/site-routes.md) — site URLs and their Markdown source files.
- [Architecture](https://memscope.esrc.dev/concepts/architecture/) — system overview.
- [Inline-hooking notes](docs/hooking.md) and [PEB notes](docs/peb.md) — repository implementation material.
- [Release history](https://github.com/Boti-Ormandi/memscope-mcp/releases) — version-specific GitHub Releases.

## Project links

- [Source repository](https://github.com/Boti-Ormandi/memscope-mcp)
- [Issues](https://github.com/Boti-Ormandi/memscope-mcp/issues)
- [MIT License](LICENSE)
