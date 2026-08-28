---
title: "CLI and paths"
description: "Console commands and exact MEMSCOPE_HOME data locations."
---

The `memscope-mcp` console command runs the server and inspects local data or bundled plugin sources. It does not change the MCP tool count.

## Commands

| Command | Behavior |
| --- | --- |
| `memscope-mcp` | Start the stdio server. |
| `memscope-mcp server` | Start the stdio server explicitly. |
| `memscope-mcp paths` | Print the resolved data-root, logs, scripts, and plugins directories. |
| `memscope-mcp list-plugins` | List bundled reference plugin names and summaries. |
| `memscope-mcp install-plugin <name>` | Copy one bundled plugin into the activated plugin directory without overwriting an existing file. |
| `memscope-mcp install-plugin <name> --force` | Explicitly overwrite the activated copy. |

`memscope-mcp version` prints the installed package version. Evergreen documentation does not use that output as a release-availability claim.

## Data-root resolution

Set `MEMSCOPE_HOME` before starting the server. The server resolves the configured path once at import/startup:

```powershell
$env:MEMSCOPE_HOME = Join-Path $env:TEMP "memscope-mcp-dev-home"
New-Item -ItemType Directory -Force $env:MEMSCOPE_HOME | Out-Null
memscope-mcp paths
```

When the variable is absent, the default is `~/.memscope-mcp` for the current Windows user. The exact resolved paths are:

```text
MEMSCOPE_HOME=<resolved data root>
LOGS_DIR=<resolved data root>\logs
SCRIPTS_DIR=<resolved data root>\scripts
PLUGINS_DIR=<resolved data root>\plugins
```

The server creates subdirectories lazily, except the session logger creates its session directory when the server starts.

## File layout

```text
$MEMSCOPE_HOME/logs/sessions/<session-id>.jsonl
$MEMSCOPE_HOME/scripts/<process>/<name>.lua
$MEMSCOPE_HOME/plugins/<activated-filename>.py
$MEMSCOPE_HOME/scripts/<process>/recordings/<name>.jsonl
$MEMSCOPE_HOME/scripts/<process>/recordings/<name>.jsonl.gz
```

`$MEMSCOPE_HOME` means the resolved data root; it is not a literal directory name. Saved scripts use the process namespace and the first line comment becomes the list description. Session logs contain bounded tool summaries and can contain sensitive paths or plugin diagnostics.

Netcap writes only below the canonical `$MEMSCOPE_HOME/scripts/<process>/recordings/` root. For reads, it can use the cwd-relative `scripts/<process>/recordings/` root as a containment-checked read-only legacy fallback. A canonical result shadows a legacy result with the same case-insensitive process and logical filename.

## Plugin installation boundary

`list-plugins` reads packaged files under `memscope_mcp/_contrib/plugins/`. `install-plugin` copies the selected source into `PLUGINS_DIR`. The runtime loader then scans only `PLUGINS_DIR/*.py` nonrecursively, in sorted filename order, excluding underscore-prefixed files. A package upgrade preserves both saved scripts and activated plugin copies; refresh requires `--force`.

See [Plugin overview](/plugins/overview/), [Plugin upgrading](/plugins/upgrading/), and [Netcap](/plugins/netcap/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/reference/cli-paths.md)
