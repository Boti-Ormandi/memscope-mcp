---
title: "Permissions and local data"
description: "Understand Windows permissions, MEMSCOPE_HOME, logs, scripts, plugins, and recordings."
---

Memscope uses the Windows permissions of the server process, so a successful server start does not grant access to every target operation. Its local data can contain process paths, diagnostics, scripts, captured buffers, and recordings.

## Windows access checks

The selected process can deny query, VM-read, VM-write, thread, or debug-related operations.

## Set a disposable data root

The default data root is `~/.memscope-mcp`. Set `MEMSCOPE_HOME` before server startup to relocate it:

```powershell
$env:MEMSCOPE_HOME = Join-Path $env:TEMP "memscope-mcp-session"
New-Item -ItemType Directory -Force $env:MEMSCOPE_HOME | Out-Null
memscope-mcp paths
```

The server uses these subdirectories:

- `logs/sessions/<session-id>.jsonl` for bounded session events and plugin diagnostics;
- `scripts/<process>/<name>.lua` for saved Lua scripts; and
- `plugins/<filename>.py` for explicitly activated plugin files.

Netcap recordings use `$MEMSCOPE_HOME/scripts/<process>/recordings/`. The cwd-relative `scripts/<process>/recordings/` path is a read-only legacy fallback.
