---
title: "Permissions and local data"
description: "Understand Windows permissions, MEMSCOPE_HOME, logs, scripts, plugins, and recordings."
---

Windows permissions and the local data root are separate boundaries. A successful server start does not grant access to every target operation, and local artifacts can contain sensitive process data.

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

---

[Source: getting-started guide](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/getting-started.md#data-and-permissions)
