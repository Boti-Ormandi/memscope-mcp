---
title: "Troubleshooting"
description: "Resolve startup, attach, memory, scan, Lua, plugin, and Netcap failures."
---

Use `memscope-mcp paths` to confirm `MEMSCOPE_HOME` and `LOGS_DIR`. It prints directories, not a session-log filename. Startup creates `LOGS_DIR\sessions\`, and the session JSONL file appears when the first event is logged. After a tool call, inspect the newest `LOGS_DIR\sessions\*.jsonl`; an `attach` result also includes the active `log_file` path. If the server fails before any tool call or logged event, use the MCP client's server diagnostics and captured stderr instead because no session file may exist. A session-specific `MEMSCOPE_HOME` keeps its logs and recordings separate from other runs.

## Server does not start

- Confirm Windows x64 and a 64-bit Python interpreter.
- Run `python -m pip show memscope-mcp` and `memscope-mcp paths` from the same environment.
- Start `memscope-mcp server` directly and inspect stderr.
- Confirm the MCP client launches the command with stdio and does not redirect stdout into a log.
- Check that the configured data root is writable and outside the repository.

## Attach fails

- Use `processes(filter="...", limit=...)` and select a live PID.
- Pass the exact name and PID to `attach` when names repeat.
- Check Windows permissions and x64 bitness.
- Use [Inspect before attach](/guides/inspect-before-attach/) to see whether query/read access works.
- A process can exit or change modules between discovery and attach; run discovery again.

## Reads, writes, or scans fail

- Resolve module-plus-offset expressions against the current snapshot.
- Confirm attachment with `isAttached()` or `getAttachedProcess()`.
- For writes, check page protection and use `verify=true` when appropriate.
- For scans, check strict `??` syntax, scope names, section existence, mode-specific fields, and status termination.
- A count is incomplete when `read_gaps_detected=true`, termination is `target_changed`, or the observation is `partial_traversal`.

## Lua fails

- Use `addr("0x...")` for large addresses.
- Use named scan options.
- Keep thread-local native attachment and dependent calls in one `callSequence`.
- Use `getLastError()` for helpers that return `nil`.
- Check the timeout and avoid unbounded loops.

## Plugin fails

Use [Plugin troubleshooting](/plugins/troubleshooting/). Confirm the direct activated path, filename order, imports, context fields, collisions, and structured diagnostic code. Do not restore raw runtime or global hook-manager access.

## Netcap fails

- Confirm an attached process has the required Winsock module/export.
- Start with `send`/`recv` and a small `max_packet_size`.
- Check ring-buffer capacity and capture drops with `captureStats()`.
- Use `header_only=true` when payload copying is unnecessary.
- Validate recording options before changing the root: `compress` must be an exact boolean and `max_size_mb` must be finite and positive.
- Check canonical `$MEMSCOPE_HOME/scripts/<process>/recordings/` before the read-only cwd-relative legacy root.
- A partial final JSONL line, invalid canonical entry, exact-case mismatch, alias, reparse point, or hard link fails closed instead of falling back.

See [Netcap](/plugins/netcap/), [Errors and status](/reference/errors-and-status/), and [Security model](/concepts/security-model/).
