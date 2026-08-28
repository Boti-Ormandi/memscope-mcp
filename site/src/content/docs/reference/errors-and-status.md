---
title: "Errors and status"
description: "Structured failures, scan termination, Lua cancellation, and plugin diagnostics."
---

Most MCP and Lua operations return structured data instead of relying on an uncaught exception. Read the operation's reference page for fields specific to that surface.

## Ordinary tool envelope

A successful ordinary wrapper usually includes `success: true`. An expected failure includes `success: false`, an error code, and a detail:

```json
{
  "success": false,
  "error": "NOT_ATTACHED",
  "detail": "Call attach first"
}
```

Common error families include `NOT_ATTACHED`/`PROCESS_NOT_ATTACHED`, `PROCESS_NOT_FOUND`, `INVALID_ADDRESS`, `ACCESS_VIOLATION`, `UNKNOWN_TYPE`, `WRITE_ERROR`, `MEMORY_NOT_WRITABLE`, `VERIFY_READ_FAILED`, `VERIFY_MISMATCH`, `INVALID_ACTION`, `SCRIPT_NOT_FOUND`, `PROCESS_MISMATCH`, `TIMEOUT`, `CANCELLED`, and `LUA_ERROR`. Exact fields vary by tool and remain in the source-backed references.

## Scan failure envelope

The strict `scan` and `scan_many` boundaries validate the raw request and return a flat application failure:

```json
{
  "success": false,
  "error": "INVALID_SCOPE",
  "detail": "Sections are valid only for module-based scopes",
  "field": "scope.filters.sections"
}
```

Stable scan error codes are:

- `INVALID_PATTERN`
- `INVALID_SCOPE`
- `INVALID_MODE`
- `INVALID_ARGUMENT`
- `MODULE_NOT_FOUND`
- `AMBIGUOUS_MODULE`
- `SECTION_NOT_FOUND`
- `PROCESS_NOT_ATTACHED`
- `INVALID_CURSOR`
- `CURSOR_STALE`
- `TARGET_CHANGED`
- `INTERNAL_SCAN_ERROR`

Expected Lua scan failures return `nil, error_table`. A valid no-match result is still a successful result with explicit status.

## Scan termination

Single scans and batch items use these termination values:

- `scope_exhausted` — the selected traversal reaches its end;
- `page_limit` — an address page reaches `limit` and includes `next_cursor`;
- `match_limit` — the cumulative match cap stops the traversal;
- `first_hit` — first mode returns a match;
- `timeout` — the scan deadline expires;
- `cancelled` — cancellation interrupts the scan;
- `target_changed` — attachment identity retires during the scan; and
- `reader_error` — the bounded reader fails.

`read_gaps_detected` is sticky. Count mode reports `observation: "complete_traversal"` only with `scope_exhausted` and no gap. Other count results report `partial_traversal`.

## Lua execution

`lua` returns `CANCELLED` when the engine observes cancellation and `TIMEOUT` when the execution deadline expires. Output captured before interruption remains in `output`; result entries are not guaranteed after cancellation. Lua functions that use a returning-nil convention expose the last diagnostic through `getLastError()` when the function records one.

## Plugin diagnostics

An isolated ordinary plugin failure emits one compact JSON record to `stderr` and one to the session log. The current structured contract is:

```json
{
  "schema": "memscope-plugin-diagnostic/v1",
  "severity": "warning",
  "code": "PLUGIN_CONTEXT_INCOMPATIBLE",
  "plugin": {
    "filename": "example.py",
    "declared_name": "example"
  },
  "cause": {
    "type": "AttributeError",
    "message": "Plugin uses a removed Lua runtime or hook-manager global; migrate to the required ExtensionContext fields."
  },
  "guidance": {
    "url": "https://memscope.esrc.dev/plugins/upgrading/",
    "required_context_fields": [
      "ctx.session",
      "ctx.table_factory",
      "ctx.hook_manager"
    ]
  },
  "channel": "stderr"
}
```

The second record uses `"channel": "session_log"`. The only codes are `PLUGIN_CONTEXT_INCOMPATIBLE` and `PLUGIN_LOAD_FAILED`. Filename, declared name, cause type, and cause message are bounded and normalized; arbitrary source paths, exception text, and secrets do not appear. Diagnostic sink failures do not turn an isolated plugin failure into a core failure.

See [Plugin troubleshooting](/plugins/troubleshooting/) and [Plugin upgrading](/plugins/upgrading/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/reference/errors-status.md)
