# Scanning

memscope exposes one strict MCP `scan` tool and three direct Lua helpers over the same bounded scanning engine. The engine compiles each query once, plans readable memory before reading, streams bounded chunks with overlap, and stops at the selected result boundary.

## MCP `scan`

A start request provides `pattern` and may provide:

```json
{
  "pattern": "48 8B 05 ?? ?? ?? ??",
  "scope": {
    "kind": "modules",
    "names": ["target.dll"],
    "filters": {}
  },
  "mode": "addresses",
  "limit": 50,
  "max_matches": 5000,
  "timeout_ms": 30000,
  "diagnostics": false
}
```

`??` is the only wildcard. Patterns compile to 1–1024 bytes and pattern text is limited to 4096 characters.

### Modes

- `addresses` returns one page of ordered hits. `limit` defaults to 50 and is bounded to 1–500. `max_matches` defaults to 5000 and caps the cumulative cursor sequence.
- `first` returns zero or one hit. It does not accept `limit` or `max_matches`.
- `count` returns a bounded count without retaining addresses. `max_matches` defaults to 5000 and is bounded to 1–100000. It does not accept `limit`.

Every retained hit includes an absolute address plus module name and module-relative offset when the address belongs to a known module.

### Continuation

Address pages continue with the opaque `next_cursor` returned by the previous response:

```json
{
  "cursor": "<opaque cursor>",
  "limit": 100,
  "timeout_ms": 30000,
  "diagnostics": false
}
```

A continuation request cannot repeat `pattern`, `scope`, `mode`, or `max_matches`. The cursor is authenticated, self-contained, tied to the server instance and attachment generation, and resumes at the first candidate address that has not been examined. It is not an offset and does not represent a memory snapshot. A process switch, reconnect, module refresh, or server restart makes an earlier cursor stale.

A full page stops immediately without looking ahead for another match. Consequently, a full final page may return a cursor whose next invocation returns an empty terminal page.

### Scopes

Omitting `scope` means all loaded modules.

All loaded modules:

```json
{"kind": "all_modules", "filters": {}}
```

Named modules:

```json
{"kind": "modules", "names": ["target.dll", "engine.dll"], "filters": {}}
```

Explicit half-open range:

```json
{
  "kind": "range",
  "start": "target.dll+0x1000",
  "end_exclusive": "target.dll+0x2000",
  "filters": {}
}
```

Address expressions accept integers, decimal strings, hexadecimal strings, `module+offset`, and `hex+offset`. Module names resolve case-insensitively against the immutable attachment snapshot. Missing or ambiguous module selectors fail before reading memory.

### Filters

Filters are applied during region planning, so excluded memory is not read:

```json
{
  "memory_types": ["image", "mapped", "private"],
  "executable": "required",
  "writable": "forbidden"
}
```

`memory_types` may contain `image`, `mapped`, and `private`. `executable` and `writable` accept `any`, `required`, or `forbidden`. PE section filters are reserved for a later release and are currently rejected rather than ignored.

### Status and errors

Successful responses include:

```json
{
  "status": {
    "termination": "scope_exhausted",
    "read_gaps_detected": false
  }
}
```

Termination values are `scope_exhausted`, `page_limit`, `match_limit`, `first_hit`, `timeout`, `cancelled`, `target_changed`, and `reader_error`. `read_gaps_detected` is sticky across one cursor sequence and means some selected memory could not be examined.

Count mode also reports `observation` as `complete_traversal` or `partial_traversal`. This describes traversal completeness, not a frozen snapshot of a mutable target.

Application failures use one flat envelope:

```json
{
  "success": false,
  "error": "MODULE_NOT_FOUND",
  "detail": "Module 'target.dll' is not present in the attachment snapshot",
  "field": "scope.names",
  "hint": "Refresh modules if the target loaded it after attachment"
}
```

Unknown and removed arguments are rejected. They are never silently ignored.

## Lua scanning

Lua exposes:

```lua
AOBScan(pattern, options?)
scanString(text, options?)
scanPointer(target, options?)
```

All options are named fields:

```lua
local hits, err = AOBScan("48 8B 05 ?? ?? ?? ??", {
  scope = {kind = "modules", names = {"target.dll"}},
  mode = "addresses",
  max_matches = 100,
  timeout_ms = 30000,
  diagnostics = false
})
```

The common fields are `scope`, `mode`, `max_matches`, `timeout_ms`, and `diagnostics`. `scanString` additionally accepts `encoding = "ascii" | "utf-16le"`. `scanPointer` additionally accepts `alignment` in the range 1–4096; alignment is based on the absolute candidate address.

Lua address mode defaults to 100 matches and allows at most 5000. It is intentionally non-paginated and reports `match_limit` when capped. First mode returns zero or one numeric entry. Count mode returns no numeric entries and places `count` and `observation` under `result.metadata`.

Expected input and domain failures return two values:

```lua
local hits, err = AOBScan("AA", {
  scope = {kind = "modules", names = {"missing.dll"}}
})

if not hits then
  print(err.error, err.detail)
end
```

A valid no-match scan returns a non-nil empty table with `metadata.status`. Script cancellation and the outer Lua deadline abort the script; a shorter scan-local deadline returns a partial result with `termination = "timeout"`.

## Migration from 0.2.x

The scanning contract is a clean break. There are no aliases, compatibility flags, or deprecated wrappers.

| Removed surface | Replacement |
| --- | --- |
| MCP `offset` | pass the previous `next_cursor` |
| MCP `_pagination` and address totals | use `next_cursor` and status; use `mode="count"` when a count is needed |
| MCP `summary_only=true` | `mode="count"` |
| MCP `max_results` | `max_matches` in addresses/count modes |
| MCP `max_results=1` first-hit convention | `mode="first"` |
| MCP `return_offset=true` | module fields are included on every known-module hit |
| MCP top-level `module` | `scope={"kind":"modules","names":[...]}` |
| MCP `address_min` / `address_max` | half-open range scope with `start` / `end_exclusive` |
| wildcard aliases `?`, `xx`, `XX`, `**` | `??` only |
| Lua positional scan arguments | one named options table |
| Lua `wide=true` | `encoding="utf-16le"` |
| Lua `AOBScanModule` | `AOBScan` with a modules scope |
| Lua empty table on invalid input | `nil, error_table` |
| Python `scan_aob_addresses` / `scan_references` imports | removed; there is no supported public Python scan API |

User scripts under `$MEMSCOPE_HOME/scripts/<process>/` are not rewritten automatically. Search those files for `AOBScanModule`, positional `AOBScan` calls, `scanString` calls with a boolean third argument, and old MCP scan field names, then update them explicitly.

Bundled plugins are copied into `$MEMSCOPE_HOME/plugins/` when installed and are not updated in place by a package upgrade. Review local modifications, then refresh a bundled copy with `memscope-mcp install-plugin <name> --force` or migrate its scan calls manually.
