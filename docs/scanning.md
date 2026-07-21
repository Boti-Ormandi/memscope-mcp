# Scanning

memscope exposes two strict MCP tools, `scan` and `scan_many`, plus four direct Lua helpers over one bounded scanning engine. Queries are compiled before a scan lease is acquired, scopes are normalized against one immutable attachment snapshot, readable intervals are planned before corpus reads, and matching streams bounded chunks with exact overlap ownership.

## MCP `scan`

A start request provides `pattern` and may provide:

```json
{
  "pattern": "48 8B 05 ?? ?? ?? ??",
  "scope": {
    "kind": "modules",
    "names": ["target.dll"],
    "filters": {
      "memory_types": ["image"],
      "executable": "any",
      "writable": "any",
      "sections": [".text"]
    }
  },
  "mode": "addresses",
  "limit": 50,
  "max_matches": 5000,
  "timeout_ms": 30000,
  "diagnostics": false
}
```

`??` is the only wildcard token. Patterns compile to at most 1024 bytes. Unknown fields, wildcard aliases, malformed tokens, empty patterns, and removed compatibility fields are rejected.

### Modes

- `addresses` returns an ordered page of at most `limit` matches. `limit` defaults to 50 and is bounded to 1-500. `max_matches` is a cumulative sequence cap bounded to 1-100000.
- `first` returns one match or `null`. It does not accept `limit` or `max_matches`.
- `count` returns a bounded count. It does not accept `limit`; `max_matches` defaults to 5000.

A match is represented as:

```json
{
  "address": "0x7FF612341000",
  "module": "target.dll",
  "module_offset": "0x21000"
}
```

`module` and `module_offset` are both `null` when the candidate start is outside the immutable module snapshot.

### Continuation

An address response may contain `next_cursor`. Continue with a cursor-only request:

```json
{
  "cursor": "<opaque token>",
  "limit": 100,
  "timeout_ms": 30000,
  "diagnostics": false
}
```

Continuation requests cannot restate `pattern`, `scope`, `mode`, or `max_matches`. The authenticated cursor binds the compiled query, normalized scope and filters, attachment generation, PID, module fingerprint, exact first unexamined candidate address, cumulative match count, and sticky gap state. Section filters are therefore continuation-bound as part of the scope fingerprint.

A full page stops at the exact page boundary without searching for a lookahead hit. A full terminal page may consequently be followed by one empty terminal page.

## MCP `scan_many`

`scan_many` searches 1-32 keyed AOB patterns during one shared target-memory traversal:

```json
{
  "patterns": [
    {"key": "singleton", "pattern": "48 8B 05 ?? ?? ?? ??"},
    {"key": "allocator", "pattern": "48 89 5C 24 ?? 57 48 83 EC ??"}
  ],
  "scope": {
    "kind": "modules",
    "names": ["target.dll"],
    "filters": {"sections": [".text"]}
  },
  "mode": "first",
  "timeout_ms": 30000,
  "diagnostics": true
}
```

Each item must contain a unique, non-empty `key` of at most 64 UTF-8 bytes and one strict AOB `pattern`. All patterns are validated and compiled before the scan acquires a lease or reads target memory. The aggregate compiled pattern length is bounded to 32768 bytes.

Batch mode is intentionally limited to `first` and `count`:

- `first` does not accept `max_matches`.
- `count` applies the same independent `max_matches` cap to every pattern; the default is 5000 and the maximum is 100000.
- Address results, cursors, pagination, and batch lookahead are not part of this surface.

A first-hit response has ordered per-pattern results and one shared traversal status:

```json
{
  "success": true,
  "mode": "first",
  "results": [
    {
      "key": "singleton",
      "match": {"address": "0x7FF612341000", "module": "target.dll", "module_offset": "0x21000"},
      "status": {"termination": "first_hit", "read_gaps_detected": false}
    },
    {
      "key": "allocator",
      "match": null,
      "status": {"termination": "scope_exhausted", "read_gaps_detected": false}
    }
  ],
  "shared": {
    "termination": "scope_exhausted",
    "read_gaps_detected": false,
    "diagnostics": null
  }
}
```

A count item contains `count`, `observation`, and `status`. Each pattern stops independently when it finds its first hit or reaches its count cap; remaining patterns continue over the same reader stream. The shared status records why the shared traversal ended. Timeout, cancellation, target change, reader failure, and final gap state are traversal-wide.

## Scopes and filters

Omitting `scope` means all loaded modules. Explicit forms are:

```json
{"kind": "all_modules", "filters": {}}
```

```json
{"kind": "modules", "names": ["target.dll", "helper.dll"], "filters": {}}
```

```json
{"kind": "range", "start": "target.dll+0x1000", "end_exclusive": "target.dll+0x9000", "filters": {}}
```

Module names resolve case-insensitively by basename. Every requested module must resolve exactly once before scanning starts. Range bounds are half-open and may be integers, hex strings, or module-plus-offset expressions.

`memory_types` may contain `image`, `mapped`, and `private`. `executable` and `writable` accept `any`, `required`, or `forbidden`. Module scopes default to `image`; range scopes default to all memory types.

### PE section filters

`filters.sections` is valid only for `all_modules` and `modules` scopes. Names are matched case-insensitively against PE section headers. Duplicate requested names are rejected, and every requested section must exist in every selected module. A missing section returns `SECTION_NOT_FOUND` before `VirtualQueryEx` or corpus scanning begins.

The planner reads and caches the selected modules' PE headers for the current attachment generation, resolves canonical remote section spelling, merges overlapping selected intervals, and intersects those intervals with the normal memory-type and protection filters. Corpus reads never include bytes outside the selected section intervals. PE-header metadata reads are necessary for resolution and are included in physical-read diagnostics; cache hits avoid repeating them.

## Status, diagnostics, and errors

Successful single-scan responses include `status`; batch responses include per-item status and a shared status. Stable termination values are:

- `scope_exhausted`
- `page_limit`
- `match_limit`
- `first_hit`
- `timeout`
- `cancelled`
- `target_changed`
- `reader_error`

`read_gaps_detected` is sticky. It becomes true if planning or reading cannot cover part of the selected scope. Count responses use `observation="complete_traversal"` only when the relevant traversal ends with `scope_exhausted` and no gap; every other count is `partial_traversal`.

When `diagnostics=true`, the bounded diagnostics object includes duration, matcher strategy counts, unique bytes examined, physical read calls and bytes, cursor-prefix bytes, region/span/candidate/verification/control-poll counts, the normalized `scope_fingerprint`, and canonical remote `sections` selected by the planner. Batch diagnostics appear once under `shared` because the target-memory traversal is shared.

Expected failures use one flat application envelope:

```json
{
  "success": false,
  "error": "INVALID_SCOPE",
  "detail": "...",
  "field": "scope.names[0]",
  "hint": "..."
}
```

Stable scan error codes are `INVALID_PATTERN`, `INVALID_SCOPE`, `INVALID_MODE`, `INVALID_ARGUMENT`, `MODULE_NOT_FOUND`, `AMBIGUOUS_MODULE`, `SECTION_NOT_FOUND`, `PROCESS_NOT_ATTACHED`, `INVALID_CURSOR`, `CURSOR_STALE`, `TARGET_CHANGED`, and `INTERNAL_SCAN_ERROR`.

## Lua scanning

Lua exposes:

```lua
AOBScan(pattern, options?)
AOBScanMany(patterns, options?)
scanString(text, options?)
scanPointer(target, options?)
```

The single-query helpers accept named `scope`, `mode`, `max_matches`, `timeout_ms`, and `diagnostics` fields. `scanString` additionally accepts `encoding = "ascii" | "utf-16le"`; `scanPointer` accepts `alignment` in 1-4096, based on the absolute candidate address.

Single-query address mode defaults to 100 matches and permits at most 5000. It is non-paginated. First mode returns zero or one numeric entry. Count mode returns no numeric entries and places `count` and `observation` under `result.metadata`.

`AOBScanMany` accepts an ordered Lua array of `{key, pattern}` tables and only `first` or `count` mode:

```lua
local items, err = AOBScanMany({
  {key = "singleton", pattern = "48 8B 05 ?? ?? ?? ??"},
  {key = "allocator", pattern = "48 89 5C 24 ?? 57 48 83 EC ??"}
}, {
  scope = {
    kind = "modules",
    names = {"target.dll"},
    filters = {sections = {".text"}}
  },
  mode = "first",
  diagnostics = true
})

if not items then error(err.detail) end
for _, item in ipairs(items) do
  print(item.key, item.match, item.status.termination)
end
print(items.metadata.shared.termination)
```

The result preserves input order. First items contain `key`, optional numeric `match`, and `status`; count items contain `key`, `count`, `observation`, and `status`. Shared traversal metadata is under `items.metadata.shared`.

Expected input and domain failures return `nil, error_table`. A valid no-match operation returns a non-nil result with explicit status. Unexpected internal programming failures still raise through the Lua engine.

## Migration from 0.2.x

The scanning contract is a clean break. There are no aliases, compatibility flags, or deprecated wrappers.

| Removed surface | Replacement |
| --- | --- |
| MCP `offset` | pass the previous `next_cursor` |
| MCP `_pagination` and address totals | use `next_cursor` and status; use `mode="count"` when a count is needed |
| MCP `summary_only=true` | `mode="count"` |
| MCP `max_results` | `max_matches` in addresses/count modes |
| MCP `max_results=1` first-hit convention | `mode="first"` |
| MCP `return_offset` | structured `module` and `module_offset` on each hit |
| MCP `module` / `address_min` / `address_max` | structured `scope` |
| MCP `readable` / `executable` / `writable` booleans | planner filters under `scope.filters` |
| Lua `AOBScanModule` | `AOBScan` with a modules scope |
| wildcard aliases `?`, `xx`, `XX`, `**` | `??` only |
| Lua positional scan arguments | one named options table |
| Lua `wide=true` | `encoding="utf-16le"` |
| Lua empty table on invalid input | `nil, error_table` |
| Python `scan_aob_addresses` / `scan_references` imports | removed; there is no supported public Python scan API |

User scripts under `$MEMSCOPE_HOME/scripts/<process>/` are not rewritten automatically. Search them for `AOBScanModule`, positional `AOBScan` calls, `scanString` calls with a boolean encoding argument, and old MCP field names, then update them explicitly.

Bundled plugins are copied into `$MEMSCOPE_HOME/plugins/` when installed and are not updated in place by a package upgrade. Review local modifications, then refresh a bundled copy with `memscope-mcp install-plugin <name> --force` or migrate its scan calls manually.
