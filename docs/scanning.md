# Scanning reference

`scan` and `scan_many` expose one strict bounded scanning engine through MCP. Lua exposes `AOBScan`, `AOBScanMany`, `scanString`, and `scanPointer` over the same scope, reader, matcher, and status rules.

## Pattern grammar

AOB patterns are non-empty strings with byte tokens and `??` wildcards. `??` is the only wildcard spelling. Input validation rejects unknown fields, malformed tokens, empty patterns, duplicate batch keys, and unsupported compatibility fields.

Patterns compile before a scan lease or target read. The matcher uses exact, all-wildcard, anchor, or regex strategies while preserving bounded reads and overlap ownership.

## MCP `scan`

A start request contains `pattern` and can contain `scope`, `mode`, `limit`, `max_matches`, `timeout_ms`, and `diagnostics`:

```json
{
  "pattern": "48 8B 05 ?? ?? ?? ??",
  "scope": {
    "kind": "modules",
    "names": ["Target.dll"],
    "filters": {
      "memory_types": ["image"],
      "executable": "required",
      "writable": "any",
      "sections": [".text"]
    }
  },
  "mode": "addresses",
  "limit": 50,
  "max_matches": 5000,
  "timeout_ms": 30000,
  "diagnostics": true
}
```

`pattern` is at most 4096 characters. `limit` is 1–500. `max_matches` is 1–100,000. `timeout_ms` is 100–30,000. Unknown fields are forbidden.

A continuation request contains `cursor` and may contain only `limit`, `timeout_ms`, and `diagnostics`:

```json
{
  "cursor": "<opaque token>",
  "limit": 100,
  "timeout_ms": 30000
}
```

The cursor binds the compiled pattern, normalized scope and filters, attachment generation, PID, module fingerprint, first unexamined address, cumulative match budget, and sticky gap state. It is authenticated by a server-local key and is not an offset or a client-editable query.

## Modes and responses

- **`addresses`** returns unique, ascending structured hits, up to `limit`. `limit` defaults to 50 and `max_matches` bounds the cumulative sequence. A full page returns `next_cursor` with `status.termination="page_limit"`.
- **`first`** returns one structured hit or `null`. It does not accept `limit` or `max_matches`.
- **`count`** returns `count`, `observation`, and no numeric hit list. It does not accept `limit`; `max_matches` defaults to 5000.

A hit has this shape:

```json
{
  "address": "0x7FF612341000",
  "module": "Target.dll",
  "module_offset": "0x21000"
}
```

`module` and `module_offset` are both `null` for an address outside the immutable module snapshot. Count mode reports `complete_traversal` only when termination is `scope_exhausted` and `read_gaps_detected` is false.

A full address page stops at the exact page boundary without searching for a lookahead hit. A full terminal page can therefore be followed by one empty terminal page.

## MCP `scan_many`

`scan_many` accepts 1–32 keyed patterns:

```json
{
  "patterns": [
    {"key": "singleton", "pattern": "48 8B 05 ?? ?? ?? ??"},
    {"key": "allocator", "pattern": "48 89 5C 24 ?? 57 48 83 EC ??"}
  ],
  "scope": {"kind": "modules", "names": ["Target.dll"]},
  "mode": "first",
  "timeout_ms": 30000,
  "diagnostics": true
}
```

Keys are unique, non-empty, and at most 64 UTF-8 bytes. Each pattern has the same 4096-character bound. All patterns compile before target access. Batch mode supports only `first` and `count`, shares one target-memory traversal, and has no address pagination or cursor. In `count` mode, `max_matches` applies independently to each pattern.

Each result item contains its key, match or count, and item status. `shared` contains the traversal-wide termination, gap state, and optional diagnostics.

## Scopes and filters

Omitting `scope` means all loaded modules. Explicit scopes are:

```json
{"kind": "all_modules", "filters": {}}
```

```json
{"kind": "modules", "names": ["Target.dll", "Helper.dll"], "filters": {}}
```

```json
{"kind": "range", "start": "Target.dll+0x1000", "end_exclusive": "Target.dll+0x9000", "filters": {}}
```

Module names resolve case-insensitively by basename and every requested name must resolve. Range bounds are half-open and accept integers, hexadecimal strings, or module-plus-offset expressions.

Filters use:

- `memory_types`: one or more of `image`, `mapped`, and `private`;
- `executable`: `any`, `required`, or `forbidden`;
- `writable`: `any`, `required`, or `forbidden`; and
- `sections`: case-insensitive PE section names for `all_modules` and `modules` scopes only.

Module scopes default to image memory. Range scopes default to all memory types. Section names are bounded, duplicate-free, and required in every selected module. A missing section returns `SECTION_NOT_FOUND` before corpus scanning.

## Status and diagnostics

Stable termination values are:

- `scope_exhausted`
- `page_limit`
- `match_limit`
- `first_hit`
- `timeout`
- `cancelled`
- `target_changed`
- `reader_error`

`read_gaps_detected` remains true once planning or reading cannot cover part of a selected scope. When `diagnostics=true`, a bounded diagnostics object includes duration, strategy counts, examined bytes, physical read calls/bytes, cursor-prefix bytes, region/span/candidate/verification/control-poll counts, a scope fingerprint, and selected canonical PE sections.

## Lua scanning

```lua
local hits, err = AOBScan("48 8B 05 ?? ?? ?? ??", {
    scope = {
        kind = "modules",
        names = {"Target.dll"},
        filters = {sections = {".text"}}
    },
    mode = "addresses",
    max_matches = 100,
    timeout_ms = 30000,
    diagnostics = true
})
if not hits then
    error(err.detail)
end
```

Single Lua queries use named fields `scope`, `mode`, `max_matches`, `timeout_ms`, and `diagnostics`. `AOBScan` modes are `addresses`, `first`, and `count`; Lua address mode defaults to 100 matches and is non-paginated. `scanString` accepts `encoding="ascii"` or `"utf-16le"`. `scanPointer` accepts `alignment` from 1 through 4096 and tests absolute candidate addresses.

`AOBScanMany` preserves input order and supports only `first` and `count`:

```lua
local items, err = AOBScanMany({
    {key = "singleton", pattern = "48 8B 05 ?? ?? ?? ??"},
    {key = "allocator", pattern = "48 89 5C 24 ?? 57 48 83 EC ??"}
}, {
    scope = {kind = "modules", names = {"Target.dll"}},
    mode = "count",
    max_matches = 5000
})
if not items then
    error(err.detail)
end
for _, item in ipairs(items) do
    print(item.key, item.count, item.observation, item.status.termination)
end
```

Expected input/domain failures return `nil, error_table`; internal unexpected failures raise through the Lua engine. See [Errors and status](reference/errors-status.md).
