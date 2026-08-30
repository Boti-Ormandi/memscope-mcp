---
title: "Scan target memory"
description: "Run strict bounded AOB, string, pointer, and batch scans."
---

Use AOB, string, and pointer scans after selecting a process and memory scope. Start with `first` when one result is expected; use address pages to retrieve multiple matches, or `count` to determine whether the selected memory was traversed completely.

## MCP address scan

```json
{
  "pattern": "48 8B 05 ?? ?? ?? ??",
  "scope": {
    "kind": "modules",
    "names": ["Target.dll"],
    "filters": {"sections": [".text"]}
  },
  "mode": "addresses",
  "limit": 25,
  "timeout_ms": 30000
}
```

`??` is the only wildcard. The address mode returns ordered structured hits and can include an authenticated `next_cursor`. Continue with the cursor only:

```json
{
  "cursor": "<opaque cursor>",
  "limit": 25,
  "timeout_ms": 30000
}
```

`first` returns one structured match or `null`. `count` returns a bounded count and an observation that distinguishes complete traversal from partial traversal.

## Lua scan

```lua
local hits, err = AOBScan("48 8B 05 ?? ?? ?? ??", {
    scope = {
        kind = "modules",
        names = {"Target.dll"},
        filters = {sections = {".text"}}
    },
    mode = "first"
})
if not hits then
    error(err.detail)
end
if #hits > 0 then
    addResult("match", toHex(hits[1]))
end
```

Lua single-query options use named fields: `scope`, `mode`, `max_matches`, `timeout_ms`, and `diagnostics`. `scanString` adds `encoding = "ascii"` or `"utf-16le"`; `scanPointer` adds `alignment` from 1 through 4096.

## Batch scan

Use `scan_many` or `AOBScanMany` for 1–32 keyed patterns in one shared traversal:

```lua
local results, err = AOBScanMany({
    {key = "singleton", pattern = "48 8B 05 ?? ?? ?? ??"},
    {key = "allocator", pattern = "48 89 5C 24 ?? 57 48 83 EC ??"}
}, {
    scope = {kind = "modules", names = {"Target.dll"}},
    mode = "first",
    diagnostics = true
})
if not results then
    error(err.detail)
end
for _, item in ipairs(results) do
    print(item.key, item.match, item.status.termination)
end
```

Batch mode supports only `first` and `count`. It has no address pagination or cursor. Keys are unique and at most 64 UTF-8 bytes.

## Scope choices

- `all_modules` selects all loaded modules.
- `modules` selects named modules case-insensitively and requires every name to resolve.
- `range` selects a half-open `[start, end_exclusive)` range.

Filters can select `image`, `mapped`, or `private` memory, and require or forbid executable or writable pages. PE-section filters are valid only for module scopes, match section names case-insensitively, and require every requested section to exist in every selected module. Missing sections fail before target corpus scanning.

## Interpret status

A valid no-match operation is not an error. Inspect `status.termination` and `read_gaps_detected`. A count is `complete_traversal` only when termination is `scope_exhausted` and no read gap exists. A page can stop at `page_limit` without looking ahead for another hit, so a terminal full page can be followed by one empty page.

See the full [Scanning reference](/reference/scanning/), [Errors and status](/reference/errors-and-status/), and [saved scripts](/guides/saved-scripts/).
