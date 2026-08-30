## Configuration

See [Configure an MCP client](/get-started/configure-client/) for a VS Code example with an explicit `MEMSCOPE_HOME` data root. The server name is `memscope-mcp`. It communicates over stdio and advertises tools and instructions; it does not expose a second transport or plugin namespace.

## Tool list

| Tool | Request shape | Purpose |
| --- | --- | --- |
| `processes` | `filter?`, `pid?`, `parent?`, `service?`, `limit?`, `offset?` | Enumerate processes, with optional service and parent filtering. Entries can include path, command line, threads, and services. |
| `attach` | `process_name`, `pid?` | Open or switch the session to a selected process and publish a module snapshot. |
| `modules` | `filter?`, `limit?`, `refresh?` | List the current snapshot; `refresh=true` publishes a new snapshot generation. |
| `read` | `address`, `type_name`, `count?` | Read primitive, special, or composite values. |
| `write` | `address`, `value`, `type_name`, `verify?` | Write typed data or bytes. `verify=true` performs writable-range validation, pre-image capture, readback, and a restore attempt after a verification failure. |
| `dump` | `address`, `size?`, `pointers_only?`, `start_offset?`, `non_null_only?`, `max_entries?`, `annotation_level?` | Inspect a bounded 4096-byte window with pointer heuristics and pagination metadata. |
| `chain` | `base`, `offsets`, `read_final?` | Follow `[[base+offset0]+offset1]...` and format the final value. |
| `scan` | start request or cursor continuation | Run one strict AOB scan in `addresses`, `first`, or `count` mode. |
| `scan_many` | `patterns`, `scope?`, `mode?`, `max_matches?`, `timeout_ms?`, `diagnostics?` | Run 1–32 keyed AOB patterns in one shared traversal; mode is `first` or `count`. |
| `lua` | `script`, `timeout?` | Execute composed Lua with loops, dependent reads, native calls, and registered extension/plugin functions. |
| `scripts` | `action`, `name?`, `process?`, `args?`, `timeout?` | List or run saved Lua scripts. File tools create and edit scripts. |

The server does not add a separate MCP tool for plugins. A plugin registers Lua functions into the existing `lua` tool.

## Read-first examples

```text
processes(filter="target", limit=20)
attach(process_name="Target.exe", pid=1234)
modules(refresh=false, limit=50)
read(address="Target.exe+0x1000", type_name="bytes", count=2)
```

`read`, `dump`, `chain`, and `scan` require an attached process. `processes` and PEB-related Lua helpers can work before attachment.

## Scan boundary

`scan` rejects unknown fields, accepts either `pattern` or `cursor`, and uses strict request models. A start request can include a structured `scope`, `mode`, `limit`, `max_matches`, `timeout_ms`, and `diagnostics`. A continuation request contains a `cursor` plus only `limit`, `timeout_ms`, and `diagnostics`. See [Scanning reference](/reference/scanning/).

`scan_many` accepts 1–32 unique `{key, pattern}` entries, strict module/range scopes, `first` or `count`, and one shared traversal status. It intentionally has no address pagination.

## Result shape

Ordinary tools return dictionaries with `success=true` or `success=false`, an error code, and a bounded `detail` when an operation fails. The strict scan boundary returns a validated flat failure envelope:

```json
{
  "success": false,
  "error": "INVALID_ARGUMENT",
  "detail": "Unknown scan argument 'offset'",
  "field": "offset"
}
```

The `write` result distinguishes `MEMORY_NOT_WRITABLE`, `WRITE_ERROR`, `VERIFY_READ_FAILED`, and `VERIFY_MISMATCH` when verification is enabled. See [Errors and status](/reference/errors-and-status/).

## Lua and scripts

Use `lua` for composed operations:

```lua
local base = getModuleBase("Target.exe")
if base then
    addResult("signature", readBytesHex(base, 2))
end
```

Use `scripts(action="list")` to obtain absolute script paths. Use file tools to create or edit a `.lua` file, then run it with `scripts(action="run", name="finder")`. A `process` argument selects the saved-script namespace; it does not attach or switch targets.

The full function contract is in the [Lua reference](/reference/lua/).
