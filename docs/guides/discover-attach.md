# Discover and attach

Start with process discovery and module inspection. This workflow keeps the first target interaction read-only and makes the PID choice explicit.

## Find the process

Use the `processes` MCP tool:

```text
processes(filter="Target", limit=20)
```

Useful filters are:

- `filter` — case-insensitive substring match on the image name;
- `pid` — exact PID lookup;
- `parent` — exact parent PID;
- `service` — service hosted by a matching process, such as `EventLog`;
- `limit` and `offset` — bounded result selection.

Entries include PID, image name, parent PID, thread count, and, when accessible, image path and command line. Service entries can appear for `svchost.exe`.

When multiple rows share a name, record the exact PID and use it for attachment:

```text
attach(process_name="Target.exe", pid=1234)
```

## Inspect before attachment

For a read-only process view without a debug session, use [Inspect before attach](inspect-before-attach.md). PEB reads can expose command lines, environment variables, debugger state, and remote module paths, so treat the results as sensitive.

## Inspect the attached snapshot

```text
modules(filter="Target", limit=50)
modules(refresh=true, limit=50)
```

The attach response includes the PID, process name, module count, key modules, saved-script information, scripts directory, and session log path. The `modules` response keeps module `name`, formatted `base`, `size`, and `path`.

`refresh=true` rebuilds the immutable module snapshot and advances the attachment generation. It does not switch the target or fire process attach/detach callbacks. A scan that holds the previous generation can report a target change.

## Lua equivalent

```lua
local process = attach("Target.exe", 1234)
if not process then
    error("attach failed")
end

for _, module in ipairs(getModules()) do
    print(module.name, toHex(module.base), module.size, module.path)
end
```

`attach(target, pid?)` accepts a process name or PID. `openProcess(pid)` remains a supported Lua alias for attach-by-PID behavior. `isAttached()` and `getAttachedProcess()` expose current session state.

## Next steps

- Read a PE signature with [Read and write memory](read-write.md).
- Run a bounded pattern scan with [Scan target memory](scan.md).
- Resolve PEB data with [Inspect before attach](inspect-before-attach.md).
- Understand generations and leases in [Session lifecycle](../concepts/session-lifecycle.md).
