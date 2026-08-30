---
title: "Inspect before attach"
description: "Read bounded PEB process information without populating the debug session."
---

PEB helpers provide read-only process information before a debug session exists. They use separate process handles with query/read access and do not populate the target session.

## Lua examples

```lua
local candidates = getProcessList("Target")
for _, item in ipairs(candidates) do
    local info = getProcessInfo(item.pid)
    if info then
        print(item.pid, info.name, info.command_line)
    end
end
```

Read a target environment or remote module list without attaching:

```lua
local env = getEnvironment(1234)
print(env.PATH, env.USERPROFILE)

for _, module in ipairs(getModulesRemote(1234)) do
    print(module.name, toHex(module.base), module.size, module.path)
end
```

Use `isBeingDebugged(pid)` for the PEB debugger flag. `getProcessInfo` includes process identity, path, parent, thread count, command line, current directory, debugger flag, and image path when each read succeeds.

## Limits

- The server and target use matching x64 layouts; cross-bitness PEB walking is not supported.
- Access-denied fields are omitted or return `nil`/an empty table according to the Lua helper.
- A process that exits during a read can produce a partial result.
- Environment reads are bounded to 64 KiB.
- Module enumeration is bounded to 1024 modules.
- Wide strings are bounded to 32 KiB.
- Command lines and environment variables can contain credentials or personal data.

The `processes` MCP tool enriches process rows with a command line when the read is available. It does not require the target to be attached.

See [PEB introspection](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/peb.md), [Discover and attach](/guides/discover-and-attach/), and [Security model](/concepts/security-model/).
