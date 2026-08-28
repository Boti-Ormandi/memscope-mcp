---
title: "Perform a first session"
description: "Attach to a selected process and begin with a bounded read-only inspection."
---

Begin with process discovery and a bounded read. This workflow does not write target memory, execute native code, install a hook, activate a plugin, or create a recording.

## 1. Choose an exact process

Use the `processes` MCP tool to filter the process list. Select an exact PID when names repeat:

```text
processes(filter="notepad", limit=10)
```

Before attachment, Lua can inspect the PEB of a selected PID with `getProcessInfo(pid)`, `getEnvironment(pid)`, `isBeingDebugged(pid)`, and `getModulesRemote(pid)`. These reads return command lines, environment variables, debugger flags, and module lists.

## 2. Attach and inspect the module snapshot

```text
attach(process_name="notepad.exe", pid=<selected_pid>)
modules(filter="notepad", limit=10)
```

`attach` opens the target process and publishes a module snapshot. `modules(refresh=true)` rebuilds that snapshot and advances the attachment generation without changing the process handle or firing attach/detach callbacks. See [session lifecycle](/concepts/session-lifecycle/) for switching, refresh, reconnect, and cleanup behavior.

## 3. Read the PE signature

```lua
local base = getModuleBase("notepad.exe")
if not base then
    error("module not found")
end
addResult("base", toHex(base))
addResult("mz", readBytesHex(base, 2))
```

A normal PE image returns `4D 5A`. Use [read and write memory](/guides/read-and-write-memory/) for typed values and the explicit boundary between read-only and mutating operations. Use [discover and attach](/guides/discover-and-attach/) for a longer read-first workflow.

---

[Source: getting-started guide](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/getting-started.md#5-perform-a-safe-first-read)
