---
title: "Perform a first session"
description: "Start the configured server, select an exact PID, attach, and read an observable PE signature."
---

Complete [installation](/get-started/install/) and the [VS Code Windows configuration](/get-started/configure-client/) first. The client configuration must contain a fresh `MEMSCOPE_HOME` before the first server start, so no previously activated plugin file is present in this session.

## 1. Start and confirm the tool list

In VS Code, run **MCP: List Servers**, select `memscope`, and start it. Confirm that the client lists 11 tools. Starting the server creates `logs/sessions/` under the configured data root, but the session JSONL file appears only when the first event is logged. Startup does not attach to a process.

## 2. Select an exact PID

Call `processes` and choose one returned PID. When names repeat, the PID distinguishes the target:

```text
processes(filter="notepad", limit=10)
```

## 3. Attach to that process

Use the exact executable name and PID from the same result:

```text
attach(process_name="notepad.exe", pid=<selected_pid>)
modules(filter="notepad", limit=10)
```

`attach` opens the selected process with the Windows permissions available to the server and publishes its module snapshot.

## 4. Read the PE signature

Run this with the `lua` tool:

```lua
local base = getModuleBase("notepad.exe")
if not base then
    error("notepad.exe module not found")
end
addResult("module_base", toHex(base))
addResult("dos_signature", readBytesHex(base, 2))
```

For a normal loaded PE image, `dos_signature` is `4D 5A`. This confirms that Memscope resolved the executable's module base and read from the selected process. The commands above do not write target memory, call a native target function, install a hook, activate a plugin, or create a recording.

Use [discover and attach](/guides/discover-and-attach/) for process-selection details and [read and write memory](/guides/read-and-write-memory/) for later operations.
