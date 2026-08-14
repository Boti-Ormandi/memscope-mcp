# Getting started

`memscope-mcp` is a Windows process-memory MCP server for reverse engineering and authorized live-process research. This path starts with process discovery and read-only inspection before it introduces writes, native execution, hooks, plugins, or recordings.

## 1. Prepare the host

Use a Windows x64 host, a 64-bit Python 3.10+ interpreter, and an MCP-compatible client with stdio support. The target process also needs to be x64. Windows access checks still apply: a process can deny query, VM-read, VM-write, thread, or debug-related operations even when the server starts successfully.

Install from the package source configured for your environment:

```powershell
python -m pip install memscope-mcp
```

Confirm the console entry point resolves:

```powershell
memscope-mcp paths
```

## 2. Configure the MCP client

The server uses stdio. A minimal client entry is:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "memscope-mcp"
    }
  }
}
```

The command starts the same server as `memscope-mcp server`. The client must keep stdin and stdout reserved for MCP traffic; diagnostics and the startup data-root line use stderr.

See [MCP tools](reference/mcp-tools.md) for the complete 11-tool surface and [CLI and paths](reference/cli-paths.md) for data-root inspection.

## 3. Choose a target without attaching

Use the `processes` MCP tool to filter by name, PID, parent PID, or service. For a process that has several instances, select an exact PID. Before attachment, Lua can also inspect the PEB of a selected PID with `getProcessInfo(pid)`, `getEnvironment(pid)`, `isBeingDebugged(pid)`, and `getModulesRemote(pid)`.

These reads can expose command lines, environment variables, executable paths, and module paths. Treat them as potentially sensitive even though they do not modify the target.

## 4. Attach and inspect modules

Attach with the selected name and PID:

```text
attach(process_name="notepad.exe", pid=<selected_pid>)
modules(filter="notepad", limit=10)
```

`attach` opens the target process and publishes a module snapshot. `modules(refresh=true)` rebuilds that snapshot and advances the attachment generation without changing the process handle or firing attach/detach callbacks. Read [Session lifecycle](concepts/session-lifecycle.md) for the consequences of switching, detaching, refreshing, or reconnecting.

## 5. Perform a safe first read

Resolve a module base and read two bytes:

```lua
local base = getModuleBase("notepad.exe")
if not base then
    error("module not found")
end
addResult("base", toHex(base))
addResult("mz", readBytesHex(base, 2))
```

A PE image normally returns `4D 5A`. Use [Read and write memory](guides/read-write.md) for typed values and the explicit boundary between read-only and mutating operations.

## Data and permissions

The default data root is `~/.memscope-mcp`. `MEMSCOPE_HOME` relocates it before server startup:

```powershell
$env:MEMSCOPE_HOME = Join-Path $env:TEMP "memscope-mcp-session"
New-Item -ItemType Directory -Force $env:MEMSCOPE_HOME | Out-Null
memscope-mcp paths
```

The server uses these subdirectories:

- `logs/sessions/<session-id>.jsonl` for bounded session events and plugin diagnostics;
- `scripts/<process>/<name>.lua` for saved Lua scripts; and
- `plugins/<filename>.py` for explicitly activated plugin files.

Netcap recordings use `$MEMSCOPE_HOME/scripts/<process>/recordings/`. The cwd-relative `scripts/<process>/recordings/` path is read-only legacy fallback only. Keep the data root outside the repository and protect it as sensitive local data.

## Before enabling powerful operations

- Read [Read and write memory](guides/read-write.md) before using `write` or Lua write helpers.
- Read [Capture calls](guides/capture-calls.md) before allocating executable memory or installing hooks.
- Read [Code execution and native calls](lua-reference.md#code-execution) before calling target functions.
- Read [Use plugins](guides/use-plugins.md) and [Plugin authoring](plugins/authoring.md) before activating Python files.
- Read [Netcap](plugins/netcap.md) before capturing or storing packet data.
- Read [Security model](concepts/security-model.md) and [SECURITY.md](../SECURITY.md) for trust boundaries and reporting.
