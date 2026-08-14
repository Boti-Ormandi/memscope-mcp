# Use saved scripts

Saved scripts keep discovery logic and dependent reads in files under the data root. They do not rewrite themselves, and they do not turn a saved namespace into an attachment operation.

## Create a script

List the current namespace:

```text
scripts(action="list")
```

The response supplies an absolute `scripts_dir` and absolute file paths. Use file tools to create or edit `<scripts_dir>\<process>\<name>.lua`. The first-line comment becomes the description.

Example file:

```lua
-- Locate the executable signature
local base = getModuleBase("Target.exe")
if not base then
    error("Target.exe is not loaded")
end
addResult("base", toHex(base))
addResult("signature", readBytesHex(base, 2))
```

The process directory is a saved-script namespace. It is not a request to attach.

## Run a script

```text
scripts(action="run", name="locate_signature")
scripts(action="run", name="locate_signature", args={"expected"="4D 5A"}, timeout=30)
```

Use `process="Target.exe"` to select a namespace explicitly. If the server is detached, an explicit `process` is required. If the server is attached, an explicit process must match the attached target case-insensitively. The process argument never attaches or switches the target.

Run responses include `requested_process`, `attached_process`, `attached_pid`, and `detached_execution`, plus script name/path/description.

## Script data and safety

The default path is `$MEMSCOPE_HOME/scripts/<process>/`. Keep `MEMSCOPE_HOME` outside the repository and use a disposable root for experiments. Scripts can call memory writes, native execution, hooks, and plugins, so review the file before running it.

The Lua engine uses a default execution timeout and supports explicit `timeout`. Cancellation preserves captured output but does not guarantee result entries after interruption. Large hexadecimal literals are normalized to `addr("0x...")`; explicit `addr()` is the clearest form for 64-bit addresses.

Scripts persist as local files. A package upgrade does not rewrite them. Review scripts when their assumptions about modules, scans, plugins, or target layouts change.

See [Lua reference](../lua-reference.md), [CLI and paths](../reference/cli-paths.md), and [Security model](../concepts/security-model.md).
