# PEB process introspection

PEB helpers read process details without opening the normal debug session. They use `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` handles, walk x64 user-mode structures with `NtQueryInformationProcess` and `ReadProcessMemory`, and close their handles after each call.

## Lua functions

```lua
getProcessInfo(pid?)
isBeingDebugged(pid?)
getEnvironment(pid?)
getModulesRemote(pid?)
```

The `processes` MCP tool also enriches process rows with `command_line` when the PEB read succeeds. `getProcessInfo` combines process identity/path data with command line, current directory, debugger flag, and image path fields. `getEnvironment` returns a Lua table. `getModulesRemote` returns `{name, base, size, path}` records without changing attachment state.

## Read path

```text
NtQueryInformationProcess(ProcessBasicInformation)
                  |
                  v
              PEB address
        +---------+---------+
        |         |         |
  ProcessParameters  Ldr  BeingDebugged
        |             |
        v             v
 command line,    InLoadOrderModuleList
 current directory,
 environment, image path
```

The implementation reads x64 PEB offsets, Unicode strings, the loader list, and environment blocks. It does not write PEB fields, bypass anti-debugging, inspect TEBs, or enumerate heaps.

## Limits and data handling

- The server and target bitness must match; WOW64 translation is not supported.
- Access denial or a target exit can produce `nil`, empty tables, or partial fields.
- Environment reads are bounded to 64 KiB.
- Module walks stop at 1024 entries.
- A wide string read is bounded to 32 KiB.
- Forwarded export resolution belongs to `resolveExport` after attachment.
- Every PEB call owns and closes its own process handle.

Command lines and environment variables can contain credentials, tokens, paths, and flags. Treat output and session logs as sensitive. See [Inspect before attach](guides/inspect-before-attach.md), [Security model](concepts/security-model.md), and [the PEB source](../memscope_mcp/utils/peb.py).
