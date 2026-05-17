# PEB Process Introspection

Read the Process Environment Block from any process by PID without opening a debug session. Command line, environment variables, debugger flag, image path, working directory, and loaded modules -- all reachable with the standard `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access. No injection, no session state.

The functionality is surfaced through the `processes` MCP tool (enriched per-entry with `command_line`) and through Lua functions for everything else.

## Scope

- **Pre-attach process detail.** `getProcessInfo(pid)` returns command line, current directory, debugger flag, and image path alongside the existing pid/name/threads.
- **Environment variables.** `getEnvironment(pid)` returns the target's environment as a Lua table, including auth tokens, debug flags, and config paths.
- **Remote module enumeration.** `getModulesRemote(pid)` walks the PEB loader list and returns `{name, base, size, path}` per module without opening a debug session.
- **Debugger check.** `isBeingDebugged(pid)` returns the PEB `BeingDebugged` byte as a boolean, or `nil` if the process cannot be opened.

All operations are read-only.

## Non-goals

- Writing PEB fields. Anti-debug bypass is intentionally out of scope.
- TEB (Thread Environment Block) reading.
- Heap enumeration via PEB.
- Kernel-mode process info (ETW, process creation callbacks).
- Cross-bitness inspection (32-bit target from 64-bit server, or vice versa). The server's bitness must match the target's; we do not implement WOW64 PEB walking.

## Architecture

`memscope_mcp/utils/peb.py` is a self-contained PEB reader: pure ctypes, no pymem dependency, no `SESSION` state. It opens its own process handle per call (so no handles leak into the session lifecycle) and reads the PEB through `NtQueryInformationProcess(ProcessBasicInformation)` + `ReadProcessMemory`.

```
NtQueryInformationProcess(ProcessBasicInformation)
                  |
                  v
            PEB address
                  |
   +--------------+--------------+
   |              |              |
   v              v              v
ProcessParameters   Ldr      BeingDebugged
   |                |
   v                v
CommandLine      InLoadOrderModuleList
CurrentDirectory  (linked list walk)
Environment
ImagePathName
   |
   v
UNICODE_STRING -> wide string read
```

Integration points:

| Layer | Role |
|-------|------|
| `memscope_mcp/utils/peb.py` | PEB reading functions: `read_process_peb`, `read_process_environment`, `read_process_modules`. Used by both Lua wrappers and the MCP tool. |
| `memscope_mcp/tools/lua/process_info.py` | Lua wrappers: `get_process_info` enriched, plus `is_being_debugged`, `get_environment`, `get_modules_remote`. |
| `memscope_mcp/extensions/core/process.py` | Registers the new Lua functions and updates the AI-facing instructions fragment. |
| `memscope_mcp/server.py` | Per-entry `command_line` enrichment in the `processes` MCP tool. |

Self-contained because PEB reading needs only `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and shares no state with the attach/detach session. Both the Lua wrappers and the `processes` MCP tool consume it. `path` in `getProcessInfo` actually comes from `QueryFullProcessImageNameW` (more reliable than the PEB `ImagePathName`); the PEB read fills in `command_line`, `current_directory`, `being_debugged`, and the PEB-derived `image_path`.

## PEB structures (x64 Windows)

All offsets are for x64 user-mode processes. Offsets are hard-coded as named constants near each read site in `memscope_mcp/utils/peb.py`; if Microsoft rearranges fields in a future ABI, those constants are the surface to update.

```c
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;                      // +0x00
    PVOID     PebBaseAddress;                  // +0x08
    ULONG_PTR AffinityMask;                    // +0x10
    LONG      BasePriority;                    // +0x18
    ULONG_PTR UniqueProcessId;                 // +0x20
    ULONG_PTR InheritedFromUniqueProcessId;    // +0x28
} PROCESS_BASIC_INFORMATION;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;             // +0x000
    BOOLEAN ReadImageFileExecOptions;          // +0x001
    BOOLEAN BeingDebugged;                     // +0x002
    PVOID   ImageBaseAddress;                  // +0x010
    PVOID   Ldr;                               // +0x018  -> PEB_LDR_DATA*
    PVOID   ProcessParameters;                 // +0x020  -> RTL_USER_PROCESS_PARAMETERS*
} PEB;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG          MaximumLength;              // +0x000
    ULONG          Length;                     // +0x004
    CURDIR         CurrentDirectory;           // +0x038  (UNICODE_STRING + Handle)
    UNICODE_STRING DllPath;                    // +0x050
    UNICODE_STRING ImagePathName;              // +0x060
    UNICODE_STRING CommandLine;                // +0x070
    PVOID          Environment;                // +0x080
} RTL_USER_PROCESS_PARAMETERS;

typedef struct _UNICODE_STRING {
    USHORT Length;                             // byte length, not char count
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;                         // +0x000
    BOOLEAN    Initialized;                    // +0x004
    LIST_ENTRY InLoadOrderModuleList;          // +0x010
} PEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;           // +0x000
    PVOID          DllBase;                    // +0x030
    PVOID          EntryPoint;                 // +0x038
    ULONG          SizeOfImage;                // +0x040
    UNICODE_STRING FullDllName;                // +0x048
    UNICODE_STRING BaseDllName;                // +0x058
} LDR_DATA_TABLE_ENTRY;
```

## Lua reference

Full function list with parameter details in [`docs/lua-reference.md`](lua-reference.md) under the **Process** category. Examples:

```lua
-- Disambiguate which Electron process is the renderer
for _, p in ipairs(getProcessList("electron")) do
    local info = getProcessInfo(p.pid)
    print(p.pid, info.command_line)
end

-- Find which process has a debugger attached
for _, p in ipairs(getProcessList()) do
    if isBeingDebugged(p.pid) then
        print("debugged:", p.pid, p.name)
    end
end

-- Read a target's environment variables without attaching
local env = getEnvironment(target_pid)
print(env.PATH, env.USERPROFILE, env.MY_DEBUG_FLAG)

-- Enumerate modules without opening a debug session
for i, m in ipairs(getModulesRemote(target_pid)) do
    print(string.format("%s @ 0x%X (%d bytes) %s", m.name, m.base, m.size, m.path))
end
```

## Constraints

| Concern | Behavior |
|---------|----------|
| Access denied (system/SYSTEM-owned processes) | Functions return empty tables or `nil`. The Lua caller decides how to react; we do not raise to the MCP layer. |
| Process exits mid-read | `ReadProcessMemory` returns `FALSE`; the affected field is dropped from the result. Other fields proceed. |
| 32-bit target from 64-bit server | Not supported. The PEB layout differs and we do not implement WOW64 translation. |
| Environment block exceeds 64 KiB | Truncated. The reader scans up to 64 KiB in 4 KiB chunks and stops at the first double-null terminator within a chunk. |
| Process has more than 1024 loaded modules | Truncated. `getModulesRemote` walks the loader list with a hard cap of 1024 entries. |
| Wide-string field exceeds 32 KiB | Truncated. `_read_remote_unicode_string` caps reads at 32 KiB to bound a corrupted `UNICODE_STRING.Length`. |
| Forwarded exports in remote modules | Not handled here. `getModulesRemote` returns the base/size/path tuple; forwarder resolution is the job of `resolveExport` against an attached process (see [`docs/hooking.md`](hooking.md)). |
| Handle leaks | None. Every call opens and closes its own handle. |
