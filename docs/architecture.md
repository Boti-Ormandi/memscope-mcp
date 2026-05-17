# Architecture and internals

A tour of the memscope-mcp codebase: where things live, the design rules that shape it, and how each subsystem is built. For installation and usage, see the top-level README. For the function-level API surface, see [`lua-reference.md`](lua-reference.md).

## Repository layout

```
memscope_mcp/
  server.py              # MCP tool definitions (thin wrappers + session logging)
  session.py             # Process attach/detach, memory primitives, threads,
                         #   VirtualProtect, allocate_near, suspend/resume,
                         #   lifecycle callbacks
  extensions/            # Generic LuaExtension contract + bootstrap
    base.py              # LuaExtension ABC and ExtensionContext
    bootstrap.py         # Core extension + user plugin registration
    core/                # Always-loaded extensions
      general.py memory.py module_scan.py execution.py
      hooking.py process.py network.py
  tools/
    memory.py            # Smart memory dump
    scanning.py          # AOB pattern scanning
    pointers.py          # Pointer chain resolution
    types.py             # Typed memory read/write
    execute.py           # Remote code execution
    hooking.py           # HookManager: ring buffer + install/remove/cleanup
    lua_scripts.py       # Script persistence
    lua/                 # Lua engine and themed function modules
  plugins/               # PluginBase (specialization of LuaExtension) + loader
  instructions/          # AI context builder (base + extensions + plugins)
  utils/
    shellcode.py         # x64 codegen: native calls + hook trampolines
    disasm.py            # Table-driven x64 length decoder + RIP-relative relocation
    pe.py                # PE export resolver (resolveExport)
    peb.py               # PEB reader: cmdline, env, debugger, remote modules
    memory_utils.py heuristics.py logger.py pointers.py
  _contrib/plugins/      # Bundled reference plugins (il2cpp, netcap)
scripts/                 # Saved Lua scripts per process (gitignored)
logs/                    # Session logs in JSONL format (gitignored)
docs/
  architecture.md        # This document
  hooking.md             # Inline hooking architecture
  peb.md                 # PEB introspection design
  lua-reference.md       # Full Lua function reference
```

The split that matters most is `memscope_mcp/extensions/core/` vs `memscope_mcp/_contrib/plugins/`. Core extensions register on every server start and their failure is fatal. Bundled plugins ship inside the wheel under `_contrib/` so `memscope-mcp install-plugin` can copy them into the user data directory, but they only activate when the user opts in by placing the file in `$MEMSCOPE_HOME/plugins/`.

## Design philosophy

Five rules shape what goes into the codebase and what stays out.

**Generic core, plugins for domains.** No target-specific code lives in `memscope_mcp/`. Game engine helpers, network protocol parsers, managed-runtime walkers all belong in plugins. The core ships primitives; plugins specialize them.

**Minimal tool surface.** Ten well-shaped MCP tools, with Lua for everything that needs composition. Adding an MCP tool is a real decision -- the smoke suite pins the count.

**One contract, two activation paths.** Core features and user plugins both implement `LuaExtension`. Core extensions are always loaded and their registration failure is hard. User plugins are gated on file presence in `$MEMSCOPE_HOME/plugins/` and isolated on failure.

**AI context is expensive.** Plugin instructions are only appended to the AI-facing documentation when the plugin is active. The MCP `instructions` channel is token-priced; the project treats it that way.

**Scripts persist, addresses don't.** ASLR shifts everything on every restart. The persistence layer saves Lua finder scripts per process, not raw addresses. The agent reuses the finder.

## Subsystems

### Inline function hooking with shared ring buffer

Hook any user-mode function by address, capture register args plus optional buffer data, and read the capture stream from Lua -- without DLL injection. `HookManager` ([`memscope_mcp/tools/hooking.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/tools/hooking.py)) reads the target's function prologue through a table-driven x64 instruction length decoder ([`memscope_mcp/utils/disasm.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/utils/disasm.py)), allocates an RWX trampoline page within +-2 GiB of the target so a 5-byte `JMP rel32` patch suffices, and falls back to a 14-byte `JMP [RIP+0]` with thread-suspension + IP redirect when near allocation fails. RIP-relative prologue instructions are rewritten by the relocator so the displaced bytes still resolve to the original target. All hooks share one lock-free ring buffer in target memory; writes claim slots with `lock cmpxchg`, overflow drops without blocking, and a status field gates partial reads.

Full architecture in [`hooking.md`](hooking.md).

### PEB introspection without attaching

`getProcessInfo`, `isBeingDebugged`, `getEnvironment`, and `getModulesRemote` read the Process Environment Block of any process the server can open with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` -- no debug session, no injection, no leaked handles. The reader ([`memscope_mcp/utils/peb.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/utils/peb.py)) is pure ctypes: `NtQueryInformationProcess(ProcessBasicInformation)` returns the PEB base, then `ReadProcessMemory` walks `ProcessParameters` (cmdline, cwd, environment), the `BeingDebugged` byte, and the `Ldr.InLoadOrderModuleList` linked list. The `processes` MCP tool surfaces the per-entry command line directly, which means filters like `processes(filter="electron")` distinguish renderer / GPU / browser instances without further work.

Full structure layout in [`peb.md`](peb.md).

### x64 shellcode generation

`executeCode` and `callSequence` work by assembling raw x64 machine code in the target process. The codegen ([`memscope_mcp/utils/shellcode.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/utils/shellcode.py)) implements the Microsoft x64 calling convention end to end: 32-byte shadow space, 16-byte stack alignment before each `CALL`, RCX/RDX/R8/R9 for the first four integer arguments and XMM0-XMM3 for floats, stack spill for arguments past the fourth, and RAX (or XMM0 for float returns) captured into a thread-local result slot. The Lua wrapper smart-detects argument types: numeric strings become integer arguments, text strings are allocated as buffers in the target process and freed after the call.

The same module also produces hook trampolines (pre- and post-call capture with optional struct-deref for WSABUF-style buffer pointers and output-pointer deref), so both `executeCode` and the hooking layer share one codegen surface.

### Extension system

Core features and user plugins share one ABC: `LuaExtension` ([`memscope_mcp/extensions/base.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/extensions/base.py)). Each extension owns a name, a description, an AI-facing instructions fragment, a `register(ctx)` method that returns Lua function bindings, and optional `on_process_attached` / `on_process_detaching` lifecycle callbacks. The bootstrap ([`memscope_mcp/extensions/bootstrap.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/extensions/bootstrap.py)) instantiates the seven built-in extensions in order, loads any user plugins from `$MEMSCOPE_HOME/plugins/` (failures logged and isolated), wires the returned function dicts into the Lua engine, and assembles the instruction bundle.

The contract is what makes hooking, PEB introspection, netcap, and any future domain helper pluggable on the same shape. Plugins inherit from `PluginBase`, a thin `LuaExtension` specialization that adds activation gating; otherwise they behave identically to core extensions at runtime.

### PE export resolution

`resolveExport(module, name)` ([`memscope_mcp/utils/pe.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/utils/pe.py)) reads the PE export directory directly from target memory and binary-searches the sorted name pointer table. Forwarded exports are resolved recursively with a depth cap of 5. The hooking layer uses this to find addresses like `ws2_32!WSARecv` without symbol files or AOB-scanning known entry points.

### Transparent reconnection

A reverse-engineering session typically outlives the target process. `DebugSession.ensure_attached` ([`memscope_mcp/session.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/session.py)) polls the cached handle with `GetExitCodeProcess` on every tool call; if the process has exited, it transparently re-opens by name and re-caches modules. Tools never surface a "process disappeared" error on a transient restart.

### Lua large-hex preprocessor

Lua 5.4 has 64-bit integers, but its parser still rejects hex literals beyond 32 bits -- `local p = 0x1F58E12ECF0` is a syntax error. The engine's preprocessor ([`memscope_mcp/tools/lua/engine.py`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/tools/lua/engine.py)) rewrites such literals to `addr("0x...")` calls, but only after protecting long strings, single- and double-quoted strings, and already-wrapped `addr()` / `parseHex()` calls from accidental rewrite. Scripts can paste raw 64-bit addresses verbatim without manual wrapping.

### Service-to-PID enumeration via SCM

Identifying which `svchost.exe` hosts a given Windows service is normally a multi-step chore. The `processes` tool calls `EnumServicesStatusExW` through the Service Control Manager and joins the result onto the process list, so `processes(service="EventLog")` returns the right PID in one call. Lazy-loaded: the SCM enumeration only runs when a query actually needs it.
