# Security policy

memscope-mcp is a Windows process-memory tool. Reading or modifying the selected process and running activated extensions are intended product behavior. Use private security reports for defects that affect another process, unrelated host data, or the package and plugin supply chain.

## Private reporting

Submit a report through GitHub private security advisories:

<https://github.com/Boti-Ormandi/memscope-mcp/security/advisories/new>

Include the affected behavior, Windows and target conditions, a minimal reproduction, impact, and any known mitigation. Remove unrelated process dumps, credentials, tokens, packet payloads, recordings, plugin source, and session logs from the report.

## Intended selected-target behavior

For the exact process selected by name and PID, and subject to the Windows permissions of the server process, memscope-mcp can:

- open process handles and read or write target memory;
- change target page protection and allocate or free target memory;
- create remote threads and call native target functions;
- install user-mode inline hooks and capture registers or bounded buffers;
- read PEB command lines, environment variables, debugger state, and module data;
- execute saved Lua and activated Python plugins; and
- persist session logs, saved scripts, captures, and recordings under `MEMSCOPE_HOME`.

Activated plugin files load as Python when the server starts. Netcap recording paths use validated Windows components and held handles, but a concurrent process running as the same Windows principal can operate on the same filesystem objects.

## Security defect classes

Private security reports are appropriate for defects that cause:

- an operation to affect a process other than the selected target or escape a requested memory/filesystem boundary;
- host-side code execution that is not the direct result of an activated plugin or an explicit documented execution operation;
- unintended disclosure through diagnostics, logs, generated artifacts, or protocol responses;
- corruption of unrelated host files or data roots;
- bypass of the documented plugin activation, path-validation, or process-selection boundaries; or
- compromise of package, plugin, build, release, or dependency integrity.

See the [security model](https://memscope.esrc.dev/concepts/security-model/) for execution and data behavior, or [security support](https://memscope.esrc.dev/support/security/) for the private report link.
