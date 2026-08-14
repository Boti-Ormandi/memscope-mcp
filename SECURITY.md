# Security policy

memscope-mcp is a Windows process-memory research tool. Reports about its intended ability to inspect or modify an authorized target are not security defects by themselves. Reports about unintended access, host compromise, unsafe isolation, or supply-chain weakness are security reports.

## Reporting a vulnerability

Use GitHub's private security advisory mechanism:

<https://github.com/Boti-Ormandi/memscope-mcp/security/advisories/new>

Do not disclose vulnerability details in a public issue. Include the affected behavior, host and target conditions, a minimal reproduction that avoids real user data, impact, and any mitigation that is already known. Redact process dumps, credentials, tokens, captured packets, plugin source, and other sensitive material from the report; share a disposable reproduction when possible.

The project acknowledges reports within 7 days. Coordinated disclosure timing is agreed case by case according to severity, exploitability, and fix complexity.

## Supported-version policy

Security fixes target the current supported minor line. Older lines may not receive security fixes. Keep the server, its dependencies, the MCP client, and activated plugins under local change control, and review package and plugin changes before use.

## Intended powers and reportable defects

The following powers are part of the product contract when the operator has authorization:

- opening a process handle and reading process memory;
- writing typed values or bytes to target memory;
- changing target page protection and allocating or freeing target memory;
- creating remote threads and calling target-native functions;
- installing user-mode inline hooks and collecting registers or bounded buffers;
- reading PEB command lines, environment variables, debugger state, and remote modules;
- running Python plugin code in the server process; and
- storing session logs, saved scripts, packet captures, and recordings under the configured data root.

A report becomes security-relevant when a defect lets an operation escape its requested target or boundary, causes unintended host-side code execution, bypasses an authorization or trust boundary, leaks secrets through diagnostics or logs, corrupts unrelated files, or weakens package/plugin supply-chain integrity.

Plugin files are executable Python supplied by the operator. Installing a plugin is a trust decision; review the file and its imports before activation. Netcap recordings use validated Windows path components and held handles, but the boundary is not a security boundary against a malicious concurrent process running as the same principal. See the [security model](docs/concepts/security-model.md) for the complete scope and residuals.
