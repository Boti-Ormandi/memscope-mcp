# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in memscope-mcp, please report it
privately via GitHub's security advisory mechanism:

https://github.com/Boti-Ormandi/memscope-mcp/security/advisories/new

Do not file public issues for security reports.

You should expect an acknowledgement within 7 days. Coordinated disclosure
timelines are negotiated case-by-case based on severity and complexity.

## Supported versions

Only the latest released minor version receives security fixes. Older
versions are not patched.

## Scope

This project is a Windows-only memory research tool. It directly reads,
writes, and patches memory in attached processes by design. Reports about
"the tool can modify process memory" or "the tool can install hooks" are
working-as-intended and not security issues; reports about flaws that allow
unintended escalation, code execution in the host running memscope-mcp itself,
or supply-chain weaknesses in the package distribution are in scope.
