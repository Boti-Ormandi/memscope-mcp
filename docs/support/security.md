# Security support

For a vulnerability, use the private advisory route in [`SECURITY.md`](../../SECURITY.md):

<https://github.com/Boti-Ormandi/memscope-mcp/security/advisories/new>

Do not include real process dumps, credentials, environment blocks, captured packets, recordings, plugin source, or session logs unless the recipient explicitly requests a redacted sample. Prefer a disposable target and data root.

The [security model](../concepts/security-model.md) explains intended process-memory powers, plugin trust, local-data sensitivity, and Netcap's same-principal concurrency boundary. The security policy distinguishes those intended powers from unintended host execution, boundary escape, path corruption, secret disclosure, or supply-chain weakness.
