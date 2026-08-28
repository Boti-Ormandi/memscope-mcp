---
title: "Security support"
description: "Report unintended security behavior through the private advisory route."
---

For a vulnerability, use the private advisory route in [`SECURITY.md`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/SECURITY.md):

<https://github.com/Boti-Ormandi/memscope-mcp/security/advisories/new>

Do not include real process dumps, credentials, environment blocks, captured packets, recordings, plugin source, or session logs unless the recipient explicitly requests a redacted sample. Prefer a disposable target and data root.

The [security model](/concepts/security-model/) documents target process effects, plugin execution, local data locations, and Netcap's same-principal concurrency boundary. The security policy distinguishes that documented behavior from unintended host execution, boundary escape, path corruption, secret disclosure, or supply-chain weakness.

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/support/security.md)
