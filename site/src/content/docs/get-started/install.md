---
title: "Install memscope-mcp"
description: "Prepare a Windows x64 host and install the memscope-mcp package."
---

Memscope runs as a local stdio MCP server on Windows. Prepare the host before configuring a client or selecting a target.

## Requirements

- Windows x64 host and x64 target processes.
- A 64-bit Python 3.10 or newer interpreter.
- An MCP-compatible client with stdio support.
- Sufficient Windows permissions for the selected process and operation.

Windows access checks still apply after the server starts. A process can deny query, VM-read, VM-write, thread, or debug-related operations.

## Install the package

Install from the package source configured for your environment:

```powershell
python -m pip install memscope-mcp
```

Confirm the console entry point resolves and inspect the local data paths:

```powershell
memscope-mcp paths
```

The bare command starts the same stdio server as `memscope-mcp server`. It does not open a network listener.

## Next step

[Configure your MCP client](/get-started/configure-client/) to start the console command over stdio. [Permissions and local data](/get-started/permissions-and-data/) documents Windows access checks and data-root locations.
