---
title: "Configure an MCP client"
description: "Start memscope-mcp over stdio from an MCP-compatible client."
---

After installing Memscope, configure an MCP-compatible client to start the local console command over stdio.

## Minimal client entry

```json
{
  "mcpServers": {
    "memscope": {
      "command": "memscope-mcp"
    }
  }
}
```

The bare command and `memscope-mcp server` start the same server. Keep stdin and stdout reserved for MCP traffic. Diagnostics and the startup data-root line use stderr.

Memscope exposes no HTTP transport, browser client, hosted API, authentication form, or remote runtime asset. The MCP client owns the child process and stdio connection.

## Confirm the surface

The server advertises exactly 11 tools. Review the [MCP tool reference](/reference/mcp-tools/) for schemas and the [CLI and paths reference](/reference/cli-and-paths/) for the resolved data root.

## Select an exact target

Use `processes` to filter by name, PID, parent PID, or service. When several processes share a name, select an exact PID. Pre-attach PEB inspection returns command lines, environment variables, executable paths, and module paths.

Continue with the [first-session guide](/get-started/first-session/).

---

[Source: getting-started guide](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/getting-started.md#2-configure-the-mcp-client)
