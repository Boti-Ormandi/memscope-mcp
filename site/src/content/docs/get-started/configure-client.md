---
title: "Configure an MCP client"
description: "Configure VS Code on Windows to start memscope-mcp over stdio with a fresh data root."
---

The examples below use VS Code on Windows. VS Code stores workspace MCP configuration in `.vscode/mcp.json`; its current MCP schema uses a top-level `servers` object and a stdio entry with `type`, `command`, and optional `env` fields. See the [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

## 1. Create a fresh data root

Before VS Code starts the server, create a new directory and keep its resolved path:

```powershell
$home = Join-Path $env:TEMP ("memscope-mcp-first-session-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $home | Out-Null
$home
```

A fresh root contains no activated plugin files. The server will create its session-log directory after startup.

## 2. Add the VS Code workspace configuration

Open a disposable or otherwise selected VS Code workspace. Run **MCP: Open Workspace Folder MCP Configuration** from the Command Palette, then write `.vscode/mcp.json` with the absolute path printed above:

```json
{
  "servers": {
    "memscope": {
      "type": "stdio",
      "command": "memscope-mcp",
      "env": {
        "MEMSCOPE_HOME": "C:\\Users\\you\\AppData\\Local\\Temp\\memscope-mcp-first-session-<new-id>"
      }
    }
  }
}
```

`command` must resolve in the environment where VS Code runs; use the full path to `memscope-mcp.exe` if it is not on `PATH`. Keep the generated `MEMSCOPE_HOME` entry in place before the first start. Activated `.py` files under that root's `plugins` directory would load at server startup.

## 3. Start and list the server

Run **MCP: List Servers**, select `memscope`, and start it. Confirm that the client lists exactly 11 tools before selecting a target. The bare command and `memscope-mcp server` start the same local stdio server.

## Other MCP clients

Other MCP clients use the same executable and environment but may use a different configuration filename and top-level schema. Their equivalent server entry must launch `memscope-mcp`, pass a fresh `MEMSCOPE_HOME` before startup, reserve stdin/stdout for MCP traffic, and read diagnostics from stderr. Check the chosen client's current documentation for its exact configuration location and schema.

Continue with [Connect to a process and read its PE signature](/get-started/first-session/).
