---
title: "Security model"
description: "Target process effects, plugin execution, and local data locations."
---

memscope-mcp runs as a local stdio server process started by the MCP client. That process holds the target process handle, the Lua engine, and activated Python plugins, so every capability below executes with the Windows access rights granted to the server process. No additional sandbox layer separates these components.

## Target process effects

After attachment, the server can read typed values and arbitrary bytes, write typed values and bytes, change target page protection, allocate/free target memory, create remote threads, call native functions, install inline hooks, and capture target buffers.

Before attachment, PEB helpers can read process command lines, environment variables, debugger state, image paths, and remote module lists with separate query/read handles. Environment and command-line data can contain credentials or personal data.

## Plugin execution

An activated `.py` file runs as Python in the server process. It can use the supported session context and any imports that its host permissions allow. The loader provides opt-in activation, deterministic filename ordering, atomic namespace publication, and failure isolation; it does not sandbox plugin code.

Activation scans only `$MEMSCOPE_HOME/plugins/*.py`. `memscope-mcp install-plugin <name>` copies a bundled source there without overwriting an existing file; `memscope-mcp install-plugin <name> --force` overwrites the activated copy. Package upgrades preserve activated copies and refresh them only through that explicit `--force` operation.

## Local data

Session logs can contain tool summaries, error details, paths, and structured plugin diagnostics. Saved scripts contain executable Lua. Netcap recordings contain target packet metadata and captured payloads. All artifacts live under `MEMSCOPE_HOME` (`~/.memscope-mcp` by default); a session-specific `MEMSCOPE_HOME` separates experiment artifacts from long-lived data.

Netcap recording names, process components, roots, and selected files use Windows handle validation, exact leaf spelling, and fail-closed checks. Canonical writes never modify the legacy fallback. The filesystem boundary prevents accidental traversal and alias escape and validates the named boundaries; it is not a defense against a malicious concurrent process with the same principal.

## Reporting

Report unintended host execution, boundary escape, path corruption, secret disclosure, or supply-chain weakness through [SECURITY.md](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/SECURITY.md).

See [Read and write memory](/guides/read-and-write-memory/), [Capture calls](/guides/capture-function-calls/), [Plugin troubleshooting](/plugins/troubleshooting/), and [Security support](/support/security/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/concepts/security-model.md)
