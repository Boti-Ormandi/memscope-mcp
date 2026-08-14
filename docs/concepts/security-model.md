# Security model

memscope-mcp is an operator-controlled research tool, not a sandbox. Its trust boundary includes the MCP client, the server process, the target process, the local data root, activated Python plugins, and any captured target data.

## Intended target powers

After attachment, the server can read typed values and arbitrary bytes, write typed values and bytes, change target page protection, allocate/free target memory, create remote threads, call native functions, install inline hooks, and capture target buffers. These effects are intentional and require operator authorization for the target.

Before attachment, PEB helpers can read process command lines, environment variables, debugger state, image paths, and remote module lists with separate query/read handles. Environment and command-line data can contain credentials or personal data.

## Plugin trust

An activated `.py` file runs as Python in the server process. It can use the supported session context and any imports that its host permissions allow. The loader provides opt-in activation, deterministic filename ordering, atomic namespace publication, and failure isolation; it does not turn plugin code into an untrusted sandbox.

Review bundled or locally authored plugin files before activation. Keep activated copies under a controlled `MEMSCOPE_HOME/plugins/` directory, and refresh them only after reviewing local changes with an explicit `memscope-mcp install-plugin <name> --force` command.

## Data trust

Session logs can contain tool summaries, error details, paths, and structured plugin diagnostics. Saved scripts contain executable Lua. Netcap recordings contain target packet metadata and captured payloads. Protect the data root and use a disposable root for experiments.

Netcap recording names, process components, roots, and selected files use Windows handle validation, exact leaf spelling, and fail-closed checks. Canonical writes never modify the legacy fallback. The filesystem boundary prevents accidental traversal and alias escape and validates the named boundaries; it is not a defense against a malicious concurrent process with the same principal.

## Operational practice

1. Start with discovery and read-only inspection.
2. Confirm the exact PID and target authorization.
3. Prefer `verify=true` for MCP writes when a writable range, pre-image, readback, and rollback attempt are useful.
4. Use small, reversible target changes and keep backups outside the target when appropriate.
5. Bound native calls and hooks, and stop them before detaching.
6. Review plugin source and local file changes before activation or refresh.
7. Keep logs and captures out of public issue reports.
8. Report unintended host, boundary, supply-chain, path, or secret-disclosure behavior through [SECURITY.md](../../SECURITY.md).

See [Read and write memory](../guides/read-write.md), [Capture calls](../guides/capture-calls.md), [Plugin troubleshooting](../plugins/troubleshooting.md), and [Security support](../support/security.md).
