# Documentation URLs

The Astro/Starlight site builds the Markdown files listed below directly from `site/src/content/docs/`. Site URLs use trailing slashes.

Base: <https://memscope.esrc.dev/>

| URL path | Markdown source |
| --- | --- |
| `/` | [`site/src/content/docs/index.md`](../site/src/content/docs/index.md) |
| `/get-started/install/` | [`site/src/content/docs/get-started/install.md`](../site/src/content/docs/get-started/install.md) |
| `/get-started/configure-client/` | [`site/src/content/docs/get-started/configure-client.md`](../site/src/content/docs/get-started/configure-client.md) |
| `/get-started/first-session/` | [`site/src/content/docs/get-started/first-session.md`](../site/src/content/docs/get-started/first-session.md) |
| `/get-started/permissions-and-data/` | [`site/src/content/docs/get-started/permissions-and-data.md`](../site/src/content/docs/get-started/permissions-and-data.md) |
| `/guides/discover-and-attach/` | [`site/src/content/docs/guides/discover-and-attach.md`](../site/src/content/docs/guides/discover-and-attach.md) |
| `/guides/read-and-write-memory/` | [`site/src/content/docs/guides/read-and-write-memory.md`](../site/src/content/docs/guides/read-and-write-memory.md) |
| `/guides/scan-memory/` | [`site/src/content/docs/guides/scan-memory.md`](../site/src/content/docs/guides/scan-memory.md) |
| `/guides/saved-scripts/` | [`site/src/content/docs/guides/saved-scripts.md`](../site/src/content/docs/guides/saved-scripts.md) |
| `/guides/inspect-before-attach/` | [`site/src/content/docs/guides/inspect-before-attach.md`](../site/src/content/docs/guides/inspect-before-attach.md) |
| `/guides/capture-function-calls/` | [`site/src/content/docs/guides/capture-function-calls.md`](../site/src/content/docs/guides/capture-function-calls.md) |
| `/guides/use-plugins/` | [`site/src/content/docs/guides/use-plugins.md`](../site/src/content/docs/guides/use-plugins.md) |
| `/plugins/overview/` | [`site/src/content/docs/plugins/overview.md`](../site/src/content/docs/plugins/overview.md) |
| `/plugins/authoring/` | [`site/src/content/docs/plugins/authoring.md`](../site/src/content/docs/plugins/authoring.md) |
| `/plugins/lifecycle-and-contract/` | [`site/src/content/docs/plugins/lifecycle-and-contract.md`](../site/src/content/docs/plugins/lifecycle-and-contract.md) |
| `/plugins/upgrading/` | [`site/src/content/docs/plugins/upgrading.md`](../site/src/content/docs/plugins/upgrading.md) |
| `/plugins/troubleshooting/` | [`site/src/content/docs/plugins/troubleshooting.md`](../site/src/content/docs/plugins/troubleshooting.md) |
| `/plugins/il2cpp/` | [`site/src/content/docs/plugins/il2cpp.md`](../site/src/content/docs/plugins/il2cpp.md) |
| `/plugins/netcap/` | [`site/src/content/docs/plugins/netcap.md`](../site/src/content/docs/plugins/netcap.md) |
| `/reference/mcp-tools/` | [`site/src/content/docs/reference/mcp-tools/index.md`](../site/src/content/docs/reference/mcp-tools/index.md) |
| `/reference/lua/` | [`site/src/content/docs/reference/lua.md`](../site/src/content/docs/reference/lua.md) |
| `/reference/scanning/` | [`site/src/content/docs/reference/scanning.md`](../site/src/content/docs/reference/scanning.md) |
| `/reference/plugin-api/` | [`site/src/content/docs/reference/plugin-api.md`](../site/src/content/docs/reference/plugin-api.md) |
| `/reference/cli-and-paths/` | [`site/src/content/docs/reference/cli-and-paths.md`](../site/src/content/docs/reference/cli-and-paths.md) |
| `/reference/errors-and-status/` | [`site/src/content/docs/reference/errors-and-status.md`](../site/src/content/docs/reference/errors-and-status.md) |
| `/concepts/architecture/` | [`site/src/content/docs/concepts/architecture.md`](../site/src/content/docs/concepts/architecture.md) |
| `/concepts/session-lifecycle/` | [`site/src/content/docs/concepts/session-lifecycle.md`](../site/src/content/docs/concepts/session-lifecycle.md) |
| `/concepts/extension-composition/` | [`site/src/content/docs/concepts/extension-composition.md`](../site/src/content/docs/concepts/extension-composition.md) |
| `/concepts/security-model/` | [`site/src/content/docs/concepts/security-model.md`](../site/src/content/docs/concepts/security-model.md) |
| `/support/troubleshooting/` | [`site/src/content/docs/support/troubleshooting.md`](../site/src/content/docs/support/troubleshooting.md) |
| `/support/compatibility/` | [`site/src/content/docs/support/compatibility.md`](../site/src/content/docs/support/compatibility.md) |
| `/support/security/` | [`site/src/content/docs/support/security.md`](../site/src/content/docs/support/security.md) |
| `/contribute/` | [`site/src/content/docs/contribute.md`](../site/src/content/docs/contribute.md) |
| `/releases/` | [`site/src/content/docs/releases.md`](../site/src/content/docs/releases.md) |

The MCP tool page is generated from `site/tools.json` by `mcp-site tools render`. Use the paths above for site links. Markdown under `site/src/content/docs/` uses root-relative site links; links to repository files use explicit GitHub URLs.
