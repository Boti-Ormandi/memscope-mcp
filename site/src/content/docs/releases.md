---
title: "Releases"
description: "Package metadata, GitHub Release history, and release workflow checks."
---

Published versions and release notes are listed in [GitHub Releases](https://github.com/Boti-Ormandi/memscope-mcp/releases). The version embedded in a Python distribution comes from [`pyproject.toml`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/pyproject.toml).

## Checks before publication

The [`release.yml`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/.github/workflows/release.yml) workflow runs the Windows Python test matrix and Ruff before building and checking the distribution. The separate [`site.yml`](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/.github/workflows/site.yml) workflow builds and installs the current wheel, compares its 11 MCP tools with `site/tools.json`, checks the generated tool reference, builds the site, and runs static, browser, and accessibility tests for pull requests and main-branch updates.

The release workflow publishes the Python package; neither workflow deploys the Astro site. See [Contributing](/contribute/) for the commands used during development.
