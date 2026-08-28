---
title: "Releases"
description: "Current release guidance and links to version-specific GitHub Release history."
---

Release materials are separate from evergreen product documentation. This page describes the boundary at a high level so contributors know where a change belongs.

## Source of truth

- README and `docs/**` describe current behavior, operations, and support.
- `SECURITY.md` and `CONTRIBUTING.md` define reporting and contribution policy.
- Release notes describe version-specific changes and belong in the project release materials.
- Site content mirrors the repository pages through the routes in [the site route inventory](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/site-routes.md).

Do not add availability claims, version-history tables, package publication claims, external service identity, or release-specific transition instructions to evergreen pages.

## Maintainer checks

Maintainers review source, tests, docs, package metadata, and distribution checks together. They run the required platform checks on a clean tree, verify the 11-tool surface and plugin/Netcap contracts, prepare release-specific notes separately, and use authenticated publication systems under their own authority.

Contributors do not add credentials, upload source or target data, change publication configuration, or publish packages/sites as part of an ordinary code or documentation change.

See [Contributing](/contribute/), [Compatibility](/support/compatibility/), and [Security support](/support/security/).

---

[View this page's repository source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/docs/releases.md)
