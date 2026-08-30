---
title: "Extension composition"
description: "Transactional core and plugin registration into one ready Lua namespace."
---

Core extensions and activated plugins share the `LuaExtension` contract. The bootstrap composes one ready Lua namespace from seven core extensions followed by the activated plugin files.

## Registration transaction

Bootstrap creates a session-bound `ExtensionContext`, stages each complete Lua mapping, validates every name and callable, checks extension-name and function-name collisions, inspects lifecycle intent, and commits the accepted mappings and callbacks as one composition.

No accepted plugin mapping or lifecycle callback becomes visible before the final commit. A collision or registration exception skips the affected ordinary plugin as a unit; an earlier accepted plugin remains active. A core extension failure, a plugin `BaseException`, or a shared commit failure quarantines the composition instead of exposing a partial supported namespace.

## Failure isolation

The plugin loader isolates ordinary import, metadata, construction, registration, and lifecycle failures. It emits a bounded structured diagnostic on stderr and in the session log, then continues with core extensions and later activated files. The diagnostic contract is documented in [Plugin troubleshooting](/plugins/troubleshooting/).

The plugin loader uses sorted activated **filenames**, not declared plugin names. This ordering matters when two files declare the same extension name or Lua function: the earlier file wins and the later collision is isolated.

## Context boundary

A plugin imports `PluginBase`, `ExtensionContext`, and `LuaExtension` from the supported package modules. Registration receives the session-bound fields `ctx.session`, `ctx.table_factory`, and `ctx.hook_manager`.

The raw Lua runtime is private. `ExtensionContext.lua`, `ctx.lua`, `ctx.engine.lua`, `memscope_mcp.tools.hooking.HOOK_MANAGER`, module-level `SESSION`, and module/session globals are not supported plugin interfaces. Use the context fields and store state on the extension instance.

`ctx.table_factory` constructs Lua tables only during engine-owned bootstrap or execution callbacks. Do not retain the factory as a route to a raw runtime, and do not construct tables from arbitrary background threads.

## Ready and failed states

The engine composition has four logical states:

- **Unbound:** generic direct registration and execution are available.
- **Bootstrapping:** registration owns the engine; execution and public registration are closed.
- **Ready:** mappings, callbacks, and the session claim are committed; saved scripts and Lua execution are available.
- **Failed:** the composition is permanently quarantined after a hard bootstrap failure.

The session claim is identity-based. A second engine cannot reuse a claimed session, and a ready engine cannot bootstrap again.

See [Plugin API](/reference/plugin-api/), [Plugin lifecycle](/plugins/lifecycle-and-contract/), and [Session lifecycle](/concepts/session-lifecycle/).
