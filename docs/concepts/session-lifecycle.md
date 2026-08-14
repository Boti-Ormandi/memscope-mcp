# Session lifecycle

A `DebugSession` binds the MCP and Lua operations to one Windows process handle, one target spelling, one PID, one immutable module snapshot, and one attachment generation. The session is detached until a successful `attach` or `attach`-equivalent operation publishes those values.

## Attach and switch

`attach(process_name, pid?)` and Lua `attach(target, pid?)` use the canonical switch path:

1. retire the current attachment and cancel active scan leases;
2. fire detach callbacks while the old process handle is still available;
3. close old target resources;
4. open the requested process and build a module snapshot;
5. publish a new generation and fire attach callbacks.

A failed open leaves the session detached. A successful open sets the target process name and PID and gives the snapshot a monotonically increasing generation identity.

## Module refresh

`modules(refresh=true)` rebuilds the snapshot on the existing process handle. Refresh retires active scan leases, publishes a new generation and snapshot, and keeps the same process handle. It does not fire process attach or detach callbacks. Use refresh when module membership changes without a process switch.

## Reconnection

Before ordinary attached operations, the session checks process liveness. If the process exits, the session retires the old attachment and attempts to reopen by the remembered target name or PID policy. A reopened process receives a new PID/snapshot/generation and attach callbacks run for the new handle.

## Scan leases

A scan acquires a stable lease containing the process handle, PID, target process spelling, module snapshot, generation, cancellation event, and attachment identity. Detach, switch, refresh, and reconnect signal cancellation and wait until every active lease releases before replacing the identity. A scan reports `TARGET_CHANGED` or a corresponding status when the lifecycle changes during execution.

## Lua composition ownership

One `MemscopeLuaEngine` owns one session composition. The engine becomes ready only after all core mappings, accepted plugin mappings, and lifecycle callbacks commit. A failed or interrupted composition becomes permanently quarantined; a second engine cannot claim the same session. The engine hides its bound session until the ready commit.

## Attach and detach callbacks

Callbacks are registered as a copy-on-write batch and invoked from a stable snapshot without holding the session lock. Callback failures are isolated and logged. A callback can register work for a later callback snapshot, but it cannot replace a composition callback. `on_process_attached` runs after a successful attach/switch; `on_process_detaching(session, process_alive)` runs before the process handle closes and receives whether cleanup can still call the live target.

Plugins keep process-bound state on the plugin instance and release hooks, allocations, capture buffers, and other handles in `on_process_detaching`. See [Plugin lifecycle](../plugins/lifecycle.md), [Extension composition](extension-composition.md), and [Inline hooking](../hooking.md).
