# Plugins

User-curated domain helpers for memscope-mcp. Drop a `.py` file in this directory and restart the server; the loader discovers every `.py` file at startup, instantiates the `PluginBase` subclass it finds, registers the plugin's Lua functions, and appends the plugin's instructions to the AI-facing documentation.

`PluginBase` is a thin specialization of `LuaExtension` (the same contract used by built-in core features under `src/extensions/core/`). The activation path is what differs: core extensions are always loaded; plugins are user-curated, isolated on failure, and loaded only when their file is present here.

This directory ships empty. Plugins live in `contrib/plugins/` and are activated by copying:

```bash
cp ../contrib/plugins/il2cpp.py .
# or
cp ../contrib/plugins/netcap.py .
```

`plugins/*.py` is gitignored so user activations don't show up as repo noise.

## Interface

A plugin is a single `.py` file containing one `PluginBase` subclass:

```python
from src.extensions.base import ExtensionContext
from src.plugins import PluginBase
from src.session import SESSION

class MyPlugin(PluginBase):
    name = "my_domain"
    description = "Helpers for My Domain"

    instructions = """
    ## My Domain Helpers
    **Available when: mydomain.dll present in modules**

    ```lua
    readMyThing(addr)  -- Read a domain-specific structure
    ```
    """

    def register(self, ctx: ExtensionContext) -> dict[str, callable]:
        self.table = ctx.table_factory
        return {"readMyThing": self._read_thing}

    def _read_thing(self, address):
        try:
            addr = int(address)
            return SESSION.read_int32(addr + 0x10)
        except Exception:
            return None
```

**Required attributes:**

- `name` -- short identifier used in logs (e.g. `"il2cpp"`)
- `description` -- one-line summary printed at load time
- `instructions` -- Markdown appended to the MCP `instructions` channel. Open with an `**Available when: <condition>**` line so the agent knows when this plugin is relevant; without that, the docs cost tokens even on unrelated targets.

**Required method:**

- `register(ctx)` -- called once at startup. Return a dict mapping Lua function names to Python callables. `ctx` is an `ExtensionContext` with `engine`, `session`, `lua`, `table_factory`, and `log_error`.

**Optional lifecycle callbacks** (override when the plugin holds process-bound state such as hooks or allocations):

- `on_process_attached(session)` -- fires after a successful attach/switch.
- `on_process_detaching(session, process_alive)` -- fires before the session closes the handle. `process_alive=True` means cleanup in the target is still possible; `False` means the process has already exited and only local state should be cleared.

## Guidelines

- Single `.py` file. No new dependencies beyond what's in `pyproject.toml`.
- Memory access goes through `SESSION` methods (`read_ptr`, `read_int32`, `read_bytes`, etc.). Don't reach into pymem directly.
- Hold domain-specific state on the plugin instance, not on `SESSION`.
- Return `None` on failure rather than raising -- match the rest of the Lua surface.
- Don't add new MCP tools from a plugin. Plugins extend the Lua surface; new tools belong in `src/server.py` (see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-mcp-tool)).
- Plugins can build on the hooking primitives in `src/tools/hooking.py` (`HOOK_MANAGER`). Register an `on_process_detaching` callback if your plugin installs hooks so they get removed when the process detaches.

## Reference plugins

[`contrib/plugins/il2cpp.py`](../contrib/plugins/il2cpp.py) -- Unity IL2CPP runtime helpers (strings, arrays, lists, dictionaries, thread attachment). Useful template for plugins that walk a managed-runtime object layout.

[`contrib/plugins/netcap.py`](../contrib/plugins/netcap.py) -- Winsock capture and analysis built on the generic hooking layer (`HOOK_MANAGER`). Exposes `startCapture` / `readPackets` / stream assembly / protocol framing / cross-reference search / session recording. Useful template for plugins that hook a known API surface and add protocol-aware parsing on top. See the Netcap section in [`../docs/lua-reference.md`](../docs/lua-reference.md#netcap-plugin) and the architecture in [`../docs/hooking.md`](../docs/hooking.md).

## Security

Plugins execute arbitrary Python code at server startup with the privileges of the MCP server process. Only activate plugins you have read and trust. A plugin can do anything the server can -- open processes, read and write memory, allocate executable pages, spawn threads in target processes.
