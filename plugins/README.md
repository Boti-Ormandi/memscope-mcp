# Plugins

User-curated domain helpers for memscope-mcp. Drop a `.py` file in this directory and restart the server; the loader discovers every `.py` file at startup, instantiates the `PluginBase` subclass it finds, registers the plugin's Lua functions, and appends the plugin's instructions to the AI-facing documentation.

This directory ships empty. Plugins live in `contrib/plugins/` and are activated by copying:

```bash
cp ../contrib/plugins/il2cpp.py .
```

`plugins/*.py` is gitignored so user activations don't show up as repo noise.

## Interface

A plugin is a single `.py` file containing one `PluginBase` subclass:

```python
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

    def register(self, engine) -> dict[str, callable]:
        self.table = engine.lua.table
        return {"readMyThing": self._read_thing}

    def _read_thing(self, address):
        try:
            addr = int(address)
            return SESSION.read_int32(addr + 0x10)
        except Exception:
            return None
```

**Required attributes:**

- `name` — short identifier used in logs (e.g. `"il2cpp"`)
- `description` — one-line summary printed at load time
- `instructions` — Markdown appended to the MCP `instructions` channel. Open with an `**Available when: <condition>**` line so the agent knows when this plugin is relevant; without that, the docs cost tokens even on unrelated targets.

**Required method:**

- `register(engine)` — called once at startup. Return a dict mapping Lua function names to Python callables. Use `engine.lua.table()` to build Lua tables for return values.

## Guidelines

- Single `.py` file. No new dependencies beyond what's in `pyproject.toml`.
- Memory access goes through `SESSION` methods (`read_ptr`, `read_int32`, `read_bytes`, etc.). Don't reach into pymem directly.
- Hold domain-specific state on the plugin instance, not on `SESSION`.
- Return `None` on failure rather than raising — match the rest of the Lua surface.
- Don't add new MCP tools from a plugin. Plugins extend the Lua surface; new tools belong in `src/server.py` (see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-mcp-tool)).

## Reference plugin

[`contrib/plugins/il2cpp.py`](../contrib/plugins/il2cpp.py) is a working example covering Unity's IL2CPP runtime structures (strings, arrays, lists, dictionaries, thread attachment). It's a useful template for any plugin that has to walk a managed-runtime object layout.

## Security

Plugins execute arbitrary Python code at server startup with the privileges of the MCP server process. Only activate plugins you have read and trust. A plugin can do anything the server can — open processes, read and write memory, allocate executable pages, spawn threads in target processes.
