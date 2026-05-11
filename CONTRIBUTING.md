# Contributing to memscope-mcp

## Philosophy

memscope-mcp is built for AI agents, not humans. This drives design decisions:

- **Minimal toolset** -- 10 core tools, not 100. New tools must provide capabilities that can't be achieved with existing tools + Lua.
- **Lua for complexity** -- Multi-step logic belongs in Lua scripts, not new MCP tools.
- **Generic core** -- Domain-specific code belongs in plugins, not `src/`. Keep the core runtime/target-agnostic.
- **AI context efficiency** -- Instructions cost tokens. Be concise. Use "Available when:" markers for conditional features.
- **Scripts persist, addresses don't** -- ASLR invalidates addresses on restart. Save the finder script, not the address.

## What We Accept

- Bug fixes
- New Lua functions that add real capability
- Domain plugins (in `contrib/plugins/`)
- Performance improvements
- Documentation clarity

## What We Don't Accept

- Convenience wrappers around existing tools
- GUI or visualization features
- Domain-specific code in core (use the plugin system)
- Features that bloat AI context without clear value

When in doubt, open an issue first.

## Code Style

Enforced by [ruff](https://docs.astral.sh/ruff/) (linting + formatting). Pre-commit hooks run automatically.

```bash
pip install -e ".[dev]"
pre-commit install
```

This installs git hooks that run `ruff check --fix` and `ruff format` on every commit. CI also checks this on PRs.

Rules are configured in `pyproject.toml`. Key settings:
- Line length: 120
- Rules: E, F, W, I (pycodestyle, pyflakes, isort)
- E722 (bare except) is allowed -- intentional in memory read code

Beyond formatting:
- Type hints on function signatures
- Docstrings with Args/Returns on public functions
- Follow patterns in `src/tools/` for new tools
- Follow `contrib/plugins/il2cpp.py` for new plugins

## Adding a Tool

1. Create function in `src/tools/your_tool.py`
2. Import and wrap with `@mcp.tool()` in `src/server.py`
3. Add docstring (this becomes the AI-facing documentation)
4. Update README

## Adding Lua Functions

1. Register in the appropriate module under `src/tools/lua/`
2. Document in `src/instructions/base.py`
3. Return `nil` on failure (Lua convention)
4. Handle both int and string address formats

## Plugins

Drop a `.py` file into the `plugins/` directory at the project root and restart the server. All `.py` files there are loaded at startup; their Lua functions and AI documentation are registered automatically. Plugins ship in `contrib/plugins/`; users activate them by copying into `plugins/`.

### Plugin Interface

A plugin is a single `.py` file with a class that extends `PluginBase`:

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
        self.table = engine.lua.table  # for creating Lua tables
        return {
            "readMyThing": self._read_thing,
        }

    def _read_thing(self, address):
        try:
            addr = int(address)
            return SESSION.read_int32(addr + 0x10)
        except Exception:
            return None
```

- **name**: short identifier (e.g. `"il2cpp"`)
- **description**: one-line summary for log output
- **instructions**: AI-facing documentation appended to the server's instructions
- **register(engine)**: called once at startup. Returns a dict mapping Lua function names to callables. Use `engine.lua.table` to create Lua table return values.

### Plugin Guidelines

- Single `.py` file extending `PluginBase`
- Use only generic SESSION methods (`read_ptr`, `read_int32`, `read_bytes`, etc.)
- Hold domain-specific state on the plugin instance, not on SESSION
- Handle errors gracefully -- return `None` on failure
- No dependencies beyond what's in `pyproject.toml`

Plugins ship in `contrib/plugins/`, not `plugins/`. Users activate them by copying into `plugins/`.

## PR Process

1. Fork and branch
2. `pip install -e ".[dev]" && pre-commit install`
3. Make focused changes (one logical change per commit)
4. Run `pytest tests/` and `ruff check src/ contrib/ tests/`
5. Submit PR with description of what and why
6. Address review feedback

## License

By contributing, you agree your contributions will be licensed under the MIT License.
