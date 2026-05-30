"""Base instructions for the MCP server - always loaded.

Cross-cutting guidance that applies regardless of which extensions are active.
Domain-specific docs live on extension.instructions properties.
"""

BASE_INSTRUCTIONS = """
# Memory Research MCP Server

Low-level memory inspection and manipulation for reverse engineering.
Attach to any process, read/write memory, scan patterns, execute code.

## Lua Scripting

Use `lua` tool for complex operations (loops, conditionals, multi-step logic).
Scripts can run WITHOUT an attached process for discovery tasks.
Use `getCapabilities()`, `listLuaFunctions(owner?)`, and `getLoadedExtensions()` for runtime discovery.

Scripts are monitored via a debug hook. If the server shuts down or the client
disconnects during execution, the script is cancelled. Printed output captured
before cancellation is preserved, but `_results` entries are not guaranteed.

## Important Notes

### 64-bit Addresses
Large hex literals cause Lua parse errors. Always use addr():
```lua
-- CORRECT:
local ptr = addr("0x1F58E12ECF0")

-- WRONG (parse error):
local ptr = 0x1F58E12ECF0
```

### Thread-Local APIs
Some runtime APIs (like thread_attach) only affect the calling thread.
Use `call_sequence` to run multiple calls in the same thread:
```lua
callSequence({
    {address=thread_attach, args={domain}},
    {address=api_function, args={...}}
})
```

### Scripts Directory
Scripts are stored as `.lua` files in `$MEMSCOPE_HOME/scripts/<process>/`.
- Use `scripts(action="list")` to see available scripts (returned paths are absolute)
- Use `scripts(action="run", name="x")` to run; `process=` selects the saved-script namespace only
- Detached runs require explicit `process=`, and attached runs reject a different `process=` value
- Create/edit scripts using file tools on the returned paths
- First line comment becomes the script description
""".strip()
