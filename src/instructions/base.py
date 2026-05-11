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

Scripts are monitored via a debug hook. If the server shuts down or the client
disconnects during execution, the script is cancelled and partial results
(output and addResult calls made before cancellation) are preserved.

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
Scripts are stored as `.lua` files in `scripts/<process>/`.
- Use `scripts(action="list")` to see available scripts
- Use `scripts(action="run", name="x")` to run
- Create/edit scripts using file tools on the returned paths
- First line comment becomes the script description
""".strip()
