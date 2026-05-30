"""General Lua helpers: address parsing, formatting, results, bitwise, timing."""

from typing import Callable

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.lua.comparisons import parse_hex_address, safe_eq, safe_ge, safe_gt, safe_int, safe_le, safe_lt, safe_ne
from ...tools.lua.utilities import (
    bit_and,
    bit_extract,
    bit_lshift,
    bit_not,
    bit_or,
    bit_rshift,
    bit_xor,
    lua_clock,
    lua_sleep,
)
from ...utils.memory_utils import is_valid_pointer


class GeneralExtension(LuaExtension):
    """Address parsing, formatting, results collection, bitwise ops, timing."""

    name = "general"
    description = "General Lua helpers"

    instructions = """
### Utilities

```lua
toHex(val)           -- Convert to hex string
fmt("0x%X", val)     -- String format
print(...)           -- Output to results
addResult(key, val)  -- Add to results dict
setResult(val)       -- Set single result value
addr("0x...")        -- Parse large hex (see below)
parseHex("0x...")    -- Alias for addr()
isNil(x)             -- nil check
orZero(x)            -- x or 0
orEmpty(x)           -- x or ""
isValidPointer(val)  -- Check valid user-mode pointer
clock()              -- High-resolution timer (milliseconds)
sleep(ms)            -- Pause execution
listLuaFunctions(owner?)  -- Registered {name, owner} entries
getLoadedExtensions()     -- Extension/plugin owner names in load order
getCapabilities()         -- Attached state, paths, wrapper flags
```

### 64-bit Safe Comparisons

```lua
safeEq(a, b)    safeNe(a, b)    safeLt(a, b)    safeGt(a, b)
safeLe(a, b)    safeGe(a, b)    safeIsZero(x)   safeNotZero(x)
safeInt(val)                      -- val if small int, else nil
```

### Bitwise Operations

```lua
band(a, b)               -- AND
bor(a, b)                -- OR
bxor(a, b)               -- XOR
bnot(a)                  -- NOT (32-bit)
lshift(a, n)             -- Left shift
rshift(a, n)             -- Logical right shift
bextract(val, offset, width?)  -- Extract bit field (width default 1)
```

Lua 5.4 also supports native operators: `a & b`, `a | b`, `a ~ b`, `a << n`, `a >> n`.
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        self._engine = ctx.engine
        self._session = ctx.session
        self._table = ctx.table_factory
        engine = self._engine

        return {
            # Address parsing
            "addr": parse_hex_address,
            "parseHex": parse_hex_address,
            # Formatting
            "toHex": engine._to_hex,
            "fmt": engine._safe_format,
            # Output
            "print": engine._lua_print,
            # Results
            "addResult": engine._add_result,
            "setResult": engine._set_result,
            # Nil helpers
            "isNil": lambda x: x is None,
            "orZero": lambda x: x if x is not None else 0,
            "orEmpty": lambda x: x if x is not None else "",
            # Validation
            "isValidPointer": lambda x: x is not None and x != 0 and is_valid_pointer(int(x)) if x else False,
            # Timing
            "clock": lua_clock,
            "sleep": lua_sleep,
            # Bitwise
            "band": bit_and,
            "bor": bit_or,
            "bxor": bit_xor,
            "bnot": bit_not,
            "lshift": bit_lshift,
            "rshift": bit_rshift,
            "bextract": bit_extract,
            # Safe 64-bit comparisons
            "safeEq": safe_eq,
            "safeNe": safe_ne,
            "safeLt": safe_lt,
            "safeGt": safe_gt,
            "safeLe": safe_le,
            "safeGe": safe_ge,
            "safeIsZero": lambda x: x is None or x == 0,
            "safeNotZero": lambda x: x is not None and x != 0,
            "safeInt": safe_int,
            # Debug
            "enableDebug": lambda: setattr(engine, "_debug_errors", True),
            "disableDebug": lambda: setattr(engine, "_debug_errors", False),
            "getLastError": lambda: engine._last_error,
            # Discovery
            "listLuaFunctions": self._list_lua_functions,
            "getLoadedExtensions": self._get_loaded_extensions,
            "getCapabilities": self._get_capabilities,
        }

    def _mapping_table(self, values: dict):
        result = self._table()
        for key, value in values.items():
            result[key] = value
        return result

    def _list_lua_functions(self, owner=None):
        owner_filter = str(owner) if owner not in (None, "") else None
        result = self._table()
        index = 1
        for name, function_owner in self._engine._function_registry.items():
            if owner_filter is not None and function_owner != owner_filter:
                continue
            result[index] = self._mapping_table({"name": name, "owner": function_owner})
            index += 1
        return result

    def _get_loaded_extensions(self):
        result = self._table()
        seen = set()
        index = 1
        for owner in self._engine._function_registry.values():
            if owner in seen:
                continue
            seen.add(owner)
            result[index] = owner
            index += 1
        return result

    def _get_capabilities(self):
        from ...paths import LOGS_DIR, MEMSCOPE_HOME, PLUGINS_DIR, SCRIPTS_DIR
        from ...utils.logger import LOGGER

        caps = self._table()
        attached = self._session.pm is not None
        caps["attached"] = attached

        if attached:
            caps["process"] = self._mapping_table(
                {
                    "pid": self._session.pid,
                    "name": self._session.target_process or "",
                    "module_count": len(self._session.modules),
                }
            )

        caps["paths"] = self._mapping_table(
            {
                "memscope_home": str(MEMSCOPE_HOME),
                "logs_dir": str(LOGS_DIR),
                "scripts_dir": str(SCRIPTS_DIR),
                "plugins_dir": str(PLUGINS_DIR),
                "session_log": str(LOGGER._get_log_file()),
            }
        )
        caps["wrappers"] = self._mapping_table(
            {
                "tool_count": 10,
                "error_normalization": True,
                "scan_options": True,
                "dump_options": True,
                "module_paths": True,
                "script_namespace_selection": True,
            }
        )
        return caps
