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
        engine = ctx.engine

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
        }
