"""Remote code execution, memory allocation."""

from typing import Callable

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.lua.code_execution import (
    alloc_lua,
    call_sequence_lua,
    call_sequence_results_lua,
    execute_code_ex_lua,
    execute_code_lua,
    free_memory_lua,
)


class ExecutionExtension(LuaExtension):
    """executeCode, callSequence, alloc, freeMemory."""

    name = "execution"
    description = "Remote code execution and memory allocation"

    instructions = """
### Code Execution

```lua
executeCode(func, arg1, arg2, ...)  -- Call function
executeCodeEx(flags, timeout, func, ...)  -- Extended call with options
callSequence({{address=x, args={...}}, ...})  -- Multi-call in ONE thread
callSequenceResults(calls, timeout?)  -- Same, but returns per-call results
allowUnsafeCodeExecution(true)  -- Disable rate limit for the current script
alloc(64)        -- Allocate N bytes
alloc("string")  -- Allocate string
alloc("string", true)  -- Allocate wide string (UTF-16)
freeMemory(addr) -- Free allocation
```
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        engine = ctx.engine
        log_err = engine._log_error

        def _allow_unsafe(enabled=True) -> bool:
            engine._execution_guard.allow_unsafe = bool(enabled)
            return engine._execution_guard.allow_unsafe

        funcs = {
            "executeCode": lambda func, *args: execute_code_lua(
                func, args, engine._output, log_err, engine._execution_guard
            ),
            "executeCodeEx": lambda flags, timeout, func, *args: execute_code_ex_lua(
                flags, timeout, func, args, engine._output, log_err, engine._execution_guard
            ),
            "callSequence": lambda calls, timeout=5000: call_sequence_lua(calls, timeout, engine._output, log_err),
            "callSequenceResults": lambda calls, timeout=5000: call_sequence_results_lua(
                calls, timeout, ctx.table_factory, engine._output, log_err
            ),
            "allowUnsafeCodeExecution": _allow_unsafe,
            "alloc": lambda size_or_str, wide=False: alloc_lua(size_or_str, wide, engine._output),
            "freeMemory": lambda addr: free_memory_lua(addr, log_err),
        }

        # Aliases for consistency
        funcs["call"] = funcs["executeCode"]
        funcs["allocateMemory"] = funcs["alloc"]
        funcs["allocString"] = funcs["alloc"]
        funcs["freeString"] = funcs["freeMemory"]
        funcs["free"] = funcs["freeMemory"]

        return funcs
