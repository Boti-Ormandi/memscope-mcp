"""Network utility functions for socket identification."""

from typing import Callable

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.lua.network import build_network_functions


class NetworkExtension(LuaExtension):
    """Socket identification helpers for network traffic analysis."""

    name = "network"
    description = "Network utility functions for socket identification"

    instructions = """
## Network Utilities

### Socket Identification

```lua
local info = getSocketInfo(socket_handle)
-- Returns: {remote_addr, remote_port, local_addr, local_port, family}
-- family is "IPv4" or "IPv6"
-- Returns nil on error or if socket is not connected
```

Use after hooking network functions to identify which connection a socket belongs to.
Calls getpeername/getsockname in the target process.
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        return build_network_functions(ctx.table_factory, ctx.log_error, ctx.engine._output)
