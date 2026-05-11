"""Network utility functions for Lua engine.

Provides socket identification helpers for network traffic analysis.
"""

import socket
import struct
from typing import Callable

from ...session import SESSION


def build_network_functions(table_factory: Callable, log_error: Callable, output: list[str]) -> dict[str, Callable]:
    """Build Lua-callable network utility functions.

    Args:
        table_factory: Callable that creates Lua tables.
        log_error: Error logging function.
        output: Output list for print statements.

    Returns:
        Dict mapping Lua function names to Python callables.
    """

    def _parse_sockaddr(data: bytes) -> dict | None:
        """Parse a sockaddr_in or sockaddr_in6 structure."""
        if len(data) < 4:
            return None

        family = struct.unpack_from("<H", data, 0)[0]
        port = struct.unpack_from(">H", data, 2)[0]  # network byte order

        if family == 2:  # AF_INET
            if len(data) < 8:
                return None
            addr_bytes = data[4:8]
            addr_str = socket.inet_ntoa(addr_bytes)
            return {"addr": addr_str, "port": port, "family": "IPv4"}
        elif family == 23:  # AF_INET6
            if len(data) < 24:
                return None
            addr_bytes = data[8:24]
            addr_str = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            return {"addr": addr_str, "port": port, "family": "IPv6"}

        return None

    def _parse_result_value(result: dict) -> int | None:
        """Extract integer return value from execute_code result dict."""
        if not result.get("success"):
            return None
        raw = result["result"]
        return int(raw, 16) if isinstance(raw, str) else int(raw)

    def get_socket_info(socket_handle):
        """Lua: getSocketInfo(socket_handle) -> {remote_addr, remote_port, local_addr, local_port, family}"""
        try:
            from ...tools.execute import execute_code
            from ...utils.pe import resolve_export

            sock = int(socket_handle)

            # Resolve ws2_32 exports
            getpeername_addr = resolve_export("WS2_32.dll", "getpeername")
            getsockname_addr = resolve_export("WS2_32.dll", "getsockname")
            if not getpeername_addr or not getsockname_addr:
                return None

            # Allocate buffers: sockaddr_in6 is 28 bytes, allocate 32 for alignment
            # Two sockaddr buffers + two namelen ints
            buf_size = 32 + 32 + 4 + 4  # peer_addr, local_addr, peer_len, local_len
            buf_addr = SESSION.allocate(buf_size, executable=False)
            if not buf_addr:
                return None

            try:
                peer_addr_buf = buf_addr
                local_addr_buf = buf_addr + 32
                peer_len_ptr = buf_addr + 64
                local_len_ptr = buf_addr + 68

                # Write initial namelen values (28 = sizeof(sockaddr_in6))
                SESSION.write_bytes(peer_len_ptr, struct.pack("<I", 28))
                SESSION.write_bytes(local_len_ptr, struct.pack("<I", 28))

                # Call getpeername(socket, sockaddr*, namelen*)
                peer_result = execute_code(getpeername_addr, [sock, peer_addr_buf, peer_len_ptr])
                # Call getsockname(socket, sockaddr*, namelen*)
                local_result = execute_code(getsockname_addr, [sock, local_addr_buf, local_len_ptr])

                result = table_factory()
                family_set = False

                # Parse peer address
                peer_ret = _parse_result_value(peer_result)
                if peer_ret is not None and peer_ret == 0:
                    peer_data = SESSION.read_bytes(peer_addr_buf, 28)
                    peer_info = _parse_sockaddr(peer_data)
                    if peer_info:
                        result["remote_addr"] = peer_info["addr"]
                        result["remote_port"] = peer_info["port"]
                        result["family"] = peer_info["family"]
                        family_set = True

                # Parse local address
                local_ret = _parse_result_value(local_result)
                if local_ret is not None and local_ret == 0:
                    local_data = SESSION.read_bytes(local_addr_buf, 28)
                    local_info = _parse_sockaddr(local_data)
                    if local_info:
                        result["local_addr"] = local_info["addr"]
                        result["local_port"] = local_info["port"]
                        if not family_set:
                            result["family"] = local_info["family"]

                return result
            finally:
                SESSION.free(buf_addr)
        except:
            log_error("getSocketInfo", Exception("socket info lookup failed"))
            return None

    return {
        "getSocketInfo": get_socket_info,
    }
