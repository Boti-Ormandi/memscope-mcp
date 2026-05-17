"""Network capture plugin - Winsock hooking and packet analysis.

Hooks ws2_32.dll send/recv/WSASend/WSARecv/sendto/recvfrom and optionally
connect/closesocket/accept/bind to capture network traffic. Supports IOCP async
correlation, UDP, packet filtering, and header-only mode.

Built on the generic hooking infrastructure from Phase 1.
Activate by copying this file to the plugins/ directory.
"""

import gzip
import ipaddress
import json
import struct
import time
from pathlib import Path
from typing import Any, Callable

from memscope_mcp.extensions.base import ExtensionContext
from memscope_mcp.plugins import PluginBase
from memscope_mcp.session import SESSION
from memscope_mcp.tools.hooking import HOOK_MANAGER
from memscope_mcp.utils.pe import resolve_export

# ==================== Hook Specifications ====================

# Microsoft x64 calling convention: arg0=rcx(1), arg1=rdx(2), arg2=r8(3), arg3=r9(4)
# hookFunction uses 1-indexed args to match Lua convention.

WINSOCK_HOOKS = {
    "send": {
        "module": "ws2_32.dll",
        "export": "send",
        "type": "pre",
        "buffer_arg": 2,  # rdx = buf ptr
        "length_arg": 3,  # r8 = len
    },
    "recv": {
        "module": "ws2_32.dll",
        "export": "recv",
        "type": "post",
        "buffer_arg": 2,  # rdx = buf ptr
        "length_arg": 0,  # return value = bytes received
    },
}

WSA_HOOKS = {
    "WSASend": {
        "module": "ws2_32.dll",
        "export": "WSASend",
        "type": "post",
        "buffer_arg": 2,  # arg1 (rdx) = LPWSABUF; captures 16-byte struct
        "length_arg": -1,  # fixed length
        "max_capture": 16,  # sizeof(WSABUF) on x64
        "stack_args": [6],  # OVERLAPPED* (Lua-indexed)
        "deref_args": {4: 4},  # *lpNumberOfBytesSent (arg3), 4 bytes
    },
    "WSARecv": {
        "module": "ws2_32.dll",
        "export": "WSARecv",
        "type": "post",
        "buffer_arg": 2,  # arg1 (rdx) = LPWSABUF; captures 16-byte struct
        "length_arg": -1,
        "max_capture": 16,
        "stack_args": [6],  # OVERLAPPED*
        "deref_args": {4: 4},  # *lpNumberOfBytesRecvd (arg3), 4 bytes
    },
}

UDP_HOOKS = {
    "sendto": {
        "module": "ws2_32.dll",
        "export": "sendto",
        "type": "pre",
        "buffer_arg": 2,  # arg1 (rdx) = data buffer
        "length_arg": 3,  # arg2 (r8) = data length
        "stack_args": [5, 6],  # sockaddr* (to), tolen
    },
    "recvfrom": {
        "module": "ws2_32.dll",
        "export": "recvfrom",
        "type": "post",
        "buffer_arg": 2,  # arg1 (rdx) = data buffer
        "length_arg": 0,  # return value = bytes received
        "stack_args": [5, 6],  # sockaddr* (from), fromlen*
    },
}

CONNECT_HOOKS = {
    "connect": {
        "module": "ws2_32.dll",
        "export": "connect",
        "type": "pre",
        "buffer_arg": 2,  # rdx = sockaddr ptr
        "length_arg": 3,  # r8 = namelen
    },
    "closesocket": {
        "module": "ws2_32.dll",
        "export": "closesocket",
        "type": "pre",
        "buffer_arg": -1,
        "length_arg": -1,
    },
}

LIFECYCLE_HOOKS = {
    "accept": {
        "module": "ws2_32.dll",
        "export": "accept",
        "type": "post",
        "buffer_arg": 2,  # arg1 (rdx) = client sockaddr (output)
        "length_arg": -1,
        "max_capture": 28,  # sizeof(sockaddr_in6)
    },
    "bind": {
        "module": "ws2_32.dll",
        "export": "bind",
        "type": "pre",
        "buffer_arg": 2,  # arg1 (rdx) = local sockaddr (input)
        "length_arg": 3,  # arg2 (r8) = namelen
    },
}

IOCP_HOOKS = {
    "GetQueuedCompletionStatus": {
        "module": "kernel32.dll",
        "export": "GetQueuedCompletionStatus",
        "type": "post",
        "buffer_arg": -1,
        "length_arg": -1,
        "deref_args": {2: 4, 4: 8},  # *arg1 (bytes_transferred, 4B), *arg3 (overlapped_ptr, 8B)
    },
}

# All data hooks merged for validation and header-only size inference
ALL_DATA_HOOKS = {**WINSOCK_HOOKS, **WSA_HOOKS, **UDP_HOOKS}
ALL_INFRA_HOOKS = {**CONNECT_HOOKS, **LIFECYCLE_HOOKS, **IOCP_HOOKS}

_DIRECTION_MAP = {
    "send": "send",
    "recv": "recv",
    "WSASend": "send",
    "WSARecv": "recv",
    "sendto": "send",
    "recvfrom": "recv",
    "connect": "connect",
    "closesocket": "close",
    "accept": "accept",
    "bind": "bind",
}

AF_INET = 2
AF_INET6 = 23

WSABUF_LEN_OFFSET = 0  # uint32
WSABUF_BUF_OFFSET = 8  # pointer (uint64)


# ==================== Helpers ====================


def _lua_table_to_list(table) -> list[int]:
    """Convert a Lua sequential table to a Python list of ints."""
    result = []
    i = 1
    while True:
        try:
            val = table[i]
            if val is None:
                break
            result.append(int(val))
            i += 1
        except (KeyError, IndexError):
            break
    return result


def _lua_table_to_string_list(table) -> list[str]:
    """Convert a Lua sequential table to a Python list of strings."""
    result = []
    i = 1
    while True:
        try:
            val = table[i]
            if val is None:
                break
            result.append(str(val))
            i += 1
        except (KeyError, IndexError):
            break
    return result


def _compress_ipv6(addr: str) -> str:
    """Compress an IPv6 address string."""
    try:
        return str(ipaddress.IPv6Address(addr))
    except ValueError:
        return addr


def _lua_table_to_bytes(table) -> bytes:
    """Convert a Lua byte table (1-indexed) to Python bytes."""
    result = bytearray()
    i = 1
    while True:
        try:
            val = table[i]
            if val is None:
                break
            result.append(int(val))
            i += 1
        except (KeyError, IndexError):
            break
    return bytes(result)


def _parse_socket_arg(socket_hex) -> int:
    """Parse a socket argument (hex string or integer) to int."""
    if isinstance(socket_hex, str):
        return int(socket_hex, 16) if socket_hex.startswith("0x") else int(socket_hex)
    return int(socket_hex)


# ==================== Value Encoding for Cross-Reference Search ====================

_SEARCH_TYPE_FORMATS = {
    "uint8": "<B",
    "int8": "<b",
    "uint16": "<H",
    "int16": "<h",
    "uint32": "<I",
    "int32": "<i",
    "uint64": "<Q",
    "int64": "<q",
    "float": "<f",
    "double": "<d",
    "uint16be": ">H",
    "int16be": ">h",
    "uint32be": ">I",
    "int32be": ">i",
}


def _encode_search_value(value_type: str, value) -> bytes | None:
    """Encode a value to its binary representation for search."""
    fmt = _SEARCH_TYPE_FORMATS.get(value_type)
    if fmt is None:
        return None
    try:
        v = float(value) if value_type in ("float", "double") else int(value)
        return struct.pack(fmt, v)
    except (struct.error, OverflowError, ValueError):
        return None


# ==================== Stream Buffer ====================


class StreamBuffer:
    """Per-socket, per-direction byte accumulation buffer."""

    __slots__ = ("send_buffer", "recv_buffer", "send_total", "recv_total")

    def __init__(self):
        self.send_buffer: bytearray = bytearray()
        self.recv_buffer: bytearray = bytearray()
        self.send_total: int = 0
        self.recv_total: int = 0


# ==================== Plugin ====================


class NetcapPlugin(PluginBase):
    """Winsock network capture built on generic hooking infrastructure."""

    name = "netcap"
    description = "Winsock network capture"

    instructions = """
## Network Capture (netcap plugin)
**Available when:** ws2_32.dll present in target process modules

### Quick Start

```lua
startCapture()                           -- hooks send/recv + connect/closesocket
-- ... interact with the application ...
local packets = readPackets(50)          -- read captured traffic
stopCapture()                            -- remove hooks, free ring buffer
```

### startCapture

```lua
startCapture({
    hooks = {"send", "recv"},            -- which Winsock functions (default: both)
    connect = true,                      -- connect/closesocket (default: true)
    lifecycle = false,                   -- accept/bind tracking (default: false)
    iocp = nil,                          -- GQCS async correlation (default: auto with WSA)
    header_only = false,                 -- no buffer capture (default: false)
    buffer_size = 1048576,               -- ring buffer size in bytes (default: 1MB)
    max_packet_size = 4096,              -- max captured bytes per packet (default: 4KB)
})
```

Valid hooks: "send", "recv", "WSASend", "WSARecv", "sendto", "recvfrom".

### WSA Hooks (WSASend/WSARecv)

Hook scatter-gather Winsock functions. Buffer data is captured server-side from
the WSABUF struct -- slight data staleness is possible under high load.

```lua
startCapture({hooks = {"WSASend", "WSARecv"}})
-- IOCP (GetQueuedCompletionStatus) auto-enabled for async I/O
```

Async completions are automatically correlated: WSARecv pending operations
are matched with GQCS completions. Async packets have `async = true`.

### UDP (sendto/recvfrom)

```lua
startCapture({hooks = {"sendto", "recvfrom"}})
local packets = readPackets(50)
-- direction = "send" or "recv", remote address in getConnections()
```

### readPackets

```lua
local packets = readPackets(100)         -- read up to 100 packets
-- Each packet: {direction, socket, socket_hex, timestamp, size, captured,
--               result, caller, hook_name, data, data_hex, data_ascii}
```

- **direction**: "send", "recv", "connect", "close", "accept", "bind"
- **socket**: socket handle (integer)
- **caller**: return address formatted as "module.dll+0xOffset"
- **data**: byte table (1-indexed), data_hex/data_ascii: string previews (first 256 bytes)
- **result**: return value of the hooked function
- **async**: true for IOCP-correlated packets

### Packet Filtering

```lua
local filtered = filterPackets(packets, {
    direction = "send",
    min_size = 100,
    contains = {0x48, 0x54, 0x54, 0x50},  -- "HTTP"
})
```

Criteria: direction, socket, min_size, max_size, hook_name, contains (byte pattern).
All criteria are AND-combined.

### Header-Only Mode

```lua
startCapture({hooks = {"send", "recv"}, header_only = true})
-- No buffer data captured. ~13,000 entries per 1MB buffer.
-- Use for traffic pattern analysis before full capture.
```

### Connection Tracking

```lua
local conns = getConnections()
-- {["0x1A4"] = {remote_ip="140.82.112.22", remote_port=443, family="IPv4", type="client"}, ...}
```

Enhanced with `lifecycle = true`:
```lua
startCapture({hooks = {"send", "recv"}, lifecycle = true})
-- Hooks accept/bind for server-side socket tracking
-- type: "client" (connect), "server" (accept), "udp" (sendto/recvfrom)
-- local_ip/local_port available if bind was observed
```

### Buffer Parsing

Work on byte tables from packet.data:

```lua
unpackUInt16(data, offset)    unpackInt16(data, offset)
unpackUInt32(data, offset)    unpackInt32(data, offset)
unpackUInt64(data, offset)    unpackFloat(data, offset)
unpackDouble(data, offset)    unpackString(data, offset, maxlen?)
unpackBytes(data, offset, len) unpackVector3(data, offset)
```

Offsets are 1-indexed (Lua convention). All values are little-endian.

```lua
packUInt16(val)   packUInt32(val)   packInt32(val)
packUInt64(val)   packFloat(val)
```

```lua
bufferFind(data, {0x48, 0x54, 0x54, 0x50})    -- find "HTTP", returns offset or nil
bufferContains(data, pattern_bytes)             -- returns bool
bufferFindAll(data, pattern_bytes)              -- returns table of all offsets
```

### Statistics

```lua
captureStats()
-- {total, dropped, entries_pending, utilization_pct, active_hooks, connections}
```

### Stream Assembly

Accumulate packet data per-socket for protocol analysis. Buffers persist across
readPackets() calls.

```lua
feedPackets(packets)                        -- accumulate into stream buffers
local stream = getStream("0x1A4", "recv")   -- get accumulated recv data
-- stream: {data = byte_table, length = N, total_fed = M}

consumeStream("0x1A4", "recv", 48)         -- remove 48 bytes after parsing
listStreams()                               -- {["0x1A4"] = {send_length, recv_length, ...}}
clearStream("0x1A4")                        -- clear one socket
clearStream()                               -- clear all
```

Stream buffers cap at 1MB per direction per socket. Oldest bytes are discarded
when the cap is exceeded.

### Protocol Framing

Split a byte buffer into protocol messages. Works on stream data or raw packet data.

```lua
-- Length-prefixed framing (most common)
local msgs = splitLengthPrefixed(stream.data, {
    length_offset = 1,           -- 1-indexed offset of length field in header
    length_size = 2,             -- 1, 2, or 4 bytes
    header_size = 4,             -- total header size before payload
    endian = "little",           -- or "big" (default: "little")
    includes_header = false,     -- length includes header bytes? (default: false)
})
-- msgs.messages: [{offset, header, payload, payload_length, total_size}, ...]
-- msgs.remainder: unconsumed bytes (partial message at end)
-- msgs.consumed: bytes consumed (pass to consumeStream)

-- Delimiter-separated (e.g., HTTP headers with CRLF)
splitDelimited(data, {0x0D, 0x0A})
-- {segments = [{offset, data, length}, ...], remainder = N, consumed = M}

-- Fixed-size records
splitFixed(data, 64)
-- {messages = [{offset, data}, ...], remainder = N, consumed = M}
```

**Workflow:** readPackets -> feedPackets -> getStream -> split -> consumeStream

### Cross-Reference

Search for byte patterns or encoded values across all captured packet data.
The bridge between packet capture and memory analysis.

```lua
-- Find byte pattern across all packets
searchPackets(packets, {0x48, 0x54, 0x54, 0x50})    -- "HTTP"
-- Returns: [{packet_index, offset, direction, socket_hex, context_hex}, ...]

-- Find encoded value in packets
searchPacketsForValue(packets, "float", 100.0)
searchPacketsForValue(packets, "uint32", 0x1234)
searchPacketsForValue(packets, "uint16be", 443)      -- big-endian (network order)
-- Types: uint8, uint16, uint32, int32, float, double,
--        uint16be, uint32be, int32be (big-endian)
```

**Cross-layer workflow:**
1. Read a value from memory: `local hp = readFloat(player + 0x100)`
2. Find it in packets: `searchPacketsForValue(packets, "float", hp)`
3. The match tells you which packet carries that field and at what offset
4. Scan memory for the packet opcode: `AOBScan("pattern from packet header")`

### Session Recording

Persist readPackets output to disk for offline analysis and long captures.

```lua
startRecording("session1")              -- readPackets auto-saves to disk
startRecording("session1", {compress = true})           -- gzip on stop
startRecording("session1", {max_size_mb = 50})          -- rotate at 50MB
startRecording("session1", {compress = true, max_size_mb = 50})  -- both
-- ... capture and analyze as normal ...
stopRecording()
-- {path, total_entries, duration_seconds, parts, compressed}

listRecordings()                        -- list recordings for current process
listRecordings("*")                     -- list across all processes
local old = loadRecording("session1")   -- auto-detects .jsonl or .jsonl.gz
local page = loadRecording("session1", {offset = 100, limit = 50})  -- paginated
feedPackets(old)                        -- stream analysis works on recordings
searchPackets(old, {0xDE, 0xAD})        -- cross-reference works on recordings
```

Files: `scripts/<process>/recordings/<name>.jsonl` (or `.jsonl.gz` if compressed)
Rotation creates `<name>_part002.jsonl`, `<name>_part003.jsonl`, etc.

### Multi-Layer Hooking

Hook at multiple layers to see data at each stage. All events share one ring buffer.

```lua
-- Layer 1: Application-level function (game sends a chat message)
local app_send = AOBScanModule("GameAssembly.dll", "pattern...")
hookFunction(app_send[1], {name="ChatSend", type="pre", buffer_arg=2, length_arg=3})

-- Layer 2: SSL (plaintext HTTP/WebSocket)
local ssl_write = resolveExport("libssl-3-x64.dll", "SSL_write")
hookFunction(ssl_write, {name="SSL_write", type="pre", buffer_arg=2, length_arg=3})

-- Layer 3: Winsock (encrypted wire bytes)
startCapture({hooks={"send","recv"}})

-- Read all events, interleaved by timestamp:
local entries = readRingBuffer(100)
--   t=100: ChatSend     arg1=msg_ptr   data="Hello world"
--   t=102: SSL_write    arg1=buf_ptr   data="POST /chat HTTP/1.1\r\n..."
--   t=104: send         arg0=socket    data="17 03 03 00 4A ..."  (TLS record)
```

Common SSL library modules to look for:
- OpenSSL 3.x: `libssl-3-x64.dll` -> `SSL_write`, `SSL_read`
- OpenSSL 1.1: `libssl-1_1-x64.dll` -> `SSL_write`, `SSL_read`
- BoringSSL (Chrome): `chrome.dll` or similar -> not exported, find via pattern scan
- Schannel: `sspicli.dll` -> `EncryptMessage`, `DecryptMessage` (SSPI, complex)

For exported SSL functions, use `resolveExport`. For statically-linked SSL, pattern scan
for known function prologues.
""".strip()

    def __init__(self) -> None:
        self._table: Callable[..., Any] | None = None
        self._capture_active: bool = False
        self._created_ring_buffer: bool = False
        self._hook_ids: dict[str, int] = {}  # hook_name -> hook_id
        self._connections: dict[int, dict] = {}  # socket_handle -> connection info
        self._pending_io: dict[int, dict] = {}  # overlapped_ptr -> {socket, buf_ptr, ...}
        self._max_pending_io: int = 1000
        self._pending_io_ttl: float = 60.0  # seconds before stale entries are evicted
        self._max_packet_size: int = 4096
        self._header_only: bool = False
        self._streams: dict[int, StreamBuffer] = {}
        self._max_stream_size: int = 1024 * 1024  # 1MB per direction per socket
        self._recording_file = None
        self._recording_path: str | None = None
        self._recording_count: int = 0
        self._recording_start: float | None = None
        self._recording_compress: bool = False
        self._recording_max_size: int | None = None  # bytes, None = no limit
        self._recording_base_name: str | None = None  # filename stem for rotation
        self._recording_part: int = 1
        self._recording_dir: Path | None = None

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        self._table = ctx.table_factory
        return {
            # Capture control
            "startCapture": self._start_capture,
            "stopCapture": self._stop_capture,
            "readPackets": self._read_packets,
            "captureStats": self._capture_stats,
            "getConnections": self._get_connections,
            "filterPackets": self._filter_packets,
            # Unpack helpers
            "unpackUInt16": self._unpack_uint16,
            "unpackInt16": self._unpack_int16,
            "unpackUInt32": self._unpack_uint32,
            "unpackInt32": self._unpack_int32,
            "unpackUInt64": self._unpack_uint64,
            "unpackFloat": self._unpack_float,
            "unpackDouble": self._unpack_double,
            "unpackString": self._unpack_string,
            "unpackBytes": self._unpack_bytes,
            "unpackVector3": self._unpack_vector3,
            # Pack helpers
            "packUInt16": self._pack_uint16,
            "packUInt32": self._pack_uint32,
            "packInt32": self._pack_int32,
            "packUInt64": self._pack_uint64,
            "packFloat": self._pack_float,
            # Search helpers
            "bufferFind": self._buffer_find,
            "bufferContains": self._buffer_contains,
            "bufferFindAll": self._buffer_find_all,
            # Stream assembly
            "feedPackets": self._feed_packets,
            "getStream": self._get_stream,
            "consumeStream": self._consume_stream,
            "listStreams": self._list_streams,
            "clearStream": self._clear_stream,
            # Protocol framing
            "splitLengthPrefixed": self._split_length_prefixed,
            "splitDelimited": self._split_delimited,
            "splitFixed": self._split_fixed,
            # Cross-reference
            "searchPackets": self._search_packets,
            "searchPacketsForValue": self._search_packets_for_value,
            # Session recording
            "startRecording": self._start_recording,
            "stopRecording": self._stop_recording,
            "loadRecording": self._load_recording,
            "listRecordings": self._list_recordings,
        }

    def on_process_detaching(self, session: Any, process_alive: bool) -> None:
        """Clean up capture state before detach."""
        if self._capture_active:
            self._cleanup(process_alive)

    # ==================== Capture Control ====================

    def _start_capture(self, opts_table=None):
        """Lua: startCapture({hooks, connect, lifecycle, iocp, header_only, buffer_size, max_packet_size})"""
        if self._capture_active:
            raise RuntimeError("Capture already active. Call stopCapture() first.")

        # Parse options
        hooks_list = ["send", "recv"]
        track_connect = True
        track_lifecycle = False
        track_iocp = None  # auto
        header_only = False
        buffer_size = 1024 * 1024  # 1MB
        max_packet_size = 4096

        if opts_table is not None:
            # _opt: safely get from Lua table (returns None for missing keys)
            def _opt(key):
                try:
                    return opts_table[key]
                except (KeyError, IndexError):
                    return None

            if _opt("hooks") is not None:
                hooks_list = _lua_table_to_string_list(opts_table["hooks"])
            if _opt("connect") is not None:
                track_connect = bool(opts_table["connect"])
            if _opt("lifecycle") is not None:
                track_lifecycle = bool(opts_table["lifecycle"])
            if _opt("iocp") is not None:
                track_iocp = bool(opts_table["iocp"])
            if _opt("header_only") is not None:
                header_only = bool(opts_table["header_only"])
            if _opt("buffer_size") is not None:
                buffer_size = int(opts_table["buffer_size"])
            if _opt("max_packet_size") is not None:
                max_packet_size = int(opts_table["max_packet_size"])

        # Auto-enable IOCP when WSA hooks are present
        if track_iocp is None:
            track_iocp = any(h in hooks_list for h in ("WSASend", "WSARecv"))

        # Validate hook names
        valid_names = set(ALL_DATA_HOOKS.keys())
        for hook_name in hooks_list:
            if hook_name not in valid_names:
                raise ValueError(f"Unknown hook '{hook_name}'. Valid: {', '.join(sorted(valid_names))}")

        self._max_packet_size = max_packet_size
        self._header_only = header_only

        # Create ring buffer if needed
        if HOOK_MANAGER.ring_buffer is None:
            entry_total_size = 0x50 + max_packet_size  # header + data
            entry_count = (buffer_size - 0x100) // entry_total_size
            if entry_count < 4:
                raise ValueError(
                    f"buffer_size {buffer_size} too small for max_packet_size {max_packet_size}. "
                    f"Need at least {0x100 + 4 * entry_total_size} bytes."
                )
            # Round down to nearest power of 2
            entry_count = 1 << (entry_count.bit_length() - 1)
            entry_count = max(entry_count, 4)

            HOOK_MANAGER.create_ring_buffer(
                entry_count=entry_count,
                max_data_size=max_packet_size,
            )
            self._created_ring_buffer = True

        # Install hooks
        installed: dict[str, int] = {}
        try:
            # Install data hooks
            for hook_name in hooks_list:
                spec = ALL_DATA_HOOKS[hook_name]
                self._install_data_hook(hook_name, spec, max_packet_size, header_only, installed)

            # Install connect hooks (if connect=true)
            if track_connect:
                for hook_name, spec in CONNECT_HOOKS.items():
                    self._install_infra_hook(hook_name, spec, max_packet_size, installed, required=False)

            # Install lifecycle hooks (if lifecycle=true)
            if track_lifecycle:
                for hook_name, spec in LIFECYCLE_HOOKS.items():
                    self._install_infra_hook(hook_name, spec, max_packet_size, installed, required=False)

            # Install IOCP hook (if iocp=true)
            if track_iocp:
                for hook_name, spec in IOCP_HOOKS.items():
                    self._install_infra_hook(hook_name, spec, max_packet_size, installed, required=False)

        except Exception:
            # Rollback: remove any hooks we installed
            for hid in installed.values():
                try:
                    HOOK_MANAGER.remove_hook(hid)
                except Exception:
                    pass
            if self._created_ring_buffer and not HOOK_MANAGER.hooks:
                try:
                    HOOK_MANAGER.destroy_ring_buffer()
                except Exception:
                    pass
                self._created_ring_buffer = False
            raise

        self._hook_ids = installed
        self._connections = {}
        self._pending_io = {}
        self._capture_active = True

        return self._table(
            hooks_installed=len(installed),
            ring_buffer=hex(HOOK_MANAGER.ring_buffer.address),
            entries=HOOK_MANAGER.ring_buffer.entry_count,
        )

    def _install_data_hook(
        self, hook_name: str, spec: dict, max_packet_size: int, header_only: bool, installed: dict
    ) -> None:
        """Resolve and install a data hook (send/recv/WSA/UDP)."""
        addr = resolve_export(spec["module"], spec["export"])
        if addr is None:
            raise RuntimeError(
                f"Cannot resolve {spec['module']}!{spec['export']}. Is {spec['module']} loaded in the target process?"
            )

        hook_kwargs: dict[str, Any] = {
            "target_addr": addr,
            "name": hook_name,
            "hook_type": spec["type"],
            "buffer_arg": spec["buffer_arg"],
            "length_arg": spec["length_arg"],
            "max_capture": spec.get("max_capture", max_packet_size),
        }
        if spec.get("stack_args"):
            hook_kwargs["stack_args"] = spec["stack_args"]
        if spec.get("deref_args"):
            hook_kwargs["deref_args"] = spec["deref_args"]

        if header_only:
            hook_kwargs["buffer_arg"] = -1
            hook_kwargs["length_arg"] = -1
            hook_kwargs.pop("max_capture", None)

        result = HOOK_MANAGER.install_hook(**hook_kwargs)
        installed[hook_name] = result["hook_id"]

    def _install_infra_hook(
        self, hook_name: str, spec: dict, max_packet_size: int, installed: dict, required: bool = False
    ) -> None:
        """Resolve and install an infrastructure hook (connect/lifecycle/IOCP)."""
        addr = resolve_export(spec["module"], spec["export"])
        if addr is None:
            if required:
                raise RuntimeError(
                    f"Cannot resolve {spec['module']}!{spec['export']}. "
                    f"Is {spec['module']} loaded in the target process?"
                )
            return  # non-fatal

        hook_kwargs: dict[str, Any] = {
            "target_addr": addr,
            "name": hook_name,
            "hook_type": spec["type"],
            "buffer_arg": spec["buffer_arg"],
            "length_arg": spec["length_arg"],
            "max_capture": spec.get("max_capture", max_packet_size),
        }
        if spec.get("stack_args"):
            hook_kwargs["stack_args"] = spec["stack_args"]
        if spec.get("deref_args"):
            hook_kwargs["deref_args"] = spec["deref_args"]

        try:
            result = HOOK_MANAGER.install_hook(**hook_kwargs)
            installed[hook_name] = result["hook_id"]
        except Exception:
            if required:
                raise
            # non-fatal for optional infra hooks

    def _stop_capture(self):
        """Lua: stopCapture()"""
        if not self._capture_active:
            raise RuntimeError("No capture active.")

        self._cleanup(process_alive=True)
        return True

    def _cleanup(self, process_alive: bool) -> None:
        """Remove netcap hooks and optionally free ring buffer."""
        if process_alive:
            for hook_id in self._hook_ids.values():
                try:
                    HOOK_MANAGER.remove_hook(hook_id)
                except Exception:
                    pass

            if self._created_ring_buffer and not HOOK_MANAGER.hooks:
                try:
                    HOOK_MANAGER.destroy_ring_buffer()
                except Exception:
                    pass

        # Close recording if active (file preserved on disk)
        if self._recording_file is not None:
            try:
                self._recording_file.close()
            except Exception:
                pass
            self._recording_file = None
            self._recording_path = None
            self._recording_count = 0
            self._recording_start = None
            self._recording_compress = False
            self._recording_max_size = None
            self._recording_base_name = None
            self._recording_part = 1
            self._recording_dir = None

        self._streams.clear()
        self._hook_ids = {}
        self._connections = {}
        self._pending_io = {}
        self._capture_active = False
        self._created_ring_buffer = False
        self._header_only = False

    # ==================== readPackets ====================

    def _read_packets(self, limit=None):
        """Lua: readPackets(limit?) -> [{direction, socket, timestamp, ...}, ...]"""
        if not self._capture_active:
            raise RuntimeError("No capture active. Call startCapture() first.")

        entries = HOOK_MANAGER.read_ring_buffer(int(limit or 100))

        # Evict stale IOCP correlation entries
        if self._pending_io:
            now = time.monotonic()
            stale = [
                k
                for k, v in self._pending_io.items()
                if "created_at" in v and now - v["created_at"] > self._pending_io_ttl
            ]
            for k in stale:
                del self._pending_io[k]

        # Build reverse map: hook_id -> hook_name
        id_to_name = {v: k for k, v in self._hook_ids.items()}

        packets = []
        for entry in entries:
            if entry["is_marker"]:
                label = ""
                if entry.get("data"):
                    label = entry["data"].decode("utf-8", errors="replace")
                packets.append(
                    self._table(
                        type="marker",
                        label=label,
                        sequence=entry["sequence"],
                    )
                )
                continue

            hook_name = id_to_name.get(entry["hook_id"])
            if hook_name is None:
                hook_name = entry.get("hook_name", "unknown")

            # WSA hooks: special processing
            if hook_name in ("WSASend", "WSARecv"):
                packet = self._process_wsa_entry(entry, hook_name)
                if packet is not None:
                    packets.append(packet)
                continue

            # GQCS: IOCP correlation
            if hook_name == "GetQueuedCompletionStatus":
                packet = self._process_gqcs_entry(entry)
                if packet is not None:
                    packets.append(packet)
                continue

            # UDP: extract peer address
            if hook_name in ("sendto", "recvfrom"):
                peer = self._extract_udp_peer(entry)
                if peer:
                    peer["type"] = "udp"
                    self._connections[entry["arg0"]] = peer

            # accept: track new socket
            if hook_name == "accept":
                new_socket = entry["result"] & 0xFFFFFFFF
                if new_socket != 0xFFFFFFFF:  # INVALID_SOCKET
                    addr_info = self._parse_sockaddr(entry.get("data", b""))
                    if addr_info:
                        self._connections[new_socket] = {
                            "remote_ip": addr_info["ip"],
                            "remote_port": addr_info["port"],
                            "family": addr_info["family"],
                            "type": "server",
                        }

            # bind: track local address
            if hook_name == "bind" and entry.get("data"):
                addr_info = self._parse_sockaddr(entry["data"])
                if addr_info:
                    conn = self._connections.setdefault(entry["arg0"], {})
                    conn["local_ip"] = addr_info["ip"]
                    conn["local_port"] = addr_info["port"]
                    conn["family"] = addr_info["family"]

            # connect: track remote address
            if hook_name == "connect" and entry.get("data"):
                addr_info = self._parse_sockaddr(entry["data"])
                if addr_info:
                    self._connections[entry["arg0"]] = {
                        "remote_ip": addr_info["ip"],
                        "remote_port": addr_info["port"],
                        "family": addr_info["family"],
                        "type": "client",
                    }

            # closesocket: remove connection
            if hook_name == "closesocket":
                self._connections.pop(entry["arg0"], None)

            # Infer size for header-only mode
            data_len = entry["data_length"]
            if self._header_only and data_len == 0:
                data_len = self._infer_header_only_size(entry, hook_name)

            # accept: use new socket as the packet socket
            socket_override = None
            if hook_name == "accept":
                new_socket = entry["result"] & 0xFFFFFFFF
                if new_socket == 0xFFFFFFFF:
                    continue  # accept failed
                socket_override = new_socket

            packets.append(
                self._build_packet(
                    entry,
                    hook_name,
                    socket_override=socket_override,
                    data=entry.get("data") if entry.get("captured_length", 0) > 0 else None,
                    data_len=data_len,
                )
            )

        if self._recording_file is not None:
            self._record_packets(packets)

        return self._table(*packets)

    # ==================== WSA Processing ====================

    def _parse_wsabuf(self, data: bytes) -> tuple[int, int] | None:
        """Parse a WSABUF struct from captured data.

        Returns:
            (buffer_length, buffer_pointer) or None if data too short.
        """
        if not data or len(data) < 16:
            return None
        buf_len = struct.unpack_from("<I", data, WSABUF_LEN_OFFSET)[0]
        buf_ptr = struct.unpack_from("<Q", data, WSABUF_BUF_OFFSET)[0]
        return (buf_len, buf_ptr)

    def _try_read_buffer(self, buf_ptr: int, length: int, max_capture: int) -> bytes | None:
        """Read buffer data from target process memory (best-effort)."""
        if not buf_ptr or length <= 0:
            return None
        read_len = min(length, max_capture)
        try:
            return SESSION.read_bytes(buf_ptr, read_len)
        except Exception:
            return None

    def _process_wsa_entry(self, entry: dict, hook_name: str) -> Any:
        """Process a WSASend/WSARecv ring buffer entry.

        For sync completion: reads buffer data server-side and returns a packet.
        For async (SOCKET_ERROR): stores in IOCP correlation table, returns None.
        """
        wsabuf = self._parse_wsabuf(entry.get("data"))
        if wsabuf is None:
            return None

        buf_len, buf_ptr = wsabuf
        socket = entry["arg0"]
        bytes_transferred = entry["arg3"]  # dereferenced by trampoline
        result = entry["result"]
        overlapped = entry.get("extra_args", {}).get("arg4", 0)

        if result == 0:
            # Sync completion
            data_len = bytes_transferred if bytes_transferred > 0 else buf_len
            data = None
            if not self._header_only:
                data = self._try_read_buffer(buf_ptr, data_len, self._max_packet_size)

            return self._build_packet(
                entry,
                hook_name,
                data=data,
                data_len=data_len,
                async_flag=False,
            )
        else:
            # SOCKET_ERROR (-1 as int32): async pending or actual error
            if overlapped:
                self._pending_io[overlapped] = {
                    "socket": socket,
                    "buf_ptr": buf_ptr,
                    "wsabuf_len": buf_len,
                    "hook_name": hook_name,
                    "sequence": entry["sequence"],
                    "created_at": time.monotonic(),
                }
                # Evict oldest entries if table exceeds limit
                if len(self._pending_io) > self._max_pending_io:
                    oldest_key = next(iter(self._pending_io))
                    del self._pending_io[oldest_key]
            return None

    def _process_gqcs_entry(self, entry: dict) -> Any:
        """Process a GQCS ring buffer entry.

        Matches against the IOCP correlation table. If a pending WSA operation
        is found, reads buffer data server-side and returns a completed packet.
        """
        if entry["result"] == 0:
            return None  # GQCS failed or timed out

        bytes_transferred = entry["arg1"]  # dereferenced
        overlapped_ptr = entry["arg3"]  # dereferenced

        if not overlapped_ptr:
            return None

        pending = self._pending_io.pop(overlapped_ptr, None)
        if pending is None:
            return None  # Not from our WSA hooks

        data = None
        if not self._header_only and bytes_transferred > 0 and pending["buf_ptr"]:
            data = self._try_read_buffer(pending["buf_ptr"], bytes_transferred, self._max_packet_size)

        return self._build_packet(
            entry,
            pending["hook_name"],
            socket_override=pending["socket"],
            data=data,
            data_len=bytes_transferred,
            async_flag=True,
        )

    # ==================== UDP Processing ====================

    def _extract_udp_peer(self, entry: dict) -> dict | None:
        """Read remote sockaddr from a sendto/recvfrom entry's extra_args."""
        extra = entry.get("extra_args", {})
        sockaddr_ptr = extra.get("arg4", 0)
        if not sockaddr_ptr:
            return None
        try:
            data = SESSION.read_bytes(sockaddr_ptr, 28)
            return self._parse_sockaddr(data)
        except Exception:
            return None

    # ==================== Packet Construction ====================

    def _build_packet(
        self,
        entry: dict,
        hook_name: str,
        direction: str | None = None,
        socket_override: int | None = None,
        data: bytes | None = None,
        data_len: int | None = None,
        async_flag: bool = False,
    ) -> Any:
        """Build a packet table from a ring buffer entry + optional overrides."""
        socket = socket_override if socket_override is not None else entry["arg0"]

        packet = {
            "direction": direction or _DIRECTION_MAP.get(hook_name, hook_name),
            "socket": socket,
            "socket_hex": hex(socket),
            "timestamp": entry["timestamp"],
            "sequence": entry["sequence"],
            "size": data_len if data_len is not None else entry.get("data_length", 0),
            "captured": len(data) if data else 0,
            "result": entry["result"],
            "caller": entry["return_addr"],
            "hook_name": hook_name,
        }

        if async_flag:
            packet["async"] = True

        if data and len(data) > 0:
            packet["data"] = self._table(*data)
            preview_len = min(len(data), 256)
            packet["data_hex"] = " ".join(f"{b:02X}" for b in data[:preview_len])
            packet["data_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:preview_len])

        return self._table(**packet)

    # ==================== Header-Only Size Inference ====================

    def _infer_header_only_size(self, entry: dict, hook_name: str) -> int:
        """Infer original data size from args when buffer capture is disabled."""
        original_spec = ALL_DATA_HOOKS.get(hook_name)
        if not original_spec:
            return 0

        orig_length_arg = original_spec.get("length_arg", -1)
        if orig_length_arg >= 1:
            # Lua-indexed arg -> 0-indexed entry key
            arg_keys = ["arg0", "arg1", "arg2", "arg3"]
            return entry.get(arg_keys[orig_length_arg - 1], 0)
        elif orig_length_arg == 0:
            # Return value (e.g., recv, recvfrom)
            return max(0, entry.get("result", 0))

        # For WSA hooks: deref_args captures *lpNumberOfBytesSent/Recvd in arg3
        if hook_name in ("WSASend", "WSARecv"):
            return entry.get("arg3", 0)

        return 0

    # ==================== filterPackets ====================

    def _filter_packets(self, packets, criteria=None):
        """Lua: filterPackets(packets, {direction, socket, min_size, max_size, hook_name, contains})"""
        if criteria is None:
            return packets

        direction = str(criteria["direction"]) if criteria["direction"] is not None else None
        socket_filter = int(criteria["socket"]) if criteria["socket"] is not None else None
        min_size = int(criteria["min_size"]) if criteria["min_size"] is not None else None
        max_size = int(criteria["max_size"]) if criteria["max_size"] is not None else None
        hook_filter = str(criteria["hook_name"]) if criteria["hook_name"] is not None else None
        contains = None
        if criteria["contains"] is not None:
            contains = _lua_table_to_list(criteria["contains"])

        result = []
        i = 1
        while True:
            pkt = packets[i]
            if pkt is None:
                break

            if direction and pkt["direction"] != direction:
                i += 1
                continue
            if socket_filter is not None and int(pkt["socket"]) != socket_filter:
                i += 1
                continue
            if min_size is not None and int(pkt["size"] or 0) < min_size:
                i += 1
                continue
            if max_size is not None and int(pkt["size"] or 0) > max_size:
                i += 1
                continue
            if hook_filter and pkt["hook_name"] != hook_filter:
                i += 1
                continue
            if contains is not None:
                pkt_data = pkt.get("data") if hasattr(pkt, "get") else (pkt["data"] if "data" in pkt else None)
                if not pkt_data or not self._buffer_contains(pkt_data, self._table(*contains)):
                    i += 1
                    continue

            result.append(pkt)
            i += 1

        return self._table(*result)

    # ==================== Connection Tracking ====================

    def _parse_sockaddr(self, data: bytes) -> dict | None:
        """Parse a sockaddr structure from captured buffer data.

        Returns:
            {ip, port, family} or None if parsing fails.
        """
        if not data or len(data) < 4:
            return None

        try:
            family = struct.unpack_from("<H", data, 0)[0]

            if family == AF_INET and len(data) >= 16:
                port = struct.unpack_from(">H", data, 2)[0]  # network byte order
                addr_bytes = data[4:8]
                ip = ".".join(str(b) for b in addr_bytes)
                return {"ip": ip, "port": port, "family": "IPv4"}

            elif family == AF_INET6 and len(data) >= 28:
                port = struct.unpack_from(">H", data, 2)[0]
                addr_bytes = data[8:24]
                groups = [f"{addr_bytes[i]:02x}{addr_bytes[i + 1]:02x}" for i in range(0, 16, 2)]
                ip = _compress_ipv6(":".join(groups))
                return {"ip": ip, "port": port, "family": "IPv6"}

        except (struct.error, IndexError):
            pass

        return None

    def _get_connections(self):
        """Lua: getConnections() -> {["0x1A4"] = {remote_ip=..., remote_port=..., ...}, ...}"""
        if not self._capture_active:
            raise RuntimeError("No capture active.")

        result = {}
        for socket_handle, conn in self._connections.items():
            entry = {}
            if "remote_ip" in conn:
                entry["remote_ip"] = conn["remote_ip"]
                entry["remote_port"] = conn["remote_port"]
            elif "ip" in conn:
                entry["remote_ip"] = conn["ip"]
                entry["remote_port"] = conn["port"]
            if "family" in conn:
                entry["family"] = conn["family"]
            if "type" in conn:
                entry["type"] = conn["type"]
            if "local_ip" in conn:
                entry["local_ip"] = conn["local_ip"]
                entry["local_port"] = conn["local_port"]
            result[hex(socket_handle)] = self._table(**entry)
        return self._table(**result)

    # ==================== captureStats ====================

    def _capture_stats(self):
        """Lua: captureStats() -> {total, dropped, entries_pending, utilization_pct, active_hooks, connections}"""
        if not self._capture_active:
            raise RuntimeError("No capture active.")

        rb_stats = HOOK_MANAGER.ring_buffer_stats()

        return self._table(
            total=rb_stats["total_captured"],
            dropped=rb_stats["total_dropped"],
            entries_pending=rb_stats["entries_pending"],
            utilization_pct=rb_stats["utilization_pct"],
            active_hooks=len(self._hook_ids),
            connections=len(self._connections),
        )

    # ==================== Buffer Unpack Helpers ====================
    # All offsets are 1-indexed (Lua convention). Little-endian.

    def _unpack_uint16(self, data, offset=None):
        """unpackUInt16(data, offset) -> uint16"""
        i = int(offset or 1)
        return int(data[i]) | (int(data[i + 1]) << 8)

    def _unpack_int16(self, data, offset=None):
        """unpackInt16(data, offset) -> int16 (signed)"""
        val = self._unpack_uint16(data, offset)
        return val - 0x10000 if val >= 0x8000 else val

    def _unpack_uint32(self, data, offset=None):
        """unpackUInt32(data, offset) -> uint32"""
        i = int(offset or 1)
        return int(data[i]) | (int(data[i + 1]) << 8) | (int(data[i + 2]) << 16) | (int(data[i + 3]) << 24)

    def _unpack_int32(self, data, offset=None):
        """unpackInt32(data, offset) -> int32 (signed)"""
        val = self._unpack_uint32(data, offset)
        return val - 0x100000000 if val >= 0x80000000 else val

    def _unpack_uint64(self, data, offset=None):
        """unpackUInt64(data, offset) -> uint64"""
        i = int(offset or 1)
        lo = self._unpack_uint32(data, i)
        hi = self._unpack_uint32(data, i + 4)
        return lo | (hi << 32)

    def _unpack_float(self, data, offset=None):
        """unpackFloat(data, offset) -> float32"""
        i = int(offset or 1)
        raw = bytes(int(data[i + j]) for j in range(4))
        return struct.unpack("<f", raw)[0]

    def _unpack_double(self, data, offset=None):
        """unpackDouble(data, offset) -> float64"""
        i = int(offset or 1)
        raw = bytes(int(data[i + j]) for j in range(8))
        return struct.unpack("<d", raw)[0]

    def _unpack_string(self, data, offset=None, maxlen=None):
        """unpackString(data, offset, maxlen?) -> string"""
        i = int(offset or 1)
        chars = []
        limit = int(maxlen or 256)
        for j in range(limit):
            try:
                b = int(data[i + j])
            except (KeyError, IndexError):
                break
            if b == 0:
                break
            chars.append(chr(b))
        return "".join(chars)

    def _unpack_bytes(self, data, offset, length):
        """unpackBytes(data, offset, length) -> byte table (sub-slice)"""
        i = int(offset or 1)
        n = int(length)
        result = [int(data[i + j]) for j in range(n)]
        return self._table(*result)

    def _unpack_vector3(self, data, offset=None):
        """unpackVector3(data, offset) -> {x, y, z}"""
        i = int(offset or 1)
        x = self._unpack_float(data, i)
        y = self._unpack_float(data, i + 4)
        z = self._unpack_float(data, i + 8)
        return self._table(x=x, y=y, z=z)

    # ==================== Buffer Pack Helpers ====================

    def _pack_uint16(self, val):
        """packUInt16(val) -> byte table"""
        v = int(val) & 0xFFFF
        return self._table(v & 0xFF, (v >> 8) & 0xFF)

    def _pack_uint32(self, val):
        """packUInt32(val) -> byte table"""
        v = int(val) & 0xFFFFFFFF
        return self._table(v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF)

    def _pack_int32(self, val):
        """packInt32(val) -> byte table (signed, two's complement)"""
        return self._pack_uint32(val)

    def _pack_uint64(self, val):
        """packUInt64(val) -> byte table"""
        v = int(val)
        return self._table(*[((v >> (i * 8)) & 0xFF) for i in range(8)])

    def _pack_float(self, val):
        """packFloat(val) -> byte table"""
        raw = struct.pack("<f", float(val))
        return self._table(*raw)

    # ==================== Buffer Search Helpers ====================

    def _buffer_find(self, data, pattern):
        """bufferFind(data, pattern_bytes) -> offset (1-indexed) or nil"""
        data_list = _lua_table_to_list(data)
        pat_list = _lua_table_to_list(pattern)
        pat_len = len(pat_list)
        for i in range(len(data_list) - pat_len + 1):
            if data_list[i : i + pat_len] == pat_list:
                return i + 1  # 1-indexed
        return None

    def _buffer_contains(self, data, pattern):
        """bufferContains(data, pattern_bytes) -> bool"""
        return self._buffer_find(data, pattern) is not None

    def _buffer_find_all(self, data, pattern):
        """bufferFindAll(data, pattern_bytes) -> table of offsets (1-indexed)"""
        data_list = _lua_table_to_list(data)
        pat_list = _lua_table_to_list(pattern)
        pat_len = len(pat_list)
        offsets = []
        for i in range(len(data_list) - pat_len + 1):
            if data_list[i : i + pat_len] == pat_list:
                offsets.append(i + 1)
        return self._table(*offsets) if offsets else self._table()

    # ==================== Stream Assembly ====================

    def _feed_packets(self, packets):
        """Lua: feedPackets(packets) -> {sockets_updated, bytes_added}

        Accumulate packet data into per-socket, per-direction stream buffers.
        Only processes packets with direction "send" or "recv" and non-nil data.

        Args:
            packets: packet list from readPackets() or loadRecording()
        """
        sockets_updated = set()
        bytes_added = 0

        i = 1
        while True:
            pkt = packets[i]
            if pkt is None:
                break

            direction = pkt["direction"]
            if direction not in ("send", "recv") or pkt["data"] is None:
                i += 1
                continue

            socket = int(pkt["socket"])
            data = _lua_table_to_bytes(pkt["data"])

            if not data:
                i += 1
                continue

            if socket not in self._streams:
                self._streams[socket] = StreamBuffer()

            stream = self._streams[socket]
            if direction == "send":
                stream.send_buffer.extend(data)
                stream.send_total += len(data)
                if len(stream.send_buffer) > self._max_stream_size:
                    excess = len(stream.send_buffer) - self._max_stream_size
                    del stream.send_buffer[:excess]
            else:
                stream.recv_buffer.extend(data)
                stream.recv_total += len(data)
                if len(stream.recv_buffer) > self._max_stream_size:
                    excess = len(stream.recv_buffer) - self._max_stream_size
                    del stream.recv_buffer[:excess]

            sockets_updated.add(socket)
            bytes_added += len(data)
            i += 1

        return self._table(sockets_updated=len(sockets_updated), bytes_added=bytes_added)

    def _get_stream(self, socket_hex, direction=None):
        """Lua: getStream(socket_hex, direction?) -> {data, length, total_fed} or nil

        Args:
            socket_hex: socket handle as hex string ("0x1A4") or integer
            direction: "send" or "recv" (default: "recv")
        """
        socket = _parse_socket_arg(socket_hex)
        dir_ = str(direction or "recv")

        stream = self._streams.get(socket)
        if stream is None:
            return None

        if dir_ == "send":
            buf = stream.send_buffer
            total = stream.send_total
        else:
            buf = stream.recv_buffer
            total = stream.recv_total

        if len(buf) == 0:
            return self._table(data=self._table(), length=0, total_fed=total)

        return self._table(
            data=self._table(*buf),
            length=len(buf),
            total_fed=total,
        )

    def _consume_stream(self, socket_hex, direction, n):
        """Lua: consumeStream(socket_hex, direction, n) -> bytes_consumed

        Remove n bytes from the front of the stream buffer.
        Call after successfully parsing a message.
        """
        socket = _parse_socket_arg(socket_hex)
        dir_ = str(direction)
        n = int(n)

        stream = self._streams.get(socket)
        if stream is None:
            return 0

        if dir_ == "send":
            consumed = min(n, len(stream.send_buffer))
            del stream.send_buffer[:consumed]
        else:
            consumed = min(n, len(stream.recv_buffer))
            del stream.recv_buffer[:consumed]

        return consumed

    def _list_streams(self):
        """Lua: listStreams() -> {["0x1A4"] = {send_length, recv_length, ...}, ...}"""
        result = {}
        for socket, stream in self._streams.items():
            result[hex(socket)] = self._table(
                send_length=len(stream.send_buffer),
                recv_length=len(stream.recv_buffer),
                send_total=stream.send_total,
                recv_total=stream.recv_total,
            )
        return self._table(**result)

    def _clear_stream(self, socket_hex=None):
        """Lua: clearStream(socket_hex?) -> true

        If socket_hex is nil, clears all stream buffers.
        """
        if socket_hex is None:
            self._streams.clear()
            return True

        socket = _parse_socket_arg(socket_hex)
        self._streams.pop(socket, None)
        return True

    # ==================== Protocol Framing ====================

    def _split_length_prefixed(self, data, spec):
        """Lua: splitLengthPrefixed(data, spec) -> {messages, remainder, consumed}

        Split a byte buffer into messages using a length-prefixed framing scheme.

        Args (spec table):
            length_offset: 1-indexed offset of length field within header
            length_size: 1, 2, or 4 bytes
            header_size: total header bytes before payload
            endian: "little" (default) or "big"
            includes_header: length field includes header bytes (default: false)

        Returns:
            messages: [{offset, header, payload, payload_length, total_size}, ...]
            remainder: unconsumed bytes at end (partial message)
            consumed: total bytes consumed
        """
        data_bytes = _lua_table_to_bytes(data)
        if len(data_bytes) == 0:
            return self._table(messages=self._table(), remainder=0, consumed=0)

        length_offset = int(spec["length_offset"] or 1) - 1  # Lua 1-indexed -> 0-indexed
        length_size = int(spec["length_size"])
        header_size = int(spec["header_size"])
        endian = str(spec["endian"] or "little")
        includes_header = bool(spec["includes_header"]) if spec["includes_header"] is not None else False

        if length_size not in (1, 2, 4):
            raise ValueError("length_size must be 1, 2, or 4")
        if header_size < length_offset + length_size:
            raise ValueError("header_size must be >= length_offset + length_size")
        if length_offset < 0:
            raise ValueError("length_offset must be >= 1")

        endian_char = "<" if endian == "little" else ">"
        fmt_map = {1: "B", 2: "H", 4: "I"}
        fmt = endian_char + fmt_map[length_size]

        messages = []
        pos = 0

        while pos + header_size <= len(data_bytes):
            field_pos = pos + length_offset
            if field_pos + length_size > len(data_bytes):
                break

            payload_length = struct.unpack_from(fmt, data_bytes, field_pos)[0]

            if includes_header:
                total_size = payload_length
                payload_length = payload_length - header_size
                if payload_length < 0:
                    break
            else:
                total_size = header_size + payload_length

            if total_size > 16 * 1024 * 1024:  # 16MB cap
                break

            if pos + total_size > len(data_bytes):
                break

            header = data_bytes[pos : pos + header_size]
            payload = data_bytes[pos + header_size : pos + total_size]

            messages.append(
                self._table(
                    offset=pos + 1,  # 1-indexed
                    header=self._table(*header),
                    payload=self._table(*payload),
                    payload_length=payload_length,
                    total_size=total_size,
                )
            )

            pos += total_size

        remainder = len(data_bytes) - pos

        return self._table(
            messages=self._table(*messages),
            remainder=remainder,
            consumed=pos,
        )

    def _split_delimited(self, data, delimiter):
        """Lua: splitDelimited(data, delimiter) -> {segments, remainder, consumed}

        Split a byte buffer by a delimiter byte sequence.

        Args:
            data: byte table
            delimiter: byte table (e.g., {0x0D, 0x0A} for CRLF)

        Returns:
            segments: [{offset, data, length}, ...]
            remainder: unconsumed bytes after last delimiter
            consumed: total bytes consumed (including delimiters)
        """
        data_bytes = _lua_table_to_bytes(data)
        delim_bytes = bytes(_lua_table_to_list(delimiter))

        if len(delim_bytes) == 0:
            raise ValueError("delimiter must not be empty")

        segments = []
        pos = 0

        while True:
            idx = data_bytes.find(delim_bytes, pos)
            if idx == -1:
                break

            segment = data_bytes[pos:idx]
            segments.append(
                self._table(
                    offset=pos + 1,  # 1-indexed
                    data=self._table(*segment),
                    length=len(segment),
                )
            )
            pos = idx + len(delim_bytes)

        remainder = len(data_bytes) - pos

        return self._table(
            segments=self._table(*segments),
            remainder=remainder,
            consumed=pos,
        )

    def _split_fixed(self, data, size):
        """Lua: splitFixed(data, size) -> {messages, remainder, consumed}

        Split a byte buffer into fixed-size chunks.

        Returns:
            messages: [{offset, data}, ...]
            remainder: unconsumed bytes at end (< size)
            consumed: total bytes consumed
        """
        data_bytes = _lua_table_to_bytes(data)
        size = int(size)

        if size <= 0:
            raise ValueError("size must be > 0")

        messages = []
        pos = 0

        while pos + size <= len(data_bytes):
            chunk = data_bytes[pos : pos + size]
            messages.append(
                self._table(
                    offset=pos + 1,  # 1-indexed
                    data=self._table(*chunk),
                )
            )
            pos += size

        remainder = len(data_bytes) - pos

        return self._table(
            messages=self._table(*messages),
            remainder=remainder,
            consumed=pos,
        )

    # ==================== Cross-Reference Search ====================

    def _search_packets(self, packets, pattern):
        """Lua: searchPackets(packets, pattern) -> [{packet_index, offset, ...}, ...]

        Find all occurrences of a byte pattern across all packet data.

        Args:
            packets: packet list from readPackets() or loadRecording()
            pattern: byte table (e.g., {0x48, 0x54, 0x54, 0x50} for "HTTP")

        Returns:
            [{packet_index, offset, direction, socket_hex, context_hex}, ...]
            offset is 1-indexed. context_hex shows bytes around the match.
        """
        pat = bytes(_lua_table_to_list(pattern))
        if len(pat) == 0:
            return self._table()

        results = []
        i = 1
        while True:
            pkt = packets[i]
            if pkt is None:
                break

            if pkt["data"] is None:
                i += 1
                continue

            data = _lua_table_to_bytes(pkt["data"])
            pos = 0
            while True:
                idx = data.find(pat, pos)
                if idx == -1:
                    break

                ctx_start = max(0, idx - 8)
                ctx_end = min(len(data), idx + len(pat) + 8)
                context = data[ctx_start:ctx_end]

                results.append(
                    self._table(
                        packet_index=i,
                        offset=idx + 1,  # 1-indexed
                        direction=pkt["direction"] or "unknown",
                        socket_hex=pkt["socket_hex"] or "unknown",
                        context_hex=" ".join(f"{b:02X}" for b in context),
                    )
                )
                pos = idx + 1

            i += 1

        return self._table(*results)

    def _search_packets_for_value(self, packets, value_type, value):
        """Lua: searchPacketsForValue(packets, type, value) -> [{...}, ...]

        Find an encoded value across all packet data.

        Args:
            packets: packet list
            type: "uint16", "uint32", "int32", "float", "double",
                  "uint16be", "uint32be" (big-endian variants)
            value: the value to search for

        Returns: same format as searchPackets
        """
        encoded = _encode_search_value(str(value_type), value)
        if encoded is None:
            raise ValueError(f"Unknown value type: {value_type}")

        return self._search_packets(packets, self._table(*encoded))

    # ==================== Session Recording ====================

    def _start_recording(self, filename=None, opts=None):
        """Lua: startRecording(filename?, {compress?, max_size_mb?}?) -> {filename, path}

        Enable recording mode. Subsequent readPackets() calls auto-append to file.
        File saved under scripts/<process>/recordings/<filename>.jsonl.

        Options:
            compress: If true, gzip the file on stopRecording() (.jsonl.gz).
            max_size_mb: Rotate to a new file when the current one exceeds this size.
        """
        if self._recording_file is not None:
            raise RuntimeError("Recording already active. Call stopRecording() first.")

        compress = False
        max_size_mb = None
        if opts is not None:
            comp_val = opts["compress"]
            if comp_val is not None:
                compress = bool(comp_val)
            size_val = opts["max_size_mb"]
            if size_val is not None:
                max_size_mb = float(size_val)

        process_name = SESSION.target_process or "unknown"
        rec_dir = Path("scripts") / process_name / "recordings"
        rec_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            filename = time.strftime("%Y%m%d_%H%M%S")
        filename = str(filename)
        if not filename.endswith(".jsonl"):
            filename += ".jsonl"

        filepath = rec_dir / filename
        self._recording_file = open(filepath, "a", encoding="utf-8")  # noqa: SIM115
        self._recording_path = str(filepath)
        self._recording_count = 0
        self._recording_start = time.time()
        self._recording_compress = compress
        self._recording_max_size = int(max_size_mb * 1024 * 1024) if max_size_mb else None
        self._recording_base_name = filename[: -len(".jsonl")]
        self._recording_part = 1
        self._recording_dir = rec_dir

        return self._table(filename=filename, path=str(filepath))

    def _stop_recording(self):
        """Lua: stopRecording() -> {path, total_entries, duration_seconds, parts, compressed}"""
        if self._recording_file is None:
            raise RuntimeError("No recording active.")

        self._recording_file.close()
        duration = time.time() - self._recording_start

        path = self._recording_path
        compressed = False
        if self._recording_compress:
            path = self._compress_recording(Path(path))
            compressed = True

        result = self._table(
            path=path,
            total_entries=self._recording_count,
            duration_seconds=round(duration, 1),
            parts=self._recording_part,
            compressed=compressed,
        )

        self._recording_file = None
        self._recording_path = None
        self._recording_count = 0
        self._recording_start = None
        self._recording_compress = False
        self._recording_max_size = None
        self._recording_base_name = None
        self._recording_part = 1
        self._recording_dir = None

        return result

    def _record_packets(self, packets_list: list) -> None:
        """Append packets to recording file. Rotates if max_size_mb exceeded."""
        for pkt in packets_list:
            record = self._serialize_packet(pkt)
            self._recording_file.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._recording_count += 1
        self._recording_file.flush()

        if self._recording_max_size is not None:
            try:
                pos = self._recording_file.tell()
            except Exception:
                pos = 0
            if pos >= self._recording_max_size:
                self._rotate_recording()

    def _rotate_recording(self) -> None:
        """Close current recording file and open the next part."""
        self._recording_file.close()

        if self._recording_compress:
            self._compress_recording(Path(self._recording_path))

        self._recording_part += 1
        filename = f"{self._recording_base_name}_part{self._recording_part:03d}.jsonl"
        filepath = self._recording_dir / filename
        self._recording_file = open(filepath, "a", encoding="utf-8")  # noqa: SIM115
        self._recording_path = str(filepath)

    def _compress_recording(self, filepath: Path) -> str:
        """Gzip a recording file and remove the original. Returns compressed path."""
        gz_path = filepath.with_suffix(filepath.suffix + ".gz")
        with open(filepath, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
            while True:
                chunk = f_in.read(65536)
                if not chunk:
                    break
                f_out.write(chunk)
        filepath.unlink()
        return str(gz_path)

    def _serialize_packet(self, pkt) -> dict:
        """Convert a Lua packet table to a JSON-serializable dict.

        Stores full data as hex (not truncated to 256-byte preview).
        """
        STRING_FIELDS = {"direction", "socket_hex", "caller", "hook_name"}
        INT_FIELDS = {"socket", "timestamp", "sequence", "size", "captured", "result"}

        d = {}
        for key in (
            "direction",
            "socket",
            "socket_hex",
            "timestamp",
            "sequence",
            "size",
            "captured",
            "result",
            "caller",
            "hook_name",
        ):
            val = pkt[key]
            if val is None:
                continue
            if key in INT_FIELDS:
                d[key] = int(val)
            elif key in STRING_FIELDS:
                d[key] = str(val)
            else:
                d[key] = val

        data_val = pkt.get("data") if hasattr(pkt, "get") else pkt["data"]
        if data_val is not None:
            data_bytes = _lua_table_to_bytes(data_val)
            if data_bytes:
                d["data_hex"] = " ".join(f"{b:02X}" for b in data_bytes)

        async_val = pkt.get("async") if hasattr(pkt, "get") else None
        if async_val:
            d["async"] = True

        return d

    def _load_recording(self, filename, opts=None):
        """Lua: loadRecording(filename, {offset, limit}?) -> packet list

        Load a recorded session. Returns packets in the same format as readPackets(),
        with full data byte tables reconstructed from stored hex.

        Args:
            filename: recording name (without .jsonl extension)
            opts: optional table with offset (skip first N entries, default 0)
                  and limit (max entries to return, default all)
        """
        process_name = SESSION.target_process or "unknown"
        filepath = self._resolve_recording_path(filename, process_name)
        if not filepath.exists():
            raise RuntimeError(f"Recording not found: {filepath}")

        offset = 0
        limit = None
        if opts is not None:
            off_val = opts["offset"]
            if off_val is not None:
                offset = int(off_val)
            lim_val = opts["limit"]
            if lim_val is not None:
                limit = int(lim_val)

        packets = []
        line_num = 0
        opener = gzip.open if str(filepath).endswith(".gz") else open
        with opener(filepath, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line_num < offset:
                    line_num += 1
                    continue
                if limit is not None and len(packets) >= limit:
                    break
                record = json.loads(line)
                pkt = self._deserialize_packet(record)
                packets.append(pkt)
                line_num += 1

        return self._table(*packets)

    def _deserialize_packet(self, record: dict):
        """Reconstruct a Lua packet table from a JSON record."""
        pkt = {}
        for k, v in record.items():
            if k == "data_hex":
                continue
            pkt[k] = v

        if "data_hex" in record and record["data_hex"]:
            data_bytes = bytes(int(b, 16) for b in record["data_hex"].split())
            pkt["data"] = self._table(*data_bytes)
            preview_len = min(len(data_bytes), 256)
            pkt["data_hex"] = " ".join(f"{b:02X}" for b in data_bytes[:preview_len])
            pkt["data_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in data_bytes[:preview_len])

        return self._table(**pkt)

    def _resolve_recording_path(self, filename, process_name: str) -> Path:
        """Resolve recording filename to full path. Auto-detects .jsonl.gz if .jsonl not found."""
        filename = str(filename)
        if not filename.endswith(".jsonl") and not filename.endswith(".jsonl.gz"):
            filename += ".jsonl"
        path = Path("scripts") / process_name / "recordings" / filename
        if not path.exists() and not filename.endswith(".gz"):
            gz_path = path.with_suffix(path.suffix + ".gz")
            if gz_path.exists():
                return gz_path
        return path

    def _list_recordings(self, process=None):
        """Lua: listRecordings(process?) -> [{filename, path, size_kb, entries, date}, ...]

        List saved recordings. If process is nil, lists for current process.
        Use process='*' to list all recordings across all processes.
        """
        if process == "*":
            rec_base = Path("scripts")
            if not rec_base.exists():
                return self._table()
            recordings = []
            for proc_dir in sorted(rec_base.iterdir()):
                rec_dir = proc_dir / "recordings"
                if rec_dir.exists():
                    recordings.extend(self._scan_recording_dir(rec_dir, proc_dir.name))
            return self._table(*recordings)

        process_name = str(process) if process else (SESSION.target_process or "unknown")
        rec_dir = Path("scripts") / process_name / "recordings"
        if not rec_dir.exists():
            return self._table()

        return self._table(*self._scan_recording_dir(rec_dir, process_name))

    def _scan_recording_dir(self, rec_dir: Path, process_name: str) -> list:
        """Scan a recordings directory and return metadata list."""
        recordings = []
        files = sorted(list(rec_dir.glob("*.jsonl")) + list(rec_dir.glob("*.jsonl.gz")))
        for f in files:
            stat = f.stat()
            name = f.name
            if name.endswith(".jsonl.gz"):
                display_name = name[: -len(".jsonl.gz")]
                compressed = True
                entry_count = None  # counting requires full decompression
            elif name.endswith(".jsonl"):
                display_name = name[: -len(".jsonl")]
                compressed = False
                with open(f, encoding="utf-8") as fh:
                    entry_count = sum(1 for line in fh if line.strip())
            else:
                continue

            recordings.append(
                self._table(
                    filename=display_name,
                    process=process_name,
                    path=str(f),
                    size_kb=round(stat.st_size / 1024, 1),
                    entries=entry_count,
                    compressed=compressed,
                    date=time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
                )
            )
        return recordings
