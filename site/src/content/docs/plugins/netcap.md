---
title: "Netcap plugin"
description: "Capture Winsock traffic and manage canonical recordings."
---

`netcap` is an opt-in Winsock capture and packet-analysis plugin for live-process research. It builds on the core inline-hooking extension and adds no MCP tool. It can observe `send`, `recv`, `WSASend`, `WSARecv`, `sendto`, `recvfrom`, connection/lifecycle calls, and IOCP completion correlation.

Activate it explicitly:

```powershell
memscope-mcp install-plugin netcap
memscope-mcp paths
```

Restart the server, attach to the intended x64 target, confirm `listLuaFunctions("netcap")`, and then choose the smallest hook set that answers the research question.

## Capture

```lua
startCapture({
    hooks = {"send", "recv"},
    connect = true,
    lifecycle = false,
    iocp = nil,
    header_only = false,
    buffer_size = 1048576,
    max_packet_size = 4096
})

-- Let the target run.
local packets = readPackets(100)
local stats = captureStats()
stopCapture()
```

Defaults use `send` and `recv`, connection tracking for `connect`/`closesocket`, a 1 MiB ring buffer, and a 4 KiB packet cap. Valid data hooks are `send`, `recv`, `WSASend`, `WSARecv`, `sendto`, and `recvfrom`. `lifecycle=true` adds `accept`/`bind` tracking. IOCP correlation uses `GetQueuedCompletionStatus`; it is automatic when WSA hooks are selected unless `iocp` is set explicitly.

`header_only=true` records metadata and infers original lengths without copying payload buffers. It is useful for traffic shape analysis, but it does not recover packet bytes.

Packet entries include `direction`, `socket`, `socket_hex`, `timestamp`, `sequence`, `size`, `captured`, `result`, `caller`, `hook_name`, and optional `data`, `data_hex`, `data_ascii`, and `async`. Marker entries use `type="marker"` and a label. `getConnections()` reports peer/local addresses, ports, family, and connection type. `filterPackets` combines direction, socket, size, hook name, and byte-pattern criteria.

## Analysis helpers

The plugin exposes these Lua functions:

```lua
unpackUInt16(data, offset?)  unpackInt16(data, offset?)
unpackUInt32(data, offset?)  unpackInt32(data, offset?)
unpackUInt64(data, offset?)
unpackFloat(data, offset?)    unpackDouble(data, offset?)
unpackString(data, offset?, maxlen?)
unpackBytes(data, offset?, length?)
unpackVector3(data, offset?)
packUInt16(value) packUInt32(value) packInt32(value)
packUInt64(value) packFloat(value)

bufferFind(data, pattern) bufferContains(data, pattern) bufferFindAll(data, pattern)
feedPackets(packets) getStream(socket_hex, direction?) consumeStream(socket_hex, direction, count)
listStreams() clearStream(socket_hex?)
splitLengthPrefixed(data, options) splitDelimited(data, delimiter) splitFixed(data, size)
searchPackets(packets, pattern) searchPacketsForValue(packets, type, value)
```

The helper inputs use dense 1-indexed byte tables. Little-endian pack/unpack helpers convert fixed-width values, and searches return 1-indexed offsets.

```lua
local packets = readPackets(100)
local hits = searchPackets(packets, {0x48, 0x54, 0x54, 0x50})
local value_hits = searchPacketsForValue(packets, "uint32", 0x1234)

feedPackets(packets)
local stream = getStream("0x1A4", "recv")
local messages = splitLengthPrefixed(stream.data, {
    length_offset = 1,
    length_size = 2,
    header_size = 4,
    endian = "little",
    includes_header = false
})
consumeStream("0x1A4", "recv", messages.consumed)
```

`bufferFind`, `bufferContains`, and `bufferFindAll` use dense 1-indexed byte tables and return 1-indexed offsets. Empty patterns match every boundary. `bufferFindAll` retains overlapping matches. `splitLengthPrefixed`, `splitDelimited`, and `splitFixed` preserve partial-message remainder and consumed-byte counts.

## Recording API

```lua
startRecording("session1")
startRecording("compressed", {compress = true})
startRecording("bounded", {max_size_mb = 50})
startRecording("both", {compress = true, max_size_mb = 50})

-- readPackets() appends packet records while recording is active.
local result = stopRecording()
local entries = loadRecording("session1")
local listed = listRecordings()
```

`startRecording` validates options before filesystem mutation:

- `compress` is absent/`nil` or an exact boolean; other values are rejected without changing recording state or touching the roots.
- `max_size_mb` is a finite positive integer or float with a valid positive byte threshold; invalid values are rejected before cleanup, directory creation, or state commit.
- filenames and the attached process name are validated Windows path components.

A recording writes JSONL under the canonical root:

```text
$MEMSCOPE_HOME/scripts/<process>/recordings/<name>.jsonl
```

With compression, the final file is `<name>.jsonl.gz`. Size limits rotate to `<name>_part002.jsonl`, `<name>_part003.jsonl`, and so on; each part uses the same canonical directory and append/validation rules.

Ordinary files use durable serialized append batches. A restart or append attempt fails closed when an existing plain JSONL file ends in a partial final line. The writer validates the held directory/file identity before and after writes and flushes file buffers after each batch. This prevents the writer from silently appending to a renamed, substituted, linked, reparse, or non-regular file.

## Canonical and legacy recording roots

Netcap writes only to:

```text
$MEMSCOPE_HOME/scripts/<process>/recordings/
```

For reads, the cwd-relative path below is a containment-checked, read-only legacy fallback:

```text
scripts/<process>/recordings/
```

Canonical candidates always precede legacy candidates. A legacy file is never moved, rewritten, compressed, deleted, or overwritten.

Filename selection is deterministic:

| Query | Candidates in each root |
| --- | --- |
| `capture` | `capture.jsonl`, then `capture.jsonl.gz` |
| `capture.jsonl` | `capture.jsonl`, then `capture.jsonl.gz` |
| `capture.jsonl.gz` | `capture.jsonl.gz` only |

The canonical root is checked before the legacy root. An invalid present canonical entry terminates the lookup; it does not fall through to another extension or the legacy root. A canonical plain file therefore wins over a canonical gzip file, and any canonical candidate wins over a legacy candidate.

A legacy load adds Lua boolean `legacy_source=true` to the returned packet table and emits one `NETCAP_LEGACY_RECORDING_PATH` warning for that load. A listing deduplicates case-insensitive `(process, logical filename)` pairs, chooses canonical over legacy and plain over gzip, and emits one warning when the result contains any unshadowed legacy entry. Shadowed legacy files are silent. Canonical listing entries omit `legacy_source`.

Listing order is stable and normalized by case-insensitive process name and logical filename, with exact spelling as a tie-breaker. An ordinary file at the scripts root is not treated as a process directory.

## Windows component and handle rules

Process names, recording names, root components, and stage names reject:

- traversal, separators, drive-qualified or absolute forms, and ambiguous path shapes;
- percent-escape tokens such as `%2e`, `%5c`, `%00`, and `%AF`;
- control, format, surrogate, noncharacter, and non-NFC forms;
- trailing dots or spaces;
- reserved Windows device names; and
- components over the bounded UTF-16 length.

The held process and file leaf spelling is exact. Ancestor and root casing follows Windows case-insensitive semantics. Reparse points, symlinks/junctions, hard links, non-regular files, delete-pending files, and final-path aliases fail closed. Invalid present canonical entries terminate rather than falling back.

The implementation holds and revalidates directory/file handles, uses no-follow flags, checks file identity and final path, and creates compression stages with a validated same-directory no-replace publication. A stage is eligible for conservative stale cleanup only when its reserved filename grammar, regular-file identity, and creation/write timestamps show at least 24 hours of age. Stages that fail any eligibility check remain intact.

## Compression publication

Gzip compression reads the canonical source through a protected handle, writes a random same-directory stage, flushes it, performs a full decompression/readback hash check, verifies the destination is absent, publishes with no-replace semantics, and retires the source only after publication. An existing destination never gets overwritten. A publication failure preserves the source and does not silently replace the destination.

The boundary rejects alias/traversal escape at its named validation points. A same-principal concurrent process can still mutate the same filesystem objects after validation. Remaining behaviors are:

- post-validation same-principal mutation;
- a partial final line after an abrupt exit;
- a reserved stale stage;
- a duplicate source/gzip pair after publication-before-retirement; and
- no directory-entry power-loss durability.

These behaviors delimit what the filesystem checks establish.

## Stop and cleanup

`stopRecording()` closes, flushes, optionally publishes gzip, and resets recording state. Detach cleanup closes active writers and directories, removes capture hooks when the process remains alive, and records cleanup errors without inventing a successful target-side cleanup. If the target already exits, local state clears while target-side cleanup may be unavailable.

See [Capture calls](/guides/capture-function-calls/), [Plugin lifecycle](/plugins/lifecycle-and-contract/), [CLI and paths](/reference/cli-and-paths/), [Security model](/concepts/security-model/), and the [Netcap source](https://github.com/Boti-Ormandi/memscope-mcp/blob/main/memscope_mcp/_contrib/plugins/netcap.py).
