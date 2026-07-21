"""Remote PE section metadata parsing and attachment-scoped caching."""

from __future__ import annotations

import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass

from memscope_mcp.scanning.lifecycle import ScanLease
from memscope_mcp.scanning.model import ModuleRecord, ScanControl, TerminationReason
from memscope_mcp.scanning.scopes import ScopeNormalizationError

ReadMemory = Callable[[int, int, int], bytes | bytearray | memoryview]

_DOS_HEADER_SIZE = 64
_NT_PREFIX_SIZE = 24
_SECTION_HEADER_SIZE = 40
_MAX_SECTION_COUNT = 1024


@dataclass(slots=True)
class SectionReadStats:
    """Physical target reads performed while resolving PE metadata."""

    read_calls: int = 0
    bytes_requested: int = 0
    bytes_read: int = 0


@dataclass(frozen=True, slots=True)
class SectionRecord:
    """One named, module-clipped PE section interval."""

    name: str
    normalized_name: str
    start: int
    end_exclusive: int


@dataclass(frozen=True, slots=True)
class SectionTable:
    """Canonical remote section metadata for one module snapshot entry."""

    module: ModuleRecord
    records: tuple[SectionRecord, ...]

    def select(self, requested_names: tuple[str, ...]) -> tuple[tuple[SectionRecord, ...], tuple[str, ...]]:
        by_name: dict[str, SectionRecord] = {}
        for record in self.records:
            by_name.setdefault(record.normalized_name, record)

        selected: list[SectionRecord] = []
        canonical_names: list[str] = []
        for requested in requested_names:
            record = by_name.get(requested)
            if record is None:
                raise ScopeNormalizationError(
                    "SECTION_NOT_FOUND",
                    f"Section '{requested}' was not found in module '{self.module.name}'",
                    field="scope.filters.sections",
                    hint="Every requested section must exist in every selected module",
                )
            selected.append(record)
            canonical_names.append(record.name)
        return tuple(selected), tuple(canonical_names)


class SectionResolutionInterrupted(RuntimeError):
    """Cooperative control stopped section metadata resolution."""

    def __init__(self, reason: TerminationReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class SectionCache:
    """Cache parsed section tables for exactly one attachment fingerprint at a time."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._module_fingerprint: bytes | None = None
        self._tables: dict[tuple[int, int], SectionTable] = {}

    def get_or_load(
        self,
        lease: ScanLease,
        module: ModuleRecord,
        *,
        read_memory: ReadMemory,
        control: ScanControl,
        stats: SectionReadStats,
    ) -> SectionTable:
        if not isinstance(lease, ScanLease):
            raise TypeError("lease must be a ScanLease")
        if not isinstance(module, ModuleRecord):
            raise TypeError("module must be a ModuleRecord")
        if not callable(read_memory):
            raise TypeError("read_memory must be callable")
        if not isinstance(control, ScanControl):
            raise TypeError("control must be a ScanControl")
        if not isinstance(stats, SectionReadStats):
            raise TypeError("stats must be SectionReadStats")

        key = (module.base, module.size)
        with self._lock:
            if self._module_fingerprint != lease.modules.fingerprint:
                self._tables.clear()
                self._module_fingerprint = lease.modules.fingerprint
            cached = self._tables.get(key)
            if cached is not None:
                return cached
            table = _read_section_table(
                lease,
                module,
                read_memory=read_memory,
                control=control,
                stats=stats,
            )
            self._tables[key] = table
            return table


def _read_section_table(
    lease: ScanLease,
    module: ModuleRecord,
    *,
    read_memory: ReadMemory,
    control: ScanControl,
    stats: SectionReadStats,
) -> SectionTable:
    dos = _read_exact(
        lease,
        module,
        module.base,
        _DOS_HEADER_SIZE,
        read_memory=read_memory,
        control=control,
        stats=stats,
    )
    if dos[:2] != b"MZ":
        raise _malformed(module, "DOS signature is missing")
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    nt_address = module.base + e_lfanew
    if e_lfanew > module.size - _NT_PREFIX_SIZE:
        raise _malformed(module, "NT headers are outside the loaded image")

    nt_prefix = _read_exact(
        lease,
        module,
        nt_address,
        _NT_PREFIX_SIZE,
        read_memory=read_memory,
        control=control,
        stats=stats,
    )
    if nt_prefix[:4] != b"PE\0\0":
        raise _malformed(module, "PE signature is missing")
    section_count = struct.unpack_from("<H", nt_prefix, 6)[0]
    optional_header_size = struct.unpack_from("<H", nt_prefix, 20)[0]
    if section_count < 1 or section_count > _MAX_SECTION_COUNT:
        raise _malformed(module, "section count is outside the supported bound")

    table_offset = e_lfanew + _NT_PREFIX_SIZE + optional_header_size
    table_size = section_count * _SECTION_HEADER_SIZE
    if table_offset > module.size or table_size > module.size - table_offset:
        raise _malformed(module, "section table is outside the loaded image")

    raw_table = _read_exact(
        lease,
        module,
        module.base + table_offset,
        table_size,
        read_memory=read_memory,
        control=control,
        stats=stats,
    )
    records: list[SectionRecord] = []
    for index in range(section_count):
        offset = index * _SECTION_HEADER_SIZE
        raw_name = raw_table[offset : offset + 8].split(b"\0", 1)[0]
        if not raw_name:
            continue
        name = raw_name.decode("latin-1")
        virtual_size, virtual_address, raw_size = struct.unpack_from("<III", raw_table, offset + 8)
        extent = max(virtual_size, raw_size)
        if virtual_address > module.size:
            raise _malformed(module, f"section '{name}' starts outside the loaded image")
        end_rva = min(module.size, virtual_address + extent)
        if end_rva < virtual_address:
            raise _malformed(module, f"section '{name}' has an invalid extent")
        records.append(
            SectionRecord(
                name=name,
                normalized_name=name.casefold(),
                start=module.base + virtual_address,
                end_exclusive=module.base + end_rva,
            )
        )
    return SectionTable(module=module, records=tuple(records))


def _read_exact(
    lease: ScanLease,
    module: ModuleRecord,
    address: int,
    size: int,
    *,
    read_memory: ReadMemory,
    control: ScanControl,
    stats: SectionReadStats,
) -> bytes:
    reason = control.poll()
    if reason is not None:
        raise SectionResolutionInterrupted(reason)
    if address < module.base or size < 1 or address + size > module.end_exclusive:
        raise _malformed(module, "metadata read is outside the loaded image")

    stats.read_calls += 1
    stats.bytes_requested += size
    try:
        raw = read_memory(lease.process_handle, address, size)
    except Exception as error:
        reason = control.poll()
        if reason is not None:
            raise SectionResolutionInterrupted(reason) from error
        raise ScopeNormalizationError(
            "INVALID_SCOPE",
            f"Could not read PE section metadata for module '{module.name}'",
            field="scope.filters.sections",
        ) from error
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("read_memory must return bytes-like data")
    data = bytes(raw)
    stats.bytes_read += len(data)
    if len(data) != size:
        raise ScopeNormalizationError(
            "INVALID_SCOPE",
            f"PE section metadata for module '{module.name}' was only partially readable",
            field="scope.filters.sections",
        )
    reason = control.poll()
    if reason is not None:
        raise SectionResolutionInterrupted(reason)
    return data


def _malformed(module: ModuleRecord, detail: str) -> ScopeNormalizationError:
    return ScopeNormalizationError(
        "INVALID_SCOPE",
        f"Malformed PE metadata for module '{module.name}': {detail}",
        field="scope.filters.sections",
    )
