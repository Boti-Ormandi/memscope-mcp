"""Stable process identity and module metadata for scan execution."""

from __future__ import annotations

import hashlib
import ntpath
import threading
from bisect import bisect_right
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from .model import ModuleRecord


class AttachmentState(Enum):
    """Lease-visible process attachment states."""

    DETACHED = "detached"
    ATTACHED = "attached"
    RETIRING = "retiring"


class ModuleSnapshotError(ValueError):
    """Raised when loaded-module metadata cannot form a safe snapshot."""


class ScanLeaseUnavailable(RuntimeError):
    """Structured failure raised when a stable scan identity is unavailable."""

    def __init__(self, error: str, detail: str) -> None:
        super().__init__(detail)
        self.error = error
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ModuleSnapshot:
    """Immutable, duplicate-aware module layout for one attachment generation."""

    generation: int
    ordered_by_base: tuple[ModuleRecord, ...]
    by_normalized_name: Mapping[str, tuple[ModuleRecord, ...]]
    fingerprint: bytes
    _bases: tuple[int, ...] = field(repr=False)

    @classmethod
    def create(cls, records: Iterable[ModuleRecord], generation: int) -> ModuleSnapshot:
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise ValueError("generation must be a positive integer")

        source = tuple(records)
        if any(not isinstance(record, ModuleRecord) for record in source):
            raise TypeError("records must contain ModuleRecord values")
        ordered = tuple(
            sorted(
                source,
                key=lambda record: (
                    record.base,
                    record.normalized_name,
                    record.path.casefold(),
                    record.name.casefold(),
                ),
            )
        )
        by_name: dict[str, list[ModuleRecord]] = {}
        previous: ModuleRecord | None = None
        for record in ordered:
            if record.normalized_name != normalize_module_name(record.name):
                raise ModuleSnapshotError(f"module {record.name!r} has a non-canonical normalized name")
            if previous is not None and record.base < previous.end_exclusive:
                raise ModuleSnapshotError(
                    f"module ranges overlap: {previous.name} and {record.name} at 0x{record.base:X}"
                )
            by_name.setdefault(record.normalized_name, []).append(record)
            previous = record

        immutable_index = MappingProxyType({name: tuple(matches) for name, matches in by_name.items()})
        return cls(
            generation=generation,
            ordered_by_base=ordered,
            by_normalized_name=immutable_index,
            fingerprint=_fingerprint(generation, ordered),
            _bases=tuple(record.base for record in ordered),
        )

    def find_all(self, module_name: str) -> tuple[ModuleRecord, ...]:
        """Return every case-insensitive basename match in stable base order."""

        return self.by_normalized_name.get(normalize_module_name(module_name), ())

    def find_by_address(self, address: int) -> ModuleRecord | None:
        """Resolve one address with logarithmic interval lookup."""

        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError("address must be a non-negative integer")
        index = bisect_right(self._bases, address) - 1
        if index < 0:
            return None
        record = self.ordered_by_base[index]
        return record if address < record.end_exclusive else None

    def to_legacy_dict(self) -> dict[str, dict[str, int | str]]:
        """Build the existing session module view for non-scanner consumers."""

        return {
            record.name: {"base": record.base, "size": record.size, "path": record.path}
            for record in self.ordered_by_base
        }


@dataclass(frozen=True, slots=True)
class ScanLease:
    """One stable process handle and module identity borrowed by a scan."""

    generation: int
    pid: int
    process_handle: int
    target_process: str
    modules: ModuleSnapshot
    lifecycle_cancel: threading.Event


def build_module_records(modules: Iterable[object]) -> tuple[ModuleRecord, ...]:
    """Convert Pymem module objects into validated immutable records."""

    records: list[ModuleRecord] = []
    for module in modules:
        path = str(getattr(module, "filename", "") or "")
        raw_name = str(getattr(module, "name", "") or "")
        name = ntpath.basename(raw_name or path)
        if not name:
            raise ModuleSnapshotError("loaded module is missing a basename")
        try:
            base = _coerce_int(getattr(module, "lpBaseOfDll"))
            size = _coerce_int(getattr(module, "SizeOfImage"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ModuleSnapshotError(f"module {name!r} has invalid base or size metadata") from exc
        try:
            records.append(
                ModuleRecord(
                    name=name,
                    normalized_name=normalize_module_name(name),
                    base=base,
                    size=size,
                    path=path,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ModuleSnapshotError(f"module {name!r} has invalid metadata: {exc}") from exc
    return tuple(records)


def normalize_module_name(module_name: str) -> str:
    """Canonicalize a module selector as a case-insensitive Windows basename."""

    if not isinstance(module_name, str):
        raise TypeError("module_name must be a string")
    normalized = ntpath.basename(module_name.strip()).casefold()
    if not normalized:
        raise ValueError("module_name must contain a basename")
    return normalized


def _coerce_int(value: object) -> int:
    if hasattr(value, "value"):
        value = getattr(value, "value")
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an integer")
    return value


def _fingerprint(generation: int, records: tuple[ModuleRecord, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(generation.to_bytes(8, "little", signed=False))
    for record in records:
        digest.update(record.base.to_bytes(8, "little", signed=False))
        digest.update(record.size.to_bytes(8, "little", signed=False))
        for value in (record.name, record.normalized_name, record.path):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "little", signed=False))
            digest.update(encoded)
    return digest.digest()
