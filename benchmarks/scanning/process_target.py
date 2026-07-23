"""Deterministic child-process memory fixture for live scanning benchmarks."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import queue
import secrets
import struct
import subprocess
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from benchmarks.scanning import CORPUS_VERSION
from benchmarks.scanning.common import address_checksum, sha256_bytes, sha256_json
from benchmarks.scanning.corpus import (
    Corpus,
    build_batch_patterns,
    build_corpus,
    build_distribution,
    inject_batch_patterns,
)
from benchmarks.scanning.manifest import CASE_BY_ID, BenchmarkCase

TARGET_FIXTURE_VERSION = "scanning-process-target-v1"

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04

if sys.platform == "win32":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    _kernel32.VirtualAlloc.restype = wintypes.LPVOID
    _kernel32.VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    _kernel32.VirtualFree.restype = wintypes.BOOL
    _kernel32.VirtualProtect.argtypes = [
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.VirtualProtect.restype = wintypes.BOOL
    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype = wintypes.HMODULE


@dataclass(frozen=True, slots=True)
class TargetMetadata:
    """Stable and live identities published by one controlled child."""

    pid: int
    base_address: int
    end_exclusive: int
    logical_size: int
    allocation_size: int
    page_size: int
    corpus_sha256: str
    expected_addresses: tuple[int, ...]
    expected_checksum: str
    batch_expected: dict[str, tuple[int, ...]]
    inaccessible_ranges: tuple[tuple[int, int], ...]
    readonly_ranges: tuple[tuple[int, int], ...]
    split_address: int | None
    topology: dict[str, Any]
    topology_fingerprint: str
    module: dict[str, Any]
    fixture_version: str
    fixture_source_sha256: str
    run_id: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> TargetMetadata:
        return cls(
            pid=int(payload["pid"]),
            base_address=int(payload["base_address"]),
            end_exclusive=int(payload["end_exclusive"]),
            logical_size=int(payload["logical_size"]),
            allocation_size=int(payload["allocation_size"]),
            page_size=int(payload["page_size"]),
            corpus_sha256=str(payload["corpus_sha256"]),
            expected_addresses=tuple(int(value) for value in payload["expected_addresses"]),
            expected_checksum=str(payload["expected_checksum"]),
            batch_expected={
                str(key): tuple(int(value) for value in values)
                for key, values in dict(payload.get("batch_expected", {})).items()
            },
            inaccessible_ranges=tuple((int(start), int(end)) for start, end in payload["inaccessible_ranges"]),
            readonly_ranges=tuple((int(start), int(end)) for start, end in payload["readonly_ranges"]),
            split_address=None if payload["split_address"] is None else int(payload["split_address"]),
            topology=dict(payload["topology"]),
            topology_fingerprint=str(payload["topology_fingerprint"]),
            module=dict(payload["module"]),
            fixture_version=str(payload["fixture_version"]),
            fixture_source_sha256=str(payload["fixture_source_sha256"]),
            run_id=str(payload["run_id"]),
        )


def relative_addresses(metadata: TargetMetadata, addresses: tuple[int, ...] | list[int]) -> list[int]:
    offsets: list[int] = []
    for address in addresses:
        if not metadata.base_address <= address < metadata.end_exclusive:
            raise ValueError("controlled-process expected address is outside the allocated range")
        offsets.append(address - metadata.base_address)
    return offsets


def relative_address_checksum(metadata: TargetMetadata, addresses: tuple[int, ...] | list[int]) -> str:
    return address_checksum(relative_addresses(metadata, addresses))


def module_fingerprint(metadata: TargetMetadata) -> str:
    return sha256_json(metadata.module)


def operation_identity(
    metadata: TargetMetadata,
    *,
    phase: str,
    cache_token: str | None = None,
) -> dict[str, Any]:
    if phase not in {"preflight", "setup", "timed"}:
        raise ValueError("operation phase is invalid")
    return {
        "run_id": metadata.run_id,
        "pid": metadata.pid,
        "attachment_generation": 1,
        "module_fingerprint": module_fingerprint(metadata),
        "target_identity_sha256": sha256_json(comparison_identity(metadata)),
        "phase": phase,
        "cache_token": cache_token,
    }


def comparison_identity(metadata: TargetMetadata) -> dict[str, Any]:
    return {
        "corpus_version": CORPUS_VERSION,
        "profile": metadata.topology.get("profile"),
        "size": metadata.logical_size,
        "sha256": metadata.corpus_sha256,
        "fixture_version": metadata.fixture_version,
        "fixture_source_sha256": metadata.fixture_source_sha256,
        "topology_fingerprint": metadata.topology_fingerprint,
        "expected_count": len(metadata.expected_addresses),
        "expected_relative_checksum": relative_address_checksum(metadata, metadata.expected_addresses),
    }


def canonical_process_records(case: BenchmarkCase, profile: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return deterministic process corpus/topology and relative expectation records."""

    effective_size = case.effective_size(profile)
    if case.kind in {"timeout", "chunk_timeout"}:
        payload = build_distribution(case.distribution, max(64 * 1024, effective_size), case.case_id)
        expected_offsets: tuple[int, ...] = ()
    elif case.pattern and effective_size > 0:
        corpus = build_corpus(case, profile, base_address=0)
        payload = corpus.data
        expected_offsets = corpus.expected_addresses
    else:
        payload = build_distribution(case.distribution, max(64 * 1024, effective_size), case.case_id)
        expected_offsets = ()

    page_size = _system_page_size()
    logical_size = len(payload)
    allocation_size = _round_up(logical_size, page_size)
    inaccessible_offsets: list[list[int]] = []
    readonly_offsets: list[list[int]] = []
    split_offset: int | None = None
    page_count = logical_size // page_size
    if case.kind == "fragmented":
        cadence = int(case.parameters.get("hole_every_pages", 16))
        inaccessible_offsets = [[page * page_size, (page + 1) * page_size] for page in range(8, page_count, cadence)]
    elif case.kind == "writable_filter":
        cadence = int(case.parameters.get("readonly_every_pages", 2))
        readonly_offsets = [[page * page_size, (page + 1) * page_size] for page in range(1, page_count, cadence)]
    elif case.kind == "boundary":
        candidate = _round_up(logical_size // 2, page_size)
        if 0 < candidate < allocation_size:
            split_offset = candidate
            readonly_offsets = [[candidate, allocation_size]]

    retained_offsets = tuple(
        offset
        for offset in expected_offsets
        if not any(start <= offset < end for start, end in inaccessible_offsets)
        and not (case.kind == "writable_filter" and any(start <= offset < end for start, end in readonly_offsets))
    )
    topology = {
        "fixture_version": TARGET_FIXTURE_VERSION,
        "corpus_version": CORPUS_VERSION,
        "case_id": case.case_id,
        "profile": profile,
        "kind": case.kind,
        "logical_size": logical_size,
        "allocation_size": allocation_size,
        "page_size": page_size,
        "inaccessible_offsets": inaccessible_offsets,
        "readonly_offsets": readonly_offsets,
        "split_offset": split_offset,
        "scope_kinds": ["range", "module"],
        "filter_kinds": ["writable", "sections"],
    }
    corpus_record = {
        "corpus_version": CORPUS_VERSION,
        "profile": profile,
        "size": logical_size,
        "sha256": sha256_bytes(payload),
        "fixture_version": TARGET_FIXTURE_VERSION,
        "fixture_source_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "topology": topology,
        "topology_fingerprint": sha256_json(topology),
    }
    expected_record = {
        "returned_count": len(retained_offsets),
        "relative_address_checksum": address_checksum(retained_offsets),
        "inaccessible_offsets": inaccessible_offsets,
        "readonly_offsets": readonly_offsets,
    }
    return corpus_record, expected_record


class ControlledProcessTarget:
    """Own one child fixture and a bounded JSON-line control channel."""

    def __init__(
        self,
        case: BenchmarkCase,
        profile: str,
        *,
        python_executable: str | Path | None = None,
        startup_timeout_s: float = 20.0,
        command_timeout_s: float = 5.0,
    ) -> None:
        if profile not in {"smoke", "release"}:
            raise ValueError("profile must be 'smoke' or 'release'")
        if startup_timeout_s <= 0 or command_timeout_s <= 0:
            raise ValueError("timeouts must be positive")
        self.case = case
        self.profile = profile
        self.python_executable = str(python_executable or sys.executable)
        self.startup_timeout_s = startup_timeout_s
        self.command_timeout_s = command_timeout_s
        self.process: subprocess.Popen[str] | None = None
        self.metadata: TargetMetadata | None = None
        self._responses: queue.Queue[dict[str, Any] | BaseException] = queue.Queue()
        self._stderr_lines: list[str] = []
        self._request_id = 0
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

    def __enter__(self) -> ControlledProcessTarget:
        if sys.platform != "win32":
            raise RuntimeError("controlled process benchmarks require Windows")
        command = [
            self.python_executable,
            "-m",
            "benchmarks.scanning.process_target",
            "--child",
            "--case-id",
            self.case.case_id,
            "--profile",
            self.profile,
        ]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self._reader_thread = threading.Thread(target=self._read_stdout, args=(self.process.stdout,), daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, args=(self.process.stderr,), daemon=True)
        self._reader_thread.start()
        self._stderr_thread.start()
        try:
            payload = self._next_response(self.startup_timeout_s)
            if payload.get("event") != "ready":
                raise RuntimeError(f"controlled child did not publish ready metadata: {payload}")
            self.metadata = TargetMetadata.from_payload(payload["target"])
        except BaseException:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5.0)
            self.process = None
            raise
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            try:
                self.command("shutdown", timeout_s=1.0)
            except Exception:
                process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
        self.process = None

    def command(self, name: str, *, timeout_s: float | None = None, **arguments: Any) -> dict[str, Any]:
        process = self.process
        if process is None or process.poll() is not None or process.stdin is None:
            raise RuntimeError("controlled child is not running")
        self._request_id += 1
        request_id = self._request_id
        message = {"request_id": request_id, "command": name, **arguments}
        process.stdin.write(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n")
        process.stdin.flush()
        response = self._next_response(timeout_s or self.command_timeout_s)
        if response.get("request_id") != request_id:
            raise RuntimeError(f"controlled child response ID mismatch: {response}")
        if not response.get("ok"):
            raise RuntimeError(str(response.get("error", "controlled child command failed")))
        return response

    def ping(self) -> dict[str, Any]:
        return self.command("ping")

    def change_protection(self, *, offset: int, size: int, protection: int) -> dict[str, Any]:
        return self.command("protect", offset=offset, size=size, protection=protection)

    def exit_now(self) -> None:
        process = self.process
        if process is None:
            return
        self.command("exit")
        process.wait(timeout=5.0)

    def stderr_text(self) -> str:
        return "".join(self._stderr_lines)

    def _read_stdout(self, stream: TextIO) -> None:
        try:
            for line in stream:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    self._responses.put(RuntimeError(f"invalid child JSON: {line.rstrip()!r}: {exc}"))
                    continue
                if not isinstance(payload, dict):
                    self._responses.put(RuntimeError("controlled child response must be a JSON object"))
                    continue
                self._responses.put(payload)
        except BaseException as exc:
            self._responses.put(exc)

    def _read_stderr(self, stream: TextIO) -> None:
        for line in stream:
            self._stderr_lines.append(line)

    def _next_response(self, timeout_s: float) -> dict[str, Any]:
        try:
            value = self._responses.get(timeout=timeout_s)
        except queue.Empty as exc:
            process = self.process
            return_code = None if process is None else process.poll()
            raise TimeoutError(
                f"controlled child response timed out (exit={return_code}, stderr={self.stderr_text()[-2000:]!r})"
            ) from exc
        if isinstance(value, BaseException):
            raise RuntimeError(f"controlled child output reader failed: {value}") from value
        return value


class _ChildAllocation:
    def __init__(self, case: BenchmarkCase, profile: str) -> None:
        if sys.platform != "win32":
            raise RuntimeError("controlled process benchmarks require Windows")
        self.case = case
        self.profile = profile
        effective_size = case.effective_size(profile)
        self.batch_expected_offsets: dict[str, tuple[int, ...]] = {}
        if case.kind == "batch":
            patterns = build_batch_patterns(int(case.parameters["patterns"]))
            data = bytearray(build_distribution(case.distribution, max(64 * 1024, effective_size), case.case_id))
            positions = inject_batch_patterns(data, patterns) if case.parameters.get("inject_all") else ()
            self.batch_expected_offsets = {
                key: (() if not positions else (int(positions[index]),))
                for index, (key, _pattern) in enumerate(patterns)
            }
            payload = bytes(data)
            self.corpus = Corpus(
                data=payload,
                base_address=0,
                pattern_bytes=b"",
                mask=b"",
                expected_addresses=(),
                data_sha256=sha256_bytes(payload),
                expected_checksum=address_checksum(()),
            )
        elif case.kind in {"timeout", "chunk_timeout"}:
            data = build_distribution(case.distribution, max(64 * 1024, effective_size), case.case_id)
            self.corpus = Corpus(
                data=data,
                base_address=0,
                pattern_bytes=b"",
                mask=b"",
                expected_addresses=(),
                data_sha256=sha256_bytes(data),
                expected_checksum=address_checksum(()),
            )
        elif case.pattern and effective_size > 0:
            self.corpus = build_corpus(case, profile, base_address=0)
        else:
            data = build_distribution(case.distribution, max(64 * 1024, effective_size), case.case_id)
            self.corpus = Corpus(
                data=data,
                base_address=0,
                pattern_bytes=b"",
                mask=b"",
                expected_addresses=(),
                data_sha256=sha256_bytes(data),
                expected_checksum=address_checksum(()),
            )
        self.page_size = _system_page_size()
        self.logical_size = len(self.corpus.data)
        self.allocation_size = _round_up(self.logical_size, self.page_size)
        self.base_address = 0
        self.inaccessible_ranges: list[tuple[int, int]] = []
        self.readonly_ranges: list[tuple[int, int]] = []
        self.split_address: int | None = None
        self.run_id = secrets.token_hex(16)

    def __enter__(self) -> _ChildAllocation:
        pointer = _kernel32.VirtualAlloc(
            None,
            self.allocation_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
        if not pointer:
            raise OSError(ctypes.get_last_error(), "VirtualAlloc failed")
        self.base_address = int(pointer)
        ctypes.memmove(self.base_address, self.corpus.data, self.logical_size)
        if self.allocation_size > self.logical_size:
            ctypes.memset(
                self.base_address + self.logical_size,
                0,
                self.allocation_size - self.logical_size,
            )
        self._apply_topology()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.base_address:
            _kernel32.VirtualFree(self.base_address, 0, MEM_RELEASE)
            self.base_address = 0

    @property
    def end_exclusive(self) -> int:
        return self.base_address + self.logical_size

    def protect(self, offset: int, size: int, protection: int) -> int:
        if offset < 0 or size <= 0 or offset + size > self.allocation_size:
            raise ValueError("protection range is outside the controlled allocation")
        address = self.base_address + offset
        old = wintypes.DWORD()
        if not _kernel32.VirtualProtect(address, size, protection, ctypes.byref(old)):
            raise OSError(ctypes.get_last_error(), "VirtualProtect failed")
        return int(old.value)

    def metadata(self) -> dict[str, Any]:
        expected_offsets = [
            address
            for address in self.corpus.expected_addresses
            if not any(start <= self.base_address + address < end for start, end in self.inaccessible_ranges)
            and not (
                self.case.kind == "writable_filter"
                and any(start <= self.base_address + address < end for start, end in self.readonly_ranges)
            )
        ]
        expected_addresses = tuple(self.base_address + offset for offset in expected_offsets)
        batch_expected = {
            key: tuple(self.base_address + offset for offset in offsets)
            for key, offsets in self.batch_expected_offsets.items()
        }
        topology = {
            "fixture_version": TARGET_FIXTURE_VERSION,
            "corpus_version": CORPUS_VERSION,
            "case_id": self.case.case_id,
            "profile": self.profile,
            "kind": self.case.kind,
            "logical_size": self.logical_size,
            "allocation_size": self.allocation_size,
            "page_size": self.page_size,
            "inaccessible_offsets": [
                [start - self.base_address, end - self.base_address] for start, end in self.inaccessible_ranges
            ],
            "readonly_offsets": [
                [start - self.base_address, end - self.base_address] for start, end in self.readonly_ranges
            ],
            "split_offset": None if self.split_address is None else self.split_address - self.base_address,
            "scope_kinds": ["range", "module"],
            "filter_kinds": ["writable", "sections"],
        }
        module = _current_executable_module()
        return {
            "pid": os.getpid(),
            "base_address": self.base_address,
            "end_exclusive": self.end_exclusive,
            "logical_size": self.logical_size,
            "allocation_size": self.allocation_size,
            "page_size": self.page_size,
            "corpus_sha256": self.corpus.data_sha256,
            "expected_addresses": list(expected_addresses),
            "expected_checksum": address_checksum(expected_addresses),
            "batch_expected": {key: list(values) for key, values in batch_expected.items()},
            "inaccessible_ranges": [list(item) for item in self.inaccessible_ranges],
            "readonly_ranges": [list(item) for item in self.readonly_ranges],
            "split_address": self.split_address,
            "topology": topology,
            "topology_fingerprint": sha256_json(topology),
            "module": module,
            "fixture_version": TARGET_FIXTURE_VERSION,
            "fixture_source_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "run_id": self.run_id,
        }

    def _apply_topology(self) -> None:
        if self.case.kind == "fragmented":
            cadence = int(self.case.parameters.get("hole_every_pages", 16))
            self.inaccessible_ranges.extend(self._protect_every(cadence, PAGE_NOACCESS, start_page=8))
        elif self.case.kind == "writable_filter":
            cadence = int(self.case.parameters.get("readonly_every_pages", 2))
            self.readonly_ranges.extend(self._protect_every(cadence, PAGE_READONLY, start_page=1))
        elif self.case.kind == "boundary":
            split_offset = _round_up(self.logical_size // 2, self.page_size)
            if 0 < split_offset < self.allocation_size:
                self.protect(split_offset, self.allocation_size - split_offset, PAGE_READONLY)
                self.split_address = self.base_address + split_offset
                self.readonly_ranges.append((self.split_address, self.base_address + self.allocation_size))

    def _protect_every(self, cadence: int, protection: int, *, start_page: int) -> list[tuple[int, int]]:
        if cadence < 1:
            raise ValueError("page cadence must be positive")
        ranges: list[tuple[int, int]] = []
        page_count = self.logical_size // self.page_size
        for page_index in range(start_page, page_count, cadence):
            offset = page_index * self.page_size
            self.protect(offset, self.page_size, protection)
            address = self.base_address + offset
            ranges.append((address, address + self.page_size))
        return ranges


def _child_main(case: BenchmarkCase, profile: str) -> int:
    with _ChildAllocation(case, profile) as target:
        _emit({"event": "ready", "target": target.metadata()})
        for line in sys.stdin:
            request: Any = None
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise ValueError("command must be a JSON object")
                request_id = request.get("request_id")
                command = request.get("command")
                if command == "ping":
                    _emit({"request_id": request_id, "ok": True, "pid": os.getpid()})
                elif command == "protect":
                    old = target.protect(
                        int(request["offset"]),
                        int(request["size"]),
                        int(request["protection"]),
                    )
                    _emit({"request_id": request_id, "ok": True, "old_protection": old})
                elif command in {"exit", "shutdown"}:
                    _emit({"request_id": request_id, "ok": True})
                    return 0
                else:
                    raise ValueError(f"unknown command {command!r}")
            except Exception as exc:
                request_id = request.get("request_id") if isinstance(request, dict) else None
                _emit({"request_id": request_id, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return 0


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _current_executable_module() -> dict[str, Any]:
    base_pointer = _kernel32.GetModuleHandleW(None)
    if not base_pointer:
        raise OSError(ctypes.get_last_error(), "GetModuleHandleW failed")
    base = int(base_pointer)
    dos_header = ctypes.string_at(base, 0x40)
    if dos_header[:2] != b"MZ":
        raise RuntimeError("current executable does not have an MZ header")
    pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
    headers = ctypes.string_at(base + pe_offset, 4 + 20 + 0x70)
    if headers[:4] != b"PE\x00\x00":
        raise RuntimeError("current executable does not have a PE header")
    optional_offset = 4 + 20
    size = struct.unpack_from("<I", headers, optional_offset + 56)[0]
    path = str(Path(sys.executable).resolve())
    return {"name": os.path.basename(path), "path": path, "base": base, "size": size}


def _system_page_size() -> int:
    class SystemInfo(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", wintypes.WORD),
            ("wReserved", wintypes.WORD),
            ("dwPageSize", wintypes.DWORD),
            ("lpMinimumApplicationAddress", wintypes.LPVOID),
            ("lpMaximumApplicationAddress", wintypes.LPVOID),
            ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
            ("dwNumberOfProcessors", wintypes.DWORD),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD),
        ]

    info = SystemInfo()
    _kernel32.GetSystemInfo(ctypes.byref(info))
    return int(info.dwPageSize)


def _round_up(value: int, multiple: int) -> int:
    return ((value + multiple - 1) // multiple) * multiple


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--case-id", choices=tuple(CASE_BY_ID))
    parser.add_argument("--profile", choices=("smoke", "release"), default="smoke")
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    if not arguments.child or arguments.case_id is None:
        raise SystemExit("process_target is launched by benchmarks.scanning.process_scan")
    return _child_main(CASE_BY_ID[arguments.case_id], arguments.profile)


if __name__ == "__main__":
    raise SystemExit(main())
