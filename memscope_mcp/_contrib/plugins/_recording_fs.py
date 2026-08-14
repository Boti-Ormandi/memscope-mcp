"""Handle-validated Windows filesystem operations for netcap recordings."""

from __future__ import annotations

import ctypes
import hashlib
import math
import ntpath
import os
import re
import time
import unicodedata
import uuid
import zlib
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Iterable

if os.name != "nt":  # pragma: no cover - the project is Windows-only
    raise RuntimeError("netcap recording storage requires Windows")

_FILE_LIST_DIRECTORY, _FILE_READ_DATA, _FILE_ADD_FILE, _FILE_APPEND_DATA, _FILE_READ_ATTRIBUTES = 1, 1, 2, 4, 0x80
_DELETE, _SYNCHRONIZE, _GENERIC_READ, _GENERIC_WRITE = 0x10000, 0x100000, 0x80000000, 0x40000000
_FILE_SHARE_READ, _FILE_SHARE_WRITE, _FILE_SHARE_DELETE = 1, 2, 4
_CREATE_NEW, _OPEN_EXISTING, _OPEN_ALWAYS = 1, 3, 4
_FILE_ATTRIBUTE_DIRECTORY, _FILE_ATTRIBUTE_REPARSE_POINT = 0x10, 0x400
_FILE_FLAG_OPEN_REPARSE_POINT, _FILE_FLAG_BACKUP_SEMANTICS = 0x200000, 0x2000000
_FILE_FLAG_SEQUENTIAL_SCAN, _FILE_TYPE_DISK, _FILE_BEGIN = 0x8000000, 1, 0
_FILE_STANDARD_INFO_CLASS, _FILE_RENAME_INFO_CLASS, _FILE_DISPOSITION_INFO_CLASS = 1, 3, 4
_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND, _ERROR_SHARING_VIOLATION = 2, 3, 32
_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS = 80, 183
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_INVALID_COMPONENT_CHARS = frozenset('<>:"/\\|?*')
_RESERVED_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"})
_RESERVED_NAMES |= frozenset(f"{kind}{suffix}" for kind in ("COM", "LPT") for suffix in (*range(1, 10), *"¹²³"))
_STAGE_RE = re.compile(r"^\.memscope-recording-stage-[0-9a-f]{32}\.tmp$")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_STAGE_MIN_STALE_AGE_SECONDS = 24 * 60 * 60


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class FILE_STANDARD_INFO(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_longlong),
        ("EndOfFile", ctypes.c_longlong),
        ("NumberOfLinks", wintypes.DWORD),
        ("DeletePending", ctypes.c_ubyte),
        ("Directory", ctypes.c_ubyte),
    ]


class FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def _api(name: str, argtypes: list, restype):
    function = getattr(_kernel32, name)
    function.argtypes, function.restype = argtypes, restype
    return function


_CreateFileW = _api(
    "CreateFileW",
    [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ],
    wintypes.HANDLE,
)
_CreateDirectoryW = _api("CreateDirectoryW", [wintypes.LPCWSTR, wintypes.LPVOID], wintypes.BOOL)
_GetFileInformationByHandle = _api(
    "GetFileInformationByHandle", [wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)], wintypes.BOOL
)
_GetFileInformationByHandleEx = _api(
    "GetFileInformationByHandleEx", [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD], wintypes.BOOL
)
_GetFinalPathNameByHandleW = _api(
    "GetFinalPathNameByHandleW", [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD], wintypes.DWORD
)
_GetFileType = _api("GetFileType", [wintypes.HANDLE], wintypes.DWORD)
_ReadFile = _api(
    "ReadFile",
    [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID],
    wintypes.BOOL,
)
_WriteFile = _api(
    "WriteFile",
    [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID],
    wintypes.BOOL,
)
_FlushFileBuffers = _api("FlushFileBuffers", [wintypes.HANDLE], wintypes.BOOL)
_SetFilePointerEx = _api(
    "SetFilePointerEx",
    [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD],
    wintypes.BOOL,
)
_GetFileSizeEx = _api("GetFileSizeEx", [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)], wintypes.BOOL)
_SetFileInformationByHandle = _api(
    "SetFileInformationByHandle", [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD], wintypes.BOOL
)
_CloseHandle = _api("CloseHandle", [wintypes.HANDLE], wintypes.BOOL)


def _winerror(message: str) -> OSError:
    error = ctypes.get_last_error()
    return ctypes.WinError(error, f"{message}: {ctypes.FormatError(error).strip()}")


def _extended(path: Path | str) -> str:
    value = os.path.abspath(os.fspath(path)).replace("/", "\\")
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _path_key(path: Path | str) -> str:
    value = _extended(path).replace("/", "\\")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    drive, tail = ntpath.splitdrive(value)
    if tail != "\\":
        value = value.rstrip("\\")
    return ntpath.normpath(value).casefold()


def same_path(left: Path | str, right: Path | str) -> bool:
    return _path_key(left) == _path_key(right)


def _invalid_unicode_component_char(char: str) -> bool:
    codepoint = ord(char)
    return (
        unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        or 0xFDD0 <= codepoint <= 0xFDEF
        or (codepoint & 0xFFFF) in {0xFFFE, 0xFFFF}
    )


def validate_component(value: object, *, label: str = "path component") -> str:
    component = str(value)
    drive, _tail = ntpath.splitdrive(component)
    if (
        not component
        or _PERCENT_ESCAPE_RE.search(component)
        or component in {".", ".."}
        or drive
        or ntpath.isabs(component)
        or any(char in _INVALID_COMPONENT_CHARS or _invalid_unicode_component_char(char) for char in component)
        or component[-1] in {".", " "}
        or unicodedata.normalize("NFC", component) != component
    ):
        raise ValueError(f"Invalid Windows {label}: {component!r}")
    basename = component.split(".", 1)[0].upper()
    if basename in _RESERVED_NAMES:
        raise ValueError(f"Reserved Windows {label}: {component!r}")
    if len(component.encode("utf-16-le")) > 510:
        raise ValueError(f"Windows {label} is too long: {component!r}")
    return component


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    index: int


@dataclass(frozen=True)
class FileMetadata:
    size: int
    modified: float
    created: float


class RecordingFsError(RuntimeError):
    def __init__(self, message: str, cleanup: Iterable[object] = ()) -> None:
        super().__init__(message)
        self.cleanup = tuple(cleanup)


@dataclass
class _HandleOwner:
    handle: int | None

    @property
    def closed(self) -> bool:
        return self.handle is None

    def close(self) -> None:
        try:
            _close_native(self)
        except Exception as exc:
            raise RecordingFsError(f"Handle close failed: {exc}", (self,)) from exc


@dataclass
class _DirectoryNode:
    handle: int | None
    identity: FileIdentity
    expected_path: Path
    exact_name: str | None = None


def _basic_info(handle: int) -> _BY_HANDLE_FILE_INFORMATION:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not _GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise _winerror("GetFileInformationByHandle failed")
    return info


def _standard_info(handle: int) -> FILE_STANDARD_INFO:
    info = FILE_STANDARD_INFO()
    if not _GetFileInformationByHandleEx(handle, _FILE_STANDARD_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)):
        raise _winerror("GetFileInformationByHandleEx(FileStandardInfo) failed")
    return info


def _identity(info: _BY_HANDLE_FILE_INFORMATION) -> FileIdentity:
    return FileIdentity(info.dwVolumeSerialNumber, (info.nFileIndexHigh << 32) | info.nFileIndexLow)


def _filetime_seconds(value: _FILETIME) -> float:
    ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
    return ticks / 10_000_000 - 11_644_473_600


def _final_path(handle: int) -> str:
    size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(size)
        copied = _GetFinalPathNameByHandleW(handle, buffer, size, 0)
        if copied == 0:
            raise _winerror("GetFinalPathNameByHandleW failed")
        if copied < size:
            return buffer.value
        size = copied + 1


def _open_native(path: Path, access: int, share: int, disposition: int, flags: int) -> int:
    ctypes.set_last_error(0)
    handle = _CreateFileW(_extended(path), access, share, None, disposition, flags, None)
    if handle == _INVALID_HANDLE_VALUE:
        raise _winerror(f"CreateFileW failed for {path}")
    return int(handle)


def _close_native(owner: object) -> None:
    handle = getattr(owner, "handle")
    if handle is None:
        return
    if not _CloseHandle(handle):
        raise _winerror("CloseHandle failed")
    owner.handle = None


def _new_directory_node(handle: int, expected_path: Path, *, exact_name: str | None = None) -> _DirectoryNode:
    owner = _HandleOwner(handle)
    try:
        node = _DirectoryNode(handle, _identity(_basic_info(handle)), expected_path, exact_name)
    except Exception as exc:
        try:
            owner.close()
        except Exception:
            raise RecordingFsError(f"Directory metadata failed: {exc}", (owner,)) from exc
        raise
    owner.handle = None
    return node


def _validate_directory_node(node: _DirectoryNode) -> None:
    if node.handle is None:
        raise RecordingFsError(f"Directory handle is closed: {node.expected_path}")
    info = _basic_info(node.handle)
    standard = _standard_info(node.handle)
    if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise RecordingFsError(f"Reparse-point directory rejected: {node.expected_path}")
    if not info.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY or not standard.Directory:
        raise RecordingFsError(f"Non-directory path component rejected: {node.expected_path}")
    if standard.DeletePending:
        raise RecordingFsError(f"Delete-pending directory rejected: {node.expected_path}")
    if _identity(info) != node.identity:
        raise RecordingFsError(f"Directory identity changed: {node.expected_path}")
    final_path = _final_path(node.handle)
    if _path_key(final_path) != _path_key(node.expected_path):
        raise RecordingFsError(f"Directory final path changed or aliases another name: {node.expected_path}")
    if node.exact_name is not None and PureWindowsPath(final_path).name != node.exact_name:
        raise RecordingFsError(f"Directory is not the exact named direct child: {node.expected_path}")


class RecordingDirectory:
    """Held, revalidated no-follow handles for every component of a directory path."""

    def __init__(self, path: Path, nodes: list[_DirectoryNode]) -> None:
        self.path = path
        self._nodes = nodes

    @property
    def handle(self) -> int:
        if not self._nodes:
            raise RecordingFsError("Recording directory is closed")
        return self._nodes[-1].handle

    @property
    def closed(self) -> bool:
        return not self._nodes

    def validate(self) -> None:
        if not self._nodes:
            raise RecordingFsError("Recording directory is closed")
        for node in self._nodes:
            _validate_directory_node(node)

    def names(self) -> list[str]:
        self.validate()
        names = [entry.name for entry in os.scandir(self.path)]
        self.validate()
        return names

    def close(self) -> None:
        first: Exception | None = None
        remaining: list[_DirectoryNode] = []
        for node in reversed(self._nodes):
            try:
                _close_native(node)
            except Exception as exc:
                first = first or exc
                remaining.append(node)
        self._nodes = list(reversed(remaining))
        if first is not None:
            raise first

    def open_existing(self, name: str, access: int = _GENERIC_READ | _FILE_READ_ATTRIBUTES) -> ProtectedFile | None:
        validate_component(name, label="recording filename")
        self.validate()
        try:
            handle = _open_native(
                self.path / name,
                access,
                _FILE_SHARE_READ,
                _OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
            )
        except OSError as exc:
            if exc.winerror in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
                return None
            raise
        protected = _owned_protected(handle, self, name)
        try:
            protected.validate()
            self.validate()
            return protected
        except Exception as exc:
            try:
                protected.close()
            except Exception:
                raise RecordingFsError(f"Recording validation failed: {exc}", (protected,)) from exc
            raise

    def child_is_directory(self, name: str) -> bool:
        validate_component(name, label="process name")
        self.validate()
        try:
            handle = _open_native(
                self.path / name,
                _FILE_READ_ATTRIBUTES,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                _OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            )
        except OSError as exc:
            if exc.winerror in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
                return False
            raise
        owner = _HandleOwner(handle)
        try:
            info = _basic_info(handle)
            standard = _standard_info(handle)
            if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                raise RecordingFsError(f"Reparse-point process directory rejected: {self.path / name}")
            is_directory = bool(info.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY and standard.Directory)
            if is_directory:
                _validate_directory_node(_DirectoryNode(handle, _identity(info), self.path / name, name))
        finally:
            owner.close()
        self.validate()
        return is_directory


def _absolute_parts(path: Path) -> tuple[Path, list[str]]:
    absolute = Path(os.path.abspath(path))
    parsed = PureWindowsPath(str(absolute))
    if not parsed.is_absolute() or not parsed.anchor:
        raise ValueError(f"Recording root must be an absolute Windows path: {path}")
    parts = list(parsed.parts)
    anchor = Path(parts.pop(0))
    for component in parts:
        validate_component(component, label="recording root component")
    return anchor, parts


def acquire_directory(
    path: Path, *, create: bool, _exact_part_indices: frozenset[int] = frozenset()
) -> RecordingDirectory | None:
    anchor, parts = _absolute_parts(path)
    nodes: list[_DirectoryNode] = []
    current = anchor
    try:
        components = [None, *parts]
        for index, component in enumerate(components):
            if component is not None:
                current /= component
            access = _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
            if create and index == len(components) - 1:
                access |= _FILE_ADD_FILE
            try:
                handle = _open_native(
                    current,
                    access,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    _OPEN_EXISTING,
                    _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
                )
            except OSError as exc:
                if component is None or exc.winerror not in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
                    raise
                if not create:
                    guard = RecordingDirectory(Path(os.path.abspath(path)), nodes)
                    guard.close()
                    return None
                if not _CreateDirectoryW(_extended(current), None):
                    error = ctypes.get_last_error()
                    if error not in {_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS}:
                        raise _winerror(f"CreateDirectoryW failed for {current}")
                handle = _open_native(
                    current,
                    access,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    _OPEN_EXISTING,
                    _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
                )
            exact_name = component if component is not None and index - 1 in _exact_part_indices else None
            node = _new_directory_node(handle, current, exact_name=exact_name)
            nodes.append(node)
            _validate_directory_node(node)
        guard = RecordingDirectory(Path(os.path.abspath(path)), nodes)
        guard.validate()
        return guard
    except Exception as exc:
        guard = RecordingDirectory(Path(os.path.abspath(path)), nodes)
        try:
            guard.close()
        except Exception:
            inherited = getattr(exc, "cleanup", ())
            raise RecordingFsError(f"Directory acquisition failed: {exc}", (*inherited, guard)) from exc
        raise


def acquire_recording_directory(scripts_root: Path, process: object, *, create: bool) -> RecordingDirectory | None:
    process_name = validate_component(process, label="process name")
    recording_path = Path(scripts_root) / process_name / "recordings"
    _anchor, parts = _absolute_parts(recording_path)
    process_index = len(parts) - 2
    return acquire_directory(
        recording_path,
        create=create,
        _exact_part_indices=frozenset({process_index}),
    )


class ProtectedFile:
    def __init__(self, handle: int, directory: RecordingDirectory, name: str) -> None:
        self.handle: int | None = handle
        self.directory = directory
        self.name = validate_component(name, label="recording filename")
        info = _basic_info(handle)
        self.identity = _identity(info)

    @property
    def closed(self) -> bool:
        return self.handle is None

    @property
    def path(self) -> Path:
        return self.directory.path / self.name

    def validate(self, *, allow_delete_pending: bool = False) -> None:
        if self.handle is None:
            raise RecordingFsError(f"File is closed: {self.path}")
        self.directory.validate()
        info = _basic_info(self.handle)
        standard = _standard_info(self.handle)
        if _GetFileType(self.handle) != _FILE_TYPE_DISK:
            raise RecordingFsError(f"Non-disk recording rejected: {self.path}")
        if info.dwFileAttributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT) or standard.Directory:
            raise RecordingFsError(f"Non-regular or reparse recording rejected: {self.path}")
        expected_links = {0, 1} if allow_delete_pending and standard.DeletePending else {1}
        if standard.NumberOfLinks not in expected_links or info.nNumberOfLinks not in expected_links:
            raise RecordingFsError(f"Hard-linked recording rejected: {self.path}")
        if standard.DeletePending and not allow_delete_pending:
            raise RecordingFsError(f"Delete-pending recording rejected: {self.path}")
        if _identity(info) != self.identity:
            raise RecordingFsError(f"Recording identity changed: {self.path}")
        final_path = _final_path(self.handle)
        if _path_key(final_path) != _path_key(self.path):
            raise RecordingFsError(f"Recording is not the named direct child: {self.path}")
        if PureWindowsPath(final_path).name != self.name:
            raise RecordingFsError(f"Recording is not the exact named direct child: {self.path}")

    def metadata(self) -> FileMetadata:
        self.validate()
        info = _basic_info(self.handle)
        metadata = FileMetadata(
            (info.nFileSizeHigh << 32) | info.nFileSizeLow,
            _filetime_seconds(info.ftLastWriteTime),
            _filetime_seconds(info.ftCreationTime),
        )
        self.validate()
        return metadata

    def seek(self, offset: int) -> None:
        if self.handle is None:
            raise RecordingFsError("Seek on closed recording")
        result = ctypes.c_longlong()
        if not _SetFilePointerEx(self.handle, offset, ctypes.byref(result), _FILE_BEGIN):
            raise _winerror("SetFilePointerEx failed")

    def read_all(self) -> bytes:
        self.validate()
        self.seek(0)
        chunks: list[bytes] = []
        while True:
            chunk = _read_some(self.handle, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        self.validate()
        return b"".join(chunks)

    def set_disposition(self, delete: bool) -> None:
        if self.handle is None:
            raise RecordingFsError("Disposition on closed recording")
        info = FILE_DISPOSITION_INFO(1 if delete else 0)
        if not _SetFileInformationByHandle(
            self.handle, _FILE_DISPOSITION_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise _winerror("SetFileInformationByHandle(FileDispositionInfo) failed")

    def delete_pending(self) -> bool:
        if self.handle is None:
            raise RecordingFsError("Query on closed recording")
        return bool(_standard_info(self.handle).DeletePending)

    def close(self) -> None:
        try:
            _close_native(self)
        except Exception as exc:
            raise RecordingFsError(f"Recording handle close failed: {exc}", (self,)) from exc


def _owned_protected(handle: int, directory: RecordingDirectory, name: str) -> ProtectedFile:
    owner = _HandleOwner(handle)
    try:
        protected = ProtectedFile(handle, directory, name)
    except Exception as exc:
        try:
            owner.close()
        except Exception:
            raise RecordingFsError(f"Recording metadata failed: {exc}", (owner,)) from exc
        raise
    owner.handle = None
    return protected


def _read_some(handle: int | None, size: int) -> bytes:
    if handle is None:
        raise RecordingFsError("Read on closed recording")
    buffer = ctypes.create_string_buffer(size)
    read = wintypes.DWORD()
    if not _ReadFile(handle, buffer, size, ctypes.byref(read), None):
        raise _winerror("ReadFile failed")
    return buffer.raw[: read.value]


def _write_all(handle: int | None, data: bytes) -> None:
    if handle is None:
        raise RecordingFsError("Write on closed recording")
    view = memoryview(data)
    while view:
        size = min(len(view), 0xFFFFFFFF)
        buffer = (ctypes.c_char * size).from_buffer_copy(view[:size])
        written = wintypes.DWORD()
        if not _WriteFile(handle, buffer, size, ctypes.byref(written), None):
            raise _winerror("WriteFile failed")
        if written.value == 0:
            raise RecordingFsError("WriteFile made no progress")
        view = view[written.value :]


def _flush(handle: int | None) -> None:
    if handle is None or not _FlushFileBuffers(handle):
        raise _winerror("FlushFileBuffers failed")


class RecordingWriter:
    def __init__(self, protected: ProtectedFile) -> None:
        self.file = protected

    @property
    def closed(self) -> bool:
        return self.file.closed

    @property
    def identity(self) -> FileIdentity:
        return self.file.identity

    @property
    def path(self) -> Path:
        return self.file.path

    @property
    def name(self) -> str:
        return self.file.name

    def write_batch(self, payload: bytes) -> None:
        try:
            self.file.validate()
            _write_all(self.file.handle, payload)
            _flush(self.file.handle)
            self.file.validate()
        except Exception as exc:
            cleanup: list[object] = []
            try:
                self.file.close()
            except Exception:
                cleanup.append(self.file)
            raise RecordingFsError(f"Recording batch failed: {exc}", cleanup) from exc

    def size(self) -> int:
        self.file.validate()
        value = ctypes.c_longlong()
        if self.file.handle is None or not _GetFileSizeEx(self.file.handle, ctypes.byref(value)):
            raise _winerror("GetFileSizeEx failed")
        self.file.validate()
        return value.value

    def close(self) -> None:
        if self.closed:
            return
        error: Exception | None = None
        try:
            self.file.validate()
            _flush(self.file.handle)
            self.file.validate()
        except Exception as exc:
            error = exc
        try:
            self.file.close()
        except Exception as exc:
            error = error or exc
        if error is not None:
            cleanup = () if self.closed else (self.file,)
            raise RecordingFsError(f"Recording close failed: {error}", cleanup) from error


def _stage_is_stale(stage: ProtectedFile, *, now: float) -> bool:
    if not _STAGE_RE.fullmatch(stage.name):
        return False
    metadata = stage.metadata()
    # Reserved grammar is ownership evidence only after the protected handle proves
    # the exact regular direct child. Fail closed unless both timestamps form a
    # trustworthy creation-then-write range within the caller's time horizon.
    timestamps = (now, metadata.created, metadata.modified)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in timestamps):
        return False
    if (
        not math.isfinite(now)
        or now <= 0
        or not math.isfinite(metadata.created)
        or not math.isfinite(metadata.modified)
        or metadata.created <= 0
        or metadata.modified <= 0
        or metadata.created > metadata.modified
        or metadata.created > now
        or metadata.modified > now
    ):
        return False
    return (
        now - metadata.created >= _STAGE_MIN_STALE_AGE_SECONDS
        and now - metadata.modified >= _STAGE_MIN_STALE_AGE_SECONDS
    )


def cleanup_stale_stages(directory: RecordingDirectory) -> None:
    now = time.time()
    for name in directory.names():
        if not _STAGE_RE.fullmatch(name):
            continue
        try:
            stage = directory.open_existing(name, _DELETE | _FILE_READ_ATTRIBUTES)
        except OSError as exc:
            if exc.winerror == _ERROR_SHARING_VIOLATION:
                continue
            raise
        if stage is None:
            continue
        try:
            if not _stage_is_stale(stage, now=now):
                continue
            stage.validate()
            stage.set_disposition(True)
            if not stage.delete_pending():
                raise RecordingFsError(f"Failed to mark stale stage delete-pending: {stage.path}")
        finally:
            stage.close()
    directory.validate()


def _require_complete_jsonl_tail(protected: ProtectedFile) -> None:
    if not protected.name.casefold().endswith(".jsonl"):
        return
    protected.validate()
    size = protected.metadata().size
    if size == 0:
        return
    protected.seek(size - 1)
    last_byte = _read_some(protected.handle, 1)
    protected.validate()
    if last_byte != b"\n":
        raise RecordingFsError(f"Refusing to append to recording with a partial final JSONL line: {protected.path}")


def open_writer(directory: RecordingDirectory, name: object) -> RecordingWriter:
    filename = validate_component(name, label="recording filename")
    directory.validate()
    handle = _open_native(
        directory.path / filename,
        _FILE_READ_DATA | _FILE_APPEND_DATA | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ,
        _OPEN_ALWAYS,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
    )
    protected = _owned_protected(handle, directory, filename)
    try:
        protected.validate()
        _require_complete_jsonl_tail(protected)
        protected.validate()
        directory.validate()
        return RecordingWriter(protected)
    except Exception as exc:
        try:
            protected.close()
        except Exception:
            raise RecordingFsError(f"Recording writer validation failed: {exc}", (protected,)) from exc
        raise


def _stage_name() -> str:
    return f".memscope-recording-stage-{uuid.uuid4().hex}.tmp"


def _open_stage(directory: RecordingDirectory) -> ProtectedFile:
    for _attempt in range(16):
        name = validate_component(_stage_name(), label="recording stage filename")
        try:
            handle = _open_native(
                directory.path / name,
                _GENERIC_READ | _GENERIC_WRITE | _DELETE | _FILE_READ_ATTRIBUTES,
                0,
                _CREATE_NEW,
                _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
            )
        except OSError as exc:
            if exc.winerror in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
                continue
            raise
        stage = _owned_protected(handle, directory, name)
        try:
            stage.validate()
            stage.set_disposition(True)
            if not stage.delete_pending():
                raise RecordingFsError("New recording stage is not delete-pending")
            stage.validate(allow_delete_pending=True)
            return stage
        except Exception as exc:
            try:
                stage.close()
            except Exception:
                raise RecordingFsError(f"Recording stage creation failed: {exc}", (stage,)) from exc
            raise
    raise RecordingFsError("Could not allocate a unique recording stage")


def _require_absent(directory: RecordingDirectory, name: str) -> None:
    name = validate_component(name, label="recording filename")
    directory.validate()
    try:
        handle = _open_native(
            directory.path / name,
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
    except OSError as exc:
        if exc.winerror in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
            directory.validate()
            return
        raise
    holder = type("_Probe", (), {"handle": handle})()
    try:
        _close_native(holder)
    finally:
        directory.validate()
    raise FileExistsError(f"Compressed recording already exists: {directory.path / name}")


def _rename_buffer(name: str, root_handle: int) -> tuple[ctypes.Array, int]:
    encoded = name.encode("utf-16-le")
    pointer_size = ctypes.sizeof(wintypes.HANDLE)
    root_offset = 8 if pointer_size == 8 else 4
    length_offset = root_offset + pointer_size
    name_offset = length_offset + ctypes.sizeof(wintypes.DWORD)
    header_size = (name_offset + 2 + pointer_size - 1) & ~(pointer_size - 1)
    buffer = ctypes.create_string_buffer(header_size + len(encoded))
    ctypes.c_uint32.from_buffer(buffer, 0).value = 0
    ctypes.c_void_p.from_buffer(buffer, root_offset).value = root_handle
    wintypes.DWORD.from_buffer(buffer, length_offset).value = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + name_offset, encoded, len(encoded))
    return buffer, header_size + len(encoded)


def _publish(stage: ProtectedFile, destination: str) -> None:
    destination = validate_component(destination, label="recording filename")
    if stage.handle is None:
        raise RecordingFsError("Publish on closed stage")
    buffer, size = _rename_buffer(str(stage.directory.path / destination), 0)
    if not _SetFileInformationByHandle(stage.handle, _FILE_RENAME_INFO_CLASS, buffer, size):
        raise _winerror("SetFileInformationByHandle(FileRenameInfo) failed")


def _compress_stream(source: ProtectedFile, stage: ProtectedFile) -> None:
    source.validate()
    stage.validate(allow_delete_pending=True)
    source.seek(0)
    original_hash = hashlib.sha256()
    original_size = 0
    compressor = zlib.compressobj(wbits=31)
    while True:
        chunk = _read_some(source.handle, 65536)
        if not chunk:
            break
        original_hash.update(chunk)
        original_size += len(chunk)
        output = compressor.compress(chunk)
        if output:
            _write_all(stage.handle, output)
    _write_all(stage.handle, compressor.flush())
    _flush(stage.handle)
    source.validate()
    stage.validate(allow_delete_pending=True)

    stage.seek(0)
    decompressor = zlib.decompressobj(wbits=31)
    readback_hash = hashlib.sha256()
    readback_size = 0
    try:
        while True:
            chunk = _read_some(stage.handle, 65536)
            if not chunk:
                break
            output = decompressor.decompress(chunk)
            readback_hash.update(output)
            readback_size += len(output)
        output = decompressor.flush()
    except zlib.error as exc:
        raise RecordingFsError("Recording gzip stage failed full readback") from exc
    readback_hash.update(output)
    readback_size += len(output)
    if not decompressor.eof or decompressor.unused_data or readback_size != original_size:
        raise RecordingFsError("Recording gzip stage failed full readback")
    if readback_hash.digest() != original_hash.digest():
        raise RecordingFsError("Recording gzip stage readback differs from source")
    source.validate()
    stage.validate(allow_delete_pending=True)


def compress_recording(directory: RecordingDirectory, source_name: str, expected_identity: FileIdentity) -> Path:
    source_name = validate_component(source_name, label="recording filename")
    source: ProtectedFile | None = None
    stage: ProtectedFile | None = None
    published = False
    destination = validate_component(source_name + ".gz", label="recording filename")
    try:
        source = directory.open_existing(source_name, _GENERIC_READ | _FILE_READ_ATTRIBUTES | _DELETE)
        if source is None:
            raise RecordingFsError(f"Recording source disappeared: {directory.path / source_name}")
        if source.identity != expected_identity:
            raise RecordingFsError(f"Recording source identity changed: {source.path}")
        source.validate()
        stage = _open_stage(directory)
        _compress_stream(source, stage)
        _require_absent(directory, destination)
        stage.set_disposition(False)
        if stage.delete_pending():
            raise RecordingFsError("Could not clear recording stage disposition")
        stage.validate()
        _publish(stage, destination)
        published = True
        stage.name = destination
        stage.validate()
        source.validate()
        directory.validate()
        stage.close()

        source.set_disposition(True)
        if not source.delete_pending():
            raise RecordingFsError("Recording source retirement was not armed")
        try:
            source.close()
        except Exception as close_error:
            source.set_disposition(False)
            if source.delete_pending():
                raise RecordingFsError("Could not preserve source after retirement close failure") from close_error
            source.close()
            raise RecordingFsError("Recording source retirement close failed; source preserved") from close_error
        return directory.path / destination
    except Exception as exc:
        cleanup: list[object] = []
        if source is not None and not source.closed:
            try:
                if published and source.delete_pending():
                    source.set_disposition(False)
                source.close()
            except Exception:
                cleanup.append(source)
        if stage is not None and not stage.closed:
            try:
                stage.set_disposition(not published)
                stage.close()
            except Exception:
                cleanup.append(stage)
        raise RecordingFsError(f"Recording compression failed: {exc}", cleanup) from exc
