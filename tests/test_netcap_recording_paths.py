"""Windows path, handle, durability, and publication tests for netcap recordings."""

from __future__ import annotations

import ctypes
import gzip
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from memscope_mcp._contrib.plugins import _recording_fs as recording_fs
from memscope_mcp._contrib.plugins import netcap as netcap_module
from memscope_mcp._contrib.plugins.netcap import NetcapPlugin


class LuaTable(dict):
    def __missing__(self, key):
        return None


def make_table(*args, **kwargs):
    result = LuaTable({index: value for index, value in enumerate(args, 1)})
    result.update(kwargs)
    return result


def make_plugin(warnings=None) -> NetcapPlugin:
    session = MagicMock()
    session.target_process = "TestGame.exe"
    manager = MagicMock(session=session)
    plugin = NetcapPlugin()
    plugin.register(
        SimpleNamespace(
            session=session,
            hook_manager=manager,
            table_factory=make_table,
            log_error=(
                (lambda operation, error: warnings.append((operation, error)))
                if warnings is not None
                else lambda *_args: None
            ),
        )
    )
    return plugin


def packet(sequence=1, data=b"x"):
    return make_table(
        direction="send",
        socket=1,
        socket_hex="0x1",
        timestamp=1,
        sequence=sequence,
        size=len(data),
        captured=len(data),
        result=len(data),
        caller="test+0x1",
        hook_name="send",
        data=make_table(*data),
    )


@dataclass(frozen=True)
class Roots:
    scripts: Path
    legacy: Path

    def recordings(self, process="TestGame.exe", *, legacy=False) -> Path:
        base = self.legacy / "scripts" if legacy else self.scripts
        return base / process / "recordings"


@pytest.fixture
def roots(tmp_path, monkeypatch) -> Roots:
    scripts = tmp_path / "canonical" / "scripts"
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    monkeypatch.setattr(netcap_module, "SCRIPTS_DIR", scripts)
    monkeypatch.chdir(legacy)
    return Roots(scripts, legacy)


def write_recording(path: Path, sequence: int, *, compressed=False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"direction": "send", "sequence": sequence}) + "\n"
    if compressed:
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            stream.write(payload)
    else:
        path.write_text(payload, encoding="utf-8")
    return path


def snapshot(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def set_creation_and_write_time(path: Path, timestamp: float) -> None:
    set_file_time = ctypes.WinDLL("kernel32", use_last_error=True).SetFileTime
    set_file_time.argtypes = [
        recording_fs.wintypes.HANDLE,
        ctypes.POINTER(recording_fs._FILETIME),
        ctypes.POINTER(recording_fs._FILETIME),
        ctypes.POINTER(recording_fs._FILETIME),
    ]
    set_file_time.restype = recording_fs.wintypes.BOOL
    ticks = int((timestamp + 11_644_473_600) * 10_000_000)
    filetime = recording_fs._FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)
    handle = recording_fs._open_native(
        path,
        0x100,  # FILE_WRITE_ATTRIBUTES
        recording_fs._FILE_SHARE_READ | recording_fs._FILE_SHARE_WRITE | recording_fs._FILE_SHARE_DELETE,
        recording_fs._OPEN_EXISTING,
        recording_fs._FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        if not set_file_time(handle, ctypes.byref(filetime), None, ctypes.byref(filetime)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        assert recording_fs._CloseHandle(handle)


def process_handle_count() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = recording_fs.wintypes.HANDLE
    get_process_handle_count = kernel32.GetProcessHandleCount
    get_process_handle_count.argtypes = [recording_fs.wintypes.HANDLE, ctypes.POINTER(recording_fs.wintypes.DWORD)]
    get_process_handle_count.restype = recording_fs.wintypes.BOOL
    count = recording_fs.wintypes.DWORD()
    if not get_process_handle_count(get_current_process(), ctypes.byref(count)):
        raise ctypes.WinError(ctypes.get_last_error())
    return count.value


class TestStartRecordingOptionValidation:
    def test_invalid_compress_keeps_roots_handles_cleanup_and_state_unchanged(self, roots):
        plugin = make_plugin()

        class CleanupOwner:
            closed = False
            calls = 0

            def close(self):
                self.calls += 1
                self.closed = True

        owner = CleanupOwner()
        cleanup_queue = [owner]
        plugin._recording_cleanup = cleanup_queue
        state_before = (
            plugin._recording_file,
            plugin._recording_path,
            plugin._recording_count,
            plugin._recording_start,
            plugin._recording_compress,
            plugin._recording_max_size,
            plugin._recording_base_name,
            plugin._recording_part,
            plugin._recording_dir,
        )
        legacy_before = snapshot(roots.legacy)

        with pytest.raises(TypeError, match=r"^compress must be a bool$"):
            plugin._start_recording("invalid-compress", make_table(compress="false"))
        baseline_handles = process_handle_count()

        for _ in range(25):
            with pytest.raises(TypeError, match=r"^compress must be a bool$"):
                plugin._start_recording("invalid-compress", make_table(compress="false"))

        assert process_handle_count() == baseline_handles
        assert not roots.scripts.exists()
        assert snapshot(roots.legacy) == legacy_before
        assert owner.calls == 0
        assert plugin._recording_cleanup is cleanup_queue
        assert (
            plugin._recording_file,
            plugin._recording_path,
            plugin._recording_count,
            plugin._recording_start,
            plugin._recording_compress,
            plugin._recording_max_size,
            plugin._recording_base_name,
            plugin._recording_part,
            plugin._recording_dir,
        ) == state_before


class TestRootsLookupAndLegacy:
    def test_writes_only_canonical_and_never_changes_legacy(self, roots):
        legacy = write_recording(roots.recordings(legacy=True) / "same.jsonl", 99)
        before = snapshot(roots.legacy)
        plugin = make_plugin()
        result = plugin._start_recording("same")
        plugin._record_packets([packet(1)])
        plugin._stop_recording()

        assert Path(result["path"]).parent == roots.recordings()
        assert roots.recordings().joinpath("same.jsonl").exists()
        assert legacy.read_text(encoding="utf-8").find('"sequence": 99') >= 0
        assert snapshot(roots.legacy) == before

    @pytest.mark.parametrize("query", ["capture", "capture.jsonl"])
    def test_canonical_gzip_precedes_legacy_plain_for_implicit_plain_queries(self, roots, query):
        write_recording(roots.recordings() / "capture.jsonl.gz", 1, compressed=True)
        write_recording(roots.recordings(legacy=True) / "capture.jsonl", 2)
        loaded = make_plugin()._load_recording(query)
        assert loaded[1]["sequence"] == 1
        assert "legacy_source" not in loaded

    def test_exact_explicit_gzip_does_not_consider_plain(self, roots):
        write_recording(roots.recordings() / "capture.jsonl", 1)
        write_recording(roots.recordings(legacy=True) / "capture.jsonl.gz", 2, compressed=True)
        loaded = make_plugin()._load_recording("capture.jsonl.gz")
        assert loaded[1]["sequence"] == 2
        assert loaded["legacy_source"] is True

    def test_plain_precedes_gzip_in_one_root(self, roots):
        write_recording(roots.recordings() / "capture.jsonl", 1)
        write_recording(roots.recordings() / "capture.jsonl.gz", 2, compressed=True)
        assert make_plugin()._load_recording("capture")[1]["sequence"] == 1

    def test_legacy_marker_and_exact_warning_once_per_call(self, roots):
        path = write_recording(roots.recordings(legacy=True) / "legacy.jsonl", 7)
        warnings = []
        plugin = make_plugin(warnings)
        first = plugin._load_recording("legacy")
        second = plugin._load_recording("legacy")
        assert first["legacy_source"] is True and second["legacy_source"] is True
        assert [item[0] for item in warnings] == ["loadRecording", "loadRecording"]
        assert all(
            str(item[1]).startswith("NETCAP_LEGACY_RECORDING_PATH: using read-only legacy recording at ")
            for item in warnings
        )
        assert all(str(path) in str(item[1]) for item in warnings)

    def test_listing_dedup_order_shadowing_and_one_warning(self, roots):
        write_recording(roots.recordings("Zoo.exe") / "same.jsonl", 1)
        write_recording(roots.recordings("Zoo.exe") / "same.jsonl.gz", 2, compressed=True)
        write_recording(roots.recordings("apple.exe") / "Zulu.JSONL", 3)
        write_recording(roots.recordings("zoo.EXE", legacy=True) / "SAME.jsonl", 4)
        write_recording(roots.recordings("Beta.exe", legacy=True) / "alpha.jsonl", 5)
        warnings = []
        listed = make_plugin(warnings)._list_recordings("*")
        entries = [listed[index] for index in range(1, 4)]
        assert [(item["process"], item["filename"]) for item in entries] == [
            ("apple.exe", "Zulu"),
            ("Beta.exe", "alpha"),
            ("Zoo.exe", "same"),
        ]
        assert entries[1]["legacy_source"] is True
        assert entries[2]["compressed"] is False
        assert [item[0] for item in warnings] == ["listRecordings"]
        assert str(warnings[0][1]).startswith("NETCAP_LEGACY_RECORDING_PATH:")

    def test_wildcard_listing_ignores_ordinary_scripts_root_files(self, roots):
        roots.scripts.mkdir(parents=True)
        roots.scripts.joinpath("README.txt").write_text("not a process", encoding="utf-8")
        write_recording(roots.recordings() / "capture.jsonl", 1)
        listed = make_plugin()._list_recordings("*")
        assert listed[1]["filename"] == "capture"
        assert listed[2] is None

    def test_missing_legacy_lookup_does_not_create_any_directory(self, roots):
        with pytest.raises(RuntimeError, match="Recording not found"):
            make_plugin()._load_recording("missing")
        assert snapshot(roots.legacy) == {}


class TestExactCaseBinding:
    @pytest.mark.parametrize(
        ("actual_name", "query", "compressed"),
        [
            pytest.param("CanonicalCase.jsonl", "canonicalcase", False, id="plain"),
            pytest.param("CanonicalCase.jsonl.gz", "canonicalcase.jsonl.gz", True, id="gzip"),
        ],
    )
    def test_wrong_case_canonical_leaf_terminates_load_and_resolve_without_fallback(
        self, roots, actual_name, query, compressed
    ):
        canonical = write_recording(roots.recordings() / actual_name, 1, compressed=compressed)
        if not compressed:
            canonical_gzip = write_recording(roots.recordings() / "canonicalcase.jsonl.gz", 2, compressed=True)
        else:
            canonical_gzip = None
        legacy_name = "canonicalcase.jsonl.gz" if compressed else "canonicalcase.jsonl"
        legacy = write_recording(roots.recordings(legacy=True) / legacy_name, 3, compressed=compressed)
        canonical_before = canonical.read_bytes()
        gzip_before = canonical_gzip.read_bytes() if canonical_gzip is not None else None
        legacy_before = legacy.read_bytes()
        warnings = []
        plugin = make_plugin(warnings)

        with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
            plugin._load_recording(query)
        with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
            plugin._resolve_recording_path(query, "TestGame.exe")

        assert canonical.read_bytes() == canonical_before
        if canonical_gzip is not None:
            assert canonical_gzip.read_bytes() == gzip_before
        assert legacy.read_bytes() == legacy_before
        assert warnings == []

    @pytest.mark.parametrize(
        ("actual_name", "query", "compressed"),
        [
            pytest.param("CanonicalCase.jsonl", "CanonicalCase", False, id="plain"),
            pytest.param("CanonicalCase.jsonl.gz", "CanonicalCase.jsonl.gz", True, id="gzip"),
        ],
    )
    def test_exact_case_plain_and_gzip_load_and_resolve(self, roots, actual_name, query, compressed):
        expected = write_recording(roots.recordings() / actual_name, 7, compressed=compressed)
        plugin = make_plugin()

        loaded = plugin._load_recording(query)
        resolved = plugin._resolve_recording_path(query, "TestGame.exe")

        assert loaded[1]["sequence"] == 7
        assert resolved.name == actual_name
        assert recording_fs.same_path(resolved, expected)

    def test_repeated_wrong_case_lookup_keeps_handles_stable_and_never_uses_gzip_or_legacy(self, roots):
        canonical = write_recording(roots.recordings() / "CanonicalCase.jsonl", 1)
        canonical_gzip = write_recording(roots.recordings() / "canonicalcase.jsonl.gz", 2, compressed=True)
        legacy = write_recording(roots.recordings(legacy=True) / "canonicalcase.jsonl", 3)
        canonical_before = canonical.read_bytes()
        gzip_before = canonical_gzip.read_bytes()
        legacy_before = legacy.read_bytes()
        warnings = []
        plugin = make_plugin(warnings)
        counts = [process_handle_count()]

        for _ in range(25):
            with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
                plugin._load_recording("canonicalcase")
            counts.append(process_handle_count())

        assert counts[-1] <= counts[0] + 1
        assert max(counts) - min(counts) <= 1
        assert canonical.read_bytes() == canonical_before
        assert canonical_gzip.read_bytes() == gzip_before
        assert legacy.read_bytes() == legacy_before
        assert warnings == []

    def test_wrong_case_open_always_fails_before_append_or_state_commit(self, roots):
        existing = write_recording(roots.recordings() / "CanonicalCase.jsonl", 99)
        before = existing.read_bytes()
        plugin = make_plugin()
        baseline_handles = process_handle_count()

        with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
            plugin._start_recording("canonicalcase")

        assert existing.read_bytes() == before
        assert plugin._recording_file is None
        assert plugin._recording_dir is None
        assert plugin._recording_path is None
        assert plugin._recording_cleanup == []
        assert process_handle_count() <= baseline_handles + 1

    def test_wrong_case_validation_close_failure_retains_file_cleanup_owner(self, roots, monkeypatch):
        write_recording(roots.recordings() / "CanonicalCase.jsonl", 1)
        directory = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=False)
        assert directory is not None
        original_close = recording_fs.ProtectedFile.close
        retained = None

        def fail_first_mismatch_close(self):
            nonlocal retained
            if self.name == "canonicalcase.jsonl" and retained is None:
                retained = self
                raise recording_fs.RecordingFsError("injected mismatch close failure", (self,))
            return original_close(self)

        monkeypatch.setattr(recording_fs.ProtectedFile, "close", fail_first_mismatch_close)
        try:
            with pytest.raises(recording_fs.RecordingFsError, match="Recording validation failed") as caught:
                directory.open_existing("canonicalcase.jsonl")
            assert retained is not None
            assert not retained.closed
            assert any(owner is retained for owner in caught.value.cleanup)
        finally:
            monkeypatch.setattr(recording_fs.ProtectedFile, "close", original_close)
            if retained is not None and not retained.closed:
                retained.close()
            directory.close()

    def test_wrong_case_process_directory_is_rejected_before_child_creation_but_wildcard_lists_actual_name(self, roots):
        actual_process = "TestGame.EXE"
        process_dir = roots.scripts / actual_process
        process_dir.mkdir(parents=True)
        marker = process_dir / "keep.txt"
        marker.write_bytes(b"keep")
        plugin = make_plugin()

        with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
            plugin._start_recording("capture")
        assert not (process_dir / "recordings").exists()
        assert marker.read_bytes() == b"keep"

        write_recording(process_dir / "recordings" / "MiXeD.jsonl", 4)
        with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
            plugin._list_recordings("TestGame.exe")
        listed = plugin._list_recordings("*")
        assert listed[1]["process"] == actual_process
        assert listed[1]["filename"] == "MiXeD"
        assert Path(listed[1]["path"]).name == "MiXeD.jsonl"
        assert listed[2] is None

    def test_ancestor_and_fixed_recordings_casing_remain_case_insensitive(self, roots, monkeypatch):
        tmp_root = roots.scripts.parents[1]
        actual_scripts = tmp_root / "CaseRoot" / "Scripts"
        actual = write_recording(actual_scripts / "TestGame.exe" / "Recordings" / "ExactLeaf.jsonl", 5)
        configured_scripts = tmp_root / "caseroot" / "scripts"
        monkeypatch.setattr(netcap_module, "SCRIPTS_DIR", configured_scripts)
        plugin = make_plugin()

        loaded = plugin._load_recording("ExactLeaf")
        resolved = plugin._resolve_recording_path("ExactLeaf", "TestGame.exe")

        assert loaded[1]["sequence"] == 5
        assert recording_fs.same_path(resolved, actual)
        assert resolved.name == "ExactLeaf.jsonl"

    def test_literal_percent_and_exact_nfc_case_distinction_round_trip(self, roots):
        plugin = make_plugin()
        plugin._session.target_process = "Proc%name.exe"
        started = plugin._start_recording("Caf\u00e9%name")
        plugin._record_packets([packet(8)])
        plugin._stop_recording()

        assert Path(started["path"]).name == "Caf\u00e9%name.jsonl"
        assert plugin._load_recording("Caf\u00e9%name")[1]["sequence"] == 8
        with pytest.raises(recording_fs.RecordingFsError, match="exact named direct child"):
            plugin._load_recording("caf\u00e9%name")


class TestComponentsAndObjects:
    @pytest.mark.parametrize(
        "name",
        [
            "",
            ".",
            "..",
            "../x",
            "x/y",
            "x\\y",
            "C:x",
            "C:\\x",
            "x:y",
            "x. ",
            "x.",
            "CON",
            "aux.txt",
            "COM1",
            "LPT².log",
            "x\x00y",
        ],
    )
    def test_strict_component_rejections(self, name):
        with pytest.raises(ValueError):
            recording_fs.validate_component(name)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("%2e", id="encoded-dot-lower"),
            pytest.param("%2E%2e", id="encoded-dotdot-mixed"),
            pytest.param("%5c", id="encoded-backslash-lower"),
            pytest.param("%5C", id="encoded-backslash-upper"),
            pytest.param("%2f", id="encoded-slash"),
            pytest.param("%3a", id="encoded-colon"),
            pytest.param("%00", id="encoded-nul"),
            pytest.param("name%20", id="encoded-trailing-space"),
            pytest.param("name%2e", id="encoded-trailing-dot"),
            pytest.param("%43%4f%4e", id="encoded-device-name"),
            pytest.param("name%2ejsonl", id="embedded-extension"),
            pytest.param("prefix%41suffix", id="embedded-safe-byte"),
            pytest.param("%af", id="lower-hex"),
            pytest.param("%AF", id="upper-hex"),
            pytest.param("%aF", id="mixed-hex"),
            pytest.param("%2e%2e%5cfile", id="adjacent-tokens"),
            pytest.param("%%%2e", id="overlapping-percent-prefix"),
            pytest.param("%252e", id="encoded-percent-prefix"),
        ],
    )
    def test_percent_escape_tokens_are_rejected_without_decoding(self, name):
        with pytest.raises(ValueError):
            recording_fs.validate_component(name)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("100%coverage", id="single-hex-then-nonhex"),
            pytest.param("percent%2", id="one-hex-digit"),
            pytest.param("percent%GG", id="nonhex-pair"),
            pytest.param("trailing%", id="trailing-percent"),
            pytest.param("literal%%name", id="double-percent-no-escape"),
        ],
    )
    def test_literal_percent_without_two_hex_digits_remains_valid(self, name):
        assert recording_fs.validate_component(name) == name

    @pytest.mark.parametrize(
        ("component", "value"),
        [
            pytest.param("process", "Game%2eexe", id="process"),
            pytest.param("recording", "capture%2ejsonl", id="recording"),
        ],
    )
    def test_percent_escape_start_components_fail_before_cleanup_or_filesystem_mutation(self, roots, component, value):
        plugin = make_plugin()

        class CleanupOwner:
            closed = False
            calls = 0

            def close(self):
                self.calls += 1
                self.closed = True

        owner = CleanupOwner()
        cleanup_queue = [owner]
        plugin._recording_cleanup = cleanup_queue
        if component == "process":
            plugin._session.target_process = value
            filename = "safe"
        else:
            filename = value
        legacy_before = snapshot(roots.legacy)

        with pytest.raises(ValueError):
            plugin._start_recording(filename)

        assert owner.calls == 0
        assert plugin._recording_cleanup is cleanup_queue
        assert plugin._recording_file is None
        assert plugin._recording_dir is None
        assert not roots.scripts.exists()
        assert snapshot(roots.legacy) == legacy_before

    def test_percent_escape_in_configured_root_fails_before_handle_or_directory_creation(self, roots):
        escaped_scripts = roots.scripts.parent / "bad%2froot" / "scripts"
        baseline_handles = process_handle_count()

        with pytest.raises(ValueError):
            recording_fs.acquire_recording_directory(escaped_scripts, "TestGame.exe", create=True)

        assert process_handle_count() == baseline_handles
        assert not escaped_scripts.parent.exists()

    @pytest.mark.parametrize(
        ("value", "case"),
        [
            pytest.param("bad\x7f", "del", id="del"),
            pytest.param("bad\u0085", "nel", id="nel"),
            pytest.param("bad\u202e", "bidi-rlo", id="bidi-rlo"),
            pytest.param("e\u0301", "non-nfc", id="non-nfc"),
        ],
    )
    @pytest.mark.parametrize("component", ["process", "recording"])
    def test_unicode_component_rejections_happen_before_mutation(self, roots, value, case, component):
        del case
        plugin = make_plugin()
        if component == "process":
            plugin._session.target_process = value
            filename = "safe"
        else:
            filename = value
        with pytest.raises(ValueError):
            plugin._start_recording(filename)
        assert not roots.scripts.exists()

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("bad\ud800", id="surrogate"),
            pytest.param("bad\ufdd0", id="noncharacter-fdd0"),
            pytest.param("bad\ufffe", id="noncharacter-fffe"),
            pytest.param("bad\U0001ffff", id="supplementary-noncharacter"),
        ],
    )
    def test_unicode_surrogate_and_noncharacter_rejections(self, name):
        with pytest.raises(ValueError):
            recording_fs.validate_component(name)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("caf\u00e9", id="nfc-latin"),
            pytest.param("q\u0301", id="canonical-combining-mark"),
            pytest.param("rocket-\U0001f680", id="supplementary"),
        ],
    )
    @pytest.mark.parametrize("component", ["process", "recording"])
    def test_valid_nfc_unicode_process_and_recording_components(self, roots, name, component):
        plugin = make_plugin()
        filename = "capture"
        if component == "process":
            plugin._session.target_process = name
        else:
            filename = name
        result = plugin._start_recording(filename)
        plugin._record_packets([packet(1)])
        plugin._stop_recording()
        path = Path(result["path"])
        assert path.exists()
        assert recording_fs.validate_component(name) == name

    def test_listing_invalid_present_recording_entry_fails_closed(self, roots):
        invalid = roots.recordings() / "bad\u202e.jsonl"
        invalid.parent.mkdir(parents=True)
        invalid.write_bytes(b"keep")
        before = invalid.read_bytes()
        with pytest.raises(ValueError):
            make_plugin()._list_recordings("TestGame.exe")
        assert invalid.read_bytes() == before

    def test_listing_invalid_present_process_entry_fails_closed(self, roots):
        invalid = roots.scripts / "bad\u0085"
        invalid.mkdir(parents=True)
        marker = invalid / "keep.txt"
        marker.write_bytes(b"keep")
        with pytest.raises(ValueError):
            make_plugin()._list_recordings("*")
        assert marker.read_bytes() == b"keep"

    def test_invalid_process_and_filename_rejected_before_mutation(self, roots):
        plugin = make_plugin()
        plugin._session.target_process = ".."
        with pytest.raises(ValueError):
            plugin._start_recording("safe")
        plugin._session.target_process = "TestGame.exe"
        with pytest.raises(ValueError):
            plugin._start_recording("..\\escape")
        assert not roots.scripts.exists()

    def test_canonical_hard_link_terminates_without_gzip_or_legacy_fallback(self, roots, tmp_path):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        outside = write_recording(tmp_path / "outside.jsonl", 1)
        os.link(outside, directory / "capture.jsonl")
        write_recording(directory / "capture.jsonl.gz", 2, compressed=True)
        legacy = write_recording(roots.recordings(legacy=True) / "capture.jsonl", 3)
        before = legacy.read_bytes()
        with pytest.raises(recording_fs.RecordingFsError, match="Hard-linked"):
            make_plugin()._load_recording("capture")
        assert legacy.read_bytes() == before

    def test_repeated_invalid_present_canonical_lookup_keeps_handles_stable_and_never_falls_back(self, roots, tmp_path):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        outside = write_recording(tmp_path / "outside-repeat.jsonl", 1)
        os.link(outside, directory / "capture.jsonl")
        canonical_gzip = write_recording(directory / "capture.jsonl.gz", 2, compressed=True)
        legacy = write_recording(roots.recordings(legacy=True) / "capture.jsonl", 3)
        gzip_before = canonical_gzip.read_bytes()
        legacy_before = legacy.read_bytes()
        warnings = []
        plugin = make_plugin(warnings)
        counts = [process_handle_count()]

        for _ in range(25):
            with pytest.raises(recording_fs.RecordingFsError, match="Hard-linked"):
                plugin._load_recording("capture")
            counts.append(process_handle_count())

        assert counts[-1] <= counts[0] + 1
        assert max(counts) - min(counts) <= 1
        assert canonical_gzip.read_bytes() == gzip_before
        assert legacy.read_bytes() == legacy_before
        assert warnings == []

    def test_invalid_present_lookup_closes_held_directory_on_exception(self, roots, tmp_path, monkeypatch):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        outside = write_recording(tmp_path / "outside-close.jsonl", 1)
        os.link(outside, directory / "capture.jsonl")
        original_close = recording_fs.RecordingDirectory.close
        closed = []

        def observe_close(self):
            if recording_fs.same_path(self.path, directory):
                closed.append(self)
            return original_close(self)

        monkeypatch.setattr(recording_fs.RecordingDirectory, "close", observe_close)
        with pytest.raises(recording_fs.RecordingFsError, match="Hard-linked"):
            make_plugin()._load_recording("capture")

        assert len(closed) == 1
        assert closed[0].closed

    def test_invalid_present_lookup_close_failure_retains_directory_cleanup_owner(self, roots, tmp_path, monkeypatch):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        outside = write_recording(tmp_path / "outside-close-fail.jsonl", 1)
        os.link(outside, directory / "capture.jsonl")
        original_close = recording_fs.RecordingDirectory.close
        failed_directory = None

        def fail_close(self):
            nonlocal failed_directory
            if failed_directory is None and recording_fs.same_path(self.path, directory):
                failed_directory = self
                raise OSError("injected directory close failure")
            return original_close(self)

        monkeypatch.setattr(recording_fs.RecordingDirectory, "close", fail_close)
        with pytest.raises(recording_fs.RecordingFsError, match="directory close failed") as caught:
            make_plugin()._load_recording("capture")

        assert failed_directory is not None
        assert not failed_directory.closed
        assert any(owner is failed_directory for owner in caught.value.cleanup)
        original_close(failed_directory)
        assert failed_directory.closed

    def test_missing_lookup_close_failure_retains_no_return_directory_cleanup_owner(self, roots, monkeypatch):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        original_close = recording_fs.RecordingDirectory.close
        failed_directory = None

        def fail_close(self):
            nonlocal failed_directory
            if failed_directory is None and recording_fs.same_path(self.path, directory):
                failed_directory = self
                raise OSError("injected missing lookup close failure")
            return original_close(self)

        monkeypatch.setattr(recording_fs.RecordingDirectory, "close", fail_close)
        with pytest.raises(recording_fs.RecordingFsError, match="lookup directory close failed") as caught:
            make_plugin()._load_recording("missing")

        assert failed_directory is not None
        assert not failed_directory.closed
        assert any(owner is failed_directory for owner in caught.value.cleanup)
        original_close(failed_directory)
        assert failed_directory.closed

    def test_nonregular_candidate_terminates(self, roots):
        candidate = roots.recordings() / "capture.jsonl"
        candidate.mkdir(parents=True)
        write_recording(roots.recordings(legacy=True) / "capture.jsonl", 3)
        with pytest.raises(recording_fs.RecordingFsError, match="Non-regular"):
            make_plugin()._load_recording("capture")

    def test_symlink_candidate_rejected_when_available(self, roots, tmp_path):
        target = write_recording(tmp_path / "target.jsonl", 1)
        candidate = roots.recordings() / "capture.jsonl"
        candidate.parent.mkdir(parents=True)
        try:
            candidate.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlink unavailable: {exc}")
        with pytest.raises(recording_fs.RecordingFsError, match="reparse"):
            make_plugin()._load_recording("capture")

    def test_held_directory_handles_prevent_namespace_replacement(self, roots):
        plugin = make_plugin()
        plugin._start_recording("capture")
        replacement = roots.recordings().with_name("replacement")
        with pytest.raises(PermissionError):
            os.rename(roots.recordings(), replacement)
        plugin._stop_recording()

    def test_lexical_root_reparse_is_rejected_without_touching_target(self, roots, tmp_path, monkeypatch):
        outside = tmp_path / "outside"
        outside.mkdir()
        link = tmp_path / "root-link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory symlink unavailable: {exc}")
        monkeypatch.setattr(netcap_module, "SCRIPTS_DIR", link / "scripts")
        with pytest.raises(recording_fs.RecordingFsError, match="Reparse-point directory"):
            make_plugin()._start_recording("capture")
        assert snapshot(outside) == {}

    def test_short_name_alias_is_rejected_when_available(self, roots):
        directory = roots.recordings()
        write_recording(directory / "LongRecordingName.jsonl", 1)
        get_short = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
        get_short.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        get_short.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        if not get_short(str(directory / "LongRecordingName.jsonl"), buffer, len(buffer)):
            pytest.skip("8.3 names unavailable")
        short_name = Path(buffer.value).name
        if short_name.casefold() == "longrecordingname.jsonl".casefold():
            pytest.skip("8.3 alias was not generated")
        guard = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=False)
        assert guard is not None
        try:
            with pytest.raises(recording_fs.RecordingFsError, match="direct child"):
                guard.open_existing(short_name)
        finally:
            guard.close()


class TestAppendRotationAndState:
    def test_existing_initial_file_is_appended(self, roots):
        path = write_recording(roots.recordings() / "capture.jsonl", 99)
        plugin = make_plugin()
        plugin._start_recording("capture")
        plugin._record_packets([packet(1)])
        plugin._stop_recording()
        assert [json.loads(line)["sequence"] for line in path.read_text(encoding="utf-8").splitlines()] == [99, 1]

    def test_empty_existing_file_is_appendable(self, roots):
        path = roots.recordings() / "capture.jsonl"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"")
        plugin = make_plugin()
        plugin._start_recording("capture")
        plugin._record_packets([packet(1)])
        plugin._stop_recording()
        assert [json.loads(line)["sequence"] for line in path.read_text(encoding="utf-8").splitlines()] == [1]

    def test_multiple_lf_terminated_records_are_appendable(self, roots):
        path = write_recording(roots.recordings() / "capture.jsonl", 90)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"direction": "send", "sequence": 91}) + "\n")
        plugin = make_plugin()
        plugin._start_recording("capture")
        plugin._record_packets([packet(1)])
        plugin._stop_recording()
        assert [json.loads(line)["sequence"] for line in path.read_text(encoding="utf-8").splitlines()] == [90, 91, 1]

    def test_existing_part_is_appended_after_rotation(self, roots):
        first = write_recording(roots.recordings() / "capture.jsonl", 90)
        second = write_recording(roots.recordings() / "capture_part002.jsonl", 91)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(max_size_mb=0.000001))
        plugin._record_packets([packet(1)])
        plugin._record_packets([packet(2)])
        plugin._stop_recording()
        assert [json.loads(line)["sequence"] for line in first.read_text().splitlines()] == [90, 1]
        assert [json.loads(line)["sequence"] for line in second.read_text().splitlines()] == [91, 2]

    def test_partial_existing_next_part_blocks_rotation_without_mutation(self, roots):
        next_part = roots.recordings() / "capture_part002.jsonl"
        next_part.parent.mkdir(parents=True)
        next_part.write_bytes(b'{"direction":"send","sequence":91}')
        before = next_part.read_bytes()
        before_hash = hashlib.sha256(before).hexdigest()
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(max_size_mb=0.000001))
        with pytest.raises(recording_fs.RecordingFsError, match="partial final JSONL line"):
            plugin._record_packets([packet(1)])
        assert next_part.read_bytes() == before
        assert hashlib.sha256(next_part.read_bytes()).hexdigest() == before_hash
        assert plugin._recording_file is None
        plugin._cleanup(process_alive=False)

    def test_batches_and_rotation_state_are_serialized(self, roots):
        plugin = make_plugin()
        plugin._start_recording("capture")
        writer = plugin._recording_file
        original = writer.write_batch
        first_entered = threading.Event()
        second_attempted = threading.Event()
        second_entered = threading.Event()
        release = threading.Event()
        calls = 0

        def blocked(payload):
            nonlocal calls
            calls += 1
            if calls == 1:
                first_entered.set()
                assert release.wait(5)
            else:
                second_entered.set()
            original(payload)

        writer.write_batch = blocked
        first = threading.Thread(target=plugin._record_packets, args=([packet(1)],))

        def second_call():
            second_attempted.set()
            plugin._record_packets([packet(2)])

        second = threading.Thread(target=second_call)
        first.start()
        assert first_entered.wait(5)
        second.start()
        assert second_attempted.wait(5)
        assert not second_entered.is_set()
        release.set()
        first.join(5)
        second.join(5)
        assert not first.is_alive() and not second.is_alive()
        assert calls == 2 and plugin._recording_count == 2
        plugin._stop_recording()

    def test_next_open_failure_resets_coherent_inactive_state(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(max_size_mb=0.000001))
        original = netcap_module.open_writer

        def fail_next(directory, name):
            if "part002" in str(name):
                raise OSError("next open failed")
            return original(directory, name)

        monkeypatch.setattr(netcap_module, "open_writer", fail_next)
        with pytest.raises(OSError, match="next open failed"):
            plugin._record_packets([packet(1)])
        assert plugin._recording_file is None
        assert plugin._recording_dir is None
        assert plugin._recording_path is None
        assert plugin._recording_part == 1
        plugin._cleanup(process_alive=False)


class TestCompressionPublicationAndStages:
    def test_existing_destination_preserves_source_and_target(self, roots):
        target = write_recording(roots.recordings() / "capture.jsonl.gz", 77, compressed=True)
        target_before = target.read_bytes()
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="already exists"):
            plugin._stop_recording()
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert target.read_bytes() == target_before
        assert not list(roots.recordings().glob(".memscope-recording-stage-*.tmp"))
        plugin._cleanup(process_alive=False)

    def test_target_created_between_absence_check_and_publish_wins(self, roots, monkeypatch):
        original = recording_fs._publish

        def race(stage, destination):
            write_recording(stage.directory.path / destination, 88, compressed=True)
            return original(stage, destination)

        monkeypatch.setattr(recording_fs, "_publish", race)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError):
            plugin._stop_recording()
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert gzip.open(roots.recordings() / "capture.jsonl.gz", "rt").read().find('"sequence": 88') >= 0
        plugin._cleanup(process_alive=False)

    def test_stage_name_collision_retries_create_new(self, roots, monkeypatch):
        collision = roots.recordings() / ".memscope-recording-stage-11111111111111111111111111111111.tmp"
        collision.parent.mkdir(parents=True)
        collision.write_bytes(b"keep")
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        collision.write_bytes(b"keep")
        names = iter([collision.name, ".memscope-recording-stage-22222222222222222222222222222222.tmp"])
        monkeypatch.setattr(recording_fs, "_stage_name", lambda: next(names))
        plugin._record_packets([packet(1)])
        plugin._stop_recording()
        assert collision.read_bytes() == b"keep"

    def test_full_readback_corruption_rejects_stage(self, roots, monkeypatch):
        original_seek = recording_fs.ProtectedFile.seek
        original_read = recording_fs._read_some
        corrupt_handles = set()

        def observe_seek(self, offset):
            result = original_seek(self, offset)
            if offset == 0 and self.name.startswith(".memscope-recording-stage-"):
                corrupt_handles.add(self.handle)
            return result

        def corrupt_read(handle, size):
            data = original_read(handle, size)
            if handle in corrupt_handles and data:
                corrupt_handles.remove(handle)
                return bytes([data[0] ^ 1]) + data[1:]
            return data

        monkeypatch.setattr(recording_fs.ProtectedFile, "seek", observe_seek)
        monkeypatch.setattr(recording_fs, "_read_some", corrupt_read)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="readback"):
            plugin._stop_recording()
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert not roots.recordings().joinpath("capture.jsonl.gz").exists()
        assert not list(roots.recordings().glob(".memscope-recording-stage-*.tmp"))
        plugin._cleanup(process_alive=False)

    def test_fresh_exact_stage_and_lookalike_are_untouched(self, roots):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        fresh = directory / ".memscope-recording-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp"
        lookalike = directory / ".memscope-recording-stage-nothex.tmp"
        fresh.write_bytes(b"fresh")
        lookalike.write_bytes(b"keep")
        plugin = make_plugin()
        plugin._start_recording("capture")
        assert fresh.read_bytes() == b"fresh"
        assert lookalike.read_bytes() == b"keep"
        plugin._stop_recording()

    def test_brand_new_exact_stage_with_old_mtime_is_not_stale(self, roots):
        stage = roots.recordings() / ".memscope-recording-stage-abababababababababababababababab.tmp"
        stage.parent.mkdir(parents=True)
        stage.write_bytes(b"fresh-owner")
        old = time.time() - recording_fs._STAGE_MIN_STALE_AGE_SECONDS - 60
        os.utime(stage, (old, old))
        plugin = make_plugin()
        plugin._start_recording("capture")
        assert stage.read_bytes() == b"fresh-owner"
        plugin._stop_recording()

    def test_old_exact_stage_removed_but_lookalike_untouched(self, roots):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        stale = directory / ".memscope-recording-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp"
        lookalike = directory / ".memscope-recording-stage-nothex.tmp"
        stale.write_bytes(b"stale")
        lookalike.write_bytes(b"keep")
        old = time.time() - recording_fs._STAGE_MIN_STALE_AGE_SECONDS - 60
        set_creation_and_write_time(stale, old)
        plugin = make_plugin()
        plugin._start_recording("capture")
        assert not stale.exists()
        assert lookalike.read_bytes() == b"keep"
        plugin._stop_recording()

    @pytest.mark.parametrize(
        ("age_delta", "expected"),
        [
            pytest.param(-1, False, id="just-below"),
            pytest.param(0, True, id="at-threshold"),
            pytest.param(1, True, id="just-above"),
        ],
    )
    def test_stage_stale_age_boundary_uses_handle_metadata(self, roots, age_delta, expected):
        directory_path = roots.recordings()
        directory_path.mkdir(parents=True)
        stage_path = directory_path / ".memscope-recording-stage-cccccccccccccccccccccccccccccccc.tmp"
        stage_path.write_bytes(b"stage")
        now = 2_000_000_000.0
        age = recording_fs._STAGE_MIN_STALE_AGE_SECONDS + age_delta
        timestamp = now - age
        set_creation_and_write_time(stage_path, timestamp)
        directory = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=False)
        assert directory is not None
        stage = directory.open_existing(stage_path.name, recording_fs._FILE_READ_ATTRIBUTES)
        assert stage is not None
        try:
            metadata = stage.metadata()
            assert metadata.created == pytest.approx(timestamp, abs=0.001)
            assert metadata.modified == pytest.approx(timestamp, abs=0.001)
            assert recording_fs._stage_is_stale(stage, now=now) is expected
        finally:
            stage.close()
            directory.close()

    @pytest.mark.parametrize(
        "case",
        [
            "zero-created",
            "negative-created",
            "zero-modified",
            "negative-modified",
            "future-created",
            "future-modified",
            "nan-created",
            "nan-modified",
            "positive-infinite-created",
            "negative-infinite-modified",
            "creation-after-write",
        ],
    )
    def test_untrusted_stage_timestamps_fail_closed_and_leave_stage_intact(self, roots, monkeypatch, case):
        now = 2_000_000_000.0
        old = now - recording_fs._STAGE_MIN_STALE_AGE_SECONDS - 60
        created, modified = {
            "zero-created": (0.0, old),
            "negative-created": (-1.0, old),
            "zero-modified": (old, 0.0),
            "negative-modified": (old, -1.0),
            "future-created": (now + 1, now + 1),
            "future-modified": (old, now + 1),
            "nan-created": (float("nan"), old),
            "nan-modified": (old, float("nan")),
            "positive-infinite-created": (float("inf"), old),
            "negative-infinite-modified": (old, float("-inf")),
            "creation-after-write": (old + 30, old),
        }[case]
        stage_path = roots.recordings() / ".memscope-recording-stage-12121212121212121212121212121212.tmp"
        stage_path.parent.mkdir(parents=True)
        stage_path.write_bytes(b"keep-stage")
        original_metadata = recording_fs.ProtectedFile.metadata

        def metadata(self):
            if self.name == stage_path.name:
                return recording_fs.FileMetadata(size=len(b"keep-stage"), modified=modified, created=created)
            return original_metadata(self)

        monkeypatch.setattr(recording_fs.ProtectedFile, "metadata", metadata)
        monkeypatch.setattr(recording_fs.time, "time", lambda: now)
        directory = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=False)
        assert directory is not None
        try:
            recording_fs.cleanup_stale_stages(directory)
        finally:
            directory.close()

        assert stage_path.read_bytes() == b"keep-stage"

    def test_unsafe_exact_stage_fails_without_mutation(self, roots, tmp_path):
        directory = roots.recordings()
        directory.mkdir(parents=True)
        outside = tmp_path / "outside-stage"
        outside.write_bytes(b"keep")
        stage = directory / ".memscope-recording-stage-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.tmp"
        os.link(outside, stage)
        old = time.time() - recording_fs._STAGE_MIN_STALE_AGE_SECONDS - 60
        set_creation_and_write_time(stage, old)
        with pytest.raises(recording_fs.RecordingFsError, match="Hard-linked"):
            make_plugin()._start_recording("capture")
        assert stage.exists() and outside.read_bytes() == b"keep"

    def test_old_exact_stage_directory_fails_without_mutation(self, roots):
        stage = roots.recordings() / ".memscope-recording-stage-dddddddddddddddddddddddddddddddd.tmp"
        stage.mkdir(parents=True)
        marker = stage / "keep.txt"
        marker.write_bytes(b"keep")
        with pytest.raises(recording_fs.RecordingFsError, match="Non-regular"):
            make_plugin()._start_recording("capture")
        assert marker.read_bytes() == b"keep"

    def test_exact_stage_junction_fails_without_touching_target(self, roots, tmp_path):
        target = tmp_path / "junction-target"
        target.mkdir()
        marker = target / "keep.txt"
        marker.write_bytes(b"keep")
        stage = roots.recordings() / ".memscope-recording-stage-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.tmp"
        stage.parent.mkdir(parents=True)
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(stage), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr or completed.stdout
        try:
            with pytest.raises(recording_fs.RecordingFsError, match="reparse"):
                make_plugin()._start_recording("capture")
            assert marker.read_bytes() == b"keep"
        finally:
            if stage.exists():
                os.rmdir(stage)

    def test_stale_stage_close_failure_retains_cleanup_ownership(self, roots, monkeypatch):
        stage = roots.recordings() / ".memscope-recording-stage-ffffffffffffffffffffffffffffffff.tmp"
        stage.parent.mkdir(parents=True)
        stage.write_bytes(b"stale")
        old = time.time() - recording_fs._STAGE_MIN_STALE_AGE_SECONDS - 60
        set_creation_and_write_time(stage, old)
        original_close = recording_fs.ProtectedFile.close
        failed = False

        def fail_stage_close(self):
            nonlocal failed
            if self.name == stage.name and not failed:
                failed = True
                raise recording_fs.RecordingFsError("injected stale stage close failure", (self,))
            return original_close(self)

        monkeypatch.setattr(recording_fs.ProtectedFile, "close", fail_stage_close)
        plugin = make_plugin()
        with pytest.raises(recording_fs.RecordingFsError, match="stale stage close failure"):
            plugin._start_recording("capture")
        assert len(plugin._recording_cleanup) == 1
        assert plugin._recording_cleanup[0].name == stage.name
        monkeypatch.setattr(recording_fs.ProtectedFile, "close", original_close)
        plugin._cleanup(process_alive=False)
        assert plugin._recording_cleanup == []
        assert not stage.exists()

    def test_live_delete_pending_stage_fails_closed_on_access_denied(self, roots):
        directory = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=True)
        assert directory is not None
        stage = recording_fs._open_stage(directory)
        plugin = make_plugin()
        with pytest.raises(PermissionError):
            plugin._start_recording("capture")
        stage.close()
        assert not stage.path.exists()
        directory.close()
        plugin._start_recording("capture")
        plugin._stop_recording()


class TestInjectedFailures:
    def test_partial_batch_failure_blocks_same_name_restart_and_preserves_bytes(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture")
        original_write = recording_fs._WriteFile
        calls = 0

        def partial_then_fail(handle, buffer, size, written, overlapped):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(handle, buffer, max(1, size // 2), written, overlapped)
            ctypes.set_last_error(5)
            return 0

        monkeypatch.setattr(recording_fs, "_WriteFile", partial_then_fail)
        with pytest.raises(recording_fs.RecordingFsError, match="batch failed"):
            plugin._record_packets([packet(1, b"partial-record-payload")])
        partial = roots.recordings() / "capture.jsonl"
        before = partial.read_bytes()
        before_hash = hashlib.sha256(before).hexdigest()
        assert before and not before.endswith(b"\n")
        assert plugin._recording_file is None
        assert plugin._recording_cleanup

        monkeypatch.setattr(recording_fs, "_WriteFile", original_write)
        with pytest.raises(recording_fs.RecordingFsError, match="partial final JSONL line"):
            plugin._start_recording("capture")
        assert partial.read_bytes() == before
        assert hashlib.sha256(partial.read_bytes()).hexdigest() == before_hash
        assert plugin._recording_file is None
        assert plugin._recording_cleanup == []

        plugin._start_recording("fresh")
        plugin._record_packets([packet(2)])
        plugin._stop_recording()
        loaded = plugin._load_recording("fresh")
        assert loaded[1]["sequence"] == 2

    def test_constructor_metadata_failure_retains_close_ownership(self, roots, monkeypatch):
        directory = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=True)
        assert directory is not None
        original_close = recording_fs._CloseHandle
        closed = []

        def fail_init(_self, *_args, **_kwargs):
            raise OSError("metadata failed")

        def observe_close(handle):
            closed.append(handle)
            return original_close(handle)

        monkeypatch.setattr(recording_fs.ProtectedFile, "__init__", fail_init)
        monkeypatch.setattr(recording_fs, "_CloseHandle", observe_close)
        with pytest.raises(OSError, match="metadata failed"):
            recording_fs.open_writer(directory, "capture.jsonl")
        assert len(closed) == 1
        directory.close()

    def test_write_failure_preserves_partial_file_and_resets(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture")

        def fail_write(*_args):
            ctypes.set_last_error(5)
            return 0

        monkeypatch.setattr(recording_fs, "_WriteFile", fail_write)
        with pytest.raises(recording_fs.RecordingFsError, match="batch failed"):
            plugin._record_packets([packet(1)])
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert plugin._recording_file is None and plugin._recording_count == 0
        plugin._cleanup(process_alive=False)

    def test_flush_failure_closes_and_resets(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture")

        def fail_flush(_handle):
            ctypes.set_last_error(5)
            return 0

        monkeypatch.setattr(recording_fs, "_FlushFileBuffers", fail_flush)
        with pytest.raises(recording_fs.RecordingFsError, match="FlushFileBuffers"):
            plugin._record_packets([packet(1)])
        assert plugin._recording_file is None
        assert roots.recordings().joinpath("capture.jsonl").exists()
        plugin._cleanup(process_alive=False)

    def test_post_flush_validation_failure_preserves_batch_and_resets(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture")
        original = recording_fs.ProtectedFile.validate
        calls = 0

        def fail_second(self, **kwargs):
            nonlocal calls
            if self.name == "capture.jsonl":
                calls += 1
                if calls == 2:
                    raise recording_fs.RecordingFsError("injected validation failure")
            return original(self, **kwargs)

        monkeypatch.setattr(recording_fs.ProtectedFile, "validate", fail_second)
        with pytest.raises(recording_fs.RecordingFsError, match="validation failure"):
            plugin._record_packets([packet(1)])
        assert plugin._recording_file is None and plugin._recording_count == 0
        assert roots.recordings().joinpath("capture.jsonl").stat().st_size > 0
        plugin._cleanup(process_alive=False)

    @pytest.mark.parametrize(
        "info_class",
        [recording_fs._FILE_DISPOSITION_INFO_CLASS, recording_fs._FILE_RENAME_INFO_CLASS],
    )
    def test_disposition_or_rename_failure_preserves_source(self, roots, monkeypatch, info_class):
        original = recording_fs._SetFileInformationByHandle

        def fail_selected(handle, selected, buffer, size):
            if selected == info_class:
                ctypes.set_last_error(5)
                return 0
            return original(handle, selected, buffer, size)

        monkeypatch.setattr(recording_fs, "_SetFileInformationByHandle", fail_selected)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError):
            plugin._stop_recording()
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert not roots.recordings().joinpath("capture.jsonl.gz").exists()
        plugin._cleanup(process_alive=False)

    def test_post_publish_validation_failure_preserves_source_and_complete_target(self, roots, monkeypatch):
        original_validate = recording_fs.ProtectedFile.validate
        injected = False

        def fail_first_published_validation(self, **kwargs):
            nonlocal injected
            if self.name == "capture.jsonl.gz" and not injected:
                injected = True
                raise recording_fs.RecordingFsError("injected post-publish validation failure")
            return original_validate(self, **kwargs)

        monkeypatch.setattr(recording_fs.ProtectedFile, "validate", fail_first_published_validation)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="post-publish validation failure"):
            plugin._stop_recording()

        source = roots.recordings() / "capture.jsonl"
        target = roots.recordings() / "capture.jsonl.gz"
        assert injected
        assert source.exists() and target.exists()
        with gzip.open(target, "rt", encoding="utf-8") as stream:
            assert json.loads(stream.readline())["sequence"] == 1
        plugin._cleanup(process_alive=False)

    def test_post_rename_stage_name_update_failure_preserves_source_and_complete_target(self, roots, monkeypatch):
        original_setattr = recording_fs.ProtectedFile.__setattr__
        injected = False
        target_existed_at_injection = False

        def fail_published_name_update(self, name, value):
            nonlocal injected, target_existed_at_injection
            current_name = getattr(self, "name", "")
            if (
                name == "name"
                and value == "capture.jsonl.gz"
                and current_name.startswith(".memscope-recording-stage-")
                and not injected
            ):
                injected = True
                target_existed_at_injection = (self.directory.path / value).exists()
                raise recording_fs.RecordingFsError("injected post-rename stage name update failure")
            return original_setattr(self, name, value)

        monkeypatch.setattr(recording_fs.ProtectedFile, "__setattr__", fail_published_name_update)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="post-rename stage name update failure"):
            plugin._stop_recording()

        source = roots.recordings() / "capture.jsonl"
        target = roots.recordings() / "capture.jsonl.gz"
        assert injected
        assert target_existed_at_injection
        assert source.exists() and target.exists()
        with gzip.open(target, "rt", encoding="utf-8") as stream:
            assert json.loads(stream.readline())["sequence"] == 1
        plugin._cleanup(process_alive=False)

    def test_published_target_close_failure_precedes_source_retirement_and_preserves_both(self, roots, monkeypatch):
        original_close = recording_fs.ProtectedFile.close
        original_set_disposition = recording_fs.ProtectedFile.set_disposition
        target_close_states = []
        retirement_armed = False

        def observe_disposition(self, delete):
            nonlocal retirement_armed
            result = original_set_disposition(self, delete)
            if self.name == "capture.jsonl" and delete:
                retirement_armed = True
            return result

        def fail_first_target_close(self):
            if self.name == "capture.jsonl.gz":
                target_close_states.append(retirement_armed)
                if len(target_close_states) == 1:
                    raise recording_fs.RecordingFsError("injected published target close failure", (self,))
            return original_close(self)

        monkeypatch.setattr(recording_fs.ProtectedFile, "set_disposition", observe_disposition)
        monkeypatch.setattr(recording_fs.ProtectedFile, "close", fail_first_target_close)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="published target close failure"):
            plugin._stop_recording()

        source = roots.recordings() / "capture.jsonl"
        target = roots.recordings() / "capture.jsonl.gz"
        assert target_close_states == [False, False]
        assert retirement_armed is False
        assert source.exists() and target.exists()
        with gzip.open(target, "rt", encoding="utf-8") as stream:
            assert json.loads(stream.readline())["sequence"] == 1
        plugin._cleanup(process_alive=False)

    def test_persistent_published_target_close_failure_retains_cleanup_owner(self, roots, monkeypatch):
        original_close = recording_fs.ProtectedFile.close
        attempts = 0

        def fail_target_close(self):
            nonlocal attempts
            if self.name == "capture.jsonl.gz":
                attempts += 1
                raise recording_fs.RecordingFsError("persistent published target close failure", (self,))
            return original_close(self)

        monkeypatch.setattr(recording_fs.ProtectedFile, "close", fail_target_close)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="persistent published target close failure"):
            plugin._stop_recording()

        target_owners = [
            owner for owner in plugin._recording_cleanup if getattr(owner, "name", None) == "capture.jsonl.gz"
        ]
        assert attempts == 2
        assert len(target_owners) == 1
        assert not target_owners[0].closed
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert roots.recordings().joinpath("capture.jsonl.gz").exists()
        monkeypatch.setattr(recording_fs.ProtectedFile, "close", original_close)
        plugin._cleanup(process_alive=False)
        assert plugin._recording_cleanup == []

    def test_retirement_failure_after_publish_preserves_both(self, roots, monkeypatch):
        original = recording_fs.ProtectedFile.set_disposition

        def fail_source_retirement(self, delete):
            if delete and self.name == "capture.jsonl":
                raise OSError("retirement failed")
            return original(self, delete)

        monkeypatch.setattr(recording_fs.ProtectedFile, "set_disposition", fail_source_retirement)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        with pytest.raises(recording_fs.RecordingFsError, match="retirement failed"):
            plugin._stop_recording()
        assert roots.recordings().joinpath("capture.jsonl").exists()
        assert roots.recordings().joinpath("capture.jsonl.gz").exists()
        with gzip.open(roots.recordings() / "capture.jsonl.gz", "rt", encoding="utf-8") as stream:
            assert json.loads(stream.readline())["sequence"] == 1
        plugin._cleanup(process_alive=False)

    def test_close_failure_is_queued_and_cleanup_retries_without_path_recovery(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture")
        plugin._record_packets([packet(1)])
        real_close = recording_fs._CloseHandle
        failed = False

        def fail_once(handle):
            nonlocal failed
            if not failed:
                failed = True
                ctypes.set_last_error(5)
                return 0
            return real_close(handle)

        monkeypatch.setattr(recording_fs, "_CloseHandle", fail_once)
        with pytest.raises(recording_fs.RecordingFsError, match="close failed"):
            plugin._stop_recording()
        assert plugin._recording_file is None
        assert plugin._recording_cleanup
        plugin._cleanup(process_alive=False)
        assert plugin._recording_cleanup == []
        assert roots.recordings().joinpath("capture.jsonl").exists()

    def test_no_target_operation_occurs_after_source_retirement_is_armed(self, roots, monkeypatch):
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        original_close = recording_fs.ProtectedFile.close
        original_validate = recording_fs.ProtectedFile.validate
        original_set_disposition = recording_fs.ProtectedFile.set_disposition
        original_delete_pending = recording_fs.ProtectedFile.delete_pending
        retirement_armed = False
        target_close_seen = False

        def reject_late_target(operation, self):
            if retirement_armed and self.name == "capture.jsonl.gz":
                raise AssertionError(f"target {operation} attempted after source retirement")

        def observe_validate(self, **kwargs):
            reject_late_target("validate", self)
            return original_validate(self, **kwargs)

        def observe_set_disposition(self, delete):
            nonlocal retirement_armed
            reject_late_target("disposition", self)
            result = original_set_disposition(self, delete)
            if self.name == "capture.jsonl" and delete:
                retirement_armed = True
            return result

        def observe_delete_pending(self):
            reject_late_target("delete-pending query", self)
            return original_delete_pending(self)

        def observe_close(self):
            nonlocal target_close_seen
            reject_late_target("close", self)
            if self.name == "capture.jsonl.gz":
                target_close_seen = True
                assert not retirement_armed
            return original_close(self)

        monkeypatch.setattr(recording_fs.ProtectedFile, "validate", observe_validate)
        monkeypatch.setattr(recording_fs.ProtectedFile, "set_disposition", observe_set_disposition)
        monkeypatch.setattr(recording_fs.ProtectedFile, "delete_pending", observe_delete_pending)
        monkeypatch.setattr(recording_fs.ProtectedFile, "close", observe_close)
        result = plugin._stop_recording()
        assert target_close_seen
        assert retirement_armed
        assert Path(result["path"]).exists()
        assert not roots.recordings().joinpath("capture.jsonl").exists()

    def test_compression_uses_no_source_rename_or_path_delete(self, roots, monkeypatch):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("path mutation API used")

        monkeypatch.setattr(os, "rename", forbidden)
        monkeypatch.setattr(os, "replace", forbidden)
        monkeypatch.setattr(os, "unlink", forbidden)
        plugin = make_plugin()
        plugin._start_recording("capture", make_table(compress=True))
        plugin._record_packets([packet(1)])
        result = plugin._stop_recording()
        assert Path(result["path"]).name == "capture.jsonl.gz"


class TestAbruptExitBoundaries:
    def _run(self, code: str, *args: Path) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).parents[1])
        completed = subprocess.run(
            [sys.executable, "-c", code, *(str(arg) for arg in args)],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr

    def test_abrupt_exit_while_staging_deletes_stage(self, roots):
        code = """
import os, sys
from pathlib import Path
from memscope_mcp._contrib.plugins import _recording_fs as fs
d = fs.acquire_recording_directory(Path(sys.argv[1]), 'TestGame.exe', create=True)
s = fs._open_stage(d)
fs._write_all(s.handle, b'incomplete')
os._exit(0)
"""
        self._run(code, roots.scripts)
        assert not list(roots.recordings().glob(".memscope-recording-stage-*.tmp"))

    def test_abrupt_exit_after_publication_preserves_source_and_complete_gzip(self, roots):
        source = write_recording(roots.recordings() / "capture.jsonl", 1)
        code = """
import os, sys
from pathlib import Path
from memscope_mcp._contrib.plugins import _recording_fs as fs
d = fs.acquire_recording_directory(Path(sys.argv[1]), 'TestGame.exe', create=False)
src = d.open_existing('capture.jsonl', fs._GENERIC_READ | fs._FILE_READ_ATTRIBUTES | fs._DELETE)
stage = fs._open_stage(d)
fs._compress_stream(src, stage)
stage.set_disposition(False)
fs._publish(stage, 'capture.jsonl.gz')
os._exit(0)
"""
        self._run(code, roots.scripts)
        assert source.exists()
        with gzip.open(roots.recordings() / "capture.jsonl.gz", "rt", encoding="utf-8") as stream:
            assert json.loads(stream.readline())["sequence"] == 1

    def test_abrupt_exit_after_armed_retirement_deletes_only_source(self, roots):
        source = write_recording(roots.recordings() / "capture.jsonl", 1)
        target = write_recording(roots.recordings() / "capture.jsonl.gz", 1, compressed=True)
        code = """
import os, sys
from pathlib import Path
from memscope_mcp._contrib.plugins import _recording_fs as fs
d = fs.acquire_recording_directory(Path(sys.argv[1]), 'TestGame.exe', create=False)
src = d.open_existing('capture.jsonl', fs._GENERIC_READ | fs._FILE_READ_ATTRIBUTES | fs._DELETE)
src.set_disposition(True)
assert src.delete_pending()
os._exit(0)
"""
        self._run(code, roots.scripts)
        assert not source.exists()
        assert target.exists()


class TestAbiAndApiSmoke:
    def test_one_byte_booleans_and_standard_layout(self):
        assert ctypes.sizeof(recording_fs.FILE_DISPOSITION_INFO) == 1
        assert recording_fs.FILE_DISPOSITION_INFO.DeleteFile.offset == 0
        assert recording_fs.FILE_STANDARD_INFO.DeletePending.offset == 20
        assert recording_fs.FILE_STANDARD_INFO.Directory.offset == 21
        assert ctypes.sizeof(recording_fs.FILE_STANDARD_INFO) == 24

    def test_rename_layout_zeroes_union_and_uses_utf16_byte_length(self):
        name = "capture.jsonl.gz"
        buffer, size = recording_fs._rename_buffer(name, 0x1234)
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        root_offset = 8 if pointer_size == 8 else 4
        length_offset = root_offset + pointer_size
        name_offset = length_offset + 4
        assert bytes(buffer[:4]) == b"\x00\x00\x00\x00"
        assert ctypes.c_void_p.from_buffer(buffer, root_offset).value == 0x1234
        assert ctypes.c_uint32.from_buffer(buffer, length_offset).value == len(name.encode("utf-16-le"))
        assert bytes(buffer[name_offset : name_offset + len(name.encode("utf-16-le"))]) == name.encode("utf-16-le")
        assert size == len(buffer)

    def test_bool_api_signatures_and_invalid_handle_contract(self):
        assert recording_fs._CreateDirectoryW.restype is ctypes.wintypes.BOOL
        assert recording_fs._GetFileInformationByHandleEx.restype is ctypes.wintypes.BOOL
        assert recording_fs._SetFileInformationByHandle.restype is ctypes.wintypes.BOOL
        assert recording_fs._FlushFileBuffers.restype is ctypes.wintypes.BOOL
        assert recording_fs._INVALID_HANDLE_VALUE == ctypes.c_void_p(-1).value

    def test_real_api_open_write_flush_validate_smoke(self, roots):
        directory = recording_fs.acquire_recording_directory(roots.scripts, "TestGame.exe", create=True)
        assert directory is not None
        writer = recording_fs.open_writer(directory, "smoke.jsonl")
        writer.write_batch(b'{"sequence":1}\n')
        identity = writer.identity
        writer.close()
        compressed = recording_fs.compress_recording(directory, "smoke.jsonl", identity)
        directory.close()
        with gzip.open(compressed, "rt", encoding="utf-8") as stream:
            assert json.loads(stream.readline())["sequence"] == 1
