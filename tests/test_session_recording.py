"""Tests for session recording helpers in the netcap plugin.

startRecording / stopRecording / _record_packets / _serialize_packet /
loadRecording / _deserialize_packet / listRecordings / _scan_recording_dir /
_resolve_recording_path / _cleanup / compression / rotation.

Pure unit tests -- no process attachment required.
Uses monkeypatch.chdir(tmp_path) so relative Path("scripts/...") resolves correctly.
"""

import gzip
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from contrib.plugins.netcap import NetcapPlugin

# ==================== Helpers ====================


class LuaTable(dict):
    """Dict that returns None for missing keys, mirroring Lua table semantics."""

    def __missing__(self, key):
        return None


def make_table(*args, **kwargs):
    """Mock Lua table factory: 1-indexed sequential args + kwargs."""
    result = LuaTable()
    for i, val in enumerate(args, 1):
        result[i] = val
    result.update(kwargs)
    return result


@dataclass
class MockContext:
    engine: Any = None
    session: Any = None
    lua: Any = None
    table_factory: Any = None
    log_error: Any = None


def make_plugin() -> NetcapPlugin:
    """Create a NetcapPlugin and register it with a mock context."""
    plugin = NetcapPlugin()
    ctx = MockContext(table_factory=make_table, log_error=lambda *a: None)
    plugin.register(ctx)
    return plugin


def make_packet(direction="send", socket=0x1A4, data=b"hello", **kwargs):
    """Build a packet table as _build_packet produces (mirrors readPackets output)."""
    pkt = {
        "direction": direction,
        "socket": socket,
        "socket_hex": hex(socket),
        "timestamp": 12345,
        "sequence": 1,
        "size": len(data) if data else 0,
        "captured": len(data) if data else 0,
        "result": len(data) if data else 0,
        "caller": "ws2_32.dll+0x1234",
        "hook_name": "send",
        "data": make_table(*data) if data else None,
    }
    pkt.update(kwargs)
    return make_table(**pkt)


# ==================== startRecording ====================


class TestStartRecording:
    def test_creates_file_in_correct_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("test_session")

        expected_dir = tmp_path / "scripts" / "TestGame.exe" / "recordings"
        assert expected_dir.exists()
        assert (expected_dir / "test_session.jsonl").exists()
        plugin._recording_file.close()

    def test_returns_filename_and_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._start_recording("my_session")

        assert result["filename"] == "my_session.jsonl"
        assert result["path"].endswith("my_session.jsonl")
        plugin._recording_file.close()

    def test_second_call_while_active_raises(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("first")
            with pytest.raises(RuntimeError, match="Recording already active"):
                plugin._start_recording("second")
        plugin._recording_file.close()

    def test_auto_generates_timestamp_filename_when_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._start_recording(None)

        # Auto-generated names match strftime pattern YYYYMMDD_HHMMSS
        filename = result["filename"]
        assert filename.endswith(".jsonl")
        stem = filename[: -len(".jsonl")]
        assert len(stem) == 15  # YYYYMMDD_HHMMSS
        assert stem[8] == "_"
        plugin._recording_file.close()

    def test_appends_jsonl_extension_if_missing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._start_recording("no_ext")

        assert result["filename"] == "no_ext.jsonl"
        plugin._recording_file.close()

    def test_does_not_duplicate_jsonl_extension(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._start_recording("already.jsonl")

        assert result["filename"] == "already.jsonl"
        assert not result["filename"].endswith(".jsonl.jsonl")
        plugin._recording_file.close()


# ==================== _record_packets / _serialize_packet ====================


class TestRecordPackets:
    def test_packets_written_as_valid_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("capture")

        pkts = [make_packet("send", 0x1A4, b"hello"), make_packet("recv", 0x1A4, b"world")]
        plugin._record_packets(pkts)
        plugin._recording_file.close()

        rec_path = tmp_path / "scripts" / "TestGame.exe" / "recordings" / "capture.jsonl"
        lines = [ln for ln in rec_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 2
        for line in lines:
            obj = json.loads(line)
            assert isinstance(obj, dict)

    def test_recording_count_increments(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("counter")

        plugin._record_packets([make_packet(data=b"a"), make_packet(data=b"b"), make_packet(data=b"c")])
        assert plugin._recording_count == 3
        plugin._recording_file.close()

    def test_full_data_stored_not_truncated(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("bigdata")

        # Data longer than 256-byte preview limit
        big_data = bytes(range(256)) + b"\xab\xcd"
        plugin._record_packets([make_packet(data=big_data)])
        plugin._recording_file.close()

        rec_path = tmp_path / "scripts" / "TestGame.exe" / "recordings" / "bigdata.jsonl"
        record = json.loads(rec_path.read_text().strip())
        # data_hex must contain all 258 bytes as hex tokens
        hex_tokens = record["data_hex"].split()
        assert len(hex_tokens) == 258
        assert hex_tokens[256] == "AB"
        assert hex_tokens[257] == "CD"


class TestSerializePacket:
    def test_all_standard_fields_serialized(self):
        plugin = make_plugin()
        pkt = make_packet("send", 0x1A4, b"\x01\x02\x03")
        record = plugin._serialize_packet(pkt)

        assert record["direction"] == "send"
        assert record["socket"] == 0x1A4
        assert record["socket_hex"] == hex(0x1A4)
        assert record["timestamp"] == 12345
        assert record["sequence"] == 1
        assert record["size"] == 3
        assert record["captured"] == 3
        assert record["result"] == 3
        assert record["caller"] == "ws2_32.dll+0x1234"
        assert record["hook_name"] == "send"

    def test_data_stored_as_hex_string(self):
        plugin = make_plugin()
        pkt = make_packet(data=b"\xde\xad\xbe\xef")
        record = plugin._serialize_packet(pkt)
        assert record["data_hex"] == "DE AD BE EF"

    def test_none_data_field_omitted(self):
        plugin = make_plugin()
        pkt = make_packet(data=None)
        record = plugin._serialize_packet(pkt)
        assert "data_hex" not in record

    def test_none_fields_are_omitted(self):
        plugin = make_plugin()
        pkt = make_table(direction="send", socket=0x1A4, socket_hex="0x1a4")
        record = plugin._serialize_packet(pkt)
        # Fields not present in pkt return None and should be omitted
        assert "timestamp" not in record
        assert "caller" not in record

    def test_async_flag_preserved(self):
        plugin = make_plugin()
        pkt = make_packet(data=b"x")
        pkt["async"] = True
        record = plugin._serialize_packet(pkt)
        assert record.get("async") is True

    def test_int_fields_coerced_to_int(self):
        plugin = make_plugin()
        pkt = make_packet(socket=0x1A4, data=b"x")
        pkt["socket"] = "420"  # string that should coerce
        record = plugin._serialize_packet(pkt)
        assert isinstance(record["socket"], int)
        assert record["socket"] == 420


# ==================== stopRecording ====================


class TestStopRecording:
    def test_returns_path_entries_duration(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("stop_test")

        plugin._record_packets([make_packet(data=b"a"), make_packet(data=b"b")])
        result = plugin._stop_recording()

        assert result["path"].endswith("stop_test.jsonl")
        assert result["total_entries"] == 2
        assert isinstance(result["duration_seconds"], float)
        assert result["duration_seconds"] >= 0.0

    def test_recording_file_is_closed_after_stop(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("closed_test")

        # Grab a reference before stopping
        f = plugin._recording_file
        plugin._stop_recording()
        assert f.closed

    def test_state_reset_after_stop(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("reset_test")

        plugin._stop_recording()
        assert plugin._recording_file is None
        assert plugin._recording_path is None
        assert plugin._recording_count == 0
        assert plugin._recording_start is None

    def test_stop_without_active_recording_raises(self):
        plugin = make_plugin()
        with pytest.raises(RuntimeError, match="No recording active"):
            plugin._stop_recording()

    def test_file_on_disk_survives_stop(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("survive")

        plugin._record_packets([make_packet(data=b"keep")])
        result = plugin._stop_recording()

        assert Path(result["path"]).exists()
        content = Path(result["path"]).read_text()
        assert content.strip()  # file has content


# ==================== loadRecording ====================


class TestLoadRecording:
    def _write_session(self, tmp_path, process, filename, packets):
        """Helper: write packets directly to a recording file."""
        plugin = make_plugin()
        rec_dir = tmp_path / "scripts" / process / "recordings"
        rec_dir.mkdir(parents=True, exist_ok=True)
        filepath = rec_dir / filename
        with open(filepath, "w", encoding="utf-8") as fh:
            for pkt in packets:
                record = plugin._serialize_packet(pkt)
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        return filepath

    def test_load_returns_correct_packet_count(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pkts = [make_packet(data=b"a"), make_packet(data=b"b"), make_packet(data=b"c")]
        self._write_session(tmp_path, "TestGame.exe", "load_test.jsonl", pkts)

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._load_recording("load_test")

        assert result[1] is not None
        assert result[2] is not None
        assert result[3] is not None
        assert result[4] is None  # only 3 packets

    def test_data_bytes_reconstructed_from_hex(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        original_data = b"\x01\x02\x03\x04\x05"
        self._write_session(tmp_path, "TestGame.exe", "bytes_test.jsonl", [make_packet(data=original_data)])

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._load_recording("bytes_test")

        pkt = result[1]
        data_tbl = pkt["data"]
        reconstructed = bytes(data_tbl[i] for i in range(1, 6))
        assert reconstructed == original_data

    def test_data_hex_and_ascii_preview_regenerated(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._write_session(tmp_path, "TestGame.exe", "preview_test.jsonl", [make_packet(data=b"ABC")])

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._load_recording("preview_test")

        pkt = result[1]
        assert pkt["data_hex"] == "41 42 43"
        assert pkt["data_ascii"] == "ABC"

    def test_scalar_fields_preserved(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pkt = make_packet("recv", 0x200, b"x", sequence=99, timestamp=55555)
        self._write_session(tmp_path, "TestGame.exe", "fields_test.jsonl", [pkt])

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._load_recording("fields_test")

        loaded = result[1]
        assert loaded["direction"] == "recv"
        assert loaded["socket"] == 0x200
        assert loaded["sequence"] == 99
        assert loaded["timestamp"] == 55555

    def test_missing_file_raises_runtime_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            with pytest.raises(RuntimeError, match="Recording not found"):
                plugin._load_recording("nonexistent")

    def test_loaded_packets_work_with_feed_packets(self, tmp_path, monkeypatch):
        """loadRecording output can be passed directly to _feed_packets."""
        monkeypatch.chdir(tmp_path)
        pkts = [
            make_packet("recv", 0x1A4, b"hello"),
            make_packet("recv", 0x1A4, b" world"),
        ]
        self._write_session(tmp_path, "TestGame.exe", "feed_test.jsonl", pkts)

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            loaded = plugin._load_recording("feed_test")

        result = plugin._feed_packets(loaded)
        assert result["bytes_added"] == 11
        assert bytes(plugin._streams[0x1A4].recv_buffer) == b"hello world"

    def test_loaded_packets_work_with_search_packets(self, tmp_path, monkeypatch):
        """loadRecording output can be passed to _search_packets."""
        monkeypatch.chdir(tmp_path)
        pkts = [
            make_packet("send", 0x1A4, b"\xde\xad\xbe\xef"),
            make_packet("send", 0x1A4, b"no_match"),
        ]
        self._write_session(tmp_path, "TestGame.exe", "search_test.jsonl", pkts)

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            loaded = plugin._load_recording("search_test")

        # _search_packets takes a byte table (1-indexed), not a string pattern
        pattern = make_table(0xDE, 0xAD, 0xBE, 0xEF)
        result = plugin._search_packets(loaded, pattern)
        assert result[1] is not None  # at least one match found
        assert result[1]["offset"] == 1  # first byte, 1-indexed


# ==================== listRecordings ====================


class TestListRecordings:
    def _create_recording(self, tmp_path, process, filename, lines=3):
        rec_dir = tmp_path / "scripts" / process / "recordings"
        rec_dir.mkdir(parents=True, exist_ok=True)
        filepath = rec_dir / filename
        with open(filepath, "w", encoding="utf-8") as fh:
            for i in range(lines):
                fh.write(json.dumps({"direction": "send", "sequence": i}) + "\n")
        return filepath

    def test_lists_files_for_current_process(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._create_recording(tmp_path, "TestGame.exe", "session_a.jsonl", lines=5)
        self._create_recording(tmp_path, "TestGame.exe", "session_b.jsonl", lines=2)

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._list_recordings()

        filenames = {result[i]["filename"] for i in (1, 2)}
        assert filenames == {"session_a", "session_b"}

    def test_entries_count_matches_lines(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._create_recording(tmp_path, "TestGame.exe", "counted.jsonl", lines=7)

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._list_recordings()

        assert result[1]["entries"] == 7

    def test_returns_filename_path_size_entries_date(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._create_recording(tmp_path, "TestGame.exe", "meta.jsonl", lines=1)

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._list_recordings()

        entry = result[1]
        assert "filename" in entry
        assert "path" in entry
        assert "size_kb" in entry
        assert "entries" in entry
        assert "date" in entry

    def test_star_lists_across_all_processes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._create_recording(tmp_path, "Game1.exe", "g1.jsonl")
        self._create_recording(tmp_path, "Game2.exe", "g2.jsonl")

        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "Game1.exe"
            result = plugin._list_recordings("*")

        filenames = {result[i]["filename"] for i in (1, 2) if result[i] is not None}
        assert "g1" in filenames
        assert "g2" in filenames

    def test_empty_directory_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # No files created -- recordings dir doesn't even exist
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._list_recordings()

        assert result[1] is None  # empty table

    def test_star_with_no_scripts_dir_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._list_recordings("*")

        assert result[1] is None


# ==================== _cleanup ====================


class TestCleanup:
    def test_cleanup_closes_recording_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("cleanup_test")

        f = plugin._recording_file
        plugin._cleanup(process_alive=True)
        assert f.closed

    def test_cleanup_recording_file_survives_on_disk(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("cleanup_survive")

        plugin._record_packets([make_packet(data=b"persist")])
        plugin._cleanup(process_alive=False)

        rec_path = tmp_path / "scripts" / "TestGame.exe" / "recordings" / "cleanup_survive.jsonl"
        assert rec_path.exists()
        assert rec_path.stat().st_size > 0

    def test_cleanup_resets_recording_state(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("state_reset")

        plugin._cleanup(process_alive=True)
        assert plugin._recording_file is None
        assert plugin._recording_path is None
        assert plugin._recording_count == 0
        assert plugin._recording_start is None

    def test_cleanup_without_active_recording_is_safe(self):
        plugin = make_plugin()
        # Should not raise
        plugin._cleanup(process_alive=True)
        plugin._cleanup(process_alive=False)


# ==================== Round-trip integration ====================


class TestRoundTrip:
    def test_start_record_stop_load_preserves_all_packets(self, tmp_path, monkeypatch):
        """Full round-trip: record N packets, load them back, verify field equality."""
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()

        packets = [
            make_packet("send", 0x1A4, b"\x01\x02\x03", sequence=1),
            make_packet("recv", 0x1A4, b"\xaa\xbb", sequence=2),
            make_packet("send", 0x200, b"hello world", sequence=3),
        ]

        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("roundtrip")
            plugin._record_packets(packets)
            plugin._stop_recording()

        plugin2 = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            loaded = plugin2._load_recording("roundtrip")

        for i, original in enumerate(packets, 1):
            loaded_pkt = loaded[i]
            assert loaded_pkt["direction"] == original["direction"]
            assert loaded_pkt["socket"] == original["socket"]
            assert loaded_pkt["sequence"] == original["sequence"]

            orig_bytes = bytes(original["data"][j] for j in range(1, original["size"] + 1))
            orig_size = original["size"]
            loaded_bytes = bytes(loaded_pkt["data"][j] for j in range(1, orig_size + 1))
            assert loaded_bytes == orig_bytes

    def test_record_stop_can_restart_new_session(self, tmp_path, monkeypatch):
        """After stopRecording, startRecording should work again."""
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()

        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("first_run")
            plugin._record_packets([make_packet(data=b"a")])
            plugin._stop_recording()
            result = plugin._start_recording("second_run")

        assert result["filename"] == "second_run.jsonl"
        plugin._recording_file.close()


# ==================== Compression ====================


class TestCompression:
    def test_stop_with_compress_creates_gz_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("comp", make_table(compress=True))

        plugin._record_packets([make_packet(data=b"hello")])
        result = plugin._stop_recording()

        assert result["compressed"] is True
        assert result["path"].endswith(".jsonl.gz")
        gz_path = Path(result["path"])
        assert gz_path.exists()
        # Original .jsonl should be removed
        jsonl_path = tmp_path / "scripts" / "TestGame.exe" / "recordings" / "comp.jsonl"
        assert not jsonl_path.exists()

    def test_compressed_file_contains_valid_gzip_data(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("valid_gz", make_table(compress=True))

        plugin._record_packets([make_packet(data=b"test123")])
        result = plugin._stop_recording()

        with gzip.open(result["path"], "rt", encoding="utf-8") as f:
            content = f.read()
        lines = [ln for ln in content.splitlines() if ln.strip()]
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["direction"] == "send"

    def test_load_recording_reads_gz_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("load_gz", make_table(compress=True))
            plugin._record_packets([make_packet(data=b"\xde\xad"), make_packet(data=b"\xbe\xef")])
            plugin._stop_recording()

        plugin2 = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            loaded = plugin2._load_recording("load_gz")

        assert loaded[1] is not None
        assert loaded[2] is not None
        assert loaded[3] is None  # only 2 packets

    def test_stop_without_compress_returns_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("no_comp")

        plugin._record_packets([make_packet(data=b"x")])
        result = plugin._stop_recording()

        assert result["compressed"] is False
        assert result["path"].endswith(".jsonl")
        assert not result["path"].endswith(".gz")

    def test_list_recordings_shows_compressed_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            # Create one compressed, one uncompressed
            plugin._start_recording("plain")
            plugin._record_packets([make_packet(data=b"a")])
            plugin._stop_recording()
            plugin._start_recording("zipped", make_table(compress=True))
            plugin._record_packets([make_packet(data=b"b")])
            plugin._stop_recording()

        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            result = plugin._list_recordings()

        entries = {result[i]["filename"]: result[i] for i in (1, 2) if result[i] is not None}
        assert entries["plain"]["compressed"] is False
        assert entries["plain"]["entries"] == 1
        assert entries["zipped"]["compressed"] is True
        assert entries["zipped"]["entries"] is None  # not counted for gz

    def test_resolve_path_auto_detects_gz(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rec_dir = tmp_path / "scripts" / "Test.exe" / "recordings"
        rec_dir.mkdir(parents=True)
        # Create only a .gz file (no .jsonl)
        gz_file = rec_dir / "session.jsonl.gz"
        with gzip.open(gz_file, "wt", encoding="utf-8") as f:
            f.write('{"direction":"send"}\n')

        plugin = make_plugin()
        path = plugin._resolve_recording_path("session", "Test.exe")
        assert str(path).endswith(".jsonl.gz")


# ==================== Rotation ====================


class TestRotation:
    def test_rotation_creates_new_part_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            # Very small max_size to trigger rotation quickly
            plugin._start_recording("rot", make_table(max_size_mb=0.0001))  # ~100 bytes

        # Write enough to trigger rotation
        for _ in range(20):
            plugin._record_packets([make_packet(data=b"A" * 100)])

        plugin._stop_recording()

        rec_dir = tmp_path / "scripts" / "TestGame.exe" / "recordings"
        files = sorted(rec_dir.glob("rot*.jsonl"))
        assert len(files) >= 2  # at least one rotation happened
        assert files[0].name == "rot.jsonl"
        assert files[1].name == "rot_part002.jsonl"

    def test_rotation_part_counter_increments(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("multi", make_table(max_size_mb=0.00005))

        for _ in range(50):
            plugin._record_packets([make_packet(data=b"X" * 200)])

        result = plugin._stop_recording()
        assert result["parts"] >= 3  # multiple rotations

    def test_rotation_with_compression(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("rotcomp", make_table(compress=True, max_size_mb=0.0001))

        for _ in range(20):
            plugin._record_packets([make_packet(data=b"B" * 100)])

        plugin._stop_recording()

        rec_dir = tmp_path / "scripts" / "TestGame.exe" / "recordings"
        # Rotated parts should be compressed (.gz), final part also compressed on stop
        gz_files = sorted(rec_dir.glob("rotcomp*.jsonl.gz"))
        assert len(gz_files) >= 2
        # No uncompressed .jsonl files should remain
        jsonl_files = sorted(rec_dir.glob("rotcomp*.jsonl"))
        assert len(jsonl_files) == 0

    def test_no_rotation_without_max_size(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("norot")

        for _ in range(20):
            plugin._record_packets([make_packet(data=b"C" * 200)])

        result = plugin._stop_recording()

        assert result["parts"] == 1
        rec_dir = tmp_path / "scripts" / "TestGame.exe" / "recordings"
        assert len(list(rec_dir.glob("norot*.jsonl"))) == 1

    def test_stop_returns_total_entries_across_parts(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("count", make_table(max_size_mb=0.0001))

        total_written = 0
        for _ in range(20):
            plugin._record_packets([make_packet(data=b"D" * 100)])
            total_written += 1

        result = plugin._stop_recording()
        assert result["total_entries"] == total_written

    def test_load_rotated_parts_individually(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("parts", make_table(max_size_mb=0.0001))

        for _ in range(20):
            plugin._record_packets([make_packet(data=b"E" * 100)])

        plugin._stop_recording()

        # Load first part
        plugin2 = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            loaded1 = plugin2._load_recording("parts")
        assert loaded1[1] is not None  # has at least one packet

        # Load second part
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            loaded2 = plugin2._load_recording("parts_part002")
        assert loaded2[1] is not None


# ==================== Cleanup with new state ====================


class TestCleanupNewState:
    def test_cleanup_resets_compression_state(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        plugin = make_plugin()
        with patch("contrib.plugins.netcap.SESSION") as mock_sess:
            mock_sess.target_process = "TestGame.exe"
            plugin._start_recording("clean", make_table(compress=True, max_size_mb=50))

        plugin._cleanup(process_alive=True)
        assert plugin._recording_compress is False
        assert plugin._recording_max_size is None
        assert plugin._recording_base_name is None
        assert plugin._recording_part == 1
        assert plugin._recording_dir is None
