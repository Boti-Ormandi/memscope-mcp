"""Tests for MCP typed raw byte reads and writes."""

import pytest

import memscope_mcp.tools.types as types_module
from memscope_mcp.tools.types import get_type_info, list_supported_types, read_typed, write_typed


class FakeBytesSession:
    def __init__(
        self,
        initial: bytes = b"\x00" * 32,
        *,
        base: int = 0x1000,
        writable: bool = True,
        readback=None,
        fail_write_on: int | None = None,
    ):
        self.memory = bytearray(initial)
        self.base = base
        self.writable = writable
        self.readback = readback
        self.fail_write_on = fail_write_on
        self.range_checks = []
        self.reads = []
        self.writes = []
        self.read_count = 0
        self.write_count = 0

    def ensure_attached(self):
        return True

    def is_memory_range_writable(self, address: int, size: int):
        self.range_checks.append((address, size))
        return self.writable

    def read_bytes(self, address: int, size: int):
        self.reads.append((address, size))
        self.read_count += 1
        if self.read_count > 1 and self.readback is not None:
            if isinstance(self.readback, Exception):
                raise self.readback
            return self.readback
        offset = address - self.base
        return bytes(self.memory[offset : offset + size])

    def write_bytes(self, address: int, data: bytes):
        data = bytes(data)
        self.write_count += 1
        self.writes.append((address, data))
        if self.fail_write_on == self.write_count:
            raise OSError("rollback write failed")
        offset = address - self.base
        self.memory[offset : offset + len(data)] = data


def install_session(monkeypatch, session: FakeBytesSession | None = None) -> FakeBytesSession:
    session = session or FakeBytesSession()
    monkeypatch.setattr(types_module, "SESSION", session)
    return session


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("DEADBEEF", b"\xde\xad\xbe\xef"),
        ("de ad BE ef", b"\xde\xad\xbe\xef"),
        ([222, 173, 190, 239], b"\xde\xad\xbe\xef"),
    ],
)
def test_write_bytes_accepts_public_payload_forms(monkeypatch, value, expected):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", value, "bytes")

    assert result == {
        "success": True,
        "address": "0x1000",
        "type": "bytes",
        "new_value": "DE AD BE EF",
        "size": 4,
    }
    assert session.writes == [(0x1000, expected)]


def test_write_sized_bytes_requires_exact_length(monkeypatch):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", "AA BB", "bytes[2]")

    assert result == {
        "success": True,
        "address": "0x1000",
        "type": "bytes[2]",
        "new_value": "AA BB",
        "size": 2,
    }
    assert session.writes == [(0x1000, b"\xaa\xbb")]


def test_write_sized_bytes_rejects_length_mismatch_before_write(monkeypatch):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", "AA BB", "bytes[3]")

    assert result["success"] is False
    assert result["error"] == "VALUE_LENGTH_MISMATCH"
    assert result["expected"] == 3
    assert result["got"] == 2
    assert session.writes == []


@pytest.mark.parametrize("value", ["", "   ", "0xDEAD", "DE-AD", "DE,AD", "DE_AD", "ABC", "DE ADZ", "DEAD BEEF"])
def test_write_bytes_rejects_malformed_hex_before_write(monkeypatch, value):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", value, "bytes")

    assert result["success"] is False
    assert result["error"] == "INVALID_BYTES_FORMAT"
    assert session.writes == []


@pytest.mark.parametrize("value", [[], [True], [1.0], ["DE"], [[1]], [None]])
def test_write_bytes_rejects_invalid_array_elements_before_write(monkeypatch, value):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", value, "bytes")

    assert result["success"] is False
    assert result["error"] == "INVALID_BYTES_FORMAT"
    assert session.writes == []


@pytest.mark.parametrize("value", [[-1], [256]])
def test_write_bytes_reuses_out_of_range_for_array_int_bounds(monkeypatch, value):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", value, "bytes")

    assert result["success"] is False
    assert result["error"] == "VALUE_OUT_OF_RANGE"
    assert session.writes == []


def test_write_bytes_rejects_zero_length_type_before_payload(monkeypatch):
    session = install_session(monkeypatch)

    result = write_typed("0x1000", "AA", "bytes[0]")

    assert result["success"] is False
    assert result["error"] == "UNKNOWN_TYPE"
    assert "positive" in result["detail"]
    assert session.writes == []


def test_verified_bytes_write_uses_parsed_payload_length_and_canonical_values(monkeypatch):
    session = install_session(monkeypatch, FakeBytesSession(b"\x00" * 8))

    result = write_typed("0x1002", "aa bb cc", "bytes", validate=True)

    assert result == {
        "success": True,
        "address": "0x1002",
        "type": "bytes",
        "old_value": "00 00 00",
        "new_value": "AA BB CC",
        "size": 3,
        "verified": True,
    }
    assert session.range_checks == [(0x1002, 3)]
    assert session.reads == [(0x1002, 3), (0x1002, 3)]
    assert session.writes == [(0x1002, b"\xaa\xbb\xcc")]


def test_verified_bytes_mismatch_restores_old_bytes_and_reports_actual_value(monkeypatch):
    session = install_session(monkeypatch, FakeBytesSession(b"\x11\x22\x33\x44", readback=b"\xaa\xbb\x00"))

    result = write_typed("0x1000", [0xAA, 0xBB, 0xCC], "bytes[3]", validate=True)

    assert result["success"] is False
    assert result["error"] == "VERIFY_MISMATCH"
    assert result["old_value"] == "11 22 33"
    assert result["new_value"] == "AA BB CC"
    assert result["actual"] == "AA BB 00"
    assert result["actual_value"] == "AA BB 00"
    assert result["rollback"] == {"attempted": True, "success": True, "value": "11 22 33"}
    assert bytes(session.memory[:4]) == b"\x11\x22\x33\x44"
    assert session.range_checks == [(0x1000, 3)]
    assert session.writes == [(0x1000, b"\xaa\xbb\xcc"), (0x1000, b"\x11\x22\x33")]


def test_verified_bytes_readback_failure_restores_old_bytes(monkeypatch):
    session = install_session(monkeypatch, FakeBytesSession(b"\x44\x55\x66\x77", readback=OSError("readback lost")))

    result = write_typed("0x1000", "AA BB CC", "bytes[3]", validate=True)

    assert result["success"] is False
    assert result["error"] == "VERIFY_READ_FAILED"
    assert result["old_value"] == "44 55 66"
    assert result["new_value"] == "AA BB CC"
    assert "readback lost" in result["detail"]
    assert result["rollback"] == {"attempted": True, "success": True, "value": "44 55 66"}
    assert bytes(session.memory[:4]) == b"\x44\x55\x66\x77"
    assert session.writes == [(0x1000, b"\xaa\xbb\xcc"), (0x1000, b"\x44\x55\x66")]


def test_verified_bytes_reports_rollback_failure(monkeypatch):
    session = install_session(
        monkeypatch,
        FakeBytesSession(b"\x10\x20\x30\x40", readback=b"\xaa\xbb\x00", fail_write_on=2),
    )

    result = write_typed("0x1000", "AA BB CC", "bytes[3]", validate=True)

    assert result["success"] is False
    assert result["error"] == "VERIFY_MISMATCH"
    assert result["rollback"] == {
        "attempted": True,
        "success": False,
        "value": "10 20 30",
        "error": "rollback write failed",
    }
    assert bytes(session.memory[:4]) == b"\xaa\xbb\xcc\x40"
    assert session.writes == [(0x1000, b"\xaa\xbb\xcc"), (0x1000, b"\x10\x20\x30")]


def test_read_bytes_returns_uppercase_spaced_hex_for_unsized_and_sized_reads(monkeypatch):
    install_session(monkeypatch, FakeBytesSession(b"\xde\xad\xbe\xef"))

    unsized = read_typed("0x1000", "bytes", count=4)
    sized = read_typed("0x1001", "bytes[2]")

    assert unsized == {
        "success": True,
        "address": "0x1000",
        "type": "bytes",
        "value": "DE AD BE EF",
        "size": 4,
    }
    assert sized == {
        "success": True,
        "address": "0x1001",
        "type": "bytes",
        "value": "AD BE",
        "size": 2,
    }


def test_bytes_type_metadata_describes_write_values():
    info = get_type_info("bytes")

    assert info["success"] is True
    assert info["write_value_formats"] == [
        "compact hex string",
        "whitespace-separated hex string",
        "JSON array of integers 0..255",
    ]


def test_sized_bytes_metadata_rejects_zero_length_type():
    info = get_type_info("bytes[0]")

    assert info["success"] is False
    assert info["error"] == "UNKNOWN_TYPE"
    assert "positive" in info["detail"]


def test_list_supported_types_exposes_writable_special_types():
    result = list_supported_types()

    assert result["writable_special_types"] == ["bytes", "bytes[N]"]
