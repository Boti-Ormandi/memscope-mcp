"""Deterministic version-neutral benchmark buffers, patterns, and oracle results."""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass
from typing import Any

from benchmarks.scanning.common import address_checksum, sha256_bytes
from benchmarks.scanning.manifest import BenchmarkCase

_CORPUS_SEED = 0x5C0FE20260720
BASE_ADDRESS = 0x10000000


@dataclass(frozen=True, slots=True)
class Corpus:
    data: bytes
    base_address: int
    pattern_bytes: bytes
    mask: bytes
    expected_addresses: tuple[int, ...]
    data_sha256: str
    expected_checksum: str


@dataclass(frozen=True, slots=True)
class MaterializedCorpus:
    data: bytes
    checksum: str
    expected_addresses: tuple[int, ...]
    expected_checksum: str
    expected_termination: str


@dataclass(frozen=True, slots=True)
class ParsedPattern:
    pattern_bytes: bytes
    mask: bytes

    @property
    def length(self) -> int:
        return len(self.pattern_bytes)

    @property
    def exact(self) -> bytes | None:
        return self.pattern_bytes if all(self.mask) else None

    @property
    def all_wildcard(self) -> bool:
        return not any(self.mask)


def parse_pattern(pattern: str) -> ParsedPattern:
    compact = "".join(pattern.split())
    if not compact or len(compact) % 2:
        raise ValueError("benchmark patterns must contain complete byte tokens")
    pattern_bytes = bytearray()
    mask = bytearray()
    for index in range(0, len(compact), 2):
        token = compact[index : index + 2]
        if token == "??":
            pattern_bytes.append(0)
            mask.append(0)
        else:
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
                raise ValueError(f"invalid benchmark pattern token {token!r}")
            pattern_bytes.append(int(token, 16))
            mask.append(0xFF)
    return ParsedPattern(bytes(pattern_bytes), bytes(mask))


def materialize_corpus(
    *,
    distribution: str,
    size: int,
    seed: int,
    pattern: str,
    injection_offsets: tuple[int, ...],
    alignment: int,
    match_cap: int,
) -> MaterializedCorpus:
    """Build a standalone matcher corpus with an independent expected result."""

    if size < 1 or alignment < 1 or match_cap < 1:
        raise ValueError("size, alignment, and match_cap must be positive")
    parsed = parse_pattern(pattern)
    data = bytearray(_seeded_distribution(distribution, size, seed))
    for offset in injection_offsets:
        _inject(data, offset, parsed)
    payload = bytes(data)
    addresses = tuple(
        find_matches(
            payload,
            parsed,
            base_address=BASE_ADDRESS,
            alignment=alignment,
            limit=match_cap,
        )
    )
    termination = "match_limit" if len(addresses) >= match_cap else "scope_exhausted"
    return MaterializedCorpus(
        data=payload,
        checksum=sha256_bytes(payload),
        expected_addresses=addresses,
        expected_checksum=address_checksum(addresses),
        expected_termination=termination,
    )


def build_corpus(case: BenchmarkCase, profile: str, *, base_address: int = 0) -> Corpus:
    size = case.effective_size(profile)
    parsed = parse_pattern(case.pattern)
    data = bytearray(_distribution(case.distribution, size, case.case_id))
    for position in _injection_positions(case, size, parsed.length):
        _inject(data, position, parsed)
    expected = tuple(
        find_matches(
            bytes(data),
            parsed,
            base_address=base_address,
            alignment=int(case.parameters.get("alignment", 1)),
            limit=_oracle_limit(case),
        )
    )
    payload = bytes(data)
    return Corpus(
        data=payload,
        base_address=base_address,
        pattern_bytes=parsed.pattern_bytes,
        mask=parsed.mask,
        expected_addresses=expected,
        data_sha256=sha256_bytes(payload),
        expected_checksum=address_checksum(expected),
    )


def build_distribution(name: str, size: int, case_id: str) -> bytes:
    """Build one deterministic benchmark distribution without a query."""

    return _distribution(name, size, case_id)


def build_batch_patterns(count: int) -> tuple[tuple[str, str], ...]:
    if not 1 <= count <= 32:
        raise ValueError("batch pattern count must be between 1 and 32")
    patterns: list[tuple[str, str]] = []
    for index in range(count):
        digest = hashlib.sha256(f"memscope-batch-{index}".encode()).digest()[:16]
        patterns.append((f"pattern_{index:02d}", " ".join(f"{value:02X}" for value in digest)))
    return tuple(patterns)


def inject_batch_patterns(data: bytearray, patterns: tuple[tuple[str, str], ...]) -> tuple[int, ...]:
    if not patterns:
        return ()
    stride = max(4096, len(data) // (len(patterns) + 1))
    positions: list[int] = []
    for index, (_key, pattern) in enumerate(patterns, start=1):
        parsed = parse_pattern(pattern)
        position = min(len(data) - parsed.length, index * stride)
        _inject(data, position, parsed)
        positions.append(position)
    return tuple(positions)


def find_matches(
    data: bytes,
    pattern: ParsedPattern,
    *,
    base_address: int = 0,
    alignment: int = 1,
    limit: int | None = None,
) -> list[int]:
    """Independent C-backed overlapping matcher used outside timed statements."""

    if pattern.length == 0 or len(data) < pattern.length:
        return []
    if alignment < 1:
        raise ValueError("alignment must be positive")

    maximum = None if limit is None else max(0, limit)
    matches: list[int] = []
    candidate_count = len(data) - pattern.length + 1
    if pattern.all_wildcard:
        first = (-base_address) % alignment
        for offset in range(first, candidate_count, alignment):
            matches.append(base_address + offset)
            if maximum is not None and len(matches) >= maximum:
                break
        return matches

    if pattern.exact is not None:
        position = 0
        while True:
            found = data.find(pattern.exact, position)
            if found < 0:
                return matches
            address = base_address + found
            if address % alignment == 0:
                matches.append(address)
                if maximum is not None and len(matches) >= maximum:
                    return matches
            position = found + 1

    expression = bytearray()
    for value, fixed in zip(pattern.pattern_bytes, pattern.mask, strict=True):
        expression.extend(re.escape(bytes((value,))) if fixed else b"[\x00-\xff]")
    regex = re.compile(b"(?=(" + bytes(expression) + b"))", re.DOTALL)
    for match in regex.finditer(data):
        address = base_address + match.start()
        if address % alignment == 0:
            matches.append(address)
            if maximum is not None and len(matches) >= maximum:
                break
    return matches


def result_checksum(addresses: list[int] | tuple[int, ...]) -> str:
    return address_checksum(addresses)


def _seeded_distribution(name: str, size: int, seed: int) -> bytes:
    if size < 0:
        raise ValueError("size must not be negative")
    if name == "zero":
        return bytes(size)
    if name == "repeated_aa":
        return b"\xaa" * size
    if name == "x86_skew":
        motif = bytes.fromhex("48 8B 00 90 FF 48 00 CC 89 75 00 48 FF 90 00 8B")
        return (motif * (size // len(motif) + 1))[:size]
    if name == "uniform":
        return random.Random(seed).randbytes(size)
    raise ValueError(f"unknown distribution {name!r}")


def _distribution(name: str, size: int, case_id: str) -> bytes:
    if size < 0:
        raise ValueError("size must not be negative")
    if name == "zero":
        return bytes(size)
    if name == "repeated_aa":
        return b"\xaa" * size
    if name == "x86_skew":
        motif = bytes.fromhex("48 8B 00 90 FF 48 00 CC 89 75 00 48 FF 90 00 8B")
        return (motif * (size // len(motif) + 1))[:size]
    if name == "uniform":
        seed = _CORPUS_SEED ^ int.from_bytes(hashlib.sha256(case_id.encode()).digest()[:8], "little")
        return random.Random(seed).randbytes(size)
    raise ValueError(f"unknown distribution {name!r}")


def _injection_positions(case: BenchmarkCase, size: int, pattern_length: int) -> tuple[int, ...]:
    if pattern_length > size:
        return ()
    positions: list[int] = []
    for label in case.parameters.get("injections", []):
        if label == "early":
            position = min(4096, size - pattern_length)
        elif label == "middle":
            position = max(0, size // 2 - pattern_length // 2)
        elif label == "late":
            position = max(0, size - pattern_length - 4096)
        elif label == "split_boundary":
            boundary = ((size // 2 + 4095) // 4096) * 4096
            position = max(0, min(size - pattern_length, boundary - pattern_length // 2))
        else:
            raise ValueError(f"unknown injection position {label!r}")
        positions.append(position)
    return tuple(dict.fromkeys(positions))


def _inject(data: bytearray, position: int, pattern: ParsedPattern) -> None:
    if not 0 <= position <= len(data) - pattern.length:
        raise ValueError("injection is outside the corpus")
    for index, (value, fixed) in enumerate(zip(pattern.pattern_bytes, pattern.mask, strict=True)):
        data[position + index] = value if fixed else (0xA5 + index * 17) & 0xFF


def _oracle_limit(case: BenchmarkCase) -> int | None:
    if case.mode == "first":
        return 1
    if case.mode == "addresses":
        return case.limit or case.max_matches
    if case.max_matches is not None:
        return case.max_matches
    return None


def corpus_metadata(corpus: Corpus) -> dict[str, Any]:
    return {
        "data_sha256": corpus.data_sha256,
        "expected_count": len(corpus.expected_addresses),
        "expected_checksum": corpus.expected_checksum,
    }
