"""Strict AOB parsing and canonical pattern compilation."""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from functools import lru_cache

from memscope_mcp.scanning.model import (
    MAX_PATTERN_BYTES,
    CompiledPattern,
    FixedSegment,
    QueryKind,
    ScanQuery,
)

MAX_PATTERN_TEXT_CHARS = 4096
_PATTERN_CACHE_SIZE = 256
_ASCII_WHITESPACE_CHARS = " \t\n\r\v\f"
_ASCII_WHITESPACE = frozenset(_ASCII_WHITESPACE_CHARS)
_ASCII_WHITESPACE_RE = re.compile(r"[ \t\n\r\v\f]")
_EXACT_PATTERN_RE = re.compile(r"(?:[0-9A-Fa-f]{2})+|[0-9A-Fa-f]{2}(?:[ \t\n\r\v\f]+[0-9A-Fa-f]{2})+")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_FINGERPRINT_DOMAIN = b"memscope-scanning-pattern-v1\0"


class PatternErrorReason(Enum):
    """Stable internal reasons beneath the public INVALID_PATTERN code."""

    INVALID_TYPE = "invalid_type"
    TEXT_TOO_LONG = "text_too_long"
    NON_ASCII_WHITESPACE = "non_ascii_whitespace"
    EMPTY = "empty"
    ODD_COMPACT_LENGTH = "odd_compact_length"
    BYTE_LENGTH = "byte_length"
    INVALID_TOKEN = "invalid_token"


class PatternCompileError(ValueError):
    """Structured internal compilation failure for adapter normalization."""

    code = "INVALID_PATTERN"
    field = "pattern"

    def __init__(self, reason: PatternErrorReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def compile_aob_pattern(pattern: str) -> CompiledPattern:
    """Compile the one accepted AOB grammar into canonical bytes and mask."""

    if not isinstance(pattern, str):
        raise PatternCompileError(PatternErrorReason.INVALID_TYPE, "Pattern must be a string")
    if len(pattern) > MAX_PATTERN_TEXT_CHARS:
        raise PatternCompileError(
            PatternErrorReason.TEXT_TOO_LONG,
            f"Pattern text exceeds {MAX_PATTERN_TEXT_CHARS} characters",
        )
    return _compile_aob_text_cached(pattern)


@lru_cache(maxsize=_PATTERN_CACHE_SIZE)
def _compile_aob_text_cached(pattern: str) -> CompiledPattern:
    if not pattern.isascii() and any(
        character.isspace() and character not in _ASCII_WHITESPACE for character in pattern
    ):
        raise PatternCompileError(
            PatternErrorReason.NON_ASCII_WHITESPACE,
            "Pattern accepts ASCII whitespace only",
        )

    stripped = pattern.strip(_ASCII_WHITESPACE_CHARS)
    if not stripped:
        raise PatternCompileError(PatternErrorReason.EMPTY, "Pattern is empty")

    has_ascii_whitespace = _ASCII_WHITESPACE_RE.search(stripped) is not None
    if not has_ascii_whitespace and len(stripped) % 2:
        raise PatternCompileError(
            PatternErrorReason.ODD_COMPACT_LENGTH,
            "Compact pattern length must be even",
        )

    if "?" not in stripped and _EXACT_PATTERN_RE.fullmatch(stripped) is not None:
        return _compile_exact_canonical(bytes.fromhex(stripped))

    if has_ascii_whitespace:
        tokens = stripped.split()
    else:
        tokens = [stripped[index : index + 2] for index in range(0, len(stripped), 2)]

    if not 1 <= len(tokens) <= MAX_PATTERN_BYTES:
        raise PatternCompileError(
            PatternErrorReason.BYTE_LENGTH,
            f"Compiled pattern length must be between 1 and {MAX_PATTERN_BYTES} bytes",
        )

    pattern_bytes = bytearray()
    mask = bytearray()
    for token in tokens:
        if token == "??":
            pattern_bytes.append(0)
            mask.append(0)
            continue
        if len(token) != 2 or any(character not in _HEX_DIGITS for character in token):
            raise PatternCompileError(
                PatternErrorReason.INVALID_TOKEN,
                f"Invalid pattern token '{token}'",
            )
        pattern_bytes.append(int(token, 16))
        mask.append(0xFF)

    return _compile_canonical_cached(bytes(pattern_bytes), bytes(mask))


def compile_exact_bytes(data: bytes | bytearray | memoryview) -> CompiledPattern:
    """Compile already-encoded exact bytes without a text/hex round trip."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PatternCompileError(PatternErrorReason.INVALID_TYPE, "Exact pattern must be bytes-like")
    return _compile_exact_canonical(bytes(data))


def _compile_exact_canonical(exact: bytes) -> CompiledPattern:
    if not 1 <= len(exact) <= MAX_PATTERN_BYTES:
        raise PatternCompileError(
            PatternErrorReason.BYTE_LENGTH,
            f"Compiled pattern length must be between 1 and {MAX_PATTERN_BYTES} bytes",
        )
    return _compile_canonical_cached(exact, b"\xff" * len(exact))


def compile_canonical_pattern(pattern_bytes: bytes, mask: bytes) -> CompiledPattern:
    """Rebuild a cursor-carried canonical pattern after strict structural validation."""

    if not isinstance(pattern_bytes, bytes) or not isinstance(mask, bytes):
        raise PatternCompileError(PatternErrorReason.INVALID_TYPE, "Canonical pattern and mask must be bytes")
    if not 1 <= len(pattern_bytes) <= MAX_PATTERN_BYTES or len(mask) != len(pattern_bytes):
        raise PatternCompileError(
            PatternErrorReason.BYTE_LENGTH,
            f"Compiled pattern length must be between 1 and {MAX_PATTERN_BYTES} bytes",
        )
    if any(value not in (0, 0xFF) for value in mask):
        raise PatternCompileError(PatternErrorReason.INVALID_TOKEN, "Canonical mask bytes must be 0 or 255")
    if any(value and not fixed for value, fixed in zip(pattern_bytes, mask, strict=True)):
        raise PatternCompileError(
            PatternErrorReason.INVALID_TOKEN,
            "Canonical wildcard bytes must use the zero value",
        )
    return _compile_canonical_cached(pattern_bytes, mask)


def make_aob_query(pattern: str, *, alignment: int = 1) -> ScanQuery:
    return ScanQuery(kind=QueryKind.AOB, pattern=compile_aob_pattern(pattern), alignment=alignment)


def make_exact_query(data: bytes | bytearray | memoryview, *, alignment: int = 1) -> ScanQuery:
    return ScanQuery(kind=QueryKind.EXACT, pattern=compile_exact_bytes(data), alignment=alignment)


def make_pointer_query(target: int, *, alignment: int = 8) -> ScanQuery:
    """Compile one little-endian x64 pointer target with absolute alignment."""

    if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target < (1 << 64):
        raise PatternCompileError(PatternErrorReason.INVALID_TYPE, "Pointer target must be an unsigned 64-bit address")
    return ScanQuery(
        kind=QueryKind.POINTER,
        pattern=compile_exact_bytes(target.to_bytes(8, "little", signed=False)),
        alignment=alignment,
    )


def format_canonical_pattern(pattern: CompiledPattern) -> str:
    """Render one canonical uppercase token per compiled byte."""

    return " ".join(
        f"{value:02X}" if mask else "??" for value, mask in zip(pattern.pattern_bytes, pattern.mask, strict=True)
    )


@lru_cache(maxsize=_PATTERN_CACHE_SIZE)
def _compile_canonical_cached(pattern_bytes: bytes, mask: bytes) -> CompiledPattern:
    segments = _fixed_segments(pattern_bytes, mask)
    fixed_byte_count = mask.count(0xFF)
    exact_bytes = pattern_bytes if fixed_byte_count == len(pattern_bytes) else None
    all_wildcard = fixed_byte_count == 0
    unique_fixed_bytes = bytes(sorted({value for value, fixed in zip(pattern_bytes, mask, strict=True) if fixed}))
    regex = None if exact_bytes is not None or all_wildcard else _compile_overlapping_regex(pattern_bytes, mask)
    fingerprint = hashlib.sha256(
        _FINGERPRINT_DOMAIN + len(pattern_bytes).to_bytes(2, "big") + pattern_bytes + mask
    ).digest()
    return CompiledPattern._from_validated_parts(
        length=len(pattern_bytes),
        pattern_bytes=pattern_bytes,
        mask=mask,
        segments=segments,
        exact_bytes=exact_bytes,
        all_wildcard=all_wildcard,
        fixed_byte_count=fixed_byte_count,
        unique_fixed_bytes=unique_fixed_bytes,
        regex=regex,
        fingerprint=fingerprint,
    )


def _fixed_segments(pattern_bytes: bytes, mask: bytes) -> tuple[FixedSegment, ...]:
    segments: list[FixedSegment] = []
    index = 0
    while index < len(pattern_bytes):
        if not mask[index]:
            index += 1
            continue
        start = index
        while index < len(pattern_bytes) and mask[index]:
            index += 1
        segments.append(FixedSegment(offset=start, literal=pattern_bytes[start:index]))
    return tuple(segments)


def _compile_overlapping_regex(pattern_bytes: bytes, mask: bytes) -> re.Pattern[bytes]:
    parts = [re.escape(bytes((value,))) if fixed else b"." for value, fixed in zip(pattern_bytes, mask, strict=True)]
    return re.compile(b"(?=(" + b"".join(parts) + b"))", re.DOTALL)


def _clear_pattern_compile_caches() -> None:
    _compile_aob_text_cached.cache_clear()
    _compile_canonical_cached.cache_clear()
