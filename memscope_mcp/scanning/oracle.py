"""Independent, deliberately naive correctness oracle for scan development."""

from __future__ import annotations

from dataclasses import dataclass

_ASCII_WHITESPACE = frozenset(" \t\n\r\v\f")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True, slots=True)
class OraclePattern:
    pattern_bytes: bytes
    mask: bytes
    canonical_text: str

    @property
    def length(self) -> int:
        return len(self.pattern_bytes)


def parse_oracle_pattern(pattern: str) -> OraclePattern:
    """Parse the strict AOB grammar without using the production compiler."""

    if not isinstance(pattern, str):
        raise ValueError("pattern must be a string")
    if len(pattern) > 4096:
        raise ValueError("pattern text exceeds 4096 characters")
    if any(character.isspace() and character not in _ASCII_WHITESPACE for character in pattern):
        raise ValueError("only ASCII whitespace is accepted")

    stripped = pattern.strip("".join(_ASCII_WHITESPACE))
    if not stripped:
        raise ValueError("pattern is empty")

    if any(character in _ASCII_WHITESPACE for character in stripped):
        tokens = stripped.split()
    else:
        if len(stripped) % 2:
            raise ValueError("compact pattern length must be even")
        tokens = [stripped[index : index + 2] for index in range(0, len(stripped), 2)]

    if not tokens or len(tokens) > 1024:
        raise ValueError("compiled pattern length must be between 1 and 1024 bytes")

    pattern_bytes = bytearray()
    mask = bytearray()
    canonical_tokens: list[str] = []
    for token in tokens:
        if token == "??":
            pattern_bytes.append(0)
            mask.append(0)
            canonical_tokens.append("??")
            continue
        if len(token) != 2 or any(character not in _HEX_DIGITS for character in token):
            raise ValueError(f"invalid pattern token: {token}")
        pattern_bytes.append(int(token, 16))
        mask.append(0xFF)
        canonical_tokens.append(token.upper())

    return OraclePattern(
        pattern_bytes=bytes(pattern_bytes),
        mask=bytes(mask),
        canonical_text=" ".join(canonical_tokens),
    )


def find_oracle_matches(
    data: bytes,
    pattern: OraclePattern,
    *,
    base_address: int = 0,
    eligible_start: int | None = None,
    eligible_end: int | None = None,
    alignment: int = 1,
    max_matches: int | None = None,
) -> list[int]:
    """Return address-ordered overlapping matches under the strict scan semantics."""

    if isinstance(base_address, bool) or not isinstance(base_address, int) or base_address < 0:
        raise ValueError("base_address must be a non-negative integer")
    if isinstance(alignment, bool) or not isinstance(alignment, int) or not 1 <= alignment <= 4096:
        raise ValueError("alignment must be between 1 and 4096")
    if max_matches is not None:
        if isinstance(max_matches, bool) or not isinstance(max_matches, int) or max_matches < 1:
            raise ValueError("max_matches must be a positive integer")

    pattern_length = pattern.length
    last_candidate_exclusive = base_address + max(0, len(data) - pattern_length + 1)
    candidate_start = base_address if eligible_start is None else max(base_address, eligible_start)
    candidate_end = last_candidate_exclusive if eligible_end is None else min(last_candidate_exclusive, eligible_end)
    if candidate_start >= candidate_end:
        return []

    matches: list[int] = []
    for address in range(candidate_start, candidate_end):
        if address % alignment:
            continue
        offset = address - base_address
        matched = True
        for index in range(pattern_length):
            if pattern.mask[index] and data[offset + index] != pattern.pattern_bytes[index]:
                matched = False
                break
        if not matched:
            continue
        matches.append(address)
        if max_matches is not None and len(matches) >= max_matches:
            break
    return matches
