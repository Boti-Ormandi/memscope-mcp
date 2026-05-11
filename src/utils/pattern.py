"""AOB (Array of Bytes) pattern parsing and matching utilities."""

from dataclasses import dataclass


@dataclass
class ParsedPattern:
    """Parsed AOB pattern with bytes and mask."""

    pattern_bytes: bytes
    mask: bytes  # 0xFF = match, 0x00 = wildcard
    length: int
    original: str


def parse_aob_pattern(pattern: str) -> ParsedPattern:
    """Parse AOB pattern string into bytes and mask.

    Supports:
        - "48 8B 05 ?? ?? ?? ?? 48 85 C0"
        - "48 8B 05 ? ? ? ? 48 85 C0"
        - "488B05????????4885C0" (no spaces)

    Args:
        pattern: Pattern string with ?? for wildcards

    Returns:
        ParsedPattern with bytes and mask
    """
    original = pattern

    # Normalize pattern - remove extra whitespace
    pattern = pattern.strip()

    # Handle no-space format
    if " " not in pattern:
        # Insert spaces every 2 characters
        pattern = " ".join(pattern[i : i + 2] for i in range(0, len(pattern), 2))

    parts = pattern.split()
    pattern_bytes = bytearray()
    mask = bytearray()

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if part in ("??", "?", "xx", "XX", "**"):
            # Wildcard
            pattern_bytes.append(0x00)
            mask.append(0x00)
        else:
            # Literal byte
            try:
                byte_val = int(part, 16)
                pattern_bytes.append(byte_val)
                mask.append(0xFF)
            except ValueError:
                raise ValueError(f"Invalid byte in pattern: {part}")

    return ParsedPattern(
        pattern_bytes=bytes(pattern_bytes), mask=bytes(mask), length=len(pattern_bytes), original=original
    )


def match_pattern(data: bytes, pattern: ParsedPattern, start: int = 0) -> list[int]:
    """Find all pattern matches in data.

    Args:
        data: Data to search
        pattern: Parsed pattern
        start: Starting offset for returned indices

    Returns:
        List of match offsets
    """
    matches = []
    pattern_len = pattern.length
    data_len = len(data)

    if pattern_len == 0 or data_len < pattern_len:
        return matches

    pattern_bytes = pattern.pattern_bytes
    mask = pattern.mask

    # Scan through data
    for i in range(data_len - pattern_len + 1):
        found = True
        for j in range(pattern_len):
            if mask[j] != 0 and data[i + j] != pattern_bytes[j]:
                found = False
                break
        if found:
            matches.append(start + i)

    return matches


def create_signature_pattern(bytes_data: bytes, mask_positions: list[int] = None) -> str:
    """Create an AOB pattern from bytes, optionally with masks.

    Args:
        bytes_data: Raw bytes
        mask_positions: List of byte positions to mask as wildcards

    Returns:
        Pattern string
    """
    mask_positions = set(mask_positions or [])
    parts = []

    for i, b in enumerate(bytes_data):
        if i in mask_positions:
            parts.append("??")
        else:
            parts.append(f"{b:02X}")

    return " ".join(parts)
