"""Safe 64-bit handling for Lua.

Lupa (Python-Lua bridge) only supports signed int64. Values >= 0x8000000000000000
cause "int too big to convert". These helpers ensure safe Python-to-Lua transfer.
"""

from typing import Optional


def to_lua_int64(value) -> Optional[int]:
    """Convert unsigned 64-bit to signed for Lua compatibility.

    Reinterprets values >= 2^63 as negative (two's complement).
    Bit pattern is preserved - 0xFFFFFFFFFFFFFFFF becomes -1.
    """
    if value is None:
        return None
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        return value - 0x10000000000000000
    return value


def to_uint64(value) -> int:
    """Convert a Lua/Python integer to an unsigned 64-bit value.

    Lua receives values above INT64_MAX as signed two's-complement numbers via
    lupa. Masking preserves the original pointer/integer bit pattern for native
    calls and hex formatting.
    """
    return int(value) & 0xFFFFFFFFFFFFFFFF


def parse_hex_address(hex_string: str) -> Optional[int]:
    """Parse hex address string to integer.

    Use this for large 64-bit addresses that can't be written as Lua literals.

    Examples:
        local addr = addr("0x1F58E12ECF0")
        local ptr = parseHex("0x1F29122D840")

    Args:
        hex_string: Hex address like "0x1F58E12ECF0" or "1F58E12ECF0"

    Returns:
        Integer address or None if invalid
    """
    try:
        if not hex_string:
            return None

        # Handle with or without 0x prefix
        hex_str = str(hex_string).strip()
        if hex_str.lower().startswith("0x"):
            hex_str = hex_str[2:]

        return to_lua_int64(int(hex_str, 16))
    except:
        return None


def safe_eq(a, b) -> bool:
    """Safe equality check for 64-bit integers. Use instead of == for addresses."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    try:
        return int(a) == int(b)
    except (OverflowError, ValueError):
        return str(a) == str(b)


def safe_ne(a, b) -> bool:
    """Safe not-equal check for 64-bit integers. Use instead of ~= for addresses."""
    return not safe_eq(a, b)


def safe_lt(a, b) -> bool:
    """Safe less-than check for 64-bit integers. Use instead of < for addresses."""
    if a is None or b is None:
        return False
    try:
        return int(a) < int(b)
    except (OverflowError, ValueError):
        return False


def safe_gt(a, b) -> bool:
    """Safe greater-than check for 64-bit integers. Use instead of > for addresses."""
    if a is None or b is None:
        return False
    try:
        return int(a) > int(b)
    except (OverflowError, ValueError):
        return False


def safe_le(a, b) -> bool:
    """Safe less-or-equal check for 64-bit integers. Use instead of <= for addresses."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    try:
        return int(a) <= int(b)
    except (OverflowError, ValueError):
        return safe_eq(a, b)


def safe_ge(a, b) -> bool:
    """Safe greater-or-equal check for 64-bit integers. Use instead of >= for addresses."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    try:
        return int(a) >= int(b)
    except (OverflowError, ValueError):
        return safe_eq(a, b)


def safe_int(value, max_val: int = 0x7FFFFFFF) -> Optional[int]:
    """Return integer if it's within safe range, else nil.

    Use this for values that SHOULD be small integers (counts, lengths, etc.)
    Returns nil if value is garbage/too large, allowing safe `if value then` checks.

    Args:
        value: Value to check
        max_val: Maximum allowed value (default: 2^31-1 for signed 32-bit)

    Example:
        local strLen = safeInt(readInteger(ptr + 0x10))
        if strLen and strLen == 24 then  -- Safe: strLen is nil if garbage
    """
    if value is None:
        return None
    try:
        v = int(value)
        if v < 0 or v > max_val:
            return None
        return v
    except (OverflowError, ValueError):
        return None
