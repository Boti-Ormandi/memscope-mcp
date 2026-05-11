"""General utility functions for Lua engine.

Timing, sleep, and bitwise operations.
"""

import time


def lua_clock() -> float:
    """High-resolution timer in milliseconds.

    Returns milliseconds since an arbitrary epoch. Use the difference
    between two calls to measure elapsed time.

    Returns:
        Float milliseconds. Example::

            local t0 = clock()
            -- ... do work ...
            local elapsed = clock() - t0
            print("Took " .. elapsed .. " ms")
    """
    return time.perf_counter() * 1000.0


def lua_sleep(ms) -> None:
    """Pause script execution for the specified duration.

    Args:
        ms: Milliseconds to sleep. Example::

            -- Poll a value every 100ms
            for i = 1, 10 do
                local val = readFloat(addr)
                print("value: " .. val)
                sleep(100)
            end
    """
    time.sleep(max(0, float(ms)) / 1000.0)


# ========== Bitwise Operations ==========
#
# Lua 5.4 has native bitwise operators (a & b, a | b, a ~ b, a << n, a >> n)
# but named functions are clearer and easier for generated code.
# These also handle nil/float inputs gracefully.


def bit_and(a, b) -> int:
    """Bitwise AND.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        a AND b. Example::

            local flags = readInteger(addr)
            if band(flags, 0x1) ~= 0 then print("bit 0 set") end
    """
    return int(a) & int(b)


def bit_or(a, b) -> int:
    """Bitwise OR.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        a OR b. Example::

            local combined = bor(flagsA, flagsB)
    """
    return int(a) | int(b)


def bit_xor(a, b) -> int:
    """Bitwise XOR.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        a XOR b.
    """
    return int(a) ^ int(b)


def bit_not(a) -> int:
    """Bitwise NOT (32-bit).

    Masks to 32 bits to match typical flag/mask usage.

    Args:
        a: Operand.

    Returns:
        NOT a (32-bit). Example::

            local mask = bnot(0xFF)  -- 0xFFFFFF00
    """
    return ~int(a) & 0xFFFFFFFF


def bit_lshift(a, n) -> int:
    """Left shift.

    Args:
        a: Value to shift.
        n: Number of bits.

    Returns:
        a << n. Example::

            local bit3 = lshift(1, 3)  -- 8
    """
    return int(a) << int(n)


def bit_rshift(a, n) -> int:
    """Logical right shift (unsigned, 64-bit).

    Args:
        a: Value to shift.
        n: Number of bits.

    Returns:
        a >> n (unsigned). Example::

            local type = rshift(band(flags, 0xF0), 4)
    """
    return (int(a) & 0xFFFFFFFFFFFFFFFF) >> int(n)


def bit_extract(value, offset, width=1) -> int:
    """Extract a bit field from a value.

    Convenience for the common pattern of shift + mask.

    Args:
        value: The integer to extract from.
        offset: Bit position of the field (0 = LSB).
        width: Number of bits (default 1 = single bit).

    Returns:
        The extracted field value. Example::

            local flags = readInteger(addr)
            local isActive = bextract(flags, 0)       -- bit 0
            local category = bextract(flags, 4, 4)    -- bits 4-7
    """
    mask = (1 << int(width)) - 1
    return (int(value) >> int(offset)) & mask
