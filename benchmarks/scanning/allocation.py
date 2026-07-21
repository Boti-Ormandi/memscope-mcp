"""Bounded Python allocation measurements for scanning benchmark cases."""

from __future__ import annotations

import gc
import tracemalloc
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def measure_peak_python_bytes(operation: Callable[[], T]) -> tuple[T, int]:
    """Run one operation and return its result plus peak traced Python bytes."""

    if not callable(operation):
        raise TypeError("operation must be callable")

    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()
    tracemalloc.start()
    try:
        result = operation()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        if gc_was_enabled:
            gc.enable()
    return result, peak
