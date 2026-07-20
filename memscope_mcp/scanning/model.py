"""Immutable core models for the internal scanning engine."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

MAX_PATTERN_BYTES = 1024
MAX_ALIGNMENT = 4096
_MAX_ADDRESS_EXCLUSIVE = 1 << 64
_MAX_ADDRESS = _MAX_ADDRESS_EXCLUSIVE - 1


class QueryKind(Enum):
    """Internal query families that share the byte matcher."""

    AOB = "aob"
    EXACT = "exact"
    POINTER = "pointer"


class MatcherStrategy(Enum):
    """Matcher implementations recorded in diagnostics."""

    EXACT = "exact"
    ALL_WILDCARD = "all_wildcard"
    ANCHOR = "anchor"
    REGEX = "regex"


class TerminationReason(Enum):
    """Stable reasons why one scan invocation stopped."""

    SCOPE_EXHAUSTED = "scope_exhausted"
    PAGE_LIMIT = "page_limit"
    MATCH_LIMIT = "match_limit"
    FIRST_HIT = "first_hit"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    TARGET_CHANGED = "target_changed"
    READER_ERROR = "reader_error"


COLLECTOR_TERMINATIONS = frozenset(
    {
        TerminationReason.PAGE_LIMIT,
        TerminationReason.MATCH_LIMIT,
        TerminationReason.FIRST_HIT,
    }
)


@dataclass(frozen=True, slots=True)
class FixedSegment:
    """One maximal contiguous run of fixed bytes in a compiled pattern."""

    offset: int
    literal: bytes

    def __post_init__(self) -> None:
        _require_non_negative_int("offset", self.offset)
        if not isinstance(self.literal, bytes) or not self.literal:
            raise ValueError("literal must be non-empty bytes")


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    """Canonical byte/mask representation independent of source spelling."""

    length: int
    pattern_bytes: bytes
    mask: bytes
    segments: tuple[FixedSegment, ...]
    exact_bytes: bytes | None
    all_wildcard: bool
    fixed_byte_count: int
    unique_fixed_bytes: bytes
    regex: re.Pattern[bytes] | None
    fingerprint: bytes

    def __post_init__(self) -> None:
        if isinstance(self.length, bool) or not 1 <= self.length <= MAX_PATTERN_BYTES:
            raise ValueError(f"length must be between 1 and {MAX_PATTERN_BYTES}")
        if not isinstance(self.pattern_bytes, bytes) or len(self.pattern_bytes) != self.length:
            raise ValueError("pattern_bytes length must equal length")
        if not isinstance(self.mask, bytes) or len(self.mask) != self.length:
            raise ValueError("mask length must equal length")
        if any(value not in (0, 0xFF) for value in self.mask):
            raise ValueError("mask bytes must be 0 or 255")
        if any(value and not fixed for value, fixed in zip(self.pattern_bytes, self.mask, strict=True)):
            raise ValueError("wildcard pattern bytes must use the canonical zero value")

        expected_fixed_count = self.mask.count(0xFF)
        if self.fixed_byte_count != expected_fixed_count:
            raise ValueError("fixed_byte_count does not match mask")
        if self.all_wildcard != (expected_fixed_count == 0):
            raise ValueError("all_wildcard does not match mask")
        if (self.exact_bytes is not None) != (expected_fixed_count == self.length):
            raise ValueError("exact_bytes presence does not match mask")
        if self.exact_bytes is not None and self.exact_bytes != self.pattern_bytes:
            raise ValueError("exact_bytes must equal pattern_bytes")

        fixed_values = bytes(sorted({value for value, mask in zip(self.pattern_bytes, self.mask, strict=True) if mask}))
        if self.unique_fixed_bytes != fixed_values:
            raise ValueError("unique_fixed_bytes does not match the fixed bytes")
        if not isinstance(self.fingerprint, bytes) or len(self.fingerprint) != 32:
            raise ValueError("fingerprint must be a 32-byte digest")

        if self.segments != _derive_fixed_segments(self.pattern_bytes, self.mask):
            raise ValueError("fixed segments do not exactly represent the mask")
        if self.exact_bytes is not None or self.all_wildcard:
            if self.regex is not None:
                raise ValueError("exact and all-wildcard patterns must not carry a regex")
        elif self.regex is None:
            raise ValueError("masked patterns require a precompiled regex fallback")


@dataclass(frozen=True, slots=True)
class ScanQuery:
    """One compiled query and its absolute-address alignment policy."""

    kind: QueryKind
    pattern: CompiledPattern
    alignment: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.kind, QueryKind):
            raise TypeError("kind must be a QueryKind")
        if not isinstance(self.pattern, CompiledPattern):
            raise TypeError("pattern must be a CompiledPattern")
        _require_positive_bounded_int("alignment", self.alignment, MAX_ALIGNMENT)
        if self.kind in {QueryKind.EXACT, QueryKind.POINTER} and self.pattern.exact_bytes is None:
            raise ValueError(f"{self.kind.value} queries require an exact pattern")


@dataclass(frozen=True, slots=True)
class ModuleRecord:
    """Immutable module identity carried into plans, windows, and hits."""

    name: str
    normalized_name: str
    base: int
    size: int
    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.normalized_name, str) or not self.normalized_name:
            raise ValueError("normalized_name must be a non-empty string")
        if not isinstance(self.path, str):
            raise TypeError("path must be a string")
        _require_address("base", self.base)
        _require_positive_bounded_int("size", self.size, _MAX_ADDRESS_EXCLUSIVE)
        if self.base + self.size > _MAX_ADDRESS_EXCLUSIVE:
            raise ValueError("module range exceeds the x64 address space")

    @property
    def end_exclusive(self) -> int:
        return self.base + self.size


@dataclass(frozen=True, slots=True)
class SearchWindow:
    """Bytes plus the exact absolute candidate-start interval they own."""

    base_address: int
    data: bytes | bytearray | memoryview
    eligible_start: int
    eligible_end: int
    module: ModuleRecord | None = None

    def __post_init__(self) -> None:
        _require_address("base_address", self.base_address)
        _require_address_boundary("eligible_start", self.eligible_start)
        _require_address_boundary("eligible_end", self.eligible_end)
        if self.eligible_end < self.eligible_start:
            raise ValueError("eligible_end must not be smaller than eligible_start")
        if not isinstance(self.data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes, bytearray, or memoryview")
        if isinstance(self.data, memoryview):
            if self.data.ndim != 1 or self.data.itemsize != 1 or not self.data.c_contiguous:
                raise ValueError("memoryview data must be one-dimensional contiguous bytes")
        if self.base_address + len(self.data) > _MAX_ADDRESS_EXCLUSIVE:
            raise ValueError("search window exceeds the x64 address space")
        if self.module is not None and not isinstance(self.module, ModuleRecord):
            raise TypeError("module must be a ModuleRecord or None")


@dataclass(frozen=True, slots=True)
class ScanHit:
    """One verified address with immutable module identity when known."""

    address: int
    module_name: str | None
    module_base: int | None

    def __post_init__(self) -> None:
        _require_address("address", self.address)
        if (self.module_name is None) != (self.module_base is None):
            raise ValueError("module_name and module_base must both be present or both be None")
        if self.module_name is not None and not self.module_name:
            raise ValueError("module_name must be non-empty when present")
        if self.module_base is not None:
            _require_address("module_base", self.module_base)


@dataclass(slots=True)
class ScanStats:
    """Mutable internal operation counters; adapters expose only stable subsets."""

    strategy_counts: dict[MatcherStrategy, int] = field(default_factory=dict)
    unique_bytes_examined: int = 0
    physical_read_calls: int = 0
    physical_bytes_requested: int = 0
    physical_bytes_read: int = 0
    unique_bytes_read: int = 0
    logical_read_chunks: int = 0
    read_gap_count: int = 0
    failed_read_bytes: int = 0
    failed_read_spans: list[tuple[int, int]] = field(default_factory=list)
    planner_query_calls: int = 0
    reader_chunk_size: int = 0
    physical_cursor_prefix_bytes: int = 0
    region_count: int = 0
    span_count: int = 0
    candidate_count: int = 0
    verification_count: int = 0
    anchor_candidates: int = 0
    segment_verifications: int = 0
    regex_candidates: int = 0
    verified_matches: int = 0
    committed_matches: int = 0
    selector_invocations: int = 0
    selector_sampled_bytes: int = 0
    selector_estimated_candidates: int = 0
    control_polls: int = 0
    matcher_invocations: int = 0
    find_calls: int = 0
    duration_ns: int = 0
    _last_examined_end: int | None = field(default=None, init=False, repr=False)

    def record_strategy(self, strategy: MatcherStrategy) -> None:
        self.strategy_counts[strategy] = self.strategy_counts.get(strategy, 0) + 1
        self.matcher_invocations += 1

    def record_examined_range(self, start: int, end: int) -> None:
        """Add one ascending half-open byte range without double-counting overlap."""

        if end <= start:
            return
        if self._last_examined_end is None or start >= self._last_examined_end:
            self.unique_bytes_examined += end - start
        elif end > self._last_examined_end:
            self.unique_bytes_examined += end - self._last_examined_end
        self._last_examined_end = end if self._last_examined_end is None else max(self._last_examined_end, end)


@dataclass(slots=True)
class ScanControl:
    """Cooperative deadline, cancellation, and outer-runtime interruption state."""

    deadline_ns: int | None = None
    target_change_checks: tuple[Callable[[], bool], ...] = ()
    cancel_checks: tuple[Callable[[], bool], ...] = ()
    interrupt_check: Callable[[], None] | None = None
    clock: Callable[[], int] = time.monotonic_ns
    poll_interval: int = 256

    def __post_init__(self) -> None:
        if self.deadline_ns is not None:
            _require_non_negative_int("deadline_ns", self.deadline_ns)
        if not isinstance(self.target_change_checks, tuple) or any(
            not callable(check) for check in self.target_change_checks
        ):
            raise TypeError("target_change_checks must be a tuple of callables")
        if not isinstance(self.cancel_checks, tuple) or any(not callable(check) for check in self.cancel_checks):
            raise TypeError("cancel_checks must be a tuple of callables")
        if self.interrupt_check is not None and not callable(self.interrupt_check):
            raise TypeError("interrupt_check must be callable or None")
        if not callable(self.clock):
            raise TypeError("clock must be callable")
        _require_positive_bounded_int("poll_interval", self.poll_interval, 1_000_000)

    def poll(self) -> TerminationReason | None:
        if self.interrupt_check is not None:
            self.interrupt_check()
        if any(check() for check in self.target_change_checks):
            return TerminationReason.TARGET_CHANGED
        if self.deadline_ns is not None and self.clock() >= self.deadline_ns:
            return TerminationReason.TIMEOUT
        if any(check() for check in self.cancel_checks):
            return TerminationReason.CANCELLED
        return None


@dataclass(slots=True)
class ScanResult:
    """Internal scan result before MCP or Lua response formatting."""

    hits: list[ScanHit]
    observed_count: int
    termination_reason: TerminationReason
    read_gaps_detected: bool
    stats: ScanStats
    next_candidate_start: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.hits, list) or any(not isinstance(hit, ScanHit) for hit in self.hits):
            raise TypeError("hits must be a list of ScanHit values")
        _require_non_negative_int("observed_count", self.observed_count)
        if not isinstance(self.termination_reason, TerminationReason):
            raise TypeError("termination_reason must be a TerminationReason")
        if not isinstance(self.read_gaps_detected, bool):
            raise TypeError("read_gaps_detected must be a bool")
        if not isinstance(self.stats, ScanStats):
            raise TypeError("stats must be ScanStats")
        if self.next_candidate_start is not None:
            _require_address_boundary("next_candidate_start", self.next_candidate_start)
            if self.termination_reason not in COLLECTOR_TERMINATIONS:
                raise ValueError("next_candidate_start is valid only for collector termination")


@dataclass(frozen=True, slots=True)
class MatcherResult:
    """One matcher invocation's stop state."""

    termination_reason: TerminationReason | None = None
    next_candidate_start: int | None = None

    def __post_init__(self) -> None:
        if self.next_candidate_start is not None:
            _require_address_boundary("next_candidate_start", self.next_candidate_start)
            if self.termination_reason not in COLLECTOR_TERMINATIONS:
                raise ValueError("next_candidate_start requires collector termination")


def _derive_fixed_segments(pattern_bytes: bytes, mask: bytes) -> tuple[FixedSegment, ...]:
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


def _require_address(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_ADDRESS:
        raise ValueError(f"{name} must be an unsigned 64-bit address")


def _require_address_boundary(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_ADDRESS_EXCLUSIVE:
        raise ValueError(f"{name} must be an unsigned 64-bit address boundary")


def _require_non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _require_positive_bounded_int(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
