"""Bounded result policies for the internal scanning engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from memscope_mcp.scanning.model import ScanHit, TerminationReason


@dataclass(frozen=True, slots=True)
class CollectorDecision:
    """Whether the matcher must stop after committing the offered hit."""

    stop: bool
    reason: TerminationReason | None = None

    def __post_init__(self) -> None:
        if self.stop != (self.reason is not None):
            raise ValueError("stopping decisions require a reason and continuing decisions cannot have one")


@dataclass(frozen=True, slots=True)
class CollectorResult:
    """Final retained hits and observed count for one invocation."""

    hits: tuple[ScanHit, ...]
    observed_count: int
    termination_reason: TerminationReason


class ScanCollector(Protocol):
    def offer(self, hit: ScanHit) -> CollectorDecision: ...

    def finish(self, reason: TerminationReason) -> CollectorResult: ...


_CONTINUE = CollectorDecision(stop=False)


class _BaseCollector:
    __slots__ = ("_hits", "_last_address", "_observed_count", "_stop_reason")

    def __init__(self) -> None:
        self._hits: list[ScanHit] = []
        self._last_address: int | None = None
        self._observed_count = 0
        self._stop_reason: TerminationReason | None = None

    def finish(self, reason: TerminationReason) -> CollectorResult:
        if not isinstance(reason, TerminationReason):
            raise TypeError("reason must be a TerminationReason")
        return CollectorResult(
            hits=tuple(self._hits),
            observed_count=self._observed_count,
            termination_reason=self._stop_reason or reason,
        )

    def _record(self, hit: ScanHit, *, retain: bool) -> None:
        if self._stop_reason is not None:
            raise RuntimeError("collector has already stopped")
        if not isinstance(hit, ScanHit):
            raise TypeError("hit must be ScanHit")
        if self._last_address is not None and hit.address <= self._last_address:
            raise ValueError("hits must be unique and address ordered")
        self._last_address = hit.address
        self._observed_count += 1
        if retain:
            self._hits.append(hit)

    def _stop(self, reason: TerminationReason) -> CollectorDecision:
        self._stop_reason = reason
        return CollectorDecision(stop=True, reason=reason)


class BoundedAddressCollector(_BaseCollector):
    """Retain a bounded address sequence without continuation semantics."""

    __slots__ = ("limit",)

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = _positive_int("limit", limit)

    def offer(self, hit: ScanHit) -> CollectorDecision:
        self._record(hit, retain=True)
        if self._observed_count >= self.limit:
            return self._stop(TerminationReason.MATCH_LIMIT)
        return _CONTINUE


class PageCollector(_BaseCollector):
    """Retain one page and stop on page or remaining cumulative match cap."""

    __slots__ = ("page_limit", "remaining_matches")

    def __init__(self, page_limit: int, *, remaining_matches: int | None = None) -> None:
        super().__init__()
        self.page_limit = _positive_int("page_limit", page_limit)
        self.remaining_matches = (
            None if remaining_matches is None else _positive_int("remaining_matches", remaining_matches)
        )

    def offer(self, hit: ScanHit) -> CollectorDecision:
        self._record(hit, retain=True)
        if self.remaining_matches is not None and self._observed_count >= self.remaining_matches:
            return self._stop(TerminationReason.MATCH_LIMIT)
        if self._observed_count >= self.page_limit:
            return self._stop(TerminationReason.PAGE_LIMIT)
        return _CONTINUE


class FirstHitCollector(_BaseCollector):
    """Retain exactly the first verified hit."""

    __slots__ = ()

    def offer(self, hit: ScanHit) -> CollectorDecision:
        self._record(hit, retain=True)
        return self._stop(TerminationReason.FIRST_HIT)


class CountCollector(_BaseCollector):
    """Count verified hits without retaining addresses."""

    __slots__ = ("max_matches",)

    def __init__(self, max_matches: int) -> None:
        super().__init__()
        self.max_matches = _positive_int("max_matches", max_matches)

    def offer(self, hit: ScanHit) -> CollectorDecision:
        self._record(hit, retain=False)
        if self._observed_count >= self.max_matches:
            return self._stop(TerminationReason.MATCH_LIMIT)
        return _CONTINUE


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value
