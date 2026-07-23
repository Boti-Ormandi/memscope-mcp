"""Predeclared scanning benchmark cases and semantic comparison fingerprints."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from benchmarks.scanning import CANDIDATE_WATCHDOG_FLOOR_S, CORPUS_VERSION, MANIFEST_VERSION
from benchmarks.scanning.common import sha256_json

ComparisonClass = Literal["apples_to_apples", "eliminated_work", "new_capability"]
SuiteTier = Literal["headline", "coverage"]

_CANDIDATE_ONLY_KINDS = frozenset({"chunk_sweep", "chunk_salvage", "chunk_timeout"})
_CONTROLLED_TARGET_KINDS = frozenset(
    {
        "reader_ceiling",
        "e2e",
        "fragmented",
        "boundary",
        "allocation",
        "writable_filter",
        "section_filter",
        "section_filter_warm",
        "timeout",
        "chunk_sweep",
        "chunk_salvage",
        "chunk_timeout",
        "cursor",
        "batch",
    }
)
_EXACT_PREFLIGHT_KINDS = frozenset(
    {
        "e2e",
        "fragmented",
        "boundary",
        "allocation",
        "writable_filter",
        "section_filter",
        "section_filter_warm",
        "chunk_sweep",
        "chunk_salvage",
    }
)
_EXACT_PREFLIGHT_PROTOCOL = {
    "operation": "exact_addresses",
    "ordered": True,
    "checksum": "sha256-u64le",
    "attachment": "same",
    "cache_state": "isolated",
    "excluded_from_timing": True,
    "independent_read_counters": True,
}


def preflight_protocol(kind: str) -> dict[str, Any]:
    return dict(_EXACT_PREFLIGHT_PROTOCOL) if kind in _EXACT_PREFLIGHT_KINDS else {}


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """One immutable benchmark identity declared before observations are collected."""

    case_id: str
    group: str
    layer: str
    kind: str
    comparison_class: ComparisonClass
    primary_metric: str
    distribution: str = "uniform"
    pattern: str = ""
    mode: str = "count"
    size_bytes: int = 0
    limit: int | None = None
    max_matches: int | None = None
    timeout_ms: int = 30_000
    process_timeout_s: float = 12.0
    tier: SuiteTier = "headline"
    headline: bool = True
    expected_strategy: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    setup_protocol: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.case_id or any(character.isspace() for character in self.case_id):
            raise ValueError("case_id must be non-empty and contain no whitespace")
        if not self.group or not self.layer or not self.kind:
            raise ValueError("group, layer, and kind must be non-empty")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative")
        if self.limit is not None and self.limit < 1:
            raise ValueError("limit must be positive")
        if self.max_matches is not None and self.max_matches < 1:
            raise ValueError("max_matches must be positive")
        if self.timeout_ms < 1 or self.process_timeout_s <= 0:
            raise ValueError("timeouts must be positive")
        if self.expected_strategy not in {None, "exact", "anchor", "regex", "all_wildcard"}:
            raise ValueError("expected_strategy is invalid")

    def effective_size(self, profile: str) -> int:
        if profile == "release" or self.size_bytes == 0:
            return self.size_bytes
        if profile != "smoke":
            raise ValueError("profile must be 'smoke' or 'release'")
        smoke_override = self.parameters.get("smoke_size_bytes")
        if smoke_override is not None:
            if isinstance(smoke_override, bool) or not isinstance(smoke_override, int) or smoke_override < 1:
                raise ValueError("smoke_size_bytes must be a positive integer")
            return smoke_override
        return max(64 * 1024, min(4 * 1024 * 1024, self.size_bytes // 16))

    def semantic_descriptor(self, profile: str) -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "corpus_version": CORPUS_VERSION,
            "case_id": self.case_id,
            "group": self.group,
            "layer": self.layer,
            "kind": self.kind,
            "comparison_class": self.comparison_class,
            "distribution": self.distribution,
            "pattern": self.pattern,
            "mode": self.mode,
            "size_bytes": self.effective_size(profile),
            "limit": self.limit,
            "max_matches": self.max_matches,
            "timeout_ms": self.timeout_ms,
            "process_timeout_s": self.process_timeout_s,
            "candidate_watchdog_timeout_s": max(self.process_timeout_s, CANDIDATE_WATCHDOG_FLOOR_S),
            "parameters": self.parameters,
            "preflight_protocol": preflight_protocol(self.kind),
            "setup_protocol": self.setup_protocol,
        }

    def semantic_fingerprint(self, profile: str) -> str:
        return sha256_json(self.semantic_descriptor(profile))


@dataclass(frozen=True, slots=True)
class MatcherCase:
    """Standalone deterministic matcher case used by the fast validation runner."""

    case_id: str
    tier: str
    family: str
    pattern: str
    distribution: str
    buffer_size: int
    seed: int
    injection_offsets: tuple[int, ...]
    alignment: int
    match_cap: int
    expected_strategy: str
    layer: str = "matcher"
    comparison_class: str = "apples_to_apples"

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "tier": self.tier,
            "family": self.family,
            "pattern": self.pattern,
            "distribution": self.distribution,
            "buffer_size": self.buffer_size,
            "seed": self.seed,
            "injection_offsets": list(self.injection_offsets),
            "alignment": self.alignment,
            "match_cap": self.match_cap,
            "expected_strategy": self.expected_strategy,
            "layer": self.layer,
            "comparison_class": self.comparison_class,
        }


_MATCHER_FAMILIES: tuple[dict[str, Any], ...] = (
    {
        "family": "exact",
        "pattern": "DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        "distribution": "uniform",
        "alignment": 1,
        "expected_strategy": "exact",
    },
    {
        "family": "selective_wildcard",
        "pattern": "?? ?? ?? ?? 8B 45 F8 48 85 C0 75 05 ?? ?? ?? ??",
        "distribution": "uniform",
        "alignment": 1,
        "expected_strategy": "anchor",
    },
    {
        "family": "alternating",
        "pattern": "48 ?? 8B ?? 00 ?? FF ?? 90 ?? CC ?? 75 ?? 89 ??",
        "distribution": "x86_skew",
        "alignment": 1,
        "expected_strategy": "anchor",
    },
    {
        "family": "sparse_rare",
        "pattern": "?? ?? A7 C3 ?? ?? E9 5D 71 ?? ?? B6 2F 84 ?? ??",
        "distribution": "x86_skew",
        "alignment": 1,
        "expected_strategy": "anchor",
    },
    {
        "family": "sparse_common",
        "pattern": "48 ?? ?? ?? 00 ?? ?? ?? 90 ?? ?? ?? FF ?? ?? ??",
        "distribution": "x86_skew",
        "alignment": 1,
        "expected_strategy": "regex",
    },
    {
        "family": "pointer",
        "pattern": "78 56 34 12 00 00 00 00",
        "distribution": "uniform",
        "alignment": 8,
        "expected_strategy": "exact",
    },
    {
        "family": "ascii",
        "pattern": "6D 65 6D 73 63 6F 70 65 2D 62 65 6E 63 68 21 21",
        "distribution": "uniform",
        "alignment": 1,
        "expected_strategy": "exact",
    },
    {
        "family": "utf16le",
        "pattern": "6D 00 65 00 6D 00 73 00 63 00 6F 00 70 00 65 00",
        "distribution": "uniform",
        "alignment": 2,
        "expected_strategy": "exact",
    },
)


def matcher_cases(tier: str) -> tuple[MatcherCase, ...]:
    if tier not in {"smoke", "headline"}:
        raise ValueError("tier must be 'smoke' or 'headline'")
    size = 512 * 1024 if tier == "smoke" else 64 * 1024 * 1024
    cases: list[MatcherCase] = []
    for index, definition in enumerate(_MATCHER_FAMILIES):
        alignment = int(definition["alignment"])
        injection = max(0, size - 4096 - 16)
        injection -= injection % alignment
        family = str(definition["family"])
        cases.append(
            MatcherCase(
                case_id=f"matcher.{family}.{tier}",
                tier=tier,
                family=family,
                pattern=str(definition["pattern"]),
                distribution=str(definition["distribution"]),
                buffer_size=size,
                seed=0x5C0FE000 + index,
                injection_offsets=(injection,),
                alignment=alignment,
                match_cap=100_000,
                expected_strategy=str(definition["expected_strategy"]),
            )
        )
    return tuple(cases)


def semantic_fingerprint(
    case: MatcherCase,
    *,
    corpus_checksum: str,
    expected_count: int,
    expected_checksum: str,
    expected_termination: str,
) -> str:
    return sha256_json(
        {
            "manifest_version": MANIFEST_VERSION,
            "corpus_version": CORPUS_VERSION,
            "case": case.as_dict(),
            "corpus_checksum": corpus_checksum,
            "expected_count": expected_count,
            "expected_checksum": expected_checksum,
            "expected_termination": expected_termination,
        }
    )


MIB = 1024 * 1024
KIB = 1024

_CHUNK_SWEEP_SIZES: tuple[tuple[str, int], ...] = (
    ("16k", 16 * KIB),
    ("32k", 32 * KIB),
    ("64k", 64 * KIB),
    ("128k", 128 * KIB),
    ("256k", 256 * KIB),
    ("512k", 512 * KIB),
    ("1m", 1 * MIB),
    ("2m", 2 * MIB),
    ("4m", 4 * MIB),
)


def _chunk_sweep_cases() -> tuple[BenchmarkCase, ...]:
    cases: list[BenchmarkCase] = []
    for label, chunk_size in _CHUNK_SWEEP_SIZES:
        shared = {
            "group": "Chunk sweep",
            "layer": "process",
            "comparison_class": "new_capability",
            "tier": "coverage",
            "headline": False,
            "process_timeout_s": 30.0,
        }
        cases.extend(
            (
                BenchmarkCase(
                    case_id=f"chunk.exact.nohit.{label}",
                    kind="chunk_sweep",
                    primary_metric="throughput",
                    distribution="uniform",
                    pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
                    mode="count",
                    size_bytes=64 * MIB,
                    max_matches=5000,
                    parameters={"chunk_size": chunk_size},
                    **shared,
                ),
                BenchmarkCase(
                    case_id=f"chunk.salvage.holes.{label}",
                    kind="chunk_salvage",
                    primary_metric="latency",
                    distribution="uniform",
                    pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
                    mode="count",
                    size_bytes=16 * MIB,
                    max_matches=5000,
                    parameters={"chunk_size": chunk_size},
                    **shared,
                ),
                BenchmarkCase(
                    case_id=f"chunk.timeout100.masked.{label}",
                    kind="chunk_timeout",
                    primary_metric="overshoot",
                    distribution="x86_skew",
                    pattern="48 ?? ?? ?? 00 ?? ?? ?? 90 ?? ?? ?? FF ?? ?? ??",
                    mode="count",
                    size_bytes=64 * MIB,
                    max_matches=100_000,
                    timeout_ms=100,
                    parameters={"chunk_size": chunk_size, "smoke_size_bytes": 64 * MIB},
                    **shared,
                ),
            )
        )
    return tuple(cases)


_CHUNK_SWEEP_CASES = _chunk_sweep_cases()

CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase(
        case_id="compile.exact16",
        group="Compile",
        layer="compile",
        kind="compile",
        comparison_class="apples_to_apples",
        primary_metric="latency",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        parameters={"iterations": 1000, "cold_unique_patterns": 512},
    ),
    BenchmarkCase(
        case_id="matcher.exact16.uniform",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="exact",
    ),
    BenchmarkCase(
        case_id="matcher.selective16.uniform",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="?? ?? ?? ?? 8B 45 F8 48 85 C0 75 05 ?? ?? ?? ??",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="anchor",
    ),
    BenchmarkCase(
        case_id="matcher.alternating16.skew",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="x86_skew",
        pattern="48 ?? 8B ?? 00 ?? FF ?? 90 ?? CC ?? 75 ?? 89 ??",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="regex",
    ),
    BenchmarkCase(
        case_id="matcher.sparse_rare16.skew",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="x86_skew",
        pattern="?? ?? A7 C3 ?? ?? E9 5D 71 ?? ?? B6 2F 84 ?? ??",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="anchor",
    ),
    BenchmarkCase(
        case_id="matcher.sparse_common16.skew",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="x86_skew",
        pattern="48 ?? ?? ?? 00 ?? ?? ?? 90 ?? ?? ?? FF ?? ?? ??",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="regex",
    ),
    BenchmarkCase(
        case_id="matcher.pointer8.uniform",
        group="Matcher CPU",
        layer="matcher",
        kind="pointer_matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="78 56 34 12 00 00 00 00",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="exact",
        parameters={"alignment": 8},
    ),
    BenchmarkCase(
        case_id="matcher.ascii16.uniform",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="6D 65 6D 73 63 6F 70 65 2D 62 65 6E 63 68 21 21",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="exact",
    ),
    BenchmarkCase(
        case_id="matcher.utf16le16.uniform",
        group="Matcher CPU",
        layer="matcher",
        kind="matcher",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="6D 00 65 00 6D 00 73 00 63 00 6F 00 70 00 65 00",
        size_bytes=64 * MIB,
        max_matches=100_000,
        expected_strategy="exact",
    ),
    BenchmarkCase(
        case_id="reader.ceiling.contiguous64m",
        group="Contiguous end-to-end",
        layer="reader",
        kind="reader_ceiling",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        size_bytes=64 * MIB,
        parameters={"chunk_size": 128 * KIB},
    ),
    *_CHUNK_SWEEP_CASES,
    BenchmarkCase(
        case_id="e2e.exact16.late.contiguous64m",
        group="Contiguous end-to-end",
        layer="process",
        kind="e2e",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        mode="count",
        size_bytes=64 * MIB,
        max_matches=5000,
        parameters={"injections": ["late"]},
    ),
    BenchmarkCase(
        case_id="e2e.selective16.late.contiguous64m",
        group="Contiguous end-to-end",
        layer="process",
        kind="e2e",
        comparison_class="apples_to_apples",
        primary_metric="throughput",
        distribution="uniform",
        pattern="8B 45 F8 48 85 C0 75 05 ?? ?? ?? ?? ?? ?? ?? ??",
        mode="count",
        size_bytes=64 * MIB,
        max_matches=5000,
        parameters={"injections": ["late"]},
    ),
    BenchmarkCase(
        case_id="e2e.fragmented.holes.exact",
        group="Fragmented end-to-end",
        layer="process",
        kind="fragmented",
        comparison_class="apples_to_apples",
        primary_metric="latency",
        distribution="uniform",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        mode="count",
        size_bytes=16 * MIB,
        max_matches=5000,
        parameters={"hole_every_pages": 16, "injections": ["early", "late"]},
    ),
    BenchmarkCase(
        case_id="e2e.boundary.split_protection.exact",
        group="Fragmented end-to-end",
        layer="process",
        kind="boundary",
        comparison_class="new_capability",
        primary_metric="invariant",
        distribution="uniform",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        mode="count",
        size_bytes=16 * MIB,
        max_matches=5000,
        parameters={
            "injections": ["split_boundary"],
            "historical_expected_failure": "no carry across adjacent readable regions",
        },
    ),
    BenchmarkCase(
        case_id="result.first.early.exact",
        group="Result latency",
        layer="process",
        kind="e2e",
        comparison_class="apples_to_apples",
        primary_metric="latency",
        distribution="uniform",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        mode="first",
        size_bytes=64 * MIB,
        parameters={"injections": ["early"]},
    ),
    BenchmarkCase(
        case_id="result.page50.dense",
        group="Result latency",
        layer="process",
        kind="e2e",
        comparison_class="apples_to_apples",
        primary_metric="latency",
        distribution="repeated_aa",
        pattern="AA",
        mode="addresses",
        size_bytes=8 * MIB,
        limit=50,
        max_matches=50,
    ),
    BenchmarkCase(
        case_id="dense.allwildcard.page100",
        group="Dense memory",
        layer="allocation",
        kind="allocation",
        comparison_class="apples_to_apples",
        primary_metric="allocation",
        distribution="zero",
        pattern="?? ?? ?? ?? ?? ?? ?? ??",
        mode="addresses",
        size_bytes=1 * MIB,
        limit=100,
        max_matches=100,
    ),
    BenchmarkCase(
        case_id="scope.writable_filter.excludes_half",
        group="Scope/filter",
        layer="process",
        kind="writable_filter",
        comparison_class="eliminated_work",
        primary_metric="read_reduction",
        distribution="uniform",
        pattern="DE AD BE EF 01 23 45 67 89 AB CD EF 10 32 54 76",
        mode="count",
        size_bytes=16 * MIB,
        max_matches=5000,
        parameters={"readonly_every_pages": 2, "injections": ["late"]},
    ),
    BenchmarkCase(
        case_id="scope.section.text.current_exe",
        group="Scope/filter",
        layer="process",
        kind="section_filter",
        comparison_class="eliminated_work",
        primary_metric="read_reduction",
        pattern="F1 E2 D3 C4 B5 A6 97 88 79 6A 5B 4C 3D 2E 1F 00",
        mode="count",
        max_matches=5000,
        parameters={"section": ".text"},
    ),
    BenchmarkCase(
        case_id="scope.section.text.current_exe.warm",
        group="Scope/filter",
        layer="process",
        kind="section_filter_warm",
        comparison_class="eliminated_work",
        primary_metric="latency",
        pattern="F1 E2 D3 C4 B5 A6 97 88 79 6A 5B 4C 3D 2E 1F 00",
        mode="count",
        max_matches=5000,
        parameters={"section": ".text"},
        setup_protocol={
            "untimed_operations": 1,
            "operation": "identical",
            "attachment": "same",
            "setup_excluded_from_timing": True,
            "historical_state": "shared_session",
            "candidate_state": "shared_section_cache_hot",
        },
    ),
    BenchmarkCase(
        case_id="cursor.pages10.limit50.dense",
        group="Cursor",
        layer="process",
        kind="cursor",
        comparison_class="eliminated_work",
        primary_metric="read_reduction",
        distribution="repeated_aa",
        pattern="AA",
        mode="addresses",
        size_bytes=1 * MIB,
        limit=50,
        max_matches=500,
        parameters={"pages": 10},
    ),
    BenchmarkCase(
        case_id="batch.count4.nohit",
        group="Batch",
        layer="process",
        kind="batch",
        comparison_class="eliminated_work",
        primary_metric="read_reduction",
        distribution="uniform",
        mode="count",
        size_bytes=64 * MIB,
        max_matches=5000,
        parameters={"patterns": 4},
    ),
    BenchmarkCase(
        case_id="batch.first16.early",
        group="Batch",
        layer="process",
        kind="batch",
        comparison_class="eliminated_work",
        primary_metric="latency",
        distribution="uniform",
        mode="first",
        size_bytes=32 * MIB,
        parameters={"patterns": 16, "inject_all": True},
    ),
    BenchmarkCase(
        case_id="control.timeout100.common_masked",
        group="Control",
        layer="process",
        kind="timeout",
        comparison_class="new_capability",
        primary_metric="overshoot",
        distribution="x86_skew",
        pattern="48 ?? ?? ?? 00 ?? ?? ?? 90 ?? ?? ?? FF ?? ?? ??",
        mode="count",
        size_bytes=64 * MIB,
        max_matches=100_000,
        timeout_ms=100,
        process_timeout_s=5.0,
        parameters={"smoke_size_bytes": 64 * MIB},
    ),
    BenchmarkCase(
        case_id="public.strict_unknown_field",
        group="Public adapters",
        layer="public",
        kind="strict_unknown",
        comparison_class="new_capability",
        primary_metric="invariant",
        pattern="AA",
    ),
)

CASE_BY_ID = {case.case_id: case for case in CASES}
if len(CASE_BY_ID) != len(CASES):
    raise RuntimeError("benchmark case IDs must be unique")


def is_candidate_only(case: BenchmarkCase) -> bool:
    return case.kind in _CANDIDATE_ONLY_KINDS


def uses_controlled_target(case: BenchmarkCase) -> bool:
    return case.kind in _CONTROLLED_TARGET_KINDS


def requires_exact_preflight(case: BenchmarkCase) -> bool:
    return bool(preflight_protocol(case.kind))


def select_cases(case_ids: list[str] | None = None, groups: list[str] | None = None) -> tuple[BenchmarkCase, ...]:
    selected = CASES
    if case_ids:
        unknown = sorted(set(case_ids) - CASE_BY_ID.keys())
        if unknown:
            raise ValueError(f"unknown benchmark case IDs: {', '.join(unknown)}")
        wanted = set(case_ids)
        selected = tuple(case for case in selected if case.case_id in wanted)
    if groups:
        wanted_groups = {group.casefold() for group in groups}
        selected = tuple(case for case in selected if case.group.casefold() in wanted_groups)
    return selected
