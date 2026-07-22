"""Tests for strict scope normalization, region planning, and bounded reads."""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes
from dataclasses import dataclass
from types import SimpleNamespace

import pymem.exception
import pytest

from memscope_mcp.scanning.collectors import BoundedAddressCollector
from memscope_mcp.scanning.contract import (
    AllModulesScopeInput,
    ModulesScopeInput,
    RangeScopeInput,
    ScanFiltersInput,
)
from memscope_mcp.scanning.engine import execute_scan_plan
from memscope_mcp.scanning.lifecycle import ModuleSnapshot, ScanLease, build_module_records
from memscope_mcp.scanning.model import ScanControl, ScanStats, TerminationReason
from memscope_mcp.scanning.pattern import make_exact_query
from memscope_mcp.scanning.planner import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_GUARD,
    PAGE_NOACCESS,
    PAGE_NOCACHE,
    PAGE_READONLY,
    PAGE_READWRITE,
    PlannedSpan,
    RegionPlan,
    is_readable_committed,
    plan_scan_regions,
    protection_capabilities,
)
from memscope_mcp.scanning.reader import RegionReader
from memscope_mcp.scanning.scopes import (
    MemoryType,
    PermissionRequirement,
    ScopeKind,
    ScopeNormalizationError,
    normalize_scan_scope,
)


@dataclass(frozen=True)
class FakeMbi:
    BaseAddress: int
    RegionSize: int
    State: int
    Protect: int
    Type: int


def module(name: str, base: int, size: int) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        lpBaseOfDll=base,
        SizeOfImage=size,
        filename=rf"C:\Target\{name}",
    )


def make_lease(
    modules: list[SimpleNamespace] | None = None,
    *,
    generation: int = 1,
    process_handle: int = 1,
) -> ScanLease:
    snapshot = ModuleSnapshot.create(build_module_records(modules or []), generation=generation)
    return ScanLease(
        generation=generation,
        pid=123,
        process_handle=process_handle,
        target_process="Target.exe",
        modules=snapshot,
        lifecycle_cancel=threading.Event(),
    )


def make_query(regions: list[FakeMbi], *, fail_at: set[int] | None = None):
    failures = fail_at or set()

    def query(_handle: int, address: int) -> FakeMbi:
        if address in failures:
            raise OSError(f"query failed at 0x{address:X}")
        for region in regions:
            if region.BaseAddress <= address < region.BaseAddress + region.RegionSize:
                return region
        raise OSError(f"unmapped query at 0x{address:X}")

    return query


def make_plan(
    lease: ScanLease,
    spans: tuple[PlannedSpan, ...],
    *,
    read_gaps_detected: bool = False,
) -> RegionPlan:
    return RegionPlan(
        generation=lease.generation,
        module_fingerprint=lease.modules.fingerprint,
        scope_fingerprint=b"s" * 32,
        spans=spans,
        region_count=len(spans),
        virtual_query_calls=len(spans),
        planner_gap_count=int(read_gaps_detected),
        read_gaps_detected=read_gaps_detected,
        first_unplanned_address=spans[0].start if read_gaps_detected and spans else None,
    )


class TestScopeNormalization:
    def test_omitted_scope_selects_modules_in_stable_base_order(self):
        lease = make_lease(
            [
                module("later.dll", 0x4000, 0x1000),
                module("target.exe", 0x1000, 0x2000),
            ]
        )

        scope = normalize_scan_scope(None, lease)

        assert scope.kind is ScopeKind.ALL_MODULES
        assert [(item.start, item.end_exclusive, item.module.name) for item in scope.ranges] == [
            (0x1000, 0x3000, "target.exe"),
            (0x4000, 0x5000, "later.dll"),
        ]
        assert scope.generation == lease.generation
        assert scope.module_fingerprint == lease.modules.fingerprint
        assert len(scope.fingerprint) == 32

    def test_named_modules_resolve_case_insensitively_and_sort_by_base(self):
        lease = make_lease(
            [
                module("later.dll", 0x4000, 0x1000),
                module("target.exe", 0x1000, 0x2000),
            ]
        )
        scope = normalize_scan_scope(
            ModulesScopeInput(kind="modules", names=["LATER.DLL", r"C:\Elsewhere\TARGET.EXE"]),
            lease,
        )

        assert scope.kind is ScopeKind.MODULES
        assert [item.module.name for item in scope.ranges] == ["target.exe", "later.dll"]

    def test_missing_and_ambiguous_modules_fail_before_planning(self):
        lease = make_lease(
            [
                module("foo.dll", 0x1000, 0x100),
                module("FOO.DLL", 0x2000, 0x100),
            ]
        )

        with pytest.raises(ScopeNormalizationError) as missing:
            normalize_scan_scope(ModulesScopeInput(kind="modules", names=["missing.dll"]), lease)
        with pytest.raises(ScopeNormalizationError) as ambiguous:
            normalize_scan_scope(ModulesScopeInput(kind="modules", names=["foo.dll"]), lease)

        assert missing.value.error == "MODULE_NOT_FOUND"
        assert missing.value.hint is not None
        assert ambiguous.value.error == "AMBIGUOUS_MODULE"
        assert "0x1000" in ambiguous.value.detail and "0x2000" in ambiguous.value.detail

    def test_range_resolves_snapshot_addresses_and_exact_half_open_bounds(self):
        lease = make_lease([module("target.exe", 0x1000, 0x2000)])
        scope = normalize_scan_scope(
            RangeScopeInput(
                kind="range",
                start="target.exe+0x20",
                end_exclusive="0x1000+64",
            ),
            lease,
        )

        assert scope.kind is ScopeKind.RANGE
        assert (scope.ranges[0].start, scope.ranges[0].end_exclusive) == (0x1020, 0x1040)

    @pytest.mark.parametrize(
        ("start", "end_exclusive", "field"),
        [
            (0x1000, 0x1000, "scope.end_exclusive"),
            (0x2000, 0x1000, "scope.end_exclusive"),
            ("-1", "0x1000", "scope.start"),
            ("0x1000+0x10+0x20", "0x2000", "scope.start"),
        ],
    )
    def test_range_rejects_invalid_or_non_half_open_bounds(self, start, end_exclusive, field):
        lease = make_lease()

        with pytest.raises(ScopeNormalizationError) as captured:
            normalize_scan_scope(
                RangeScopeInput(kind="range", start=start, end_exclusive=end_exclusive),
                lease,
            )

        assert captured.value.error == "INVALID_SCOPE"
        assert captured.value.field == field

    def test_filters_normalize_to_immutable_enum_values(self):
        lease = make_lease([module("target.exe", 0x1000, 0x1000)])
        scope = normalize_scan_scope(
            AllModulesScopeInput(
                kind="all_modules",
                filters=ScanFiltersInput(
                    memory_types=["image", "private"],
                    executable="required",
                    writable="forbidden",
                ),
            ),
            lease,
        )

        assert scope.filters.memory_types == frozenset({MemoryType.IMAGE, MemoryType.PRIVATE})
        assert scope.filters.executable is PermissionRequirement.REQUIRED
        assert scope.filters.writable is PermissionRequirement.FORBIDDEN


class TestRegionPlanner:
    def test_planner_clips_regions_and_excludes_known_unreadable_pages_without_gap_status(self):
        lease = make_lease([module("target.exe", 0x1000, 0x3000)])
        scope = normalize_scan_scope(None, lease)
        regions = [
            FakeMbi(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_IMAGE),
            FakeMbi(0x2000, 0x1000, MEM_COMMIT, PAGE_NOACCESS, MEM_IMAGE),
            FakeMbi(0x3000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE),
        ]

        plan = plan_scan_regions(lease, scope, query_memory=make_query(regions))

        assert [(span.start, span.end_exclusive) for span in plan.spans] == [
            (0x1000, 0x2000),
            (0x3000, 0x4000),
        ]
        assert plan.region_count == 3
        assert plan.virtual_query_calls == 3
        assert plan.read_gaps_detected is False

    def test_module_scope_defaults_to_image_pages_while_range_allows_private_pages(self):
        lease = make_lease([module("target.exe", 0x1000, 0x2000)])
        regions = [
            FakeMbi(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_IMAGE),
            FakeMbi(0x2000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        ]

        module_plan = plan_scan_regions(
            lease,
            normalize_scan_scope(None, lease),
            query_memory=make_query(regions),
        )
        range_plan = plan_scan_regions(
            lease,
            normalize_scan_scope(
                RangeScopeInput(kind="range", start=0x1000, end_exclusive=0x3000),
                lease,
            ),
            query_memory=make_query(regions),
        )

        assert [(span.start, span.end_exclusive) for span in module_plan.spans] == [(0x1000, 0x2000)]
        assert [(span.start, span.end_exclusive) for span in range_plan.spans] == [
            (0x1000, 0x2000),
            (0x2000, 0x3000),
        ]

    def test_planner_applies_type_and_tri_state_permission_filters(self):
        lease = make_lease([module("target.exe", 0x1000, 0x4000)])
        scope = normalize_scan_scope(
            AllModulesScopeInput(
                kind="all_modules",
                filters=ScanFiltersInput(
                    memory_types=["image", "mapped"],
                    executable="required",
                    writable="forbidden",
                ),
            ),
            lease,
        )
        regions = [
            FakeMbi(0x1000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ | PAGE_NOCACHE, MEM_IMAGE),
            FakeMbi(0x2000, 0x1000, MEM_COMMIT, PAGE_EXECUTE, MEM_IMAGE),
            FakeMbi(0x3000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE),
            FakeMbi(0x4000, 0x1000, MEM_COMMIT, PAGE_READONLY, MEM_MAPPED),
        ]

        plan = plan_scan_regions(lease, scope, query_memory=make_query(regions))

        assert [(span.start, span.end_exclusive) for span in plan.spans] == [(0x1000, 0x2000)]

    def test_query_failure_is_sticky_and_later_module_ranges_still_plan(self):
        lease = make_lease(
            [
                module("first.dll", 0x1000, 0x1000),
                module("second.dll", 0x4000, 0x1000),
            ]
        )
        scope = normalize_scan_scope(None, lease)
        regions = [
            FakeMbi(0x1000, 0x800, MEM_COMMIT, PAGE_READWRITE, MEM_IMAGE),
            FakeMbi(0x4000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_IMAGE),
        ]

        plan = plan_scan_regions(
            lease,
            scope,
            query_memory=make_query(regions, fail_at={0x1800}),
        )

        assert [(span.start, span.end_exclusive) for span in plan.spans] == [
            (0x1000, 0x1800),
            (0x4000, 0x5000),
        ]
        assert plan.read_gaps_detected is True
        assert plan.planner_gap_count == 1
        assert plan.first_unplanned_address == 0x1800

    def test_pymem_virtual_query_failure_is_recorded_as_a_gap(self):
        lease = make_lease([module("target.exe", 0x1000, 0x1000)])
        scope = normalize_scan_scope(None, lease)

        def fail_query(_handle: int, _address: int):
            raise pymem.exception.WinAPIError(5)

        plan = plan_scan_regions(lease, scope, query_memory=fail_query)

        assert plan.spans == ()
        assert plan.read_gaps_detected is True
        assert plan.planner_gap_count == 1
        assert plan.first_unplanned_address == 0x1000

    def test_malformed_virtual_query_metadata_is_not_downgraded_to_a_gap(self):
        lease = make_lease([module("target.exe", 0x1000, 0x1000)])
        scope = normalize_scan_scope(None, lease)

        def malformed_query(_handle: int, _address: int):
            return SimpleNamespace(
                BaseAddress=0x1000,
                RegionSize=0x1000,
                State="committed",
                Protect=PAGE_READWRITE,
                Type=MEM_IMAGE,
            )

        with pytest.raises(TypeError, match=r"MEMORY_BASIC_INFORMATION\.State must be an integer"):
            plan_scan_regions(lease, scope, query_memory=malformed_query)

    def test_range_spans_are_split_for_stable_module_annotation(self):
        lease = make_lease([module("target.dll", 0x2000, 0x100)])
        scope = normalize_scan_scope(
            RangeScopeInput(kind="range", start=0x1F00, end_exclusive=0x2200),
            lease,
        )
        regions = [FakeMbi(0x1F00, 0x300, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE)]

        plan = plan_scan_regions(lease, scope, query_memory=make_query(regions))

        assert [
            (span.start, span.end_exclusive, None if span.module is None else span.module.name) for span in plan.spans
        ] == [
            (0x1F00, 0x2000, None),
            (0x2000, 0x2100, "target.dll"),
            (0x2100, 0x2200, None),
        ]

    def test_protection_semantics_reject_guard_noaccess_and_execute_only(self):
        assert is_readable_committed(MEM_COMMIT, PAGE_READONLY)
        assert is_readable_committed(MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE)
        assert not is_readable_committed(MEM_COMMIT, PAGE_NOACCESS)
        assert not is_readable_committed(MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD)
        assert not is_readable_committed(MEM_COMMIT, PAGE_EXECUTE)
        assert protection_capabilities(PAGE_EXECUTE_READ).executable is True
        assert protection_capabilities(PAGE_EXECUTE_READ).writable is False

    def test_planner_stops_cleanly_when_control_is_already_cancelled(self):
        lease = make_lease([module("target.exe", 0x1000, 0x1000)])
        scope = normalize_scan_scope(None, lease)

        plan = plan_scan_regions(
            lease,
            scope,
            query_memory=lambda *_args: pytest.fail("VirtualQueryEx should not run"),
            control=ScanControl(cancel_checks=(lambda: True,)),
        )

        assert plan.spans == ()
        assert plan.termination_reason is TerminationReason.CANCELLED

    def test_planner_binds_lifecycle_target_change_before_virtual_query(self):
        lease = make_lease([module("target.exe", 0x1000, 0x1000)])
        lease.lifecycle_cancel.set()
        scope = normalize_scan_scope(None, lease)

        plan = plan_scan_regions(
            lease,
            scope,
            query_memory=lambda *_args: pytest.fail("VirtualQueryEx should not run"),
        )

        assert plan.spans == ()
        assert plan.termination_reason is TerminationReason.TARGET_CHANGED

    def test_query_failure_repolls_lifecycle_before_recording_a_gap(self):
        lease = make_lease([module("target.exe", 0x1000, 0x1000)])
        scope = normalize_scan_scope(None, lease)

        def query_then_retire(_handle: int, _address: int):
            lease.lifecycle_cancel.set()
            raise OSError("target retired during query")

        plan = plan_scan_regions(lease, scope, query_memory=query_then_retire)

        assert plan.spans == ()
        assert plan.termination_reason is TerminationReason.TARGET_CHANGED
        assert plan.read_gaps_detected is False
        assert plan.planner_gap_count == 0


class TestRegionReaderAndWindows:
    def test_reader_never_crosses_planned_span_or_chunk_boundaries(self):
        lease = make_lease()
        spans = (
            PlannedSpan(0x1000, 0x1800, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None),
            PlannedSpan(0x2000, 0x2800, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None),
        )
        plan = make_plan(lease, spans)
        calls: list[tuple[int, int]] = []

        def read(_handle: int, address: int, size: int) -> bytes:
            calls.append((address, size))
            return b"A" * size

        reader = RegionReader(
            lease,
            plan,
            ScanStats(),
            read_memory=read,
            target_alive=lambda _handle: True,
            chunk_size=0x400,
        )

        fragments = list(reader)

        assert calls == [
            (0x1000, 0x400),
            (0x1400, 0x400),
            (0x2000, 0x400),
            (0x2400, 0x400),
        ]
        assert [(item.start, item.end_exclusive) for item in fragments] == [
            (0x1000, 0x1400),
            (0x1400, 0x1800),
            (0x2000, 0x2400),
            (0x2400, 0x2800),
        ]

    def test_failed_middle_page_salvages_both_sides_with_bounded_calls(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x4000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        stats = ScanStats()

        def read(_handle: int, address: int, size: int) -> bytes:
            if address < 0x3000 and address + size > 0x2000:
                raise OSError("middle page is unreadable")
            return bytes((address // 0x1000,)) * size

        reader = RegionReader(
            lease,
            plan,
            stats,
            read_memory=read,
            target_alive=lambda _handle: True,
            chunk_size=0x3000,
            page_size=0x1000,
        )

        fragments = list(reader)

        assert [(item.start, item.end_exclusive) for item in fragments] == [
            (0x1000, 0x2000),
            (0x3000, 0x4000),
        ]
        assert reader.read_gaps_detected is True
        assert stats.read_gap_count == 1
        assert stats.failed_read_bytes == 0x1000
        assert stats.physical_read_calls == 5
        assert stats.physical_bytes_requested == 0x8000
        assert stats.physical_bytes_read == 0x2000
        assert stats.unique_bytes_read == 0x2000
        assert stats.failed_read_spans == [(0x2000, 0x3000)]

    def test_unaligned_failed_read_salvages_each_physical_page_fragment(self):
        lease = make_lease()
        span = PlannedSpan(0x1800, 0x2800, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        stats = ScanStats()

        def read(_handle: int, address: int, size: int) -> bytes:
            if address < 0x2800 and address + size > 0x2000:
                raise OSError("second page is unreadable")
            return b"L" * size

        reader = RegionReader(
            lease,
            plan,
            stats,
            read_memory=read,
            target_alive=lambda _handle: True,
            chunk_size=0x1000,
            page_size=0x1000,
        )

        fragments = list(reader)

        assert [(item.start, item.end_exclusive) for item in fragments] == [(0x1800, 0x2000)]
        assert reader.read_gaps_detected is True
        assert stats.read_gap_count == 1
        assert stats.failed_read_bytes == 0x800
        assert stats.failed_read_spans == [(0x2000, 0x2800)]
        assert stats.unique_bytes_read == 0x800
        assert stats.physical_read_calls == 3

    def test_target_death_short_circuits_salvage(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x3000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        stats = ScanStats()

        reader = RegionReader(
            lease,
            plan,
            stats,
            read_memory=lambda *_args: (_ for _ in ()).throw(OSError("dead")),
            target_alive=lambda _handle: False,
            chunk_size=0x2000,
        )

        assert list(reader) == []
        assert reader.termination_reason is TerminationReason.TARGET_CHANGED
        assert reader.read_gaps_detected is False
        assert stats.physical_read_calls == 1

    def test_liveness_probe_failure_is_reader_error_not_target_change(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x3000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))

        reader = RegionReader(
            lease,
            plan,
            ScanStats(),
            read_memory=lambda *_args: (_ for _ in ()).throw(OSError("read failed")),
            target_alive=lambda _handle: (_ for _ in ()).throw(OSError("probe failed")),
            chunk_size=0x2000,
        )

        assert list(reader) == []
        assert reader.termination_reason is TerminationReason.READER_ERROR
        assert reader.read_gaps_detected is False

    def test_internal_read_failure_is_not_downgraded_to_an_unreadable_gap(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x2000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))

        reader = RegionReader(
            lease,
            plan,
            ScanStats(),
            read_memory=lambda *_args: (_ for _ in ()).throw(TypeError("internal reader defect")),
            target_alive=lambda _handle: True,
            chunk_size=0x1000,
        )

        with pytest.raises(TypeError, match="internal reader defect"):
            list(reader)

    def test_overlap_stream_finds_long_pattern_across_small_chunks(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x1009, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        memory = b"xxABCDEyy"

        result = execute_scan_plan(
            make_exact_query(b"ABCDE"),
            lease,
            plan,
            BoundedAddressCollector(10),
            read_memory=lambda _handle, address, size: memory[address - 0x1000 : address - 0x1000 + size],
            target_alive=lambda _handle: True,
            chunk_size=3,
            page_size=2,
        )

        assert [hit.address for hit in result.hits] == [0x1002]
        assert result.termination_reason is TerminationReason.SCOPE_EXHAUSTED
        assert result.stats.logical_read_chunks == 3

    def test_contiguous_planned_spans_share_tail_without_duplicate_hits(self):
        lease = make_lease()
        spans = (
            PlannedSpan(0x1000, 0x1003, MEM_COMMIT, PAGE_READONLY, MEM_PRIVATE, None),
            PlannedSpan(0x1003, 0x1008, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE, None),
        )
        plan = make_plan(lease, spans)
        memory = b"xxABCDEy"

        result = execute_scan_plan(
            make_exact_query(b"ABCDE"),
            lease,
            plan,
            BoundedAddressCollector(10),
            read_memory=lambda _handle, address, size: memory[address - 0x1000 : address - 0x1000 + size],
            target_alive=lambda _handle: True,
            chunk_size=0x100,
        )

        assert [hit.address for hit in result.hits] == [0x1002]
        assert result.stats.candidate_count == 1

    def test_failed_gap_clears_tail_and_preserves_later_complete_match(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x100C, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        memory = b"xxAB----ABCD"

        def read(_handle: int, address: int, size: int) -> bytes:
            if address < 0x1008 and address + size > 0x1004:
                raise OSError("middle page unavailable")
            return memory[address - 0x1000 : address - 0x1000 + size]

        result = execute_scan_plan(
            make_exact_query(b"ABCD"),
            lease,
            plan,
            BoundedAddressCollector(10),
            read_memory=read,
            target_alive=lambda _handle: True,
            chunk_size=0xC,
            page_size=4,
        )

        assert [hit.address for hit in result.hits] == [0x1008]
        assert result.read_gaps_detected is True
        assert result.stats.read_gap_count == 1

    def test_aligned_pointer_match_can_cross_chunk_boundary(self):
        lease = make_lease()
        span = PlannedSpan(0x2000, 0x200C, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        pointer = bytes.fromhex("8877665544332211")
        memory = pointer + b"tail"

        result = execute_scan_plan(
            make_exact_query(pointer, alignment=8),
            lease,
            plan,
            BoundedAddressCollector(10),
            read_memory=lambda _handle, address, size: memory[address - 0x2000 : address - 0x2000 + size],
            target_alive=lambda _handle: True,
            chunk_size=4,
            page_size=2,
        )

        assert [hit.address for hit in result.hits] == [0x2000]

    def test_cross_module_match_is_annotated_by_candidate_start(self):
        lease = make_lease(
            [
                module("first.dll", 0x3000, 4),
                module("second.dll", 0x3004, 4),
            ]
        )
        spans = (
            PlannedSpan(0x3000, 0x3004, MEM_COMMIT, PAGE_READONLY, MEM_IMAGE, lease.modules.ordered_by_base[0]),
            PlannedSpan(0x3004, 0x3008, MEM_COMMIT, PAGE_READONLY, MEM_IMAGE, lease.modules.ordered_by_base[1]),
        )
        plan = make_plan(lease, spans)
        memory = b"ABCDEFGH"

        result = execute_scan_plan(
            make_exact_query(memory),
            lease,
            plan,
            BoundedAddressCollector(10),
            read_memory=lambda _handle, address, size: memory[address - 0x3000 : address - 0x3000 + size],
            target_alive=lambda _handle: True,
            chunk_size=4,
            page_size=2,
        )

        assert [(hit.address, hit.module_name, hit.module_base) for hit in result.hits] == [
            (0x3000, "first.dll", 0x3000)
        ]

    def test_lifecycle_cancellation_is_distinct_from_request_cancellation(self):
        lease = make_lease()
        span = PlannedSpan(0x1000, 0x2000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, None)
        plan = make_plan(lease, (span,))
        lease.lifecycle_cancel.set()

        changed = execute_scan_plan(
            make_exact_query(b"A"),
            lease,
            plan,
            BoundedAddressCollector(10),
            read_memory=lambda *_args: pytest.fail("read should not run"),
        )
        cancel_lease = make_lease()
        cancelled = execute_scan_plan(
            make_exact_query(b"A"),
            cancel_lease,
            make_plan(cancel_lease, (span,)),
            BoundedAddressCollector(10),
            control=ScanControl(cancel_checks=(lambda: True,)),
            read_memory=lambda *_args: pytest.fail("read should not run"),
        )

        assert changed.termination_reason is TerminationReason.TARGET_CHANGED
        assert cancelled.termination_reason is TerminationReason.CANCELLED


class TestControlledWin32Reader:
    def test_known_noaccess_hole_is_excluded_before_reads(self):
        with allocated_pages(3) as allocation:
            base, page_size, handle = allocation
            ctypes.memmove(base + 2 * page_size + 32, b"RIGHT", 5)
            old = protect(base + page_size, page_size, PAGE_NOACCESS)
            try:
                lease = make_lease(process_handle=handle)
                scope = normalize_scan_scope(
                    RangeScopeInput(kind="range", start=base, end_exclusive=base + 3 * page_size),
                    lease,
                )
                plan = plan_scan_regions(lease, scope)
                result = execute_scan_plan(
                    make_exact_query(b"RIGHT"),
                    lease,
                    plan,
                    BoundedAddressCollector(10),
                    chunk_size=3 * page_size,
                    page_size=page_size,
                )

                assert [(span.start, span.end_exclusive) for span in plan.spans] == [
                    (base, base + page_size),
                    (base + 2 * page_size, base + 3 * page_size),
                ]
                assert [hit.address for hit in result.hits] == [base + 2 * page_size + 32]
                assert result.read_gaps_detected is False
            finally:
                protect(base + page_size, page_size, old)

    def test_protection_change_after_planning_is_salvaged_and_marked(self):
        with allocated_pages(3) as allocation:
            base, page_size, handle = allocation
            ctypes.memmove(base + 2 * page_size + 64, b"AFTER", 5)
            lease = make_lease(process_handle=handle)
            scope = normalize_scan_scope(
                RangeScopeInput(kind="range", start=base, end_exclusive=base + 3 * page_size),
                lease,
            )
            plan = plan_scan_regions(lease, scope)
            old = protect(base + page_size, page_size, PAGE_NOACCESS)
            try:
                result = execute_scan_plan(
                    make_exact_query(b"AFTER"),
                    lease,
                    plan,
                    BoundedAddressCollector(10),
                    chunk_size=3 * page_size,
                    page_size=page_size,
                )

                assert [hit.address for hit in result.hits] == [base + 2 * page_size + 64]
                assert result.read_gaps_detected is True
                assert result.stats.read_gap_count == 1
                assert result.stats.failed_read_bytes == page_size
            finally:
                protect(base + page_size, page_size, old)


class allocated_pages:
    def __init__(self, count: int) -> None:
        self.count = count
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.page_size = _system_page_size(self.kernel32)
        self.size = self.count * self.page_size
        self.base = 0
        self.handle = 0

    def __enter__(self) -> tuple[int, int, int]:
        self.kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        self.kernel32.VirtualAlloc.restype = wintypes.LPVOID
        self.kernel32.VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
        self.kernel32.VirtualFree.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

        pointer = self.kernel32.VirtualAlloc(None, self.size, 0x1000 | 0x2000, PAGE_READWRITE)
        if not pointer:
            raise OSError(ctypes.get_last_error(), "VirtualAlloc failed")
        self.base = int(pointer)
        ctypes.memset(self.base, 0, self.size)

        handle = self.kernel32.OpenProcess(0x0400 | 0x0010, False, os.getpid())
        if not handle:
            self.kernel32.VirtualFree(self.base, 0, 0x8000)
            raise OSError(ctypes.get_last_error(), "OpenProcess failed")
        self.handle = int(handle)
        return self.base, self.page_size, self.handle

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
        if self.base:
            self.kernel32.VirtualFree(self.base, 0, 0x8000)


def protect(address: int, size: int, protection: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualProtect.argtypes = [
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.VirtualProtect.restype = wintypes.BOOL
    old = wintypes.DWORD()
    if not kernel32.VirtualProtect(address, size, protection, ctypes.byref(old)):
        raise OSError(ctypes.get_last_error(), "VirtualProtect failed")
    return old.value


def _system_page_size(kernel32) -> int:
    class SystemInfo(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", wintypes.WORD),
            ("wReserved", wintypes.WORD),
            ("dwPageSize", wintypes.DWORD),
            ("lpMinimumApplicationAddress", wintypes.LPVOID),
            ("lpMaximumApplicationAddress", wintypes.LPVOID),
            ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
            ("dwNumberOfProcessors", wintypes.DWORD),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD),
        ]

    info = SystemInfo()
    kernel32.GetSystemInfo(ctypes.byref(info))
    return int(info.dwPageSize)
