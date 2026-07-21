"""Deterministic evidence-runner tests for scanning engine and public adapters."""

from __future__ import annotations

from pathlib import Path

from benchmarks.scanning.common import read_raw_artifact, validate_raw_artifact, write_raw_artifact
from benchmarks.scanning.engine import run_engine_suite
from benchmarks.scanning.public_api import run_public_api_suite

ROOT = Path(__file__).parents[1]


def test_engine_evidence_records_exact_cursor_batch_and_control_invariants(tmp_path):
    artifact = run_engine_suite(
        repo_root=ROOT,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
    )

    validate_raw_artifact(artifact)
    by_id = {case["case_id"]: case for case in artifact["cases"]}

    cursor = by_id["cursor.pages10.limit50.no_earlier_work"]["observations"][0]["work"]
    assert cursor["candidate_counts"] == [50] * 10
    assert cursor["matches"] == 500
    assert cursor["logical_bytes_before_resume"] == 0
    assert cursor["post_limit_candidate_work"] == 0
    assert cursor["lease_released"] is True

    safety = by_id["cursor.safety.stale_gap_cap"]["observations"][0]["work"]
    assert safety["cumulative_sequence_returned_count"] == 3
    assert safety["cumulative_termination"] == "match_limit"
    assert safety["cumulative_next_cursor"] is None
    assert safety["cumulative_candidate_count"] == 1
    assert safety["sticky_gap_status"] is True
    assert safety["sticky_gap_cursor_state"] is True
    assert safety["stale_error"] == "CURSOR_STALE"
    assert safety["stale_physical_read_calls"] == 0
    assert safety["all_leases_released"] is True

    first = by_id["batch.first16.one_pass"]["observations"][0]["work"]
    assert first["batch_values"] == first["independent_values"]
    assert first["region_passes"] == 1
    assert first["batch_statuses"] == first["independent_statuses"]
    assert set(first["batch_statuses"].values()) == {"first_hit"}
    assert first["batch_physical_bytes_read"] < first["separate_physical_bytes_read"]

    count = by_id["batch.count4.one_pass"]["observations"][0]["work"]
    assert count["batch_values"] == count["independent_values"]
    assert count["batch_statuses"] == count["independent_statuses"]
    assert set(count["batch_statuses"].values()) == {"scope_exhausted"}
    assert count["batch_physical_bytes_read"] * 4 == count["separate_physical_bytes_read"]

    capped = by_id["batch.count2.independent_caps"]["observations"][0]["work"]
    assert capped["batch_values"] == {"single": 2, "triple": 2}
    assert capped["batch_values"] == capped["independent_values"]
    assert capped["batch_statuses"] == {"single": "match_limit", "triple": "match_limit"}
    assert capped["batch_statuses"] == capped["independent_statuses"]
    assert capped["shared_termination"] == "match_limit"
    assert capped["batch_physical_bytes_read"] * 2 == capped["separate_physical_bytes_read"]

    deadline = by_id["control.injected_deadline"]["observations"][0]["work"]
    assert deadline["termination"] == "timeout"
    assert deadline["logical_tick_overshoot"] == 1
    assert deadline["lease_released"] is True

    cancelled = by_id["control.in_band_cancellation"]["observations"][0]["work"]
    assert cancelled["physical_read_calls"] == 0
    assert cancelled["next_cursor"] is None

    changed = by_id["control.target_change"]["observations"][0]["work"]
    assert changed["error"] == "TARGET_CHANGED"
    assert changed["physical_read_calls"] == 0

    responsive = by_id["control.async_responsiveness"]["observations"][0]["work"]
    assert responsive["unrelated_progress"] is True
    assert responsive["scan_completed_after_progress"] is True

    cleanup = by_id["control.task_cancellation_cleanup"]["observations"][0]["work"]
    assert cleanup["cancelled_error_propagated"] is True
    assert cleanup["worker_cleanup_precedes_propagation"] is True
    assert cleanup["lease_released"] is True

    output = tmp_path / "engine-evidence.json"
    write_raw_artifact(output, artifact)
    assert read_raw_artifact(output) == artifact


def test_public_evidence_records_strict_fastmcp_lua_formatting_and_clean_break(tmp_path):
    artifact = run_public_api_suite(
        repo_root=ROOT,
        profile="smoke",
        warmups=0,
        repetitions=1,
        implementation_label="test-candidate",
    )

    validate_raw_artifact(artifact)
    by_id = {case["case_id"]: case for case in artifact["cases"]}

    fastmcp = by_id["public.fastmcp.strict_flat_contract"]["observations"][0]["work"]
    assert fastmcp["unknown_rejected_before_handler"] is True
    assert fastmcp["handler_calls"] == 3
    assert fastmcp["flat_structured_union"] is True
    assert fastmcp["modes"] == ["addresses", "first", "count"]

    formatting = by_id["public.output.formatting_sizes"]["observations"][0]["work"]
    sizes = formatting["serialized_bytes"]
    assert sizes["addresses_1"] < sizes["addresses_100"] < sizes["addresses_500"]
    assert formatting["count_5000_is_summary_only"] is True

    lua = by_id["public.lua.normalization_and_formatting"]["observations"][0]["work"]
    assert lua["batch_keys"] == ["aob", "ascii"]
    assert lua["unknown_error"]["field"] == "options.legacy"
    assert lua["lease_released"] is True

    serialized = by_id["public.lua.serialized_runtime"]["observations"][0]["work"]
    assert serialized["execution_lock_observed"] is True
    assert serialized["maximum_active_callbacks"] == 1
    assert serialized["entry_order"] == ["block", "mark"]

    clean_break = by_id["public.clean_break.audit"]["observations"][0]["work"]
    assert clean_break["surviving_removed_terms"] == []
    assert all(clean_break["removed_paths"].values())
    assert all(clean_break["registered_scan_helpers"].values())
    assert clean_break["instructions_named_only"] is True

    output = tmp_path / "public-evidence.json"
    write_raw_artifact(output, artifact)
    assert read_raw_artifact(output) == artifact
