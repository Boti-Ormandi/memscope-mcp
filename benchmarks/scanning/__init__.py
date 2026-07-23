"""Reproducible scanning benchmark and evidence tooling."""

BENCHMARK_SCHEMA_VERSION = 2
COMPARISON_SCHEMA_VERSION = 3
CORPUS_VERSION = "scanning-corpus-v1"
MANIFEST_VERSION = "scanning-manifest-v5"
CANDIDATE_WATCHDOG_FLOOR_S = 30.0
HISTORICAL_EXACT_PREFLIGHT_TIMEOUT_S = 30.0
HISTORICAL_PREPARATION_ERROR_MARGIN_S = 5.0
PAIRING_PROTOCOL = {
    "algorithm": "sha256-case-block-v1",
    "seed_payload": "{case_id}:{block}",
    "labels": ["AB", "BA"],
}
DRIVER_PROTOCOL = {
    "module": "benchmarks.scanning.driver",
    "version": 3,
    "historical_phase_handshake": "jsonl-ready-stdin-run-timed-start-v2",
}
