# Scanning benchmarks

This directory contains deterministic benchmark inputs and machine-readable raw evidence for the scanning engine. Benchmark code is repository tooling and is not part of the installed package.

## Compilation and matcher evidence

The paired manifest includes `compile.exact16`, which measures repeated compilation of one exact pattern after ten warmups. Manifest v5 also records a separate untimed-from-primary cold-unique submeasurement over 512 distinct exact patterns, exceeding the production compiler's bounded cache capacity. Reports therefore show the repeated-query path without concealing cache-miss cost in the raw observation metrics.

The matcher suite covers exact, selective wildcard, alternating, sparse rare, sparse common, pointer-aligned, ASCII, and UTF-16LE query shapes. Each case has a stable ID, deterministic corpus, semantic fingerprint, independently derived expected result, raw observations, and operation counters.

Run the quick validation profile, which scales declared matcher cases down to at most 4 MiB each:

```powershell
python -m benchmarks.scanning.matcher --profile smoke --output benchmark-results/matcher-smoke.json
```

Run the fixed 64 MiB matcher matrix used for release evidence:

```powershell
python -m benchmarks.scanning.matcher --profile release --warmups 3 --repetitions 10 --output benchmark-results/matcher-release.json
```

## Controlled-process evidence

The process runner launches a child Python process, allocates and touches deterministic Win32 memory, publishes versioned topology metadata, and attaches through the production `DebugSession` and `ScanExecutor` path. Benchmark schema 2 records preflight, setup, and timed operations separately. Historical and candidate process cases with deterministic completion expectations first perform an untimed exact-address preflight with ordered absolute and target-relative addresses plus full SHA-256 checksums; timeout-control timing remains termination-based and count-mode timing remains unchanged. Each operation records a run ID, process ID, attachment generation, module fingerprint, target-identity fingerprint, phase and, where applicable, a cache token. Candidate process evidence also records the manifest-bound effective outer-watchdog deadline, whether an outer watchdog was actually enforced, and the enforcing context. Standalone process runs record `standalone_diagnostic_no_outer_watchdog` and never claim a false process watchdog. Read instrumentation retains every call's address, requested size, returned size, success state, aggregate byte counts, exact ranges, failed calls, and unique logical union. Raw `ReadProcessMemory` ceiling measurements remain separate from end-to-end scanning.

Run a focused smoke pass:

```powershell
python -m benchmarks.scanning.process_scan --profile smoke --warmups 0 --repetitions 1 --case-id reader.ceiling.contiguous64m --case-id e2e.exact16.late.contiguous64m --output benchmark-results/process-smoke.json
```

Run all controlled-process cases against the checked-out implementation:

```powershell
python -m benchmarks.scanning.process_scan --profile release --warmups 2 --repetitions 7 --output benchmark-results/process-release.json
```

The controlled matrix covers contiguous and fragmented ranges, a match crossing a chunk/protection boundary, post-plan protection changes and page-aligned read salvage, dense/first/page/count collectors, writable and PE-section filters, peak Python allocation, and chunk sizes from 16 KiB through 4 MiB. The child protocol also exposes deterministic protection-change and target-exit controls for lifecycle tests.

The warm PE-section case has a manifest-bound setup protocol. After an isolated correctness preflight and any generic runner warmups, it performs exactly one untimed identical scan on the same attachment. Candidate setup and measurement share one dedicated `SectionCache`, while every operation has fresh I/O instrumentation and setup work is excluded from the timed observation. Raw metrics retain the setup read counts, byte counts, read sizes, selected sections, and timed read work. The comparator blocks the row unless the candidate setup performs cold metadata reads and the timed operation performs only the selected-section corpus read. Manifest-v4 warm observations did not preserve the cache across setup and measurement and are superseded for warm-cache and complete-bundle claims.

The current production reader chunk is 256 KiB. A fresh production recommendation requires the exact manifest-v5 27-case throughput/salvage/timeout matrix in canonical order, the release profile, at least one warmup, at least three repetitions, correct validated observations, and enforced candidate timeout watchdogs. The policy chooses the smallest chunk within 10% of the best end-to-end median only when it preserves the provisional 128 KiB baseline's salvage p95 and timeout-overshoot p95 within the declared tolerance. Any subset, smoke run, low-sample run, or standalone no-watchdog run remains diagnostic, records no production `selected_chunk_size`, and may expose only a separate diagnostic selection.

Use `--case-id <id>` repeatedly to select specific cases. Generated artifacts live under `benchmark-results/`, which is ignored by Git.

Correctness and expected strategy checks are performed before an artifact is accepted. Schema-2 validation resolves every case ID against the current suite manifest, enforces canonical order and profile, reconstructs canonical manifest/corpus/expected records, recomputes semantic fingerprints, derives observation correctness and statistics from observations, and recomputes any chunk recommendation. Rehashing a forged record or serialized summary does not make it canonical. Raw artifacts are not historical comparisons or publication claims by themselves; paired baseline execution and generated publication reports are separate benchmark surfaces.

## Paired historical comparison

The paired runner compares the frozen historical implementation with the current checkout in deterministic SHA-256-derived AB/BA blocks. Historical and candidate observations run in separate subprocesses. Every historical case completes imports, setup, warmups, and deterministic validation before it flushes a ready record and waits for an explicit parent command. Exact process cases additionally preserve their ordered-address preflight and optional warm setup evidence. After authorization, the child flushes a second timed-start proof immediately before returning to the timed statement. The parent starts the manifest watchdog only after validating both proofs. A timed-phase expiry therefore preserves available correctness and provenance evidence and attributes the lower bound only to timed work; an import/setup failure, missing or invalid proof, or process expiry before timed-start validation is a blocking driver error, never censorship. The historical source is mounted through a benchmark-owned detached worktree with an ownership record; cleanup refuses dirty, moved, or commit-mismatched worktrees. Recovery recreates the bounded ownership root after removing the last stale run so the next comparison can allocate its worktree safely.

Quick diagnostic bundle:

```powershell
python -m benchmarks.scanning.run --before-ref c534fbd --profile smoke --blocks 1 --output benchmark-results/scanning-smoke
```

Clean release bundle:

```powershell
python -m benchmarks.scanning.run --before-ref c534fbd --profile release --output benchmark-results/scanning-release
```

Use `--case <case_id>` or `--group <group>` repeatedly for partial diagnostics. `--before-root` accepts an already materialized historical tree when worktree creation is intentionally managed elsewhere. Release-profile evidence rejects a dirty candidate tree unless `--allow-dirty-release` is supplied for diagnostics.

The bundle contains raw artifacts for both sides, JSON and CSV comparison tables, a complete Markdown report, a concise post draft, and deterministic SVG charts. Historical timed-phase censorship has a dedicated finite schema: the timeout must exactly equal the manifest `process_timeout_s`, the nanosecond lower bound is derived exactly, and preparation, comparison identity, and any applicable preflight/setup/read evidence remain mandatory. Candidate observations use the manifest-bound effective outer watchdog `max(process_timeout_s, 30.0)`; the child records that actual deadline and paired-parent enforcement context, and expiry is a blocking driver error rather than censorship. Timeout controls are valid only when termination is exactly `timeout`, `timed_out` is true, the timeout budget and effective watchdog provenance match the manifest, overshoot is exact, and implementation-specific control evidence is present; raw chunk selection recomputes timeout p95 only from those validated observations. Cursor and batch rows record actual per-call reads from each implementation's runtime I/O path; aggregate byte fields, ranges, union size, and a checksum over the complete operation log are recomputed from those calls. Comparison schema 3 binds canonical environment and row content with a digest. Report generation verifies that digest, supported versions, canonical row fields and statistics, status/count consistency, correctness, blocking state, and release eligibility before rendering. Candidate errors, semantic incompatibility, incorrect results, false warm-state evidence, unsupported versions, or nonfinite/ill-typed observations are blocking. Missing, neutral, censored, and regressing selected rows remain visible by stable `case_id`.

Row completeness and release eligibility are separate results. Smoke, subsets, one-block release runs, and dirty release diagnostics remain valid engineering artifacts but reports and posts label them non-release-eligible. Release eligibility requires the supported versions, release profile, the exact full manifest order, at least seven paired blocks, clean exact Git commit/tree identities for historical source, candidate source, and tooling, tooling identity equal to the candidate source, complete nonblocking rows, and exactly the manifest-declared candidate-only cases.

