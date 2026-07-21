# Scanning benchmarks

This directory contains deterministic benchmark inputs and machine-readable raw evidence for the scanning engine. Benchmark code is repository tooling and is not part of the installed package.

## Matcher evidence

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

The process runner launches a child Python process, allocates and touches deterministic Win32 memory, publishes versioned topology metadata, and attaches through the production `DebugSession` and `ScanExecutor` path. Setup, corpus generation, topology mutation, and independent address-checksum validation occur outside timed observations. Raw `ReadProcessMemory` ceiling measurements are kept separate from end-to-end scanning.

Run a focused smoke pass:

```powershell
python -m benchmarks.scanning.process_scan --profile smoke --warmups 0 --repetitions 1 --case-id reader.ceiling.contiguous64m --case-id e2e.exact16.late.contiguous64m --output benchmark-results/process-smoke.json
```

Run all controlled-process cases against the checked-out implementation:

```powershell
python -m benchmarks.scanning.process_scan --profile release --warmups 2 --repetitions 7 --output benchmark-results/process-release.json
```

The controlled matrix covers contiguous and fragmented ranges, a match crossing a chunk/protection boundary, post-plan protection changes and page-aligned read salvage, dense/first/page/count collectors, writable and PE-section filters, peak Python allocation, and chunk sizes from 16 KiB through 4 MiB. The child protocol also exposes deterministic protection-change and target-exit controls for lifecycle tests.

When all chunk cases run with the release profile, at least one warmup, and at least three repetitions, the raw artifact records the production recommendation. The policy chooses the smallest chunk within 10% of the best end-to-end median only when it preserves the provisional 128 KiB baseline's salvage p95 and timeout-overshoot p95 within the declared tolerance. Lower-sample runs retain their measurements but are marked insufficient for production selection.

Use `--case-id <id>` repeatedly to select specific cases. Generated artifacts live under `benchmark-results/`, which is ignored by Git.

Correctness and expected strategy checks are performed before an artifact is accepted. Raw artifacts are not historical comparisons or publication claims by themselves; paired baseline execution and generated publication reports are separate benchmark surfaces.
