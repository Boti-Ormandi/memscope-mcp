# Scanning benchmarks

This directory contains deterministic benchmark inputs and machine-readable raw evidence for the scanning engine. Benchmark code is not part of the installed package.

The matcher suite currently covers exact, selective wildcard, alternating, sparse rare, sparse common, pointer-aligned, ASCII, and UTF-16LE query shapes. Each case has a stable ID, deterministic corpus, semantic fingerprint, independently derived expected result, raw observations, and operation counters.

Run the quick validation profile, which scales the declared matcher cases down to at most 4 MiB each:

```powershell
python -m benchmarks.scanning.matcher --profile smoke --output benchmark-results/matcher-smoke.json
```

Run the fixed 64 MiB matcher matrix used for release evidence:

```powershell
python -m benchmarks.scanning.matcher --profile release --warmups 3 --repetitions 10 --output benchmark-results/matcher-release.json
```

Use `--case-id <id>` repeatedly to select specific cases. Generated artifacts live under `benchmark-results/`, which is ignored by Git.

Correctness and expected strategy selection are checked before an artifact is accepted. Corpus generation and reference matching are outside timed statements. The current raw matcher artifact is not a historical comparison or a publication claim by itself; paired baseline execution, controlled-process measurements, comparison statistics, reports, and charts are separate benchmark surfaces.
