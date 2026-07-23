# Netcap buffer-search benchmarks

This directory contains deterministic repository tooling for `bufferFind`, `bufferContains`, and `bufferFindAll`. It is not included in the installed package and adds no runtime dependency.

The schema-2 benchmark compares:

- an independent frozen copy of the legacy sequential Lua-table converter and list-slice search oracle;
- the checked-out production `NetcapPlugin`, invoked through real Lupa Lua tables and Lua closures.

Release timing gates use only those end-to-end production calls. Conversion-only rows are diagnostic and are excluded from release performance decisions. The benchmark contains no benchmark-local optimized search kernel.

## Profiles

Run the bounded dirty-tree smoke diagnostic:

```powershell
python -m benchmarks.netcap.buffer_search `
  --profile smoke `
  --output benchmark-results/netcap-buffer-search-smoke.json
```

A smoke artifact validates normally but remains `insufficient`. Gate enforcement therefore returns a nonzero status:

```powershell
python -m benchmarks.netcap.buffer_search `
  --profile smoke `
  --enforce-gates `
  --output benchmark-results/netcap-buffer-search-smoke-enforced.json
```

Run the full release matrix only from a clean committed tree with no competing timing workload:

```powershell
python -m benchmarks.netcap.buffer_search `
  --profile release `
  --enforce-gates `
  --output benchmark-results/netcap-buffer-search-release.json
```

Release eligibility requires all 34 cases, unchanged source and Git identity throughout the run, a clean candidate tree before and after measurement, and at least the canonical per-size sampling:

| Input size | Warmups | Paired observations |
|---:|---:|---:|
| 64 B | 3 | 101 |
| 4 KiB | 3 | 25 |
| 262,000 B | 3 | 9 |
| 1 MiB | 3 | 9 |

`--warmups` and `--repetitions` may increase these values. Lower overrides are accepted only for diagnostics and make the artifact `insufficient`. `--enforce-gates` fails both `insufficient` and `fail` artifacts.

Use `--case-id <id>` repeatedly for bounded diagnostics. A partial release profile remains `insufficient` even when every measured case is faster.

## Evidence contract

Before runtime binding or measurement, the runner captures source hashes and module origins for:

- `benchmarks/netcap/__init__.py`;
- `benchmarks/netcap/buffer_search.py`;
- `memscope_mcp/_contrib/plugins/netcap.py`.

Each module path and origin must equal its canonical path under the selected repository root, and the recorded Git root must equal that same root. Out-of-tree modules and unrelated Git roots are rejected. The runner also captures commit, tree, branch, dirty state, and the complete porcelain status with every untracked path plus its hash. The same identity is captured after measurement and must be unchanged. Local release eligibility additionally recomputes the current source and Git identity from the exact recorded repository and requires exact equality with both recorded snapshots. A forged serialized clean snapshot cannot suppress the live `candidate-tree-dirty` finding. Offline or moved artifacts may pass structural validation, but remain non-release-eligible until verified against that exact repository. A dirty tree is valid diagnostic evidence but is never release-eligible.

The raw artifact includes:

- a declared and bounded semantic parity sample space;
- one canonical row for each of 211 scenarios and all 633 operations, including scenario identity, input fingerprints, baseline and candidate result or exception fingerprints, pass/fail, and an aggregate commitment hash;
- balanced AB/BA order schedules and all raw timing observations;
- conversion diagnostics;
- exact allocation, Lua-heap, and retained-growth matrices;
- environment and source identity metadata;
- recomputed gate rows and insufficiency reasons.

Validation reconstructs the exact 211-scenario/633-operation matrix, re-executes candidate observations, and rejects unsupported schemas, incomplete or duplicate matrices, scope expansion, unexpected rows, out-of-tree source identities, raw sample-length mismatches, forged parity observations, aggregates, or commitments, non-finite or boolean numeric evidence, inconsistent heap or retained-growth arithmetic, incorrect medians or ratios, and serialized gate status that does not match recomputed evidence. Timing gates are recomputed from the validated `perf_counter` resolution recorded in the artifact, not from the verifier host. Release evidence requires that resolution to be a finite float greater than zero and no larger than 100 nanoseconds.

## Stable coverage

The release matrix covers 64-byte, 4 KiB, 262,000-byte, and 1 MiB inputs with:

- first, final, and absent matches for `bufferFind` and `bufferContains`;
- sparse and absent `bufferFindAll` cases;
- overlapping matches on a bounded 64-byte input;
- a bounded dense 4 KiB `bufferFindAll` case.

Dense and empty-pattern 1 MiB `bufferFindAll` timing is deliberately excluded because output construction is proportional to every input boundary. Empty-pattern and overlap semantics remain covered by correctness tests.

## Gates

For production Lua end-to-end measurements:

- the 4 KiB case-set geometric mean must be at most `0.90`;
- the combined 262,000-byte and 1 MiB geometric mean must be at most `0.85`;
- no individual 4 KiB-or-larger case may exceed `1.10`;
- no individual 64-byte case may exceed `1.15`.

Timing thresholds allow one recorded `perf_counter` resolution tick when converted to an absolute duration limit.

For no-match and sparse allocation cases, candidate peak traced Python memory may not exceed the oracle peak by more than `len(data) + len(pattern) + 8192` bytes. Both lengths are rebuilt from the canonical case payload rather than trusted from serialized metadata. Allocation evidence uses exactly three samples for 4 KiB cases and one sample for 262,000-byte cases. Lua-heap evidence uses exactly three samples for every selected heap case and variant. Retained Lua growth uses exactly 100 calls. Lua result heap may not exceed the oracle by more than the larger of 4 KiB or 5%, and non-negative retained growth must remain at or below 64 KiB.

Generated artifacts belong under ignored `benchmark-results/`. Retain the JSON file and its SHA-256 hash when using a diagnostic or release run as review evidence.
