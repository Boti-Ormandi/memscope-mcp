# Scanning Engine and Adapter Evidence

The scanning benchmark package includes deterministic evidence runners for contracts that are more useful as exact invariants than as noisy timing comparisons.

## Engine and control evidence

Run the fake-reader cursor, batch, deadline, cancellation, target-change, responsiveness, and lease-cleanup cases with:

```powershell
python -m benchmarks.scanning.engine `
  --profile smoke `
  --warmups 0 `
  --repetitions 3 `
  --output artifacts/scanning-engine.json
```

The artifact records:

- every cursor page's exact candidate count and resume address;
- physical reads performed by a shared batch versus equivalent independent scans;
- injected logical deadline overshoot and control-poll counts;
- cancellation and target-change results, cursor suppression, and lease release;
- proof that a blocked scan worker permits unrelated request-loop progress;
- proof that transport cancellation waits for worker cleanup before propagating.

## Public adapter evidence

Run the FastMCP, output-formatting, Lua, and clean-break cases with:

```powershell
python -m benchmarks.scanning.public_api `
  --profile smoke `
  --warmups 0 `
  --repetitions 3 `
  --output artifacts/scanning-public-api.json
```

The artifact records:

- rejection of unknown FastMCP fields before handler invocation;
- the flat structured response union and registered input/output schema hashes;
- serialization sizes for supported retained-result counts;
- Lua named-table normalization, result metadata, batch ordering, and stable error tuples;
- exclusive ownership of the mutable Lua runtime across concurrent callers;
- absence of removed scanner modules, names, and shipped instruction forms.

## Evidence policy

Both runners emit the same versioned raw-artifact envelope as the matcher and controlled-process suites. Each case validates correctness before accepting observations. Wall-clock duration and throughput are retained for inspection, but normal tests gate only deterministic semantic and cleanup invariants. Machine-dependent timing thresholds belong in explicitly controlled release evidence, not ordinary CI.

Use repeated `--case-id` options to select individual cases. The runners reject duplicate or unknown case IDs, require a Git identity, and write artifacts atomically through the shared benchmark serializer.
