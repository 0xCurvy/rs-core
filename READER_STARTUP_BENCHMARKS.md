# Zkey reader startup benchmark — 4 September 2026

Current implementation and audit status: [6 September follow-up](SECURITY_PERFORMANCE_AUDIT.md). This document retains historical context and measurements.

**Correction, 5 September 2026:** the archived build metadata and binaries show
identical executable hashes for the “previous” and “fixed” reader labels, for
both matrix layouts. Those comparisons did not isolate the authentication fix
and cannot support the earlier conclusion that it had negligible overhead.
The tables below are retained as historical raw observations, with those labels
invalidated. Use the freshly rebuilt current implementations in
[RESIDENT_OPTIMIZATIONS.md](RESIDENT_OPTIMIZATIONS.md) for current startup results.

## Method and scope

- Host: Apple M4 Pro, 10 performance and 4 efficiency cores, 48 GB RAM,
  macOS 26.5.1; Rust 1.94.0, arm64.
- Source: base commit `e17b71116bcd8c68795df3c1a4f7cec32b3068a8` plus the current
  working tree, including the audit fixes. Build metadata records source and
  executable hashes.
- Baseline: a temporary copy of that same working tree, with only the default
  reader restored to its previous hash/parse/hash implementation. That reader
  is vulnerable to transient file substitution and exists here only as a
  benchmark baseline. The application retains the fix.
- Builds: ordinary Cargo release settings, no `RUSTFLAGS` or release-profile
  environment overrides. All variants use `curvy-benchmarks`, which enables
  the prover's `parallel` feature. One worker therefore means that same parallel
  build configured with one Rayon worker, not a separate serial-feature build.
- Matrix variants: default nested matrices and opt-in `compact-matrix`.
  Reader variants: previous, fixed, and opt-in `zkey-single-pass`.
- Each key/worker/profile combination has one warm-up and nine measured fresh
  processes. Profile order rotates and reverses between rounds. Files are warm
  in the OS page cache; no other builds or benchmarks ran during the timed sweep.
- Timing is `whole_key_wtns --load-only`'s `zkey_parse_and_auth_ms`: authentication,
  key and matrix parsing, point spot checks, and verifying-key preparation.
  It excludes initial thread-pool construction, witness evaluation, proof
  generation, and Node initialization outside this Rust call. Full process wall
  time is also retained in the raw results.
- RSS is each child's high-water mark from macOS `wait4`, reported in MiB
  (1,048,576 bytes). Tables show the median of nine process peaks, not retained
  idle memory. `wait4` avoids the sandbox-blocked `kern.clockrate` query made by
  `/usr/bin/time -l`.
- All **324 measured loads and 36 warm-ups succeeded**, checked the expected
  artifact pin, and reported the expected constraint and public-input counts.
  This is a load benchmark; it does not generate proofs.

## Production keys

These files match the production hashes recorded in
[`PRODUCTION_BENCHMARKS.md`](PRODUCTION_BENCHMARKS.md).

| Notes | Bytes | MiB | Constraints | SHA-256 |
|---:|---:|---:|---:|---|
| 2 | 91,785,620 | 87.5 | 150,769 | `dea6b15860701dee9c77ee2a6916ccda7735590012572d526a3714f8e429ed33` |
| 5 | 129,200,756 | 123.2 | 226,236 | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` |
| 10 | 227,925,172 | 217.4 | 391,313 | `6986b1a778c87fe3cc29c31b74785e62e8e987b0ddc885fd9062265e6c037d22` |

The earlier report's 50-note key was not found in the local artifact locations
searched, so this follow-up does not claim results for that key.

## Thirteen workers

Times are median milliseconds. A positive change means the fixed reader took
longer. Peak RSS values are median MiB.

| Notes | Matrices | Previous | Fixed | Change | Previous RSS | Fixed RSS |
|---:|---|---:|---:|---:|---:|---:|
| 2 | Nested | 126.084 | 127.518 | +1.14% | 160.5 | 160.2 |
| 5 | Nested | 179.536 | 179.191 | −0.19% | 218.2 | 218.0 |
| 10 | Nested | 312.611 | 313.043 | +0.14% | 373.6 | 373.3 |
| 2 | Compact | 114.487 | 114.671 | +0.16% | 110.6 | 110.6 |
| 5 | Compact | 161.182 | 160.708 | −0.29% | 151.4 | 151.6 |
| 10 | Compact | 277.998 | 279.480 | +0.53% | 242.1 | 242.0 |

For the 10-note nested case, previous min/median/max was
309.142 / 312.611 / 315.884 ms, with population standard deviation 1.997 ms.
The fixed reader measured 307.103 / 313.043 / 317.014 ms, with standard deviation
2.702 ms. The small difference between medians sits within the observed run
variation; this sweep does not establish a statistically significant difference.

## One worker

| Notes | Matrices | Previous | Fixed | Change | Previous RSS | Fixed RSS |
|---:|---|---:|---:|---:|---:|---:|
| 2 | Nested | 130.336 | 130.748 | +0.32% | 154.0 | 154.0 |
| 5 | Nested | 182.732 | 182.726 | 0.00% | 210.7 | 210.7 |
| 10 | Nested | 322.820 | 320.952 | −0.58% | 366.2 | 366.2 |
| 2 | Compact | 116.332 | 120.224 | +3.35% | 102.0 | 102.0 |
| 5 | Compact | 163.627 | 164.830 | +0.74% | 142.8 | 142.8 |
| 10 | Compact | 288.382 | 288.161 | −0.08% | 232.1 | 232.1 |

The largest observed median increase was 3.892 ms in the 2-note compact case.
Its previous and fixed ranges overlapped: 113.622–122.840 ms and
113.843–123.371 ms respectively. Small changes should not be generalized into
an exact performance guarantee across hosts or cache conditions.

## Opt-in single-pass reader

The existing single-pass feature remains faster and uses more peak memory in
this sweep. It hashes bytes during parsing and validates the digest before
returning the key; the fixed default authenticates each buffered chunk before
exposing it to the parser. These remain distinct authentication policies.

| Notes | Matrices | One-worker time | One-worker RSS | Thirteen-worker time | Thirteen-worker RSS |
|---:|---|---:|---:|---:|---:|
| 2 | Nested | 77.624 | 173.7 | 74.456 | 180.1 |
| 5 | Nested | 105.676 | 235.0 | 105.228 | 241.1 |
| 10 | Nested | 183.975 | 387.5 | 179.717 | 395.8 |
| 2 | Compact | 60.430 | 125.1 | 59.189 | 127.9 |
| 5 | Compact | 83.984 | 160.1 | 82.888 | 166.2 |
| 10 | Compact | 147.124 | 263.0 | 142.162 | 262.5 |

On the 217 MiB key with nested matrices and thirteen workers, single-pass loading
is 42.6% faster than the fixed default and adds 22.6 MiB to median peak RSS. The
benchmark does not change the feature defaults.

## Reproduction and raw data

- [Runner](tools/benchmarks/measure_reader_startup.py)
- [Configuration](tools/benchmarks/results/reader-startup-2026-09-04/config.json)
- [All samples, warm-ups, and distributions](tools/benchmarks/results/reader-startup-2026-09-04/results.json)
- [Build commands, hashes, environment, and source state](tools/benchmarks/results/reader-startup-2026-09-04/metadata.json)
- [Patch restoring the previous reader in a temporary source copy](tools/benchmarks/results/reader-startup-2026-09-04/baseline.patch)

Copy the working tree to a temporary directory excluding `.git`, `target`, and
`node_modules`, then apply `baseline.patch` there with `patch -p1`. Build
`whole_key_wtns` from both trees using `cargo build --release --locked -p
curvy-benchmarks --bin whole_key_wtns`, saving each executable before building
another variant. Repeat with `--features compact-matrix`. For the current
single-pass variants, add `zkey-single-pass` to the respective feature list.
The metadata records the exact commands used for all six binaries.

Update the configuration's executable and artifact paths for the new temporary
builds, then run:

```bash
python3 tools/benchmarks/measure_reader_startup.py config.json results.json
```

Cold-storage behavior, the unavailable 50-note key, and end-to-end Node or proof
latency remain outside this measurement. The older production report's complete
proving timings remain historical measurements.
