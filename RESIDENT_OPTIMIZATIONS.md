# Resident optimizations — 5 September 2026

Current implementation and audit status: [6 September follow-up](SECURITY_PERFORMANCE_AUDIT.md). This document retains historical context and measurements.

Implemented: compact matrices as the native Node default; a resident loader that authenticates pinned manifest chunks before parsing; resident SAGE and compiled-cache loading in Rust, Node, and C; a bounded Node proof queue on each prover’s private Rayon pool; and opt-in reusable witness, FFT, and MSM scalar-conversion buffers.

Compact matrices primarily save memory in the current loader. The manifest is the startup speed improvement. SAGE primarily saves witness memory; compiled caches reduce witness initialization time. Scratch retention is **off by default** because the repeated-proof experiment did not justify its memory and latency cost. Core, C, and WASM matrix defaults are unchanged.

## Key loading

Current implementations, 13 Rayon workers, nine fresh processes per cell after one warm-up. Times include authentication, parsing, point spot checks, and verifying-key preparation. RSS is the median process peak, including transient parser buffers. The manifest path includes reading and authenticating its small manifest file.

| Notes | Nested ms / MiB | Compact ms / MiB | Manifest + compact ms / MiB |
| --- | ---: | ---: | ---: |
| 2 | 157.8 / 160.5 | 162.7 / 110.5 | 57.7 / 128.0 |
| 5 | 223.4 / 218.1 | 231.4 / 151.7 | 79.3 / 167.8 |
| 10 | 389.9 / 374.3 | 403.3 / 241.9 | 134.9 / 263.3 |

For 10 notes, manifest + compact lowers load time from 389.9 to 134.9 ms (65.4%) and peak RSS from 374.3 to 263.3 MiB (29.7%). Compact alone uses 35.4% less peak memory, with a 3.4% startup cost in this sweep. Its default adoption is specific to native Node. One-worker results are also in the raw data; those builds still enable `parallel`.

## Repeated proofs and SAGE

Each row has 22 measured, self-verified proofs across two fresh processes, plus one warm-up proof per process. Backend order reverses in the second round. All builds use compact matrices and 13 workers. Timing includes witness evaluation, proof generation, self-verification, serialization, and workspace cleanup when enabled. Inputs insert one synthetic note into an empty depth-30 tree and pad the rest of each production batch with zero skip slots; public hashes are checked as BN254 field elements. These are representative circuit sizes, not an exhaustive input distribution.

| Notes | Witness backend | Witness load ms | Proof median / p95 ms | Peak MiB |
| --- | --- | ---: | ---: | ---: |
| 2 | Graph | 35.5 | 243.5 / 250.9 | 197.2 |
| 2 | SAGE, compile source | 49.7 | 245.4 / 250.8 | 166.1 |
| 2 | SAGE, compiled cache | 9.5 | 246.8 / 254.8 | 160.2 |
| 2 | SAGE, compiled cache + scratch | 9.5 | 257.0 / 266.7 | 172.1 |
| 5 | Graph | 53.6 | 343.0 / 354.2 | 260.8 |
| 5 | SAGE, compile source | 74.5 | 346.8 / 357.8 | 201.4 |
| 5 | SAGE, compiled cache | 15.2 | 354.5 / 965.9 | 213.2 |
| 5 | SAGE, compiled cache + scratch | 15.9 | 356.0 / 1119.3 | 235.6 |
| 10 | Graph | 91.1 | 589.3 / 607.6 | 455.9 |
| 10 | SAGE, compile source | 125.4 | 589.6 / 603.3 | 360.5 |
| 10 | SAGE, compiled cache | 27.2 | 591.3 / 600.3 | 355.0 |
| 10 | SAGE, compiled cache + scratch | 25.2 | 611.9 / 622.1 | 384.1 |

On the 10-note circuit, cached SAGE reduces peak RSS from 455.9 to 355.0 MiB (22.1%). Proof time is effectively unchanged. Loading a compiled program takes 27.2 ms versus 125.4 ms to authenticate and compile its source graph. The source and compiled-program digests are pinned independently.

The five-note cache rows had pronounced tail outliers on this shared workstation. Raw timings are retained; their p95 should not be treated as a stable service latency estimate. No other builds or benchmarks were run by this agent during the timed sweeps.

Scratch reuses evaluator values and assignments, three FFT vectors, and the H/assignment scalars supplied to MSM. It does not pool MSM buckets or dependency-owned FFT temporaries. Limits were 128 MiB per workspace; combined retained capacities were 41.2, 45.9, and 87.9 MiB for 2, 5, and 10 notes. Buffers are zeroized on success, error, panic unwinding, and drop, and discarded when the idle cap is exceeded. These limits do not bound active proof memory. Caller input copies and dependency temporaries are outside the clearing guarantee.

For 10 notes, scratch raised median proof time from 591.3 to 611.9 ms and peak RSS from 355.0 to 384.1 MiB. It remains an explicit Rust `scratch` experiment; Node/C/WASM defaults do not retain these buffers.

## Native matrix gates

Five measured self-verified proofs plus one warm-up per fresh process, using the same input recipe. The parallel builds use 13 workers. Separate `--no-default-features` benchmark builds disable Curvy/arkworks parallel features for the serial comparisons. Compact serial selects Curvy’s MSM/proof assembly instead of stock ark-groth16, so these rows measure the complete feature choice, not CSR evaluation alone.

| Notes | Parallel nested ms / MiB | Parallel compact ms / MiB | Serial nested ms / MiB | Serial compact ms / MiB |
| --- | ---: | ---: | ---: | ---: |
| 2 | 244.7 / 253.6 | 243.5 / 197.0 | 1592.4 / 483.8 | 1832.2 / 184.3 |
| 5 | 336.0 / 339.2 | 337.2 / 259.2 | 2228.0 / 846.5 | 2612.4 / 244.4 |
| 10 | 584.4 / 587.5 | 584.0 / 457.1 | 4200.9 / 1366.7 | 4860.1 / 440.5 |

The parallel result supports the Node default: similar proof latency with materially lower peak memory. The serial gate **does not support changing the universal or C default**: compact saves memory but is about 15–17% slower on these proofs. Those defaults stay unchanged; further browser/mobile promotion work is deferred until there is a suitable serial tradeoff.

```sh
cargo build --release --locked -p curvy-benchmarks --no-default-features \
  --bin resident_repeated
# Copy the serial nested executable before building the compact variant.
cargo build --release --locked -p curvy-benchmarks --no-default-features \
  --features compact-matrix --bin resident_repeated
python3 tools/benchmarks/measure_resident_matrices.py MATRIX_CONFIG OUTPUT_JSON
```

## Queue behavior

Node `prove()` still returns a Promise. A FIFO admits at most `maxPendingProofs` jobs, including the running job (default 8, range 1–64), and rejects overload immediately. Waiting jobs occupy no libuv workers. Queue capacity is released before settling the Promise, avoiding a false overload when a capacity-one caller submits its next sequential proof. Panics and ordinary proof errors become Promise rejections.

The integration regression runs Node with `UV_THREADPOOL_SIZE=1`, queues 32 proofs, then schedules filesystem I/O. The I/O completes before all proofs; all accepted proofs subsequently complete. Additional tests exercise overload, invalid input, capacity recovery, and authenticated SAGE/manifest/cache initialization.

## Validation

- Workspace default: 193 passed, one existing ignored test. All features: 198 passed, one existing ignored test.
- Clippy across the workspace, all targets and all features: no warnings.
- Node: 10 integration tests passed; Rust queue and private-pool tests pass.
- C boundary: 12 tests passed, including both SAGE constructors and wrong cache/source pins. Generated header covers the existing 26 WASM functions and 102 members across 13 classes, plus the new C constructors.
- Portable WASM: 381 parity checks passed. Threaded WASM with compact matrices builds successfully (the toolchain emits its expected unstable-atomics warning); no browser performance claim is made.
- Manifest regressions reject changed chunks before parsing, truncated streams, extra bytes, and wrong manifest/zkey pins; the valid read-only stream produces a verified proof.
- Scratch and ordinary proof assembly match stock ark-groth16 with fixed randomizers, including zero randomizers. Repeated witness/proof use, input failures, panic cleanup, and retention limits are covered.

## Reproduction and scope

Apple M4 Pro, 10 performance and 4 efficiency cores, 48 GB; macOS arm64; Rust 1.94. Ordinary Cargo release settings. Process RSS uses Darwin `wait4` bytes. Raw pins, configurations, samples, executable hashes, and host information are under [`tools/benchmarks/results/resident-2026-09-05`](tools/benchmarks/results/resident-2026-09-05). All keys, manifests, and compiled programs are authenticated. Manifest generation checks its chunk table against the whole-key digest before recording pins. Artifacts remain outside this repository.

```sh
cargo build --release --locked -p curvy-benchmarks --bin whole_key_wtns
# Copy the nested executable to its configured path before the next build.
cargo build --release --locked -p curvy-benchmarks --features scratch \
  --bin whole_key_wtns --bin resident_repeated
python3 tools/benchmarks/measure_reader_startup.py LOAD_CONFIG OUTPUT_JSON
python3 tools/benchmarks/measure_resident_repeated.py BINARY ARTIFACTS_JSON OUTPUT_JSON
```

The manifests and caches can be regenerated with `zkey_chunk_manifest` and `derive_sage_cache`; artifact metadata records all trusted digests. The 50-note artifacts were unavailable. No universal matrix default is promoted: threaded-browser/mobile performance gates remain outstanding.

**Correction to the earlier benchmark:** both archived “previous” and “fixed” executables had identical hashes within each matrix layout. Their comparison did not measure the authentication fix. [The earlier report](READER_STARTUP_BENCHMARKS.md) now invalidates those labels. This report freshly builds both current layouts and records distinct executable hashes; it makes no claim about the old fix’s overhead.
