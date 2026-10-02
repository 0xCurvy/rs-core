# Optimization decision log

What was tried, what was kept, what was rejected, and why. Check this before
starting performance work so you don't repeat a dead end. Numbers are summarized
from [benchmarks.md](benchmarks.md), which also has the re-run commands.
Correctness and authenticated-artifact boundaries ([security.md](security.md))
take precedence over any benchmark win.

Status meanings: **Kept** (default behavior), **Opt-in** (behind a feature or
option, deliberately not default), **Rejected/closed** (measured and dropped),
**Disabled** (deliberately not enabled).

## Ground rules that shaped every decision

- BN254 field, curve, randomness and final Groth16 verification stay in arkworks.
  Curvy owns artifact framing, witness/QAP evaluation, scalar recoding, bucket
  scheduling and memory lifetimes. Do not add a second BN254 implementation.
- Bulk zkey points are built without a per-point subgroup check only after the
  pinned digest has authenticated the bytes (`crates/prover/src/zkey.rs`,
  `crates/prover/src/authenticated_reader.rs`). Any parser speedup must keep
  authentication before unchecked parsing.
- Every high-level proof self-verifies. Keep that gate; it costs about 0.7 ms.
- Resource limits (`curvy_witness::Limits`) are a denial-of-service boundary.
  Do not widen them to make one artifact load.

## Kept

| Decision (date) | Why / evidence | Code |
|---|---|---|
| Reuse the transformed `A` domain vector for `A·B` (25 Aug) | Removes 32 B per domain element (512 MiB at 2^24) | `crates/prover/src/qap.rs` |
| One QAP kernel for nested, CSR, scratch and streaming proving (6 Sep) | Single audited path computing `A·B − C` on the odd coset; independent quadratic-interpolation oracle in tests | `crates/prover/src/qap.rs` |
| Parallel proof reuses the assignment bigint vector for the L query (25 Aug) | Removes 32 B per private assignment element | `crates/prover/src/groth16_prover.rs` |
| Decode zkey G1/G2 query sections in 8 MiB chunks (25 Aug) | Replaces a query-sized raw allocation with an 8 MiB ceiling; conversion stays parallel per chunk | `crates/prover/src/zkey.rs` (`POINT_PARSE_CHUNK_BYTES`) |
| Authenticated seekable reader for native file loads (25 Aug; chunk recheck 4 Sep) | No full zkey byte buffer beside the parsed key; costs a second (page-cached) file pass. Its overhead has never been validly measured (benchmarks 5) | `crates/prover/src/authenticated_reader.rs`, `ResidentProver::from_artifacts_reader`, `Prover::from_zkey_reader` |
| Compact CSR parse uses sequential buffered reads, not `SeekFrom::Current(32)` per coefficient (25 Aug) | Seeking a `BufReader` discarded its buffer: 50-note compact parse 4,431 -> 769 ms | `crates/prover/src/zkey.rs` |
| Drop the parsed input buffer before allocating the assignment (25 Aug) | Removes `32 * input_buffer_len` bytes of overlap | `crates/witness/src/lib.rs` |
| Streaming JSON input visitor and 19-digit Horner decimal parsing (7 Sep) | No `serde_json::Value` DOM copy; decimal parsing linear (15 MiB in 30.6 ms) | `crates/witness/src/input.rs` |
| SIGNET v2 body (varint distances, ZigZag deltas) (25 Aug) | 56–58% smaller raw, 62–69% smaller zstd; with compact parsing, ~26% faster bundle load | `crates/signet/src/lib.rs`, decoder in `crates/witness` (`signet-v2`, opt-in by design: accepting a new artifact format must be deliberate) |
| SIGNET zstd level 9 (25 Aug) | 4 MiB window under the consumer's 8 MiB cap; level 19 lands exactly on the cap | `crates/signet`; cap in `Limits` |
| Drain zstd stdout while writing stdin (25 Aug) | Fixed a pipe deadlock on the 80.8 MB v1 graph | `crates/signet/src/lib.rs` |
| Native CLI carries batch limits through graph decoding (25 Aug) | Lets the 50-note v1 graph load without widening client defaults | `crates/prover/src/bin/curvy-native-prover.rs` |
| Poseidon permutation on two fixed stack buffers (25 Aug) | No per-round heap allocation; −8.6% per binary hash | `crates/core/src/poseidon/mod.rs` |
| Optimized Poseidon schedule as the `curvy-core` default (25 Aug) | 1.15–4.44x per hash, −29% Merkle workloads; WASM gzip +24.6% accepted. Direct schedule stays as oracle via `default-features = false` | `crates/core/src/poseidon/optimized_constants.rs`, `crates/core/testdata/poseidon_constants_optimized.bin`, generator `tools/benchmarks/src/bin/generate_poseidon_optimized.rs` |
| Lazy per-arity Poseidon table decoding, eager framing validation (25 Aug) | First hash 2.71 -> 0.046 ms, −1.57 MiB RSS. `every_arity_decodes_and_matches_its_digests` keeps all tables authenticated under `cargo test` | `crates/core/src/poseidon/optimized_constants.rs` |
| Fixed-width BN254 backend for Poseidon and decimal conversion (8 Sep) | Removed private-input timing signals; signing hash stage 13–17 -> 21–23 µs accepted | `crates/core/src/secret_field.rs`, `crates/core/src/poseidon/mod.rs` |
| Fixed-width signing arithmetic with complete projective formulas (7 Sep) | Security change; also seed signing 6.62 -> 1.21 ms in WASM | `crates/core/src/secret_arithmetic.rs` |
| Serial resident MSM window ≈ ln(points) + 2, capped at 16 (6 Sep) | Serial compact 11–18% faster; parallel keeps the adaptive policy | `crates/prover/src/msm.rs` (`resident_window_bits`) |
| SPARROW `native_adaptive()`: window from each query's point count, 524,288-point chunks (25 Aug) | Validated with `native_window_sweep`; window width is deployment metadata, not part of any digest | `crates/prover/src/sparrow.rs` (`StreamingConfig`) |
| Parallel SPARROW bucket window reduction (1 Oct) | Independent per-window running sums; 3–7x for that phase per the code comment, no end-to-end re-measurement | `crates/prover/src/msm.rs` |
| Batch-affine MSM bucket accumulation, wider parallel/SPARROW windows (1 Oct; 16,384–524,288-point band settled at 12 bits on production keys) | Resident G1 −21 to −37%, G2 −34 to −50%, SPARROW query −37 to −53%; whole production proofs −18 to −32%. XYZZ kept below 4,096 points and as the overflow for repeatedly hit buckets | `crates/prover/src/msm.rs` (`AffineBuckets`, `adaptive_window_bits`, `BATCH_AFFINE_MIN_POINTS`), `crates/prover/src/sparrow.rs` |
| Curvy proof assembly and batch-affine MSM in the default serial build (1 Oct) | Previously stock `ark-groth16`. Native serial proofs −16 to −22% and −19 to −24% peak RSS; portable browser −14 to −23%, browser memory unchanged, module −3% (benchmarks 6.5) | `crates/prover/src/lib.rs`, `crates/prover/src/msm.rs` (`serial_window_bits`) |
| Manifest-authenticated resident loading (5 Sep) | 10-note load 389.9 -> 134.9 ms, −30% RSS | `crates/prover/src/artifacts/manifest.rs` (`zkey-manifest`), `Prover::from_zkey_manifest_reader` |
| Node: compact matrices and a bounded FIFO queue on the prover's private pool (5 Sep) | Same parallel latency, ~22% less RSS; waiting proofs hold no libuv worker | `bindings/node/Cargo.toml` (`default = ["compact-matrix"]`), `bindings/node/src/queue.rs` |
| Node `ResidentProver.create()` on a native task (25 Aug) | Event-loop delay 117.9 -> 1.5 ms during load | `bindings/node/src/lib.rs` |
| Packed field boundaries (25 Aug) | 262,144-field assignment: 67.8 -> 1.95 ms, −60% bytes | `bindings/node/src/lib.rs`, `crates/prover/src/wasm_api.rs` (`calculatePacked`), `bindings/ffi/src/prover.rs` |
| FFI registry map lock only for lookup, then per-handle locks (25 Aug) | Independent handles no longer wait behind a long proof | `bindings/ffi/src/registry.rs` |
| Parallel SPARROW record decoding; browser chunk hashing overlapped with parsing (2 Oct) | SHA-256 was the browser's serial bottleneck: SPARROW −5 to −12%, heap −12 to −22% at 4 workers; native neutral (+0.0 / −1.5%) (benchmarks 6.10) | `crates/prover/src/sparrow.rs` (`PARALLEL_DECODE_MIN_RECORDS`), `crates/prover/src/sparrow/manifest.rs` (`push_complete_chunk`) |
| Reverse owned-leaf index in `ShardedNotesTree` (7 Sep) | Removes repeated full scans in restore/mark/adopt; restore O(n log n) | `crates/core/src/imt.rs` (`owned_leaves`) |

## Opt-in (not promoted)

| Decision (date) | Why not default | Code |
|---|---|---|
| `compact-matrix` for Rust, C and WASM (25 Aug – 6 Sep) | Serial compact was 15–17% slower (5 Sep), still ~5% slower at 2 notes after window tuning (6 Sep). Browser (1 Oct): peak RSS only −5 to −7% in threaded and portable builds, portable +5.8% slower at 2 notes; below the 15% memory bar (benchmarks 6.4). Mobile gate outstanding. Default only in Node | `crates/prover/Cargo.toml`, `bindings/ffi/Cargo.toml`, `scripts/build-wasm.sh --compact-matrix` |
| `zkey-single-pass` forward parser (prototype) | Since 7 Sep (audit L4) it sits behind `AuthenticatedReader`, so it no longer saves an I/O pass; requires the Groth16 header before the query sections. Old timings are stale | `crates/prover/src/zkey.rs` (`read_zkey_sequential`) |
| `scratch` retained witness/FFT/MSM-scalar buffers (5 Sep) | 10 notes: +3.5% latency, +29 MiB. MSM buckets and arkworks FFT temporaries are not pooled | `crates/prover/src/workspace.rs`, `crates/witness/src/workspace.rs` |
| SAGE for resident proving and compiled caches (5 Sep) | −22% RSS and 27 ms warm load, but adds a derived artifact with its own trusted pin and cache lifecycle | `crates/witness/src/sage.rs`, `ResidentProver::with_sage` / `from_compiled_sage` |
| SPARROW streaming prover | Bounded memory at 37–45% more latency than an already-resident key; needs a manifest and SAGE integration. Excluded from default crates and npm | `crates/prover/src/sparrow.rs` (`sparrow`) |
| `wasm-simd-msm` + `wasm-simd-fft` simd128 kernels (2 Oct, branch `poc/wasm-simd`) | Browser proofs 1.4–2x faster on the Fold2 and desktop; threaded 8-worker FFT 0.35x of ark-poly; +179–200 KB gzip (benchmarks 6.9, 6.10). Not default until: a real Safari/iOS run, the 1.4x speed gate confirmed on x86-64 CI, and a phone A/B of the current build | `crates/prover/src/msm_simd/`, `crates/prover/src/simd_fft/`, `scripts/build-wasm.sh --simd`, guards `scripts/check-simd-codegen.mjs`, `scripts/simd-selftest.mjs` |

## Rejected or closed

| Idea (date) | Result | Code / harness |
|---|---|---|
| Precomputed i16 digits on top of wider serial windows (6 Sep) | At most 2% faster, up to 19 MiB more peak RSS | `crates/prover/src/msm.rs` (recoding stays random-access) |
| Run the five proof MSMs (H, L, A, B1, B2) concurrently (25 Aug) | 1.9% slower at 524,288 points and 8 workers | `crates/prover/src/proof_bench.rs` (`materialized_concurrent`) |
| Chunked scalar materialization in the production proof path (25 Aug) | 9.3% faster and −11% RSS synthetically, but the deployed conversion already costs single-digit ms; not worth the extra proof-path complexity. Closed, benchmark-only | `crates/prover/src/proof_bench.rs` (`chunked_sequential`) |
| GLV endomorphism for the batch-affine MSM (2 Oct) | Lower bound without decomposition already +16 to +34% at 8 workers and at most 10.7% faster serially (benchmarks 6.10) | not implemented |
| Short MSM for scalars below 2^64 (2 Oct) | Real witnesses have no scalars between 2 and 2^224 | not implemented |
| Zero/one scalar split outside the SIMD resident MSM (2 Oct) | Native noise (−1.8 to +1.5%); SPARROW ones routing −3.5 to +1.2% with up to 8 MiB more heap. Kept in the SIMD resident MSM only (−2 to −10%) | `crates/prover/src/msm_simd/mod.rs` (`try_sum`) |
| Concurrent SIMD transforms of A, B and C (2 Oct) | Within ±5% of one at a time on 2–8 workers; +38 MB heap at 2^19 | `crates/prover/src/simd_fft/mod.rs` |
| cargo-fuzz for the SIMD kernels (2 Oct) | They compile only for wasm32; a seed-driven, time-bounded stress mode runs instead | `scripts/simd-selftest.mjs`, `fuzz/README.md` |
| Browser SPARROW MSM chunks above 524,288 points | No latency gain, larger footprint | `StreamingConfig` |
| Compact matrices inside SPARROW | Not applicable: SPARROW never builds constraint matrices | `crates/prover/src/sparrow.rs` |
| Reduce out-of-range Poseidon table values modulo the field | Rejecting them is stricter and cheaper | `crates/core/src/poseidon/optimized_constants.rs` |
| Widen client graph limits for the 50-note v1 graph | Limits are host security policy; use `Limits::batch_prover()` or SIGNET v2 | `crates/witness/src/lib.rs` |
| zstd levels above 9 for SIGNET | Level 19 reaches the 8 MiB window cap; raising it requires a coordinated consumer change | `crates/signet` |

## Disabled on purpose

| Setting | Reason | Code |
|---|---|---|
| `ark-ec/parallel`, `ark-groth16/parallel` | arkworks 0.6 builds private Rayon pools inside large MSMs, which wasm-bindgen-rayon workers cannot spawn. Curvy schedules MSMs on the host's existing pool; `ark-ff`/`ark-poly`/`ark-std` parallel stay on | `crates/prover/Cargo.toml` (`parallel` feature comment) |
| `curvy-core/parallel` in the Node binding | Tree work stays serial so one service cannot fan out across all cores by accident | `bindings/node/Cargo.toml` |
| Thread counts above one by default | Native CLI (`CURVY_PROVER_NUM_THREADS`) and Node (`threads`) default to 1 to respect container quotas | `crates/prover/src/bin/curvy-native-prover.rs`, `bindings/node/src/lib.rs` |

## Measurement lessons

- The 4 September reader comparison used identical executables for "previous"
  and "fixed"; record and compare binary SHA-256s before trusting an A/B result.
- Two checkouts sharing one `CARGO_TARGET_DIR` produced byte-identical
  benchmark binaries (2 Oct): `curvy-prover` is also a cdylib, so its library
  output names carry no hash and one build reused the other's. Give each
  checkout its own target dir.
- The MSM schedule fixture used repeated bases, so its test could not catch a
  base/scalar misalignment; it now uses distinct bases.
- Do not add standalone Poseidon gains to proving totals: SIGNET/SAGE evaluate
  compiled circuit operations, not `curvy_core::poseidon`.
- Browser aggregate RSS is not comparable with native per-child RSS, and Docker
  x86-64 emulation is not x86-64 performance evidence.
- Small-sample results on one shared workstation describe that machine only;
  five-note cache p95 outliers on 5 September are an example.
