# Performance optimization audit

Current implementation and audit status: [6 September follow-up](SECURITY_PERFORMANCE_AUDIT.md). This document retains historical context and measurements.

This audit covers proving, witness evaluation, native Node, C FFI, and browser
WebAssembly. It records changes made on 25 August 2026 and the next work worth
measuring. Correctness and authenticated-artifact boundaries take precedence
over a benchmark win.

The complete production-key comparison, artifact digests, SIGNET/SAGE parity,
and whole-versus-stream deployment guidance are in
[`PRODUCTION_BENCHMARKS.md`](PRODUCTION_BENCHMARKS.md).

## Implemented

| Area | Change | Peak-memory / throughput effect |
|---|---|---|
| QAP witness map | Reuse the transformed `A` domain vector for `A * B` | Removes one `Fr` per domain element: `32 * domain_size` bytes (512 MiB for a `2^24` domain) |
| Parallel whole-key proof | Reuse the assignment bigint vector for the `L` query | Removes one `BigInt<4>` per private witness: 32 bytes per private assignment element |
| Zkey parsing | Decode G1/G2 query sections in bounded 8 MiB byte chunks | Replaces a raw allocation as large as the complete query with an 8 MiB ceiling; parallel conversion remains enabled inside each chunk |
| Native file-backed proving | Add authenticated seekable-reader constructors and use them in Node and the native CLI | Removes the complete zkey file byte vector from the resident initialization set; costs a second file pass, normally served by the OS page cache |
| Witness evaluation | Release the parsed input-field buffer before allocating the output assignment | Removes overlap of `32 * input_buffer_len` bytes with the assignment allocation |
| Poseidon / Merkle | Use two fixed stack buffers for the permutation | Eliminates all per-round heap allocations. For binary Poseidon this removes the state allocation plus about 65 mix allocations per hash |
| C FFI | Narrow the registry map lock to lookup and use per-handle locks | Independent handles no longer serialize behind a multi-second proof or other long operation |
| Packed boundaries | Add packed Node tree inputs/roots and packed WASM/C witness assignments | Avoids decimal formatting/parsing and JSON arrays while retaining the existing methods |
| Node initialization | Add `ResidentProver.create(options)` on a native task | Authentication and parsing no longer block the Node event loop; the synchronous constructor remains available |

The Poseidon change has a direct local release-mode A/B measurement. A harness
chained 50,000 binary hashes and ran each implementation five times on the same
arm64 host. Median time fell from 11,939.1 ns/hash to 10,915.2 ns/hash, an 8.6%
improvement. All runs produced the same final field value, and the committed
cross-language Poseidon, Merkle, witness, WASM, and FFI parity suites pass.

The other memory reductions are derived from concrete removed allocations. The
deployment artifacts live in the adjacent circuits workspace rather than this
repository; the compact-matrix section below now records authenticated
production-key latency and RSS measurements against them.

### Boundary and initialization measurements

Release measurements on the same arm64 macOS host:

| Boundary | Fixture | Existing median | New median | Result |
|---|---:|---:|---:|---:|
| Witness assignment encoding, seven runs | 262,144 full-width fields | JSON: 67.820 ms, 20,828,749 bytes | packed: 1.953 ms, 8,388,608 bytes | 97.1% faster and 59.7% fewer output bytes |
| Node indexed-tree construction, seven runs | 4,096 leaves, depth 16 | JSON: 45.138 ms | packed: 44.299 ms | 1.9% faster; Poseidon tree construction dominates |
| Node initialization, five runs | authenticated 256 MiB padded zkey fixture | constructor: 117.853 ms first-timer delay | async factory: 1.496 ms first-timer delay | 98.7% less event-loop delay; total initialization stayed about 117.5 ms |

The padded zkey fixture isolates file hashing and task dispatch; it is not a
production proving-key benchmark. The packed witness benchmark is reproducible
with `cargo run --release -p curvy-benchmarks --bin witness_boundary`.

## Proof MSM scheduling measurement (benchmark-only; closed)

`proof_msm_schedule` runs Curvy's real MSM kernel over deterministic,
equal-sized H, L, A, B1, and B2 stand-ins. Its correctness test requires the
sequential, concurrent, and chunked results to be identical. Five-run medians
at 131,072 points per query were:

| Workers | Materialized sequential | Materialized concurrent | 16,384-point chunks |
|---:|---:|---:|---:|
| 1 | 3,157.979 ms | 3,111.831 ms | 2,835.485 ms |
| 2 | 1,572.958 ms | 1,572.908 ms | 1,436.487 ms |
| 4 | 856.611 ms | 815.823 ms | 781.888 ms |
| 8 | 492.275 ms | 426.041 ms | 453.658 ms |

Outer concurrency did not generalize to the larger sweep. At 524,288 points
and eight workers, its five-run median was 1,586.727 ms versus 1,557.752 ms
sequential, 1.9% slower. Bounded scalar materialization was 1,413.510 ms, 9.3%
faster. Sampled peak RSS was 267,936 KiB sequential, 267,504 KiB concurrent,
and 238,032 KiB chunked: chunks removed 29,904 KiB (11.2%) from the whole
synthetic process, consistent with replacing two 16 MiB bigint vectors with a
512 KiB chunk.

Conclusion: do not enable outer concurrency by default. Scalar chunking also
stays benchmark-only and is closed as production work. Its synthetic memory
result is real, but the deployed scalar-conversion boundary is already in
single-digit milliseconds; the extra proof-path complexity is not worth that
remaining opportunity. The harness remains useful evidence, not a rollout
candidate.

## Opt-in prototypes

### 3. Compact constraint rows

Implemented behind `curvy-prover/compact-matrix`, with the ordinary nested
arkworks representation still the default. Section 4 is read twice: the first
pass validates indices and counts rows, and the second fills exact
`row_offsets: Box<[u32]>`, `coefficients: Box<[Fr]>`, and
`signals: Box<[u32]>` arrays. The production feature never materializes both
representations. A direct compact QAP evaluator feeds the same proof assembly
used by the parallel path, in either serial or parallel mode.

On a 64-bit host this removes two 24-byte `Vec` headers per constraint and
replaces them with two four-byte offsets. At a `2^24` domain, row metadata alone
falls by about 640 MiB, before allocator metadata, row capacity slack, and the
four bytes of tuple padding saved per coefficient by split arrays.

Release-mode synthetic measurements used 1,048,576 rows, one coefficient every
five rows, 15 samples, and the same exact row capacities as the current parser:

| Workers | Nested evaluation | Compact evaluation | Change |
|---:|---:|---:|---:|
| 1 | 5.425 ms | 4.384 ms | 19.2% faster |
| 4 | 1.424 ms | 1.147 ms | 19.5% faster |

Retained payload for that one-matrix fixture fell from 33,554,464 to 11,744,084
bytes, a 65.0% reduction. The committed one-constraint zkey fell from 272 to 88
retained matrix bytes. Applying the representation formula to a `2^24` domain
and 6.46 million retained coefficients projects about 1,014.4 MiB nested versus
349.8 MiB compact, a 664.6 MiB reduction.

Production-artifact measurements used the four pending-notes-commitment v2
keys, an Apple M4 Pro (10 performance + 4 efficiency cores, 48 GB), macOS
26.5.1, Rust 1.94.0, release mode, 13 Rayon workers, and warm local files. Each
timing is a seven-sample median from an alternating nested/compact sweep after
one warm-up. Every one of the 56 measured proofs self-verified. The zkey digest
was checked before the unchecked point parser ran.

| Notes | Zkey | WTNS | Constraints | Witness fields | Zkey SHA-256 |
|---:|---:|---:|---:|---:|---|
| 2 | 87.53 MiB | 4.56 MiB | 150,769 | 149,452 | `dea6b15860701dee9c77ee2a6916ccda7735590012572d526a3714f8e429ed33` |
| 5 | 123.22 MiB | 6.85 MiB | 226,236 | 224,505 | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` |
| 10 | 217.37 MiB | 11.86 MiB | 391,313 | 388,476 | `6986b1a778c87fe3cc29c31b74785e62e8e987b0ddc885fd9062265e6c037d22` |
| 50 | 882.53 MiB | 48.33 MiB | 1,594,033 | 1,583,596 | `cdb5cdff6bbb9a58d9cce8d811811d8244e6851ecdf6fabb2e90704416af62ee` |

| Notes | Nested auth + parse | Compact auth + parse | Parse change | Nested proof | Compact proof | Proof change | Nested total | Compact total | Total change |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 92.571 ms | 78.652 ms | 15.0% faster | 237.548 ms | 236.500 ms | 0.4% faster | 333.404 ms | 318.810 ms | 4.4% faster |
| 5 | 131.591 ms | 112.600 ms | 14.4% faster | 325.270 ms | 324.589 ms | 0.2% faster | 462.168 ms | 440.820 ms | 4.6% faster |
| 10 | 228.913 ms | 192.482 ms | 15.9% faster | 571.729 ms | 573.605 ms | 0.3% slower | 809.385 ms | 775.331 ms | 4.2% faster |
| 50 | 914.943 ms | 768.871 ms | 16.0% faster | 2,360.440 ms | 2,362.510 ms | 0.1% slower | 3,310.764 ms | 3,164.197 ms | 4.4% faster |

The total-time min/median/max ranges were 331.311/333.404/345.962 versus
314.674/318.810/322.279 ms (2 notes), 453.202/462.168/467.130 versus
434.387/440.820/455.504 ms (5), 805.167/809.385/828.844 versus
772.929/775.331/810.795 ms (10), and 3,289.682/3,310.764/3,368.414 versus
3,137.426/3,164.197/3,177.510 ms (50), nested then compact. Proof-generation
standard deviations were 4.955/2.406, 4.520/7.258, 9.108/13.945, and
26.808/14.586 ms. WTNS decode medians ranged from 2.540 to 29.480 ms and
self-verification from 0.697 to 0.725 ms, with no representation-dependent
effect.

Peak RSS came from separate macOS `/usr/bin/time -l` processes. `Load RSS`
exits after authenticated parsing; `proof RSS` includes the key, WTNS,
assignment, FFT/MSM scratch, proof, and self-verification. Matrix payload is an
exact retained-array calculation; RSS is the operating-system high-water mark.

| Notes | Matrix payload nested -> compact | Load RSS nested -> compact | Load reduction | Proof RSS nested -> compact | Proof reduction |
|---:|---:|---:|---:|---:|---:|
| 2 | 35.6 -> 22.4 MiB | 161.0 -> 111.3 MiB | 30.9% | 198.4 -> 143.1 MiB | 27.9% |
| 5 | 47.2 -> 33.4 MiB | 217.4 -> 150.7 MiB | 30.7% | 259.9 -> 180.7 MiB | 30.5% |
| 10 | 84.7 -> 57.6 MiB | 377.9 -> 242.7 MiB | 35.8% | 442.3 -> 315.4 MiB | 28.7% |
| 50 | 342.6 -> 234.1 MiB | 1,412.7 -> 870.6 MiB | 38.4% | 1,736.3 -> 1,191.7 MiB | 31.4% |

The first production sweep also found and fixed a benchmark-visible parser
defect: pass one used `SeekFrom::Current(32)` per coefficient. Seeking a
`BufReader` discarded its buffer and made the 50-note parse about five times
slower. A sequential buffered read reduced compact auth+parse from a 4,431 ms
median to 769 ms. This is the implementation measured above.

Differential tests cover empty and duplicate-bearing randomized rows, exact H
vectors, fixed-randomizer proof equality, normal randomized proving, and final
verification against arkworks. The parallel-native production gate is positive:
compact matrices reduce full-proof RSS about 28-31%, reduce end-to-end latency
about 4%, and leave reusable-key proof latency unchanged. Remaining promotion
gates are:

- production zkey load RSS/time and whole-proof RSS/time on serial native,
  portable WASM, and threaded WASM.

Promote it only if those gates pass and the retained-memory win survives real
artifacts. Until then, the current arkworks-compatible matrix remains the safer
default.

### 5. Algebraically optimized Poseidon (promoted)

`curvy-core/poseidon-optimized` is now the default, with passthrough features in
the WASM, Node, and C binding crates. `default-features = false` retains the
direct schedule as an oracle and size-sensitive fallback. The Rust generator
derives folded C, P, and sparse S tables from Curvy's canonical C/M file. Its output matched
circomlibjs's optimized C/M/P/S values for every arity. The committed 754 KiB
binary table has SHA-256
`d0c52916660a9de7e0d2ee457a741db6dcf28f6e1ae253c9f2bca9be79bfd36e`;
it records and validates the canonical-source digest plus a digest for every
emitted table. CI regenerates it byte for byte.

The detailed release A/B used seven samples of 3,000 chained hashes per arity on
the same arm64 host. Ranges below are min-median-max. `Multiplies` counts BN254
field multiplications in the S-boxes and matrix layers; loop/index arithmetic is
not included.

| Arity | Direct us/hash | Optimized us/hash | Latency reduction | Throughput | Multiplies direct -> optimized | Arithmetic reduction |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6.226-6.297-6.387 | 5.288-5.482-8.946 | 12.9% | 1.15x | 472 -> 416 | 11.9% |
| 2 | 10.931-11.035-11.140 | 7.650-7.753-7.893 | 29.7% | 1.42x | 828 -> 600 | 27.5% |
| 3 | 17.573-17.632-17.776 | 10.167-10.224-10.246 | 42.0% | 1.72x | 1,288 -> 784 | 39.1% |
| 4 | 27.284-27.383-27.456 | 13.617-13.644-13.733 | 50.2% | 2.01x | 2,000 -> 1,040 | 48.0% |
| 5 | 37.796-38.170-38.202 | 16.533-16.725-17.140 | 56.2% | 2.28x | 2,772 -> 1,272 | 54.1% |
| 6 | 52.195-52.505-52.680 | 20.402-20.598-20.677 | 60.8% | 2.55x | 3,836 -> 1,568 | 59.1% |
| 7 | 68.381-68.776-69.481 | 24.179-24.365-24.703 | 64.6% | 2.82x | 4,992 -> 1,856 | 62.8% |
| 8 | 84.120-84.333-84.744 | 27.802-28.021-28.126 | 66.8% | 3.01x | 6,156 -> 2,124 | 65.5% |
| 9 | 100.228-100.460-100.651 | 31.172-31.267-31.442 | 68.9% | 3.21x | 7,220 -> 2,360 | 67.3% |
| 10 | 130.811-131.052-131.621 | 37.554-37.610-37.696 | 71.3% | 3.48x | 9,416 -> 2,816 | 70.1% |
| 11 | 141.604-142.160-142.601 | 39.785-40.003-40.352 | 71.9% | 3.55x | 10,260 -> 3,000 | 70.8% |
| 12 | 176.510-177.022-181.728 | 46.201-46.389-46.895 | 73.8% | 3.82x | 12,844 -> 3,484 | 72.9% |
| 13 | 215.374-216.798-217.185 | 53.291-53.452-53.524 | 75.3% | 4.06x | 15,834 -> 4,004 | 74.7% |
| 14 | 215.299-215.980-219.241 | 54.349-54.544-55.421 | 74.7% | 3.96x | 15,840 -> 4,080 | 74.2% |
| 15 | 257.489-258.185-258.946 | 61.008-61.135-61.698 | 76.3% | 4.22x | 19,008 -> 4,608 | 75.8% |
| 16 | 304.724-304.953-305.355 | 68.478-68.651-69.013 | 77.5% | 4.44x | 22,576 -> 5,168 | 77.1% |

For state width `t` and `R_P` partial rounds, the direct matrix layers cost
`(8 + R_P) * t^2` multiplications. The factored schedule costs
`8 * t^2 + R_P * (2t - 1)`, saving exactly `R_P * (t - 1)^2`; both schedules
retain the same `3 * (8t + R_P)` S-box multiplications. This explains why the
measured gain grows with arity and closely tracks the arithmetic reduction.

An application-level, nine-sample benchmark used the real
`IndexedMerkleTree`. Bulk-building 4,096 leaves at depth 16 fell from
42.678/43.259/43.637 ms to 30.253/30.532/30.813 ms, 29.4% lower median latency.
Inserting 256 leaves into a depth-30 tree fell from
80.078/80.720/81.678 ms to 56.794/57.311/57.596 ms, 29.0% lower. This includes
tree storage, reverse-index bookkeeping, and allocation, not just permutation
time.

Across 11 fresh processes, first binary-hash initialization was
3.972/4.295/4.626 ms direct versus 1.872/1.922/2.057 ms optimized, a 55.3%
median reduction. That optimized figure has since been superseded by per-arity
lazy decoding (below). Packed tables make the current benchmark executable 314,992
bytes smaller (1,668,656 -> 1,353,664, 18.9%) and the raw portable WASM module
301,986 bytes smaller (11.8%) than the decimal-table reference build. The field
values have high entropy, however, so the WASM gzip grows by 231,520 bytes
(24.6%), from 942,085 to 1,173,605 bytes. The resulting 1.12 MiB module is
still substantially smaller than the approximately 5 MB Go artifact it
replaces, so this deployment-size tradeoff was accepted.

#### 5a. Per-arity lazy constant decoding

The first release decoded all 16 arities on the first hash: 24,060 field
elements and 64 table digests, about 754 KiB of work, before a single
permutation could run. The protocol only hashes at arities 1, 2, 3, and 5, and
a binary Merkle node needs 384 of those 24,060 elements.

Loading is now split. A framing pass still runs once and still validates the
magic, format version, `R_F`, the canonical source digest, and every arity's
declared table dimensions, but it decodes no field elements. Each arity's
SHA-256 table checks and field conversion are deferred to the first hash at
that arity and cached in a per-arity `OnceLock`. Structural validation
therefore stays eager and loud; only the expensive per-arity work moves.

Measured on one arm64 host, 15 fresh processes each, first binary-hash
initialization (min/median/max):

| Build | Cold init | Peak RSS |
|---|---:|---:|
| Eager decode | 2.228/2.710/6.367 ms | 3,552 KiB |
| Lazy decode | 0.030/0.046/0.309 ms | 1,944 KiB |

A 59x median reduction in first-hash latency and 1.57 MiB less resident memory.
Decoding canonically rather than reducing every value modulo the field is part
of that: rejecting an out-of-range table value is both stricter and cheaper
than folding it into range.
The saving has two parts: the decoded field elements for 15 unused arities are
never allocated, and the pages of the embedded table backing them are never
touched. Steady-state throughput is unchanged - per-arity digests were
identical to the eager build across all 16 arities - because the hot path
trades a `LazyLock` dereference plus a `BTreeMap` lookup for one `OnceLock`
acquire load.

Deferred decoding means an arity nobody hashes at never has its table digests
checked. `every_arity_decodes_and_matches_its_digests` forces all 16 so the
committed artifact stays fully authenticated under `cargo test`, and the
all-arity differential gate does the same as a side effect.

The ordinary permutation remains a unit-test oracle. The fast differential
gate covers boundary/basis inputs and 256 deterministic full-width inputs per
arity; an ignored release gate raises that to 10,000 per arity. The existing
poseidon-lite, independent `pso-poseidon`, Merkle, note, EdDSA, witness, WASM,
and FFI vectors remain unchanged. The 160,000-case release gate was also run
successfully. Regenerated tables, independent native vectors, FFI, native Node,
371 portable-WASM JS parity checks, SIGNET v1/v2 portable-WASM parity, and a
threaded-WASM all-features build all passed before promotion. Native x64 and
real-browser timing remain useful portability measurements, not correctness or
rollout blockers.

Primary references: the [Poseidon efficient-implementation appendix](https://eprint.iacr.org/2019/458.pdf)
and [circomlibjs's optimized runtime](https://github.com/iden3/circomlibjs/blob/main/src/poseidon_opt.js).

## Follow-up status

Resident SAGE, manifest loading, Node queueing, bounded reads, shared artifact
organization, and the QAP/MSM audit are implemented. The current validation,
measurement results, and remaining hardware/release gates are tracked in
[SECURITY_PERFORMANCE_AUDIT.md](SECURITY_PERFORMANCE_AUDIT.md).

## Benchmark discipline

For proving changes, record artifact digests, assignment/domain sizes, target,
worker count, window policy, chunk size, allocator, warm/cold file state, sample
count, proof verification, and peak-memory method. For browser results, also
record browser/OS/device, cross-origin isolation, shared-memory availability,
WASM module variant, worker placement, and thermal behavior.

## Resident follow-up, 5 September 2026

Implemented compact matrices as the Node default; manifest-authenticated forward
resident loading; SAGE and independently pinned compiled caches in resident
Rust, Node, and C APIs; and a bounded Node proof queue that runs directly on the
private Rayon pool. Experimental per-active-proof witness, FFT, and MSM scalar
conversion buffers have explicit idle retention caps and zeroization on all
exit paths. They remain opt-in after repeated-proof measurements failed to show
a useful speed improvement. [Full measurements](RESIDENT_OPTIMIZATIONS.md) also
correct the earlier reader benchmark's duplicate previous/fixed binaries.
