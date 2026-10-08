# wasm-field: the ceiling for BN254 MSM arithmetic in WebAssembly

Isolated proof of concept. It is **not** part of the rs-core workspace
(`[workspace]` in its own `Cargo.toml`), so `cargo build --workspace` and CI
never build it. It depends only on the arkworks 0.6.0 crates already pinned in
the root `Cargo.lock`, which was copied here and pruned by cargo.

Question: identical Rust proves a 2-note proof in 1.52 s natively but 3.99 s in
portable WASM on the same Apple M-series host. MSM bucket accumulation
dominates, and arkworks' 4x64-bit Montgomery `Fq` needs 64x64->128 products
that wasm32 has to emulate. How fast can the arithmetic get in WASM, and what
would that buy a portable browser proof?

**Answer.** A 4-lane simd128 Montgomery multiplication on nine 29-bit limbs
runs at 11.2–11.9 ns per element in V8, 1.2–1.27x native arkworks (9.4 ns) and
3.1x faster than arkworks compiled to WASM (35–37 ns). A batch-affine MSM
kernel built on it (production's `AffineBuckets` algorithm, unchanged
scheduling) is 1.9–2.3x faster than the same kernel on arkworks' `Fq` for G1,
and 2.0–2.4x for G2, in Node and Chromium alike, which is 1.3–1.4x the time of
native arkworks (down from 2.6–3.0x). MSM is 77–81% of a portable proof, so the
projected portable 2/5/10-note browser proofs get **1.55–1.66x faster**
(Chromium: 3.88 -> ~2.45 s for 2 notes), 1.39–1.41x if only G1 is ported. Measured 1 Oct 2026, Apple M4
Pro (10P + 4E), Rust 1.94.0, Node 22.22.3 (V8 12.4), Chromium 143.0.7499.4
(Playwright 1.57); host 1-minute load 4–19 (an Android emulator, iOS simulator
and desktop apps were running), each table median of 3 (7 for fields).

## Results

### A. Fq and Fq2 arithmetic (ns per operation; native / Node / Chromium)

Throughput = 256 independent operations per pass (the MSM pattern); latency =
a dependent chain. simd4 is per element (a 4-lane operation counts four); its
"from/to arkworks" row is the transposition into/out of lane form, on top of
u29x9's conversion.

| Op | ark | u32x8 | u29x9 | simd4 |
|---|---:|---:|---:|---:|
| mul, throughput | 9.36 / 35.21 / 36.95 | 29.14 / 37.14 / 38.64 | 20.78 / 22.38 / 22.40 | — / **11.23 / 11.88** |
| mul, latency | 12.60 / 36.36 / 37.16 | 34.47 / 38.53 / 39.24 | 24.52 / 28.95 / 31.03 | — / 12.57 / 12.39 |
| square, throughput | 9.07 / 27.65 / 31.19 | 31.12 / 37.23 / 39.01 | 19.78 / 18.28 / 18.37 | — / **9.62 / 10.10** |
| square, latency | 12.44 / 27.23 / 30.75 | 35.54 / 41.39 / 38.75 | 25.25 / 27.10 / 28.23 | — / 10.21 / 10.30 |
| add, throughput | 4.35 / 6.36 / 6.33 | 8.08 / 8.97 / 8.81 | 6.03 / 6.35 / 6.63 | — / 3.07 / 3.04 |
| add, latency | 3.01 / 2.39 / 2.40 | 3.41 / 3.69 / 3.28 | 9.15 / 10.11 / 9.35 | — / 4.70 / 4.81 |
| sub, throughput | 2.40 / 5.34 / 5.37 | 3.61 / 4.60 / 4.27 | 4.40 / 4.42 / 4.40 | — / 2.43 / 2.37 |
| sub, latency | 5.49 / 2.47 / 2.46 | 8.61 / 8.49 / 8.25 | 9.57 / 13.75 / 13.94 | — / 3.65 / 3.66 |
| from arkworks | 0.92 / 1.75 / 1.80 | 0.83 / 4.14 / 4.29 | 20.15 / 21.17 / 21.72 | — / +1.03 / +1.04 |
| to arkworks | 1.01 / 2.45 / 2.51 | 1.11 / 2.44 / 2.64 | 26.82 / 26.83 / 26.69 | — / +2.08 / +2.00 |
| inverse (via arkworks) | 1,444 / 2,256 / 1,563 | 1,468 / 2,226 / 1,515 | 1,521 / 2,298 / 1,570 | — |

| WASM / native arkworks | mul Node | mul Chromium | square Node | square Chromium | mul vs WASM arkworks |
|---|---:|---:|---:|---:|---:|
| ark | 3.76 | 3.95 | 3.05 | 3.44 | 1.00x |
| u32x8 | 3.97 | 4.13 | 4.10 | 4.30 | 0.95x |
| u29x9 | 2.39 | 2.39 | 2.02 | 2.03 | 1.57x |
| simd4 | **1.20** | **1.27** | **1.06** | **1.11** | **3.13x** |

Fq2 (throughput): arkworks mul 35.3 / 116.9 / 122.8, square 34.4 / 95.1 / 93.2;
Karatsuba over u29x9 mul 85.0 / 89.8 / 114.1, square 56.2 / 53.4 / 62.5; the
G2 kernel's 4-element layout (`Fq2x4`, 3 `mul4` per 4 products) mul
— / **45.4 / 49.5**, square — / **27.9 / 29.2**, add/sub 2.4–3.2 (2.5–2.6x
faster than arkworks in WASM, 1.28–1.40x the time of native arkworks). Packing three base products of
a single Fq2 product into one `mul4` (`Fq2Simd` used as a scalar type) only
reaches 88.8 / 91.6: per-call transposition eats the gain.

u29x9 with LLVM auto-vectorization off (`-C no-vectorize-slp
-C no-vectorize-loops`, Node): mul latency 24.1 vs 29.0, sub latency 8.6 vs
13.8, throughput unchanged (see the codegen notes).

### B. Correctness

Every check compares against arkworks; any mismatch panics (a trap in WASM).
All passed: 14,457,635 checks per native run (seeds 1–3), 22,184,394 in Node
and in Chromium (the WASM runs add the simd4 and `Fq2Simd` sections). Per
representation: 200k random pairs (all ops, conversions, equality, zero test,
inverse every 64th), all pairs of 140 edge values (0, 1, 2, p-1, p-2,
(p±1)/2, 2^k-1/2^k/2^k+1 at every 29-, 32- and 64-bit limb boundary, both as
integers and as raw Montgomery forms, plus 8 random), 1M-step random chains of mixed
operations whose intermediates never leave the representation; for 9x29 raw
limbs: both encodings x and x+p, values to 2^257-1 and unnormalized limbs to
2^30-1 into mul/square, result bounds (< 2p, limbs < 2^29), generated vs loop
form; for simd4: each lane bit-identical to scalar u29x9 on all raw edges, plus
4M lane-chain checks; Fq2: 1.19M edge-pair checks, 50k random pairs, 250k-step
chains. Kernel: production's adversarial cases (repeated bases, P and -P,
identities, all-equal / zero / one / complementary / edge scalars) at widths 4
and 9 with batch sizes 1, 3 and default, plus every width 3..=16 on random
inputs, for G1 and G2 and every field/applier; and every timed MSM below
(2^14..2^19 points, random, generator and witness-like scalars) is asserted
equal to arkworks' `VariableBaseMSM`.

### C. G1 kernel (ms, random bases and scalars)

ark / u29x9 = the generic kernel instantiated with that field (production's
scalar batch application); simd = u29x9 with the 4-lane application and
reduction. Speedup = ark / simd in the same engine.

| Points | w | ark native | u29x9 native | ark Node | u29x9 Node | simd Node | ark Chromium | u29x9 Chromium | simd Chromium | speedup Node | speedup Chromium |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2^14 | 12 | 48.3 | 88.3 | 134.7 | 100.3 | 65.9 | 134.4 | 102.7 | 62.9 | 2.05x | 2.14x |
| 2^14 | 13 | 52.0 | 96.5 | 153.4 | 102.6 | 67.4 | 148.7 | 106.9 | 65.7 | 2.28x | 2.26x |
| 2^14 | 14 | 62.4 | 118.6 | 189.2 | 123.8 | 81.2 | 184.9 | 132.6 | 83.6 | 2.33x | 2.21x |
| 2^16 | 12 | 164.3 | 316.5 | 451.3 | 340.5 | 240.5 | 438.3 | 346.0 | 233.4 | 1.88x | 1.88x |
| 2^16 | 13 | 161.7 | 291.7 | 430.9 | 321.7 | 218.3 | 419.1 | 328.8 | 211.8 | 1.97x | 1.98x |
| 2^16 | 14 | 161.3 | 315.4 | 460.9 | 322.5 | 216.7 | 445.7 | 340.4 | 213.0 | 2.13x | 2.09x |
| 2^18 | 12 | 634.5 | 1,191.1 | 1,780.4 | 1,294.5 | 905.3 | 1,658.2 | 1,285.3 | 888.9 | 1.97x | 1.87x |
| 2^18 | 13 | 586.1 | 1,097.1 | 1,611.2 | 1,163.4 | 813.6 | 1,527.1 | 1,189.1 | 798.3 | 1.98x | 1.91x |
| 2^18 | 14 | 573.7 | 1,041.4 | 1,570.3 | 1,120.0 | 771.6 | 1,471.5 | 1,148.7 | 761.3 | 2.04x | 1.93x |

u32x8 (Node, 2^14): 137.3 / 152.4 / 195.8 ms at w12/13/14, no better than
arkworks. Accumulation per bucket addition at 2^18, w14: native arkworks 110 ns;
WASM arkworks 279–298, u29x9 216–222, simd 149–151 ns. Inside the kernel: the
one inversion per batch (through arkworks, conversions included) is 0.5–1.4% of
simd kernel time at w13–14 (2.3–2.8% at w12, where batches are smaller);
converting the bases from arkworks once costs 0.7 / 2.9 / 10.9 ms at
2^14 / 2^16 / 2^18 (1.4% of the kernel), not included above. Reduction (running
sums) drops from 145 to 50 ms at 2^18 w14 with the 4-segment SIMD reduction.

**(iii) Anchor.** The production kernel through `benchG1Msm` of an unmodified
`scripts/build-wasm.sh {nodejs,web} --bench` build, against this kernel on the
identical input (every base the generator, scalars `i * 0x9e3779b97f4a7c15 + 1`,
which are 64-bit, so only ~5 windows carry digits):

| Points | w | production Node | PoC ark Node | PoC simd Node | production Chromium | PoC ark Chromium | PoC simd Chromium |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2^14 | 13 | 27.9 | 24.2 | 16.5 | 26.6 | 22.9 | 15.9 |
| 2^16 | 13 | 73.2 | 65.2 | 60.7 | 71.5 | 60.2 | 48.2 |
| 2^18 | 12 | 338.7 | 287.9 | 256.2 | 312.2 | 280.6 | 242.1 |
| 2^18 | 13 | 261.6 | 223.6 | 182.0 | 250.0 | 215.0 | 173.9 |
| 2^18 | 14 | 283.9 | 253.8 | 211.7 | 275.9 | 232.3 | 201.9 |

Production takes 6–27% (typically ~15%) longer than the PoC's arkworks
instantiation (production here is SPARROW's point-major
`accumulate_affine_windows`; the PoC is the resident window-major loop), so
the PoC baseline is not slower than production. The simd gain is small on
this input because identical bases make the scheduler defer and spill a third
to two thirds of all additions to XYZZ overflow buckets, which stay scalar in
the PoC; it is not a
realistic input, so the projection below uses production-shaped inputs.

### D. G2 kernel (ms, random inputs)

| Points | w | ark native | u29x9 native | ark Node | Fq2/u29x9 Node | simd Node | ark Chromium | Fq2/u29x9 Chromium | simd Chromium | speedup Node | speedup Chromium |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2^14 | 12 | 148.1 | 278.5 | 415.9 | 368.7 | 186.3 | 393.2 | 342.3 | 181.2 | 2.23x | 2.17x |
| 2^14 | 13 | 166.2 | 310.1 | 465.1 | 445.6 | 198.2 | 438.3 | 372.1 | 201.8 | 2.35x | 2.17x |
| 2^14 | 14 | 208.9 | 403.8 | 611.1 | 641.5 | 251.8 | 580.7 | 472.9 | 262.2 | 2.43x | 2.21x |
| 2^16 | 12 | 481.3 | 898.1 | 1,310.2 | 1,010.1 | 636.1 | 1,313.0 | 1,157.6 | 632.6 | 2.06x | 2.08x |
| 2^16 | 13 | 459.2 | 883.4 | 1,309.7 | 1,038.5 | 607.6 | 1,296.1 | 1,110.5 | 612.6 | 2.16x | 2.12x |
| 2^16 | 14 | 499.5 | 947.3 | 1,421.8 | 1,272.2 | 624.1 | 1,389.1 | 1,200.8 | 645.8 | 2.28x | 2.15x |
| 2^18 | 13 | 1,745.4 | 3,219.8 | 4,849.7 | 3,480.6 | 2,283.7 | 4,639.4 | 4,062.7 | 2,287.5 | 2.12x | 2.03x |
| 2^18 | 14 | 1,733.1 | 3,218.0 | 4,778.8 | 3,564.8 | 2,228.9 | 4,537.4 | 3,908.1 | 2,138.6 | 2.14x | 2.12x |

simd = `Fq2x4` lanes (four independent G2 additions per group). G2 is 2.9–3.1x
the cost of G1 at equal size, as expected.

### E. Portable proofs and the Amdahl projection

Measured with the instrumented `scripts/build-wasm.sh web` build (production
keys, real inputs, median of 3 proofs after a warm-up; "proof" is `prove()`:
witness, Groth16, self-verification). Chromium:

| Notes | proof ms | witness | witness map (QAP+FFT) | MSM G1 | MSM G2 | other | MSM share |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 3,883 | 42 | 843 | 2,302 (59.3%) | 672 (17.3%) | 23 | 76.5% |
| 5 | 5,148 | 63 | 880 | 2,989 (58.1%) | 1,173 (22.8%) | 43 | 81.2% |
| 10 | 9,457 | 99 | 1,815 | 5,407 (57.0%) | 2,102 (22.1%) | 34 | 79.1% |

(Node: 4,149 / 5,349 / 9,485 ms, MSM 77.1 / 81.7 / 79.5%.) Each proof makes
four G1 calls (H: 2^18 points for 2/5 notes, 2^19 for 10, uniform scalars;
L, A, B1: 149k / 225k / 388k points) and one G2 call (B2). The witness scalars
were measured inside these proofs: 48 / 42 / 40% zeros, 32 / 26 / 23% ones,
the rest at least 2^64 (no other small values).

Method: for each call, the kernel ratio arkworks/simd was measured at the
call's size, `serial_window_bits` width (14 / 15 for H, 13 / 13 / 14 for the
witness queries) and scalar mix (`witness:ZERO:ONE` inputs), and applied to
the production call's measured time. Chromium ratios: H 1.98x (2^18) and
2.09x (2^19); witness G1 1.89–1.93x; G2 1.99–2.00x. *Conservative* takes, per
call, the smaller of that saving and the absolute ms saved on the synthetic
configuration (production's B1/B2 calls are cheaper than the synthetic ones
because those queries contain identity bases).

| Notes | proof ms | G1 only | G1 + G2 | G1 + G2, conservative | + per-call base conversion | if MSM cost 0 |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 3,883 | 2,758 (1.41x) | 2,424 (1.60x) | 2,452 (1.58x) | 1.56x | 4.26x |
| 5 | 5,148 | 3,701 (1.39x) | 3,117 (1.65x) | 3,139 (1.64x) | 1.61x | 5.23x |
| 10 | 9,457 | 6,734 (1.40x) | 5,685 (1.66x) | 5,691 (1.66x) | 1.62x | 4.89x |

Node gives 1.38–1.40x (G1 only) and 1.59–1.67x (G1 + G2); an earlier full
run on the same kernel code gave 1.55–1.66x (conservative, Chromium).

## How to run

```sh
cd poc/wasm-field
./build.sh            # native binary + wasm (production portable flags) + a no-SLP wasm
./run-all.sh          # every experiment; JSON into target/claude-scratch/wasm-field/results
python3 report.py     # the tables in this README
```

All build output, browser profiles and results live under
`target/claude-scratch/wasm-field/` (override with `WASM_FIELD_SCRATCH`).
Single commands:

```sh
S=../../target/claude-scratch/wasm-field
$S/pkg/poc-native test 1 200000 1000000 100                 # differential tests, native
node js/node.mjs $S/pkg/wasm_field_poc.wasm test 1 200000 1000000 100
node js/chromium.mjs $S/pkg/wasm_field_poc.wasm fields 1 7  # field microbenchmarks in Chromium
node js/node.mjs $S/pkg/wasm_field_poc.wasm msm 18 12,13,14 ark,u29x9,simd random 3      # G1
node js/node.mjs $S/pkg/wasm_field_poc.wasm msm 16 13 ark,simd witness:0.484:0.322 3 g2  # G2
```

`msm SIZE WIDTHS FIELDS INPUT REPS [g1|g2]`: SIZE is log2(points) below 64,
else a point count; INPUT is `random`, `generator` (production's
`phase_bench` input) or `witness:ZERO:ONE` (that fraction of 0 and 1 scalars,
the rest uniform, as measured in the production witnesses). Every run asserts
each result equals arkworks' `VariableBaseMSM::msm_bigint`.

`run-all.sh` also uses, when given:

- `ANCHOR_DIR`: the unmodified repository's
  `CURVY_WASM_OUT_DIR=$S/anchor scripts/build-wasm.sh {nodejs,web} --bench`
  (run with `CARGO_TARGET_DIR` and `TMPDIR` in the scratch directory);
  `js/anchor.mjs` times its `benchG1Msm` export.
- `INSTR_PKG`, `CASES`: an instrumented copy of the portable browser build
  (below) and a benchmark case file (production 2/5/10-note zkeys and graphs,
  circuit input, expected publics); `js/proof-phases.mjs` runs real proofs.

The instrumented copy is `git archive HEAD` extracted into the scratch
directory with `instrument-prover.patch` applied (`patch -p1`). The patch adds
a `phase_timing` module that accumulates `performance.now()` deltas around
witness calculation, `witness_map_from_matrices` (QAP + FFTs), every
`msm::msm_bigint` call (G1 / G2, size, and the scalar mix: zeros, ones,
< 2^64) and verification, exported as `phaseTimings()` / `msmCalls()`; then
`scripts/build-wasm.sh web` builds it. The arithmetic is untouched; the timers
add two JS calls per phase. Every timed proof self-verifies inside `prove()`
and its public signals are checked.

## Layout

| File | Contents |
|---|---|
| `src/field.rs` | `PocField` trait; `Ark` (arkworks `Fq`, the baseline) |
| `src/u32x8.rs` | 8x32-bit saturated limbs, no-carry CIOS, R = 2^256 (free conversion) |
| `src/u29x9.rs` | 9x29-bit unsaturated limbs, lazy carries; bounds argument in the module docs |
| `src/gen_u29.rs` | generated (`gen.py`), fully unrolled 9x29 mul/square, scalar and 4-lane SIMD |
| `src/simd.rs` | 4-lane simd128 9x29 (`U29x9x4`, limb-sliced), add/sub, loop-form references |
| `src/fq2.rs` | Fq2 = Fq[u]/(u^2+1): arkworks baseline, Karatsuba over 9x29, SIMD-lane variant |
| `src/lanes.rs` | `Lanes4`: 4-lane vectors of Fq (`U29x9x4`) and Fq2 (`Fq2x4`) |
| `src/msm.rs` | the batch-affine kernel, a port of production `AffineBuckets`, generic over curve and field |
| `src/simd_msm.rs` | 4-lane batch application (four Montgomery-trick chains, one inversion) |
| `src/simd_reduce.rs` | 4-lane running-sum reduction (four bucket segments per window) |
| `src/check.rs`, `src/simd_bench.rs` | differential tests; SIMD microbenchmarks and tests |
| `src/bench.rs`, `src/lib.rs`, `src/main.rs` | benchmarks, command dispatch, native runner |
| `js/` | Node and Chromium (Playwright from `tools/browser`) runners, anchor, proof phases |
| `instrument-prover.patch` | phase timers for a scratch copy of `crates/prover` (experiment E) |

The WASM module is a bare `cdylib` (no wasm-bindgen): it imports
`env.now_ms` (`performance.now()`) and `env.log`, so the identical `.wasm`
runs under Node and in a Chromium page. Chromium pages are served with
COOP/COEP (cross-origin isolated, 5 us timer resolution).

## Representations

1. **ark**: `ark_bn254::Fq`, 4x64-bit Montgomery (R = 2^256). In wasm32 every
   64x64->128 product is a `__multi3` call doing four 32x32 products.
2. **u32x8**: eight saturated 32-bit limbs, CIOS with u64 accumulators and
   gnark's no-carry variant (top word of p < 2^31 - 1). Same R as arkworks, so
   converting is a limb reinterpretation. Squaring reuses multiplication.
3. **u29x9**: nine unsaturated 29-bit limbs, R = 2^261, operand-scanning
   Montgomery with u64 column accumulators and one carry per outer iteration.
   *Why 9x29*: a column collects at most 2n products (a*b and q*p) plus one
   carry below 2^(64-w), so `2n * 2^(2w) + 2^(64-w) <= 2^64` must hold with
   n = ceil(256/w) (R > 4p keeps the [0, 2p) invariant). w = 32 and 30 fail
   (2^68, 2^64.17); w = 29, n = 9 gives 2^62.17 with 1.8 bits to spare and the
   fewest products (2n^2 = 162); w = 28 or 26 need 10 limbs (200 products).
   Values stay weakly reduced (< 2p, normalized limbs); multiplication accepts
   any value below 2^257 and limbs up to 2^30 - 1 (columns stay below
   2^63.5), so sums of reduced values may be multiplied unreduced. Squaring
   computes 45 cross products once. Add/sub carry-propagate and conditionally
   subtract 2p, branch-free.
4. **simd4**: representation 3, four independent elements limb-sliced into
   nine `v128`s; `i64x2.extmul_{low,high}_i32x4_u` yields four 29x29-bit
   products per two instructions (V8 arm64: UMULL/UMULL2). Lane results are
   bit-identical to u29x9 (tested). An f64/FMA variant was not built: exact
   products need a fused multiply-add, and wasm's only FMA
   (`f64x2.relaxed_madd`) may or may not fuse depending on the engine, so a
   correct kernel would have to fall back to two-product splitting (Dekker),
   about 17 flops per 52-bit limb product; it cannot beat 2 products per
   `extmul`.

Codegen findings that decided the results (all visible with `wasm-dis`):

- **`extmul` is fragile.** `core::arch::wasm32::u64x2_extmul_low_u32x4` is a
  generic `mul(zext, zext)`. LLVM folded the splatted p limbs into 64-bit
  vector constants and hoisted loop-invariant extends, after which the backend
  emitted `i64x2.mul`, which V8 emulates on arm64 (NEON has no 64-bit lane
  multiply). Loading the p splats with a volatile read (`gen_u29.rs`) restored
  `extmul` and took the 4-lane multiplication from 26.7 to ~11.5 ns per
  element.
- Splitting a 4-lane multiplication into two 2-lane halves to cut register
  pressure (`mul4_split`) did not help (21–22 ns per element).
- **SLP auto-vectorization hurts the scalar u29x9 path** the same way (it packs
  pairs of 29x29 products into `i64x2.mul`); the no-SLP build is reported
  beside it. Production builds use default flags, so an integration would need
  explicit SIMD (as here) or a crate-wide `-C no-vectorize-slp`.
- **Inlining every 4-lane multiplication into the kernel is slower.** Six
  inlined ~700-instruction `mul4` bodies in one function overwhelm V8's
  register allocator; calling them out of line made the SIMD kernel 1.9x
  faster. The scalar u29x9 multiplication is the opposite (out of line is
  slower), so only the SIMD calls are outlined.
- The loop form of the 9x29 multiplication was not fully unrolled by LLVM
  (69 ns natively); `gen.py` emits straight-line code with columns named by
  absolute index, so the operand-scanning shift is free renaming (21–25 ns).
- Liftoff vs TurboFan: V8 has no on-stack replacement for WASM, so a benchmark
  loop inlined into a function that runs once could stay in the baseline
  tier. Field results with `--no-liftoff` matched the default run (and
  `--liftoff-only` was up to 1.5x slower), so the reported numbers are
  optimized code.

## What are the limits?

**Per-operation WASM / native ratio** (vs native arkworks, throughput):
arkworks 3.8–4.0x for multiplication and 3.0–3.4x for squaring; u32x8 about
4x (saturated limbs still split every product into 32-bit halves, the same work
as `__multi3` minus the call); u29x9 2.4x / 2.0x; simd4 **1.20–1.27x /
1.06–1.11x**. Fq2: arkworks 3.3–3.5x, `Fq2x4` 1.28–1.40x. Natively, 9x29 is
2.2x slower than arkworks, so this is a WASM-only representation.

**The floor.** Native arkworks multiplies in 9.4 ns (throughput) / 12.6 ns
(latency), about 42 / 57 cycles at ~4.5 GHz. A 4-lane multiplication needs per
element 162 products = 81 `extmul` (two products each) + 81 lane adds + ~30
instructions for q, carries and normalization: ~190 vector instructions, at
least ~48 cycles (~10.6 ns) on four 128-bit pipes. It measures 11.2–11.9 ns, so
it sits at the NEON issue limit; 9x29 is already the fewest products without
in-loop carries, so there is no further multiplication headroom in this
formulation on this CPU. The kernel spends 149–151 ns per bucket addition
against ~92 ns of arithmetic (6 `mul4` + 1 `sqr4` + ~6 subtractions per
element) and 110 ns for native arkworks; the rest is lane transposition
(~9 ns), scalar classification and denominators, digit recoding, scheduling
and memory. A layout that avoids repacking and classifies in lanes might
approach native arkworks (~2.6x over WASM arkworks instead of 2.0x); that is
an estimate, not measured.

**MSM kernel speedup in WASM:** G1 1.87–2.33x, G2 2.03–2.43x over the same
kernel on arkworks, in both engines (largest at 2^14 with wide windows, where
the 4-segment reduction matters most).

**Whole proof (Amdahl):** MSM is 77–81% of a portable proof (G1 57–59%, G2
17–23%), the witness map 16–22%. Porting G1 and G2 gives 1.55–1.66x; G1 alone
1.39–1.41x; even a free MSM would stop at 4.3–5.3x. After the port the witness
map (QAP evaluation and Fr FFTs, 843 ms = 35% of the projected 2-note
proof) is the next limit; it has the same 64-bit multiply problem over Fr and
its butterflies are naturally 4-lane parallel, so the same technique could
plausibly bring the 2-note proof to ~1.9–2.0 s (~2x). That is an unmeasured
estimate. The native
proof (1.52 s) bounds what any WASM arithmetic work can reach.

## What a full integration needs

1. **Dispatch.** `msm.rs::batch_affine_msm` already picks BN254 G1/G2 by
   `TypeId`; add a `cfg(all(target_arch = "wasm32", target_feature =
   "simd128"))` branch running this kernel (G1: `U29x9` + `SimdApply`, G2:
   `Fq2Simd` + `SimdApply`). The PoC keeps production's `AffineBuckets`
   scheduling, so SPARROW's persistent per-window buckets
   (`accumulate_affine_windows`, `release_scratch`) map one-to-one. Native
   builds keep arkworks.
2. **Conversions.** Bases per call: 10–32 ms (G1) and 20–48 ms (G2) per proof
   call, already in the "+ per-call base conversion" column (about −0.04x).
   Scalars are untouched (same `BigInt` digits); window sums come back as
   arkworks points; the per-batch inversion goes through arkworks (0.5–3% of
   kernel time). Converting at key load would save the per-call cost but
   needs a custom proving-key layout; keeping both forms adds 76/148 bytes
   per G1/G2 base (about +185 MB at 10 notes), too much next to the
   270–660 MiB WASM heap peaks. SPARROW could decode chunk points straight into
   29-bit limbs.
3. **G2:** done here (`Fq2x4`, the same generic applier and reduction).
4. **Threading:** the kernel is per window and needs only per-worker scratch,
   so `wasm-threads` builds keep parallelizing windows over Rayon. Not
   measured; per-worker gains should carry over, unverified.
5. **Memory layout of bases:** array-of-structs `[u32; 9]` coordinates
   (76 / 148 bytes per G1 / G2 point vs arkworks' 72 / 136). A batch gathers
   random buckets, so a limb-sliced base layout would not remove the
   transposition (~1 ns per element per operand).
6. **Build and CI:** simd128 is already required by the portable build. Add
   differential tests run as WASM under Node (as `js/node.mjs ... test`), a
   codegen guard (`wasm-dis`, zero `i64x2.mul` in the kernel), and a
   performance gate.
7. **Code size:** ~1,500 hand-written lines (field, Fq2, lanes, applier,
   reduction, generator) plus ~1,700 generated, outside the tests.

## Risks

- **Coverage.** Only V8 on an Apple M4 Pro was measured. Firefox does not
  launch here; Safari (JavaScriptCore), x86-64 V8 (which lowers `extmul` to
  shuffles + PMULUDQ) and mobile ARM (the Galaxy Z Fold2's Cortex-A77 has two
  128-bit pipes, not four) are unmeasured, and the SIMD gain depends on vector
  multiply throughput. Measure the Fold2 and Safari before enabling by default.
- **Codegen fragility**, observed three times here: LLVM silently turned
  `extmul` into emulated `i64x2.mul` (2.4x slower multiplication), inlined SIMD
  bodies made V8's register allocation 1.9x slower, and SLP auto-vectorization
  slowed the scalar path. A Rust, LLVM or V8 update can regress speed with
  every test still green, hence the guards above.
- **Correctness.** Proofs self-verify, so a wrong MSM gives a rejected proof
  (denial of service for some witnesses), never an accepted invalid one. The
  bounds are argued and edge-tested and every benchmarked MSM matched
  arkworks, but production should also fuzz the field operations and the
  kernel natively and in WASM, with arkworks kept as the oracle.
- **Maintenance:** BN254-specific, WASM-only arithmetic beside arkworks,
  including generated code.
- **Memory:** per-call conversion adds a transient copy of the largest query
  (20 MB at 2^18 G1 points, 40 MB at 2^19). That is below the parse-time heap
  peak, but should be confirmed with `tools/browser/measure.mjs`.

## Recommendation

**Go, staged.** Portable browser proofs for 2/5/10 notes get ~1.6x faster
(Chromium 2-note 3.88 s -> ~2.45 s), with a contained change behind the
existing BN254 dispatch and arkworks kept as the fallback and test oracle.
Suggested order:

1. Port the G1 + G2 SIMD kernel behind a cargo feature in the
   wasm32 + simd128 path, with per-call conversion, WASM differential tests
   and the codegen guard in CI.
2. Measure threaded builds, the Fold2 and Safari, then switch it on by default.
3. Then the Fr FFT.

Do not integrate u32x8 (no gain), or scalar u29x9 without SIMD (1.4x, and
superseded).

## Scratch layout

Everything is under `target/claude-scratch/wasm-field/`. `results/` holds the
JSON behind these tables (`report.py`), and `results-run1/` holds an earlier
full run on the same kernel code. `results-run2-g1-loaded/` is the G1 table
from a run hit by a load spike (20–27), which was re-measured. Build
directories were deleted after the runs.
