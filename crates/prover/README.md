# curvy-prover — arkworks Groth16 over snarkjs artifacts

An arkworks Groth16 prover (**ark-groth16 CircomReduction**) over snarkjs
on the protocol's circuits, using the production `.zkey`s and real witnesses. `src/zkey.rs` + `src/qap.rs` are vendored from `ark-circom 0.5.0`
(MIT/Apache-2.0) minus its wasmer witness calculator, so one crate builds both
**native** (rayon, `parallel` feature) and **wasm32** (single-threaded).

Every proof produced here was **cross-verified by snarkjs** (`groth16.verify`
against the zkey-derived vkey) — i.e. accepted by the exact pairing check the
on-chain verifier runs.

## Results (2026-07-04, Apple M4 Pro 14-core, Node 22)

Prove step only; witnesses precomputed (circom wasm witness gen is ~77 ms for
aggregation and unchanged across provers). snarkjs = multithreaded (worker
threads). zkey parse happens once per session and is excluded from prove times.

| | aggregation `_2_3_30` (26k constraints) | pending-commit `_5_30` (226k) |
|---|---|---|
| snarkjs prove (Node, MT) | 560 ms | 3,020 ms |
| **ark native, rayon 14-core** | **89 ms (6.3×)** | **389 ms (7.8×)** |
| ark native, 1 thread | 676 ms | — |
| **ark wasm, 1 thread (Node)** | **1,822 ms (0.31×)** | **7,710 ms (0.39×)** |
| zkey parse (validated, as vendored) | 1.3 s / 4.0 s (native/wasm) | 8.1 s / 23.9 s |
| **zkey parse (unchecked + parallel)** | **15 ms / 20 ms** | **60 ms / 134 ms** |

**Real browser run** (headless Chrome 150, cross-origin isolated page, same
machine; snarkjs uses its own workers across all 14 cores in every row):

| aggregation `_2_3_30` | prove (median) | vs snarkjs (529 ms) |
|---|---|---|
| ark wasm + rayon, 14 threads | **261 ms** | **2.0×** |
| ark wasm + rayon, 8 threads | 277 ms | 1.9× |
| ark wasm + rayon, 4 threads | 507 ms | ≈1× (worst case: snarkjs still had 14 cores) |
| ark zkey parse (browser, once) | 3.8 s | — |

## What this decides

- **Server (batch-prover): switch.** Native ark-groth16 is already
  rapidsnark-class on the 226k circuit (3.0 s → 0.39 s) with zero C++/asm
  packaging pain, pure vetted arkworks deps, and zkey parsed once at startup.
  There is no reason to bring in rapidsnark for this workload.
- The zkey parse cost was ~100% per-point curve/subgroup validation (ark-circom's
  `Affine::new` on ~1M G1 + ~230k G2 per load of a static artifact). This crate's
  vendored `zkey.rs` now uses `new_unchecked` + rayon-parallel section conversion,
  with a vk-anchor spot-check; artifact integrity belongs on the .zkey itself
  (content hash, once). Cold start: pending 23.9 s → **134 ms** in-browser.
  A long-lived worker is still right (don't re-fetch 129 MB), but parse no
  longer matters.

## Reproduce

```bash
# witnesses + baselines: copy scripts/dump-witnesses.test.ts into
# a project that can drive the TS witness builders, set POC_OUT_DIR, and run it with
# vitest — it writes agg.wtns / pending.wtns / *-vkey.json and prints the
# snarkjs prove baselines.

cargo build --release
target/release/curvy-prover <circuit.zkey> <witness.wtns> [iters] [out-prefix]
RAYON_NUM_THREADS=1 target/release/curvy-prover ...   # single-thread baseline

# wasm (single-threaded):
cargo build --target wasm32-unknown-unknown --release --no-default-features --features "std,wasm"
wasm-bindgen --target nodejs --out-dir pkg-node target/wasm32-unknown-unknown/release/prover_poc.wasm
printf '{ "type": "commonjs", "main": "prover_poc.js" }\n' > pkg-node/package.json
# then: new WasmProver(zkeyBytes) once, .proveOnly(wtnsBytes) per proof
```

## wasm + rayon threads (browser)
> Needs nightly + build-std + atomics, plus the
>  explicit link flags (shared imported memory, TLS exports for wasm-bindgen's
>  threads transform)

```bash
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals \
  -C link-arg=--shared-memory -C link-arg=--import-memory \
  -C link-arg=--max-memory=2147483648 \
  -C link-arg=--export=__heap_base -C link-arg=--export=__data_end \
  -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size \
  -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base' \
cargo +nightly build --release --target wasm32-unknown-unknown \
  -Z build-std=panic_abort,std --no-default-features --features std,wasm-threads
wasm-bindgen --target web --out-dir pkg-web-threads target/wasm32-unknown-unknown/release/prover_poc.wasm
```

## browser bench: COOP/COEP server + page in www/

```bash
node www/server.mjs   # http://localhost:8787/?threads=N  (ark+rayon, then snarkjs)
```