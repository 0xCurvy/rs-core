# curvy-prover

Authenticated Curvy witness evaluation and self-verified arkworks Groth16
proving for snarkjs artifacts.

- `ResidentProver` (HAWK profile) loads a deployment's `curvy-graph-v1`
  artifact and matching `.zkey` and keeps the authenticated parsed key for
  reuse.
- `StreamingProver` (SPARROW profile) reads the key sequentially with bounded
  memory.
- `Prover` is the lower-level API for an existing snarkjs `.wtns` assignment.

The crate also provides the `curvy-native-prover` executable and the standalone
prover WASM module.

## Install

```toml
[dependencies]
curvy-prover = "=0.1.2"
```

## Prove from circuit input JSON

```rust,no_run
use std::{fs::File, io::BufReader};
use curvy_prover::ResidentProver;

let mut zkey = BufReader::new(File::open("circuit.zkey")?);
let graph = std::fs::read("circuit.graph.bin")?;
let prover = ResidentProver::from_artifacts_reader(
    &mut zkey,
    "0000000000000000000000000000000000000000000000000000000000000000",
    &graph,
    "0000000000000000000000000000000000000000000000000000000000000000",
)?;
let proof = prover.prove_json(r#"{"amount":"42"}"#)?;

println!("{}", proof.proof_json);
println!("{}", proof.public_signals_json);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Both artifact hashes are checked before their parsers run. Every proof is
verified before it is returned.

File-backed native callers should use `from_artifacts_reader` or
`Prover::from_zkey_reader`. These hash the zkey in a first pass, then
re-authenticate each buffered chunk before parsing it, including after seeks,
so a file changed during loading cannot substitute key bytes. The opt-in
`zkey-single-pass` parser reads through the same authenticated chunk view and
also checks its forward-pass digest before returning the key.

WASM and C callers that pass the zkey as bytes get point sections decoded in
bounded 8 MiB chunks. Use `StreamingProver` when the complete parsed proving key
is too large for the target.

Witness-only callers can use `WasmWitnessGraph.calculatePacked` (WASM) or
`curvy_witness_graph_calculate_packed` (C ABI). Both return concatenated
canonical 32-byte big-endian field elements.

## Arithmetic and artifact authentication

BN254 field and curve arithmetic and final proof verification use arkworks.
Proof assembly uses the `ark-groth16` 0.6 equations with batch-affine BN254
MSMs.

Bulk zkey points are parsed without a per-point subgroup check, so zkey bytes
must be authenticated before parsing:

- native whole-key loads authenticate the pinned zkey digest before parsing and
  recheck each reader chunk before exposing its bytes;
- `zkey-single-pass` loads use the same authenticated chunk view;
- manifest loads authenticate each complete chunk before parsing, against a
  manifest whose own pin is the trust root (see
  [Additional resident paths](#additional-resident-paths));
- callers of `StreamingProofBuilder` or the raw WASM framing methods
  (`beginZkey`, `beginZkeySection`, `pushZkeySectionChunk`, `endZkeySection`)
  must authenticate the bytes before supplying them; and
- every completed proof is verified with arkworks before it is returned.

## Features and execution targets

| Feature | Purpose |
|---|---|
| `std` | Native standard-library support; enabled by default |
| `bench` | Development-only native/WASM arithmetic benchmark kernels; implies `sparrow` |
| `compact-matrix` | Two-pass CSR zkey matrices and direct compact QAP evaluation |
| `parallel` | Opt-in QAP, FFT, and MSM work on one host-initialized Rayon pool |
| `signet-v2` | Opt-in compact SIGNET v2 witness-graph decoder, without SAGE or SPARROW |
| `zkey-manifest` | Shared authenticated chunk manifests for resident and streaming loads |
| `zkey-single-pass` | Opt-in one-pass zkey parse over pre-authenticated chunks; the Groth16 header must precede the query sections |
| `sage` | Opt-in SAGE for resident proving, including independently pinned compiled caches |
| `scratch` | Experimental caller-owned, zeroized witness/FFT/MSM-scalar buffers; implies compact matrices |
| `sparrow` | Opt-in SPARROW and SAGE bounded-memory sequential-zkey proving |
| `wasm` | Portable wasm-bindgen prover API |
| `wasm-simd-msm` | Opt-in SIMD batch-affine BN254 G1/G2 MSM; takes effect only on wasm32 with `simd128` |
| `wasm-simd-fft` | Opt-in SIMD witness-map FFT; takes effect only on wasm32 with `simd128` |
| `wasm-simd-selftest` | Development only, never shipped: in-WASM self-tests and kernel benchmark for the SIMD features |
| `wasm-threads` | Shared-memory browser prover with `initThreadPool(n)` |

Without `parallel`, proving runs on one thread. With `parallel`, the
`curvy-native-prover` executable reads `CURVY_PROVER_NUM_THREADS` (1 to 64,
default 1); library consumers configure the global Rayon pool. Threaded WASM
hosts set the worker count by awaiting the generated module's
`initThreadPool(n)`. Proof calls never construct nested pools. Do not enable
`ark-ec/parallel` or `ark-groth16/parallel` in threaded WASM builds: their MSMs
create private Rayon pools that browser workers cannot spawn.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
commands, output directories, and threaded-browser requirements.

## Streaming prover (SPARROW)

SPARROW (Streaming Prover Architecture for Resource-Restricted One-pass
Workflows) is the opt-in bounded-memory Groth16 prover. It and its SAGE witness
engine are not in the default features or the published WASM builds.
`StreamingProver` never retains the zkey or a complete query section. Browser
builds export `WasmStreamingProver`.

See [SPARROW.md](SPARROW.md) for artifact publication, native and browser flows,
the SAGE cache, tuning, and the security boundary.

## Published examples

- `artifact_manifest_check` validates the graph, zkey, WTNS fixture,
  verification key, and R1CS digest as one release bundle. It fully parses raw
  or zstd graphs and WTNS data. Ceremony and constraint semantics still require
  `snarkjs zkey verify` and `snarkjs wtns check`.
- `zkey_chunk_manifest` generates and fully verifies a one-pass SPARROW chunk
  manifest.
- `derive_sage_cache` derives a SAGE program for hosts that manage their own
  validated local cache.

## Additional resident paths

`Prover::from_zkey_manifest_reader` (feature `zkey-manifest`) accepts any `Read`
source starting at byte zero and a `ZkeyChunkManifest` built from the manifest
pin and the zkey pin. Each complete chunk is authenticated against the manifest
before parsing; truncated or excess streams fail. The Groth16 header must
precede the query sections. The manifest pin is the sole trust root: the zkey
pin is only compared with the whole-file digest the manifest claims, and that
digest is not recomputed during loading. Run `ZkeyChunkManifest::verify_reader`,
which recomputes it, before publishing the manifest pin.

`ResidentProver::with_sage` and `from_compiled_sage` (feature `sage`) use SAGE
with a resident proving key. Compiled caches require both their own pin and the
expected source graph pin. All resident constructors validate assignment size.

The experimental `scratch` feature adds `ProofWorkspace` and
`prove_json_with_workspace`, alongside `curvy_witness::WitnessWorkspace`:

- each active proof needs its own exclusive mutable workspaces;
- construct them with explicit maximum retained byte counts; a zero limit
  retains nothing;
- the limits bound idle capacity, not active peak memory;
- owned buffers are zeroized on success, error, panic unwinding, and drop; and
- MSM buckets are not reused.

Default APIs retain no workspaces between proofs.

`prove_assignment`, `prove_json`, and `prove_wtns` verify the proof before
returning it. Low-level `Prover::prove` and `prove_with_workspace` do not; their
callers must verify the proof. Direct assignments must begin with the constant
one signal.

[Release validation tooling](../../tools/artifacts/README.md) stages and validates
the exact bundle against its independently pinned PTAU and reference witness.
