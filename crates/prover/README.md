# curvy-prover

Authenticated Curvy witness evaluation and self-verified arkworks Groth16
proving for existing snarkjs artifacts.

`CircuitProver` combines a deployment's `curvy-graph-v1` artifact and matching
`.zkey`. `Prover` can instead consume an existing snarkjs `.wtns` assignment.
This crate also publishes the `curvy-native-prover` executable and can be built
as the standalone prover WASM module.

## Install

```toml
[dependencies]
curvy-prover = "=0.1.0-rc.4"
```

## Prove from circuit input JSON

```rust,no_run
use curvy_prover::CircuitProver;

let zkey = std::fs::read("circuit.zkey")?;
let graph = std::fs::read("circuit.graph.bin")?;
let prover = CircuitProver::from_artifacts(
    &zkey,
    "0000000000000000000000000000000000000000000000000000000000000000",
    &graph,
    "0000000000000000000000000000000000000000000000000000000000000000",
)?;
let proof = prover.prove_json(r#"{"amount":"42"}"#)?;

println!("{}", proof.proof_json);
println!("{}", proof.public_signals_json);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Both artifact hashes are checked before their respective parsers run. Generated
proofs are verified internally before being returned.

## Cryptographic and audit boundary

The prover intentionally keeps BN254 field arithmetic, curve operations, and
final verification in arkworks. The default serial path delegates proof
assembly directly to stock `ark-groth16` 0.6. The opt-in `parallel` path uses a
small Curvy assembly layer with the same equations so large MSMs run on the
Rayon pool already initialized by the host. It does not implement separate
field or curve formulas. SPARROW additionally changes evaluation order,
batching, and memory ownership while using the same scalar recoder and arkworks
group operations.

Bulk zkey points are constructed without repeating a subgroup check for every
point. That optimization is inside an explicit artifact trust boundary:

- native whole-key loads authenticate the pinned zkey digest before parsing;
- the one-pass path authenticates each complete manifest chunk before parsing;
- direct users of `SparrowProofBuilder` must perform one of those
  authentication steps before supplying bytes; and
- every completed proof is verified with arkworks before it is returned.

The browser two-response fallback authenticates its first response before proof
construction, then parses and hashes a freshly opened second response. Its final
digest comparison and proof verification gate the result, but unlike manifest
mode it does not authenticate each second-response byte before parsing it.

This separation keeps the project-owned audit surface focused on artifact
framing, witness/QAP evaluation, scalar recoding, bucket scheduling, and
lifecycle management. It does not mean the crate has received an external
security audit. The arithmetic layer remains in arkworks.

## Features and execution targets

| Feature | Purpose |
|---|---|
| `std` | Native standard-library support; enabled by default |
| `bench` | Development-only native/WASM arithmetic benchmark kernels; implies `sparrow` |
| `parallel` | Opt-in QAP, FFT, and MSM work on one host-initialized Rayon pool |
| `signet-v2` | Opt-in compact SIGNET v2 witness-graph decoder, without SAGE or SPARROW |
| `sparrow` | Opt-in SPARROW and SAGE bounded-memory sequential-zkey proving |
| `wasm` | Portable wasm-bindgen prover API |
| `wasm-threads` | Shared-memory browser prover with `initThreadPool(n)` |

Without `parallel`, the ordinary prover calls stock serial arkworks. With
`parallel`, the native executable accepts `CURVY_PROVER_NUM_THREADS=1..64` and
defaults to one thread; library consumers can configure Rayon globally.
Threaded WASM hosts choose the worker count by awaiting the generated module's
`initThreadPool(n)`. Proof calls on this path never construct nested pools;
`ark-ec/parallel` and `ark-groth16/parallel` are deliberately not enabled
because their arkworks 0.6 MSM path creates private pools that browser workers
cannot spawn.

Native SPARROW hosts can start from `SparrowConfig::native_adaptive()`. It
selects a Pippenger window independently for each query from its point count and
uses a bounded point batch. This is a performance policy only; hosts may
override it from measurements on their own hardware. The ordinary whole-key
prover uses the same point-count policy internally. Window width is deployment
metadata, not part of the proving-key or manifest digest. The non-published
`curvy-benchmarks` workspace package contains the window sweep used to validate
target-specific settings.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
commands, output directories, and threaded-browser requirements.

## SPARROW

SPARROW is Curvy's opt-in bounded-memory Groth16 proving engine. It and SAGE are
excluded from the crate's default features and normal published WASM builds.
`SparrowProver`
combines an authenticated SIGNET graph, SAGE witness
evaluation, direct coefficient evaluation, and persistent Pippenger buckets. It
never retains the zkey or a complete query section. Browser builds export
`WasmSparrowProver`. The preferred Cache API adapter authenticates a
pinned per-chunk manifest and feeds one `Cache.match()` response body without
calling `arrayBuffer()`; the original whole-digest/two-response protocol remains
available. On first use, the browser compiles the authenticated SIGNET graph to
`SAGEPC01`, round-trip validates it, and stores it as origin-local derived data.
Warm runs authenticate and load that cache instead of repeating slot allocation.
The source graph digest remains the trust anchor; the derived entry is versioned
by compiler semantics and is evicted if its metadata, digest, source binding, or
decoder validation fails.

See [SPARROW.md](SPARROW.md) for artifact publication, native and browser flows,
the SAGE cache protocol, tuning, and the security boundary. See
[BENCHMARKS.md](BENCHMARKS.md) for concise whole-key, SPARROW, and SAGE cache
measurements.

## Published examples

The crate archive contains only examples that support artifact integration:

- `artifact_manifest_check` validates the graph, zkey, WTNS fixture,
  verification key, and R1CS as one release bundle;
- `zkey_chunk_manifest` generates and fully verifies a one-pass SPARROW chunk
  manifest; and
- `derive_sage_cache` demonstrates explicit SAGE program derivation for hosts
  that manage their own validated local cache.

Benchmark binaries and interactive browser/mobile harnesses are development
tools rather than library examples. They remain in the source repository but
are excluded from the published crate.
