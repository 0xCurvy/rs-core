# curvy-prover

Authenticated Curvy witness evaluation and self-verified arkworks Groth16
proving for existing snarkjs artifacts.

`ResidentProver` is the HAWK profile (High-throughput Authenticated Whole-Key
prover): it combines a deployment's `curvy-graph-v1` artifact and matching
`.zkey`, retaining the authenticated parsed key for reuse. `StreamingProver` is
the SPARROW profile (Streaming Prover Architecture for Resource-Restricted
One-pass Workflows): it consumes the key sequentially with bounded memory.
`Prover` is the lower-level API for an existing snarkjs `.wtns` assignment.
This crate also publishes the `curvy-native-prover` executable and can be built
as the standalone prover WASM module.

## Install

```toml
[dependencies]
curvy-prover = "=0.1.0-rc.5"
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

Both artifact hashes are checked before their respective parsers run. Generated
proofs are verified internally before being returned.

File-backed native callers should prefer `from_artifacts_reader` or
`Prover::from_zkey_reader`: by default the zkey is hashed in a first pass, then
each buffered chunk is authenticated again before parsing, including after
seeks. This prevents concurrent file changes from substituting key bytes without
retaining the complete file. The opt-in `zkey-single-pass` parser also reads through this authenticated
chunk view, then checks its forward-pass digest before returning the key.
Byte-oriented WASM and C callers
still avoid whole-query staging because point sections are decoded in bounded
8 MiB chunks. Use the SPARROW `StreamingProver` when retaining the complete
parsed proving key is itself too large for the target.

Witness-only WASM callers can use `WasmWitnessGraph.calculatePacked`; the C ABI
offers `curvy_witness_graph_calculate_packed`. Both return concatenated
canonical 32-byte big-endian field elements and avoid decimal JSON output.

## Cryptographic and audit boundary

The prover intentionally keeps BN254 field arithmetic, curve operations, and
final verification in arkworks. The default serial path delegates proof
assembly directly to stock `ark-groth16` 0.6. The opt-in `parallel` and
`compact-matrix` paths use a small Curvy assembly layer with the same equations;
the former schedules large MSMs on the host's Rayon pool, while the latter
retains CSR constraints through QAP evaluation. Neither implements separate
field or curve formulas. SPARROW additionally changes evaluation order, batching,
and memory ownership while using the same scalar recoder and arkworks group
operations.

Bulk zkey points are constructed without repeating a subgroup check for every
point. That optimization is inside an explicit artifact trust boundary:

- default native whole-key loads authenticate the pinned zkey digest before
  parsing and recheck each reader chunk before exposing its bytes;
- opt-in `zkey-single-pass` loads use the same pre-authenticated chunk view;
- the one-pass path authenticates each complete manifest chunk before parsing;
- direct users of `StreamingProofBuilder` must perform one of those
  authentication steps before supplying bytes; and
- every completed proof is verified with arkworks before it is returned.

The browser adapter records private 64 KiB chunk hashes during successful whole-file
authentication, then checks each chunk of the second response before forwarding it
to Rust. Use this adapter or the pinned-manifest adapter; the raw WASM framing
methods require the caller to authenticate bytes before supplying them. SPARROW
rejects domains above 2^22 before allocating its QAP arrays.

This separation keeps the project-owned audit surface focused on artifact
framing, witness/QAP evaluation, scalar recoding, bucket scheduling, and
lifecycle management. It does not mean the crate has received an external
security audit. The arithmetic layer remains in arkworks.

## Features and execution targets

| Feature | Purpose |
|---|---|
| `std` | Native standard-library support; enabled by default |
| `bench` | Development-only native/WASM arithmetic benchmark kernels; implies `sparrow` |
| `compact-matrix` | Prototype two-pass CSR zkey matrices and direct compact QAP evaluation |
| `parallel` | Opt-in QAP, FFT, and MSM work on one host-initialized Rayon pool |
| `signet-v2` | Opt-in compact SIGNET v2 witness-graph decoder, without SAGE or SPARROW |
| `zkey-manifest` | Shared authenticated chunk manifests for resident and streaming loads |
| `sage` | Opt-in SAGE for resident proving, including independently pinned compiled caches |
| `scratch` | Experimental caller-owned, zeroized witness/FFT/MSM-scalar buffers; implies compact matrices |
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

Native SPARROW hosts can start from `StreamingConfig::native_adaptive()`. It
selects a Pippenger window independently for each query from its point count and
uses a bounded point batch. This is a performance policy only; hosts may
override it from measurements on their own hardware. The ordinary whole-key
prover uses the same point-count policy internally. Window width is deployment
metadata, not part of the proving-key or manifest digest. The non-published
`curvy-benchmarks` workspace package contains the window sweep used to validate
target-specific settings.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
commands, output directories, and threaded-browser requirements.

## Streaming prover (SPARROW)

SPARROW (Streaming Prover Architecture for Resource-Restricted One-pass
Workflows) is Curvy's opt-in bounded-memory Groth16 proving engine. It and SAGE
are excluded from the crate's default features and normal published WASM
builds. `StreamingProver` combines an authenticated SIGNET graph, SAGE witness
evaluation, direct coefficient evaluation, and persistent Pippenger buckets. It
never retains the zkey or a complete query section. Browser builds export
`WasmStreamingProver`. The preferred Cache API adapter authenticates a
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
  verification key, and R1CS digest as one release bundle. It fully parses raw
  or zstd graphs and WTNS data; ceremony and constraint semantics still require
  `snarkjs zkey verify` and `snarkjs wtns check`;
- `zkey_chunk_manifest` generates and fully verifies a one-pass SPARROW chunk
  manifest; and
- `derive_sage_cache` demonstrates explicit SAGE program derivation for hosts
  that manage their own validated local cache.

Benchmark binaries and interactive browser/mobile harnesses are development
tools rather than library examples. They remain in the source repository but
are excluded from the published crate.

## Additional resident paths

`Prover::from_zkey_manifest_reader` (feature `zkey-manifest`) accepts any `Read`
source starting at byte zero and a `ZkeyChunkManifest` authenticated with both
trusted pins. Complete chunks authenticate before parsing; truncated or excess
streams fail. The Groth16 header must precede query sections. The manifest's
whole-file digest and chunk table must be checked together by release tooling
before its independent pin is published, as with SPARROW.

`ResidentProver::with_sage` and `from_compiled_sage` (feature `sage`) use SAGE
with a resident proving key. Compiled caches require both their own pin and
the expected source graph pin. All resident constructors validate assignment
size, and `prove_json` self-verifies before returning.

The experimental `scratch` feature adds `ProofWorkspace` and
`prove_json_with_workspace`, alongside `curvy_witness::WitnessWorkspace`.
Each active proof needs exclusive mutable workspaces. Construct them with
explicit maximum retained byte counts; a zero limit retains nothing. The limits
apply to idle capacity, not active peak memory. Owned buffers are zeroized on
success, error, panic unwinding, and drop; caller inputs and temporary copies
inside dependencies are outside this guarantee. MSM bucket reuse is not enabled.
Default APIs retain no workspaces between proofs. See
[measurements and promotion decisions](../../RESIDENT_OPTIMIZATIONS.md).

The complete `prove_assignment`, `prove_json`, and `prove_wtns` APIs self-verify.
Low-level `Prover::prove` and `prove_with_workspace` return a proof without
verification; their callers must verify it. Direct assignments must begin with
the constant one signal.

The source repository's [current audit](../../SECURITY_PERFORMANCE_AUDIT.md)
describes the QAP/MSM arithmetic checks, parser fuzzing, and release gates.
[Release validation tooling](../../tools/artifacts/README.md) stages and validates
the exact bundle against its independently pinned PTAU and reference witness.
