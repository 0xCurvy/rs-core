# Streaming prover (SPARROW) integration guide

SPARROW (**Streaming Prover Architecture for Resource-Restricted One-pass
Workflows**) is the opt-in bounded-memory Groth16 prover in `curvy-prover`.
`StreamingProver` evaluates the witness with SAGE and reads a snarkjs proving
key sequentially, so the host never holds the complete zkey or a complete query
section. Every returned proof is verified with arkworks first.

Use SPARROW when peak memory matters more than latency. Use the HAWK
`ResidentProver` when the host can hold the full proving key and reuse it. Use
the lower-level `Prover` only when the host already has a `.wtns` assignment.

## Enable SPARROW

SPARROW and SAGE are not in the default crate features or WASM builds.

For native Rust:

```toml
[dependencies]
curvy-prover = { version = "=0.1.2", features = ["sparrow"] }
curvy-witness = { version = "=0.1.2", features = ["sage", "signet-v2"] }
```

Add `parallel` when the application has a host-initialized Rayon pool:

```toml
[dependencies]
curvy-prover = { version = "=0.1.2", features = ["parallel", "sparrow"] }
curvy-witness = { version = "=0.1.2", features = ["sage", "signet-v2"] }
```

For direct WASM builds:

```bash
scripts/build.sh wasm-web --sparrow
scripts/build.sh wasm-web-threads --sparrow
```

The threaded build requires a cross-origin-isolated page and an initialized
`wasm-bindgen-rayon` pool. The published WASM packages do not include SPARROW;
applications that ship it should load it from a separate opt-in entry.

## Artifact set

Publish and pin these values together:

| Item | Required metadata | Purpose |
|---|---|---|
| SIGNET graph | exact byte length and SHA-256 | Source for authenticated SAGE compilation |
| snarkjs zkey | exact byte length and SHA-256 | Groth16 proving key |
| chunk manifest | exact byte length and SHA-256 | Trust root for one-pass proofs; authenticates each zkey chunk before parsing |
| verification key | version or digest | Verifies proofs outside the prover |
| circuit dimensions | public inputs and assignment size | Rejects mismatched artifact bundles during publication |

The zkey manifest contains the zkey digest, zkey length, chunk size, and one
SHA-256 per consecutive chunk. Generate and validate it with:

```bash
cargo run --release -p curvy-prover --features sparrow \
  --example zkey_chunk_manifest -- \
  circuit.zkey circuit.zkey.manifest 1048576
```

The generator reopens the zkey and calls `ZkeyChunkManifest::verify_reader`
before it reports success. Publication pipelines should also run the artifact
bundle validator and the upstream snarkjs ceremony and witness checks:

```bash
cargo run --release -p curvy-prover \
  --example artifact_manifest_check -- \
  circuit.zkey circuit.signet circuit.wtns verification_key.json circuit.r1cs
```

The graph, zkey, manifest, and verification key must come from the same circuit
build. Do not select artifacts by filename alone.

## Native API

The one-pass manifest flow is the recommended native integration:

```rust,no_run
use std::{fs, fs::File};
use curvy_prover::{StreamingConfig, StreamingProver};
use curvy_witness::Limits;

let graph = fs::read("circuit.signet")?;
let manifest = fs::read("circuit.zkey.manifest")?;
let input = fs::read_to_string("input.json")?;

let prover = StreamingProver::from_signet_bytes(
    &graph,
    "GRAPH_SHA256",
    "ZKEY_SHA256",
    Limits::client(),
    StreamingConfig::native_adaptive(),
)?;

let proof = prover.prove_json_with_manifest(
    &input,
    &mut File::open("circuit.zkey")?,
    &manifest,
    "MANIFEST_SHA256",
)?;

println!("{}", proof.proof_json);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`prove_json_with_manifest` reads the zkey once and authenticates each complete
chunk before any of its bytes reach the point parser. Without a manifest,
`prove_json` authenticates the complete file, rewinds it, and hashes the
proving pass again while parsing. Use it only when a deployment cannot publish a
chunk manifest.

Use `Limits::client()` for client circuits and `Limits::batch_prover()` for
larger server-side circuits. The limits bound decoded graph dimensions and
allocations. Take them from the deployment profile, never from untrusted
artifact contents.

## SAGE cache

`SAGEPC01` is a deterministic, locally derived cache of the SAGE instruction
program. It is not a deployment artifact and does not replace the pinned SIGNET
graph.

On first use, a host should:

1. Load the SIGNET bytes through `SageGraph::from_bytes_with_limits`, which
   authenticates the pinned source digest before parsing.
2. Serialize the compiled evaluator with `to_compiled_bytes` or
   `WasmStreamingProver.compiledSageProgram()`.
3. Hash the program bytes.
4. Release the compiler-produced evaluator.
5. Reload the bytes through the normal compiled-program decoder.
6. Store the validated bytes as origin-local derived data.

The cache key must contain:

- the source SIGNET SHA-256;
- `sage::CACHE_VERSION` or the WASM `sageCacheVersion()` value;
- the client or batch limits profile; and
- the host's cache layout version.

Every warm load must authenticate the cached program against an independently
trusted program digest and pass the source graph digest to
`from_compiled_sage_bytes` or `fromCompiledSageWithConfig`. A cache entry's own
hash is not a trusted digest, and the source digest inside a compiled blob does
not prove correct compilation. Publish program digests through the trusted
artifact channel.

Delete and rebuild an entry after any digest, metadata, format, dimension,
index, or source-binding failure.

## Browser stream flow

In a browser, stream the zkey to the module chunk by chunk, for example from a
cached `Response.body`, without buffering it whole:

1. Initialize the portable or threaded SPARROW WASM module.
2. Load or derive the SAGE program.
3. Authenticate and parse the small zkey manifest in full.
4. Open one cached zkey `Response`.
5. Coalesce browser stream pieces to the manifest chunk size.
6. Pass each complete chunk to `pushManifestZkeyChunk`.
7. Call `finishManifestProof` and accept only its self-verified result.

Run the proof in a dedicated worker. The WASM calls are synchronous and block
the thread that makes them.

Cache API storage counts against origin quota. Request persistent storage where
appropriate and handle eviction and `QuotaExceededError`.

## Memory lifecycle

SPARROW retains the assignment, QAP working vectors, H scalars, one query's
Pippenger buckets, and a bounded base/scalar chunk. It does not retain the full
zkey, coefficient table, or complete query vectors.

For one proof on a memory-constrained host, use the one-shot WASM methods. They
release the compiled SAGE program after successful witness calculation, so the
QAP and MSM phases can reuse its memory. Invalid input leaves the prover
reusable.

`WasmStreamingProver` also exposes recovery for interrupted streams:

- `abortProof()` clears an active proof after a failed or aborted stream; it is
  idempotent;
- `resetZkeyAuthentication()` restarts whole-file authentication from byte 0
  and is refused while a proof is active;
- a failed `finishZkeyAuthentication()` recreates the authenticator, so the
  caller can retry; and
- after an aborted one-shot proof the graph has been released, so construct a
  new prover.

The read-only `zkeyAuthenticated`, `proofActive`, and `graphReleased` getters
report that state.

For repeated proofs of the same circuit, keep the validated SAGE evaluator and
use the reusable path. Release the instance when the circuit or account session
is no longer active.

## Window and chunk configuration

Window width and MSM chunk size affect only performance and memory. They do not
change the MSM result and are not part of any artifact digest.

Native callers should start with `StreamingConfig::native_adaptive()`, which
selects a Pippenger window for each query from its point count and uses a
bounded point batch. Browser and mobile hosts should pin values measured on
their target devices.

## Security boundary

SPARROW parses bulk zkey points without a per-point subgroup check. This is
safe only behind this authentication boundary:

- the native manifest path authenticates each complete chunk before parsing;
- the native fallback and the public `prove_reader` helpers use
  `AuthenticatedReader`, which authenticates the whole zkey and rechecks each
  chunk before parsing;
- the browser two-response helper checks second-response chunks against hashes
  recorded during the successful first pass;
- direct `StreamingProofBuilder` callers must provide an equivalent boundary;
  its final digest does not make parsing of unauthenticated bytes safe; and
- every completed proof is verified with arkworks before release.

The manifest pin is the sole trust root for one-pass parsing. The zkey pin
supplied with it (`expected_zkey_sha256` in `StreamingProver`, or the zkey
argument of `ZkeyChunkManifest::from_bytes`) is only compared with the
whole-file digest the manifest claims; proving does not recompute that digest.
Artifact publication must call `ZkeyChunkManifest::verify_reader`, the only
check that recomputes it, so the manifest's chunk table, length, and whole-file
digest are known to describe the same zkey.

Input checks:

- all streaming headers reject domains above 2^22 before QAP allocation;
- native, manifest, and WASM loads also cap the domain at the authenticated
  zkey length divided by 64 (one 64-byte H-query point per domain element);
- `prove_reader` and `prove_reader_owned` require `Read + Seek`; use a pinned
  manifest for non-seekable input;
- assignment element zero must equal one before streaming begins; and
- verification-key anchors must be non-identity points.

## Verification

Run the feature-specific suite before distributing a SPARROW build:

```bash
cargo test -p curvy-prover --features sparrow
cargo test -p curvy-prover --features parallel,sparrow
```
