# SPARROW integration guide

SPARROW is the opt-in bounded-memory Groth16 prover in `curvy-prover`. It uses
SAGE for witness evaluation and processes a snarkjs proving key sequentially so
the host does not need to retain the complete zkey or a complete query section.
Every returned proof is verified with arkworks before it leaves the crate.

Use SPARROW when peak memory is more important than the lowest possible latency.
Use `CircuitProver` or `Prover` when the host has enough memory to load the full
proving key and prefers the simpler whole-key flow.

Measured memory and latency comparisons are in [BENCHMARKS.md](BENCHMARKS.md).

## Enable SPARROW

SPARROW and SAGE are excluded from the default crate and WASM builds.

For native Rust:

```toml
[dependencies]
curvy-prover = { version = "=0.1.0-rc.5", features = ["sparrow"] }
curvy-witness = { version = "=0.1.0-rc.5", features = ["sage", "signet-v2"] }
```

Add `parallel` when the application has a host-initialized Rayon pool:

```toml
[dependencies]
curvy-prover = { version = "=0.1.0-rc.5", features = ["parallel", "sparrow"] }
curvy-witness = { version = "=0.1.0-rc.5", features = ["sage", "signet-v2"] }
```

For direct WASM builds:

```bash
scripts/build-wasm.sh web --sparrow
scripts/build-wasm.sh web --threads --sparrow
```

The threaded build requires a cross-origin-isolated page and an initialized
`wasm-bindgen-rayon` pool. SPARROW is not present in the normal published WASM
entries. An application that distributes it should use a separate opt-in entry
so ordinary users do not download SAGE or the streaming prover.

## Artifact set

A production integration should publish and pin these values together:

| Item | Required metadata | Purpose |
|---|---|---|
| SIGNET graph | exact byte length and SHA-256 | Source for authenticated SAGE compilation |
| snarkjs zkey | exact byte length and SHA-256 | Groth16 proving key |
| chunk manifest | exact byte length and SHA-256 | Authenticates each zkey chunk before parsing |
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
before it writes a successful result. Publication pipelines should also run the
artifact bundle validator and the upstream snarkjs ceremony and witness checks:

```bash
cargo run --release -p curvy-prover \
  --example artifact_manifest_check -- \
  circuit.zkey circuit.signet circuit.wtns verification_key.json circuit.r1cs
```

The graph, zkey, manifest, and verification key must come from the same circuit
build. Do not select artifacts by filename alone.

## Native API

The one-pass manifest flow is the preferred native integration:

```rust,no_run
use std::{fs, fs::File};
use curvy_prover::sparrow::{SparrowConfig, SparrowProver};
use curvy_witness::Limits;

let graph = fs::read("circuit.signet")?;
let manifest = fs::read("circuit.zkey.manifest")?;
let input = fs::read_to_string("input.json")?;

let prover = SparrowProver::from_signet_bytes(
    &graph,
    "GRAPH_SHA256",
    "ZKEY_SHA256",
    Limits::client(),
    SparrowConfig::native_adaptive(),
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
chunk before any of its bytes reach the unchecked point parser. The fallback
`prove_json` method authenticates the complete file, rewinds it, and hashes the
proof pass again while parsing. Use the fallback only when a deployment cannot
publish a chunk manifest.

Choose `Limits::client()` for client circuits and `Limits::batch_prover()` for
larger server-side circuits. These limits bound decoded graph dimensions and
allocations; they are part of the deployment profile and should not be inferred
from untrusted artifact contents.

## SAGE cache

`SAGEPC01` is a deterministic, locally derived cache of the SAGE instruction
program. It is not a deployment artifact and does not replace the pinned SIGNET
graph.

On first use, a host should:

1. Load the SIGNET bytes through `SageGraph::from_bytes_with_limits`, which
   authenticates the pinned source digest before parsing.
2. Serialize the compiled evaluator with `to_compiled_bytes` or
   `WasmSparrowProver.compiledSageProgram()`.
3. Hash the program bytes.
4. Release the compiler-produced evaluator.
5. Reload the bytes through the normal compiled-program decoder.
6. Store the validated bytes as origin-local derived data.

The cache key must contain:

- the source SIGNET SHA-256;
- `sage::CACHE_VERSION` or the WASM `sageCacheVersion()` value;
- the client or batch limits profile; and
- the cache layout version owned by the host adapter.

Every warm load must authenticate the cached program digest and supply the
source graph digest to `from_compiled_sage_bytes` or
`fromCompiledSageWithConfig`. Delete and rebuild an entry after any digest,
metadata, format, dimension, index, or source-binding failure.

Raw cache bytes provide the lowest warm-load latency. Compression saves storage
but adds decompression CPU and requires an additional bounded streaming decoder.
Choose the storage representation from measurements on the deployment devices.

## Browser stream flow

The preferred browser path uses Cache API because a cached `Response.body` is a
sequential stream that maps directly to the manifest protocol. It does not call
`arrayBuffer()` for the zkey.

The host sequence is:

1. Initialize the portable or threaded SPARROW WASM module.
2. Load or derive the SAGE program.
3. Authenticate and parse the small zkey manifest in full.
4. Open one cached zkey `Response`.
5. Coalesce browser stream pieces to the manifest chunk size.
6. Pass each complete chunk to `pushManifestZkeyChunk`.
7. Call `finishManifestProof` and accept only its self-verified result.

Keep the top-level proof operation in a dedicated worker. The Rust calls are
synchronous once they enter WASM, so putting them on the UI thread can block
rendering and wallet interactions.

Cache API and OPFS both use origin quota. Cache API is the simpler fit for the
current sequential layout. Consider OPFS when an application needs resumable
partial downloads, synchronous offset reads in a worker, parallel section reads,
or application-managed files. In either case, request persistent storage where
appropriate and handle eviction and `QuotaExceededError`.

## Memory lifecycle

SPARROW retains the assignment, QAP working vectors, H scalars, one query's
Pippenger buckets, and a bounded base/scalar chunk. It does not retain the full
zkey, coefficient table, or complete query vectors.

For one proof on a memory-constrained host, use the one-shot WASM methods. They
release the compiled SAGE program after successful witness calculation so its
allocation can be reused by the QAP and MSM phases. Invalid input leaves the
prover reusable.

For repeated proofs of the same circuit, keep the validated SAGE evaluator and
use the reusable path. Release the instance when the circuit or account session
is no longer active.

## Window and chunk configuration

Window width and MSM chunk size are performance and memory settings. They do
not change the mathematical MSM result and are not part of any artifact digest.

Native callers should start with `SparrowConfig::native_adaptive()`. It selects
a window independently for each authenticated query size and uses a bounded
point batch. Browser and mobile hosts should pin values measured on their target
devices because worker scheduling, process limits, and thermal behavior differ.

Record the following values with benchmark and deployment metadata:

- crate or WASM package version;
- target and CPU architecture;
- worker count;
- window policy or fixed window bits;
- MSM chunk points;
- manifest chunk bytes; and
- artifact digests.

Change a pin only when repeated self-verifying runs show an improvement larger
than normal thermal and scheduling noise. The benchmark package contains the
window sweep and end-to-end comparison tools described in
[BENCHMARKS.md](BENCHMARKS.md).

## Security boundary

SPARROW constructs bulk zkey points without repeating subgroup validation for
every point. This is safe only behind the documented authentication boundary:

- the native manifest path authenticates each complete chunk before parsing;
- the native fallback authenticates the whole zkey before its parsing pass;
- direct `SparrowProofBuilder` callers must provide an equivalent boundary; and
- every completed proof is verified with arkworks before release.

The manifest is an independently pinned trust root for one-pass parsing. Its
claimed whole-file digest is not recomputed during proving. Artifact publication
must call `ZkeyChunkManifest::verify_reader` so the manifest's chunk table,
length, and whole-file digest are known to describe the same zkey.

SPARROW retains arkworks for BN254 field arithmetic, group operations,
randomness, Groth16 proof construction, and final verification. The Curvy-owned
surface covers artifact framing, authentication order, SAGE and QAP evaluation,
scalar recoding, bucket scheduling, and allocation lifetimes. This boundary
supports review but is not a claim of an external security audit.

## Verification

Run the feature-specific suite before distributing a SPARROW build:

```bash
cargo test -p curvy-prover --features sparrow
cargo test -p curvy-prover --features parallel,sparrow
```
