# @0xcurvy/rs-core-node

Native Node-API bindings for the Curvy Rust core and authenticated Groth16
prover. Backend services should use this package instead of loading the browser
WASM package or spawning a separate prover process.

The package is artifact-driven: `ResidentProver` is the HAWK
(High-throughput Authenticated Whole-Key prover) API and accepts any compatible
`curvy-graph-v1` witness graph with its matching snarkjs zkey.

```js
const { ResidentProver } = require("@0xcurvy/rs-core-node");

const prover = await ResidentProver.create({
  zkeyPath: "/var/lib/curvy/circuit.zkey",
  zkeySha256: "...64 lowercase hex characters...",
  witnessGraphPath: "/var/lib/curvy/circuit.graph.bin",
  witnessGraphSha256: "...64 lowercase hex characters...",
  threads: 1,
  maxPendingProofs: 8,
});

const result = await prover.prove(JSON.stringify(circuitInput));
const proof = JSON.parse(result.proofJson);
const publicSignals = JSON.parse(result.publicSignalsJson);
```

`ResidentProver.create(options)` is the preferred startup path: file reads,
authentication, parsing, and thread-pool construction run on a native task and
do not block the Node event loop. `new ResidentProver(options)` is the explicit
synchronous startup path.

Every instance reports `mode === "resident"` and `profile === "HAWK"`; include
these fields in service metrics alongside the phase timings.

## Threads

`threads` defaults to `1`. Every prover owns a fixed Rayon pool, and concurrent
calls on that prover enter a bounded FIFO queue. Accepted proofs run directly on
that pool; waiting requests do not occupy shared libuv workers.
`maxPendingProofs` counts the running proof plus waiting proofs, defaults to 8,
and accepts 1–64. Excess calls return a rejected Promise (`QueueFull`). Failed
proofs release their slot, so callers can retry after completion. Inputs retain
the client JSON size limit (16 MiB). This prevents a backend from consuming all
host cores by accident while still allowing an operator to opt into measured
multicore proving. The value must be between 1 and 64.

Tree construction remains serial even when proof generation uses more than one
thread. This is deliberate: the Node package does not enable `curvy-core`'s
global parallel feature.

Large tree inputs can stay binary instead of becoming JSON arrays of decimal
strings. `IndexedMerkleTree.fromPackedLeaves`, `rootPacked`, and
`buildPendingCommitmentPacked` use concatenated canonical 32-byte big-endian
BN254 field elements; the original JSON methods remain compatible.

## Supported artifacts

All artifact bytes are authenticated before use. A graph/zkey pair must match
in assignment size, and every proof is self-verified before it crosses the
Node-API boundary. Proving keys and witness graphs are deployment artifacts and
are not included in this npm package.

The native binding authenticates and parses the zkey through a seekable file
reader. It does not retain a second full-file byte buffer alongside the parsed
proving key; this materially lowers initialization peak memory for large keys.
Initialization and proof generation both use the instance's configured Rayon
pool, so `threads` also limits parallel key decoding during startup.

The prebuilt release targets are:

- macOS arm64 for local development;
- Linux x64 GNU for CI and x64 backend hosts;
- Linux arm64 GNU for Graviton staging and production hosts;
- Windows x64 MSVC for Windows backend and development hosts.

All binaries use Node-API 8.

## Resident loading options

Native Node builds now use compact constraint matrices by default. The Rust,
C, and WASM package defaults remain separate. Measurements and their scope are
in [the resident benchmark report](../../RESIDENT_OPTIMIZATIONS.md).

For one-pass key loading, supply `zkeyManifestPath` and
`zkeyManifestSha256` together, alongside the existing `zkeySha256`. The manifest
is authenticated in full, and every key chunk is checked before parsing. Publish
both pins through trusted deployment metadata; the existing
`zkey_chunk_manifest` release tool verifies whole-file and chunk consistency.
Without a manifest, the authenticated seekable reader remains available.

Set `useSage: true` to compile the authenticated graph into SAGE during startup.
For faster subsequent startup, derive a cache with `derive_sage_cache`, then
supply `sageProgramPath` and `sageProgramSha256` together. Keep
`witnessGraphSha256` pinned to the original graph; `witnessGraphPath` is optional
when loading a compiled program. The cache pin and source pin are both checked.
`witnessBackend` reports `graph` or `sage`. Client artifact limits still apply.
SAGE remains an explicit choice.

`buildPendingCommitment` and its packed counterpart accept `batchSize` in
`1..=4096`. The bound is checked before parsing, padding, or cloning the tree;
input byte budgets also scale with that bound. Rejection preserves the live tree.
Synchronous exports include an unwind guard in addition to input validation.

Security resource limits: `buildPendingCommitment` and its packed variant accept
1–4096 slots, checked before parsing or padding. Zkeys must be regular files no
larger than 4 GiB; the read limit continues to apply if a file grows. Synchronous
exports catch Rust unwinds, but allocation aborts cannot be caught: the bounds
prevent the reported oversized-batch path before allocation.

The repository-owned loader selects only published platform targets. It ignores
`NAPI_RS_NATIVE_LIBRARY_PATH`, invokes no subprocesses, and always checks both
package and compiled binary versions. Build with the package's `npm run build`
script (`napi --no-js`) to preserve this loader. Queued proof JSON and calculated
assignments are cleared when their Rust ownership ends; caller JavaScript copies
remain caller-owned. Proof timings depend on the private witness and should not
be sent to untrusted telemetry.
