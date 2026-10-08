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

## Closing

A prover keeps its parsed key (often gigabytes) and its Rayon pool until it is
closed or garbage-collected. Call `await prover.close()` to release them
deterministically, for example before loading a replacement key:

- proofs accepted before `close()` still settle normally; later `prove()` calls
  reject with `prover is closed` (`code: "Closing"`), while metadata getters
  (`numConstraints`, `verifyingKeyDigest`, …) keep returning the values captured
  at load;
- the promise resolves once the last accepted proof has finished and the key and
  worker pool have been freed;
- repeated calls are no-ops that resolve at the same point.

The loader also installs `Symbol.asyncDispose` (awaits `close()`) and
`Symbol.dispose` (starts it), so `await using` works on runtimes with explicit
resource management. Each prover reports its zkey size to V8 as external memory
so garbage-collection pressure reflects the native key; `close()` returns that
accounting immediately.

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

## Notes frontier

`NotesFrontier` is the constant-space form of the notes tree: the completed
subtrees along its right-hand edge and the leaf count, at most 1,015 bytes as a
depth-30 snapshot. `append` and `appendPacked` add leaves, and
`buildPendingCommitment` and its packed counterpart return the same circuit
input as `IndexedMerkleTree` does for the same tree and notes. A batch prover
only ever appends, so it can hold a frontier instead of every leaf.

```js
const { NotesFrontier } = require("@0xcurvy/rs-core-node");

// From the snapshot the indexer stores with each block ...
const frontier = NotesFrontier.fromSnapshot(snapshotBytes);
// ... or rebuilt from the committed notes, a page at a time.
const rebuilt = NotesFrontier.production();
for (const page of pages) rebuilt.appendPacked(page);

const before = frontier.snapshot();
const input = frontier.buildPendingCommitment(batchSize, JSON.stringify(noteIds));
// If the commit built from `input` does not land, go back:
const undone = NotesFrontier.fromSnapshot(before);
```

A frontier is only as right as the snapshot or leaves it came from: compare
`root()` and `leafCount` with the contract before proving. It holds no leaves,
so it cannot prove that an earlier leaf is in the tree, and it cannot tell that a
note id is already in it; only a repeat inside one batch is rejected. One
`append` call takes at most 1,048,576 leaves, all or none. Depth is at most 31.

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

## Artifact budget

Artifacts are read under the client budget by default: a witness graph of at
most 64 MiB and 2,000,000 nodes. Set `batchProfile: true` for the batch-prover
budget of 96 MiB and 8,000,000 nodes, which the 20- and 50-note
pending-commitment circuits need. Leave it off in a process that does not load
those circuits: the budget is also the most an artifact can make the process
allocate.

## Resident loading options

Native Node builds now use compact constraint matrices by default. The Rust,
C, and WASM package defaults remain separate.

For one-pass key loading, supply `zkeyManifestPath` and
`zkeyManifestSha256` together. On this path the manifest pin is the sole trust
root: the manifest is authenticated against it, and every key chunk is checked
against the manifest's chunk digests before parsing. `zkeySha256` is still
required but is only compared with the whole-file digest the manifest claims;
the key is not rehashed, so it adds no independent check. Publish the manifest
pin through trusted deployment metadata; the `zkey_chunk_manifest` release tool
verifies whole-file and chunk consistency when the manifest is produced. Without
a manifest, `zkeySha256` authenticates the key through the seekable reader.

Set `useSage: true` to compile the authenticated graph into SAGE during startup.
For faster subsequent startup, derive a cache with `derive_sage_cache`, then
supply `sageProgramPath` and `sageProgramSha256` together. Keep
`witnessGraphSha256` pinned to the original graph; `witnessGraphPath` is optional
when loading a compiled program. The cache pin and source pin are both checked.
`witnessBackend` reports `graph` or `sage`. The artifact budget in force still applies.
SAGE remains an explicit choice.

`buildPendingCommitment` and its packed counterpart accept `batchSize` in
`1..=4096`. The bound is checked before parsing, padding, or cloning the tree;
input byte budgets also scale with that bound. Rejection preserves the live tree.
Synchronous exports include an unwind guard in addition to input validation.

Zkeys must be regular files no larger than 4 GiB; the read limit continues to
apply if a file grows.

The repository-owned loader selects only published platform targets. It ignores
`NAPI_RS_NATIVE_LIBRARY_PATH`, invokes no subprocesses, and always checks both
package and compiled binary versions. Build with the package's `npm run build`
script (`napi --no-js`) to preserve this loader.

## Releasing

`npm run build:release` runs on an Apple Silicon host with Docker Buildx. It
builds and tests macOS arm64 natively and both Linux targets in containers, then
stages every package under `release/`. Before publishing:

1. Smoke-test the Windows binary on a Windows x64 host. It is cross-compiled
   with a pinned `cargo-xwin` in a Linux container and is never loaded or tested
   there. From a checkout of the release commit, copy the staged
   `release/npm/win32-x64-msvc/curvy_rs_core_node.win32-x64-msvc.node` into
   `bindings/node/` and run `npm ci --ignore-scripts && npm test`.
2. Publish the platform packages first, then the root package, using the
   commands the script prints.
