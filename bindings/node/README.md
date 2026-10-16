# @0xcurvy/rs-core-node

Native Node-API bindings for the Curvy Rust core and authenticated Groth16
prover, for backend services.

`ResidentProver` accepts any compatible `curvy-graph-v1` witness graph with its
matching snarkjs zkey.

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

`ResidentProver.create(options)` reads, authenticates and parses the artifacts
and builds the thread pool on a native task, without blocking the event loop.
`new ResidentProver(options)` does the same synchronously.

Every instance reports `mode === "resident"` and `profile === "HAWK"`; include
these fields in service metrics alongside the phase timings.

## Closing

A prover keeps its parsed key (often gigabytes) and its Rayon pool until it is
closed or garbage-collected. Call `await prover.close()` to release them, for
example before loading a replacement key:

- proofs accepted before `close()` still settle normally; later `prove()` calls
  reject with `prover is closed` (`code: "Closing"`), while metadata getters
  (`numConstraints`, `verifyingKeyDigest`, …) keep returning the values captured
  at load;
- the promise resolves once the last accepted proof has finished and the key and
  worker pool have been freed;
- repeated calls are no-ops that resolve at the same point.

The loader also installs `Symbol.asyncDispose` (awaits `close()`) and
`Symbol.dispose` (starts it), so `await using` works on runtimes with explicit
resource management. Each prover reports its zkey size to V8 as external memory;
`close()` returns that accounting immediately.

## Threads

- `threads` defaults to `1`. Each prover owns a fixed Rayon pool.
- Concurrent calls on one prover enter a bounded FIFO queue and run on that pool;
  waiting requests do not occupy libuv workers.
- `maxPendingProofs` counts the running proof plus waiting proofs. It defaults
  to 8 and must be between 1 and 64. Excess calls return a rejected Promise
  (`QueueFull`). Failed proofs release their slot.
- Proof inputs are limited to 16 MiB of JSON.
- Tree construction is serial: this package does not enable `curvy-core`'s
  `parallel` feature.

Large tree inputs can stay binary. `IndexedMerkleTree.fromPackedLeaves`,
`rootPacked`, and `buildPendingCommitmentPacked` use concatenated canonical
32-byte big-endian BN254 field elements; the JSON methods are also available.

## Notes frontier

`NotesFrontier` is the constant-space form of the notes tree: the completed
subtrees along its right-hand edge and the leaf count, at most 1,015 bytes as a
depth-30 snapshot. `append` and `appendPacked` add leaves, and
`buildPendingCommitment` and its packed counterpart return the same circuit
input as `IndexedMerkleTree` does for the same tree and notes. A batch prover
only appends, so it can hold a frontier instead of every leaf.

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

- A frontier is only as correct as the snapshot or leaves it came from: compare
  `root()` and `leafCount` with the contract before proving.
- It holds no leaves, so it cannot prove that an earlier leaf is in the tree or
  detect a note id already in it; only a repeat inside one batch is rejected.
- One `append` call takes at most 1,048,576 leaves, all or none. Depth is at
  most 31.

## Calldata-bound circuits

The aggregator's calldata-bound circuits take their values as calldata words and
expose three public signals, `[commitment, y, x]`. `bindCalldata` (JSON array of
decimal strings) and `bindCalldataPacked` (32-byte big-endian words) compute all
three the way the circuit and the contract do, and return them in that order.

- Words must already be field elements below the modulus; larger values are
  rejected, not reduced.
- One call takes at most 8,192 words. The JSON form has a byte budget sized for
  that many compact decimals, so send it without whitespace.

`buildBoundPendingCommitment` and `buildBoundPendingCommitmentPacked`, on both
`IndexedMerkleTree` and `NotesFrontier`, append a batch and return the
calldata-bound pending-notes circuit's input. Nothing changes unless every id is
accepted: at least one, at most `batchSize`, none zero, none repeated, and for
`IndexedMerkleTree` none already in the tree. A refused batch throws with code
`InvalidArg`; a full tree, or any other failure, with `GenericFailure`.

```js
const input = frontier.buildBoundPendingCommitment(batchSize, JSON.stringify(noteIds));
// input.circuitInputJson: the witness input, `x` included
// input.noteIds: what `commitPendingNotes` is sent, without the padding
// input.newNotesRoot, input.newNoteIndex: the tree after the batch
// The proof's public signals are [input.commitment, input.y, input.x].
```

`nextLeafFrontier()` returns the circuit's `frontier` input for the next batch.
`buildPendingCommitment` builds the input of the SHA-256 pending-notes circuit.

`buildPendingCommitment`, `buildBoundPendingCommitment` and their packed
counterparts accept `batchSize` as an integer in `1..=4096`; a fraction, a
negative number, `NaN` or a larger number is rejected, not converted. The bound
is checked before parsing, padding, or cloning the tree, and input byte budgets
scale with it. A rejected call leaves the tree unchanged. Synchronous exports
also catch Rust panics.

## Artifacts

All artifact bytes are authenticated before use. A graph/zkey pair must match
in assignment size, and every proof is self-verified before it crosses the
Node-API boundary. Proving keys and witness graphs are not included in this
package.

- Zkeys must be regular files no larger than 4 GiB; the limit also applies if
  the file grows during the read.
- `threads` also limits parallel key decoding during startup.
- Node builds enable compact constraint matrices (`compact-matrix`); the Rust
  crates, C ABI and WASM package do not by default.

### Artifact budget

Artifacts are read under the client budget by default: a witness graph of at
most 64 MiB and 2,000,000 nodes. Set `batchProfile: true` for the batch-prover
budget of 96 MiB and 8,000,000 nodes, which the 20- and 50-note
pending-commitment circuits need. Leave it off in a process that does not load
those circuits: the budget is also the most an artifact can make the process
allocate.

### Zkey manifest

For one-pass key loading, supply `zkeyManifestPath` and `zkeyManifestSha256`
together. The manifest pin is then the only trust root: the manifest is
authenticated against it, and every key chunk is checked against the manifest's
chunk digests before parsing. `zkeySha256` is still required but is only
compared with the whole-file digest the manifest claims; the key is not
rehashed, so it adds no independent check. Distribute the manifest pin through
trusted deployment metadata. The `zkey_chunk_manifest` tool verifies whole-file
and chunk consistency when it produces the manifest. Without a manifest,
`zkeySha256` authenticates the key.

### SAGE

Set `useSage: true` to compile the authenticated graph into SAGE during startup.
To start faster, derive a cache with `derive_sage_cache`, then supply
`sageProgramPath` and `sageProgramSha256` together. Keep `witnessGraphSha256`
pinned to the original graph; `witnessGraphPath` is optional when loading a
compiled program. Both the cache pin and the source pin are checked.
`witnessBackend` reports `graph` or `sage`. The artifact budget still applies.

## Platforms

Requires Node.js 22.16 or newer. Prebuilt binaries, all on Node-API 8:

- macOS arm64;
- Linux x64 GNU;
- Linux arm64 GNU;
- Windows x64 MSVC.

The package's loader selects only these published targets. It ignores
`NAPI_RS_NATIVE_LIBRARY_PATH`, invokes no subprocesses, and checks both the
package and compiled binary versions. Build with `npm run build`
(`napi --no-js`) to keep this loader.

## Releasing

`scripts/publish.sh node` builds, checks and publishes these packages; see
[RELEASING.md](../../RELEASING.md).
