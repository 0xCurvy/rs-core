# Changelog

All notable changes to the `rs-core` crates, bindings and packages are recorded
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Release candidates share one workspace version and may break APIs between
candidates.

## [0.1.0-rc.6] - Unreleased

Changes since `v0.1.0-rc.5` (`e17b711`, 17 August 2026). Background:
[docs/security.md](docs/security.md), [docs/optimizations.md](docs/optimizations.md),
[docs/benchmarks.md](docs/benchmarks.md).

### Breaking

- C/WASM: `curvy_verify_merkle_proof` and `verifyMerkleProof` take the expected tree `depth` as a new first argument and reject proofs of any other length.
- C: every object `*_free` now returns `CurvyStatus` (was `void`); unknown, stale, wrong-type and repeated frees return `InvalidHandle`.
- C: malformed input (decimal, hex key, point, JSON string array, key length, packed field) returns `InvalidArgument` instead of `Error`; `Error` now means a well-formed value the core rejected.
- C: a rejected null output pointer replaces `curvy_last_error`, and each fallible call (including a successful one) invalidates the previous error pointer.
- Rust/Node/C: `CircuitProver` is renamed `ResidentProver` (`CircuitProverOptions` -> `ResidentProverOptions`, `curvy_circuit_prover_*` -> `curvy_resident_prover_*`), with no aliases.
- Stealth: point coordinates must be canonical unsigned decimals with no leading zeros; values at or above the modulus and negatives are rejected.
- Stealth: the identity point (`"0.0"`) is rejected as a key and by send/meta; scans skip such announcements.
- Stealth: `send_with_r` requires `r` as a canonical decimal in `[1, p)` of the BN254 scalar field.
- Stealth: spend and view private keys must be exactly 64 unprefixed hex characters; shorter keys must be left-padded explicitly.
- Node: `ResidentProver` metadata getters (`numConstraints`, `verifyingKeyDigest`, ...) keep returning load-time values after `close()`; only `prove()` rejects (`code: "Closing"`).
- Node: `buildPendingCommitment` and its packed variant accept `batchSize` 1–4096 only; zkeys must be regular files of at most 4 GiB.
- Witness input JSON is strict: duplicate or excess values, fractions, exponents, `+`, `_` and whitespace in decimals are rejected.
- `prove_reader` and `prove_reader_owned` require `Read + Seek`; use a pinned manifest for non-seekable sources.
- Warm compiled-SAGE reuse requires a trusted program pin (`expectedSageProgramSha256` in the browser adapter); without one each run recompiles.
- Manifest construction returns `curvy_prover::artifacts::manifest::ArtifactError`; the old streaming manifest path is a re-export.
- `version()` and `curvy_version` report the workspace version instead of the hard-coded `v1.0.2`.
- Rust `eddsa::ephemeral_pub_key` panics on scalars of 2^256 or more; WASM and C return errors.
- `scripts/build-npm.mjs` refuses to replace an existing output directory it did not create.

### Added

- Rust: `ResidentProver::from_artifacts_reader`, `from_artifacts_with_limits` and `Prover::from_zkey_reader` for authenticated seekable loading.
- Rust: `zkey-manifest` feature with `Prover::from_zkey_manifest_reader` and `ZkeyChunkManifest::verify_reader`.
- Rust: `sage` feature with `ResidentProver::with_sage` and `from_compiled_sage`.
- Rust: opt-in `compact-matrix`, `zkey-single-pass` and `scratch` (`ProofWorkspace`, `WitnessWorkspace`) prototypes.
- Rust: `ProverMode`, `verifying_key_digest()`, `witness_backend()` and `assignment_to_packed_be`.
- Rust: `imt::verify_proof_at_depth`.
- WASM: byte-input `SeedSigner` and `ScalarSigner` handles and `ephemeralPubKeyBytes`.
- WASM: `WasmWitnessGraph.calculatePacked` and SPARROW `abortProof` / `resetZkeyAuthentication`.
- C: byte-input signer handles (`curvy_seed_signer_*`, `curvy_scalar_signer_*`) and `curvy_ephemeral_pub_key_bytes`.
- C: `curvy_witness_graph_calculate_packed`, `curvy_resident_prover_new_sage` and `curvy_resident_prover_new_compiled_sage`.
- C: `curvy_resident_prover_mode`, `_profile` and `_verifying_key_digest`.
- Node: `ResidentProver.create()` loads on a native task instead of the event loop.
- Node: `close()` with `Symbol.dispose` / `Symbol.asyncDispose`, and the `closed` getter.
- Node: bounded FIFO proof queue (`maxPendingProofs`, default 8, 1–64) on each prover's private pool.
- Node: `zkeyManifestPath`/`zkeyManifestSha256`, `useSage` and `sageProgramPath`/`sageProgramSha256` options.
- Node: `mode`, `profile`, `witnessBackend` and `verifyingKeyDigest` getters; resident key reported to V8 as external memory.
- Node: packed tree methods `IndexedMerkleTree.fromPackedLeaves`, `rootPacked` and `buildPendingCommitmentPacked`.
- Node: `NotesFrontier`, the constant-space form of the notes tree (`production`, `fromSnapshot`, `snapshot`, `depth`, `append`, `buildPendingCommitment` and packed variants); it returns the same pending-commitment input as `IndexedMerkleTree`.
- Node: `batchProfile` option reads artifacts under the batch-prover budget (`Limits::batch_prover()`); the default stays the client budget.
- Rust: `NotesFrontier::append_with_siblings` returns the inclusion siblings of a leaf as it is appended.
- Tools: release bundle validator (`tools/artifacts`), leakage harness and weekly workflow (`tools/leakage`), browser proof checks (`tools/browser`).
- Tools: parser fuzz workspace (`fuzz/`) reaching authenticated parsers, the SAGE compiler and compressed programs.
- Docs: `CHANGELOG.md` and `docs/benchmarks.md`, `docs/optimizations.md`, `docs/security.md`.

### Fixed

- Stealth point parsing no longer panics on the identity point.
- All-zero byte keys report `ZeroSecretScalar`.
- C: thread-local error state uses `try_with`, so frees from thread-local destructors cannot abort the process.
- Prover: `ZkeyHashMismatch`, `InvalidExpectedHash`, `Io` and manifest chunk mismatches stay typed instead of being flattened to strings.
- Prover: resident zkeys whose domain does not match the circuit's are rejected instead of yielding invalid proofs.
- Prover: noncanonical Montgomery field encodings are rejected before arkworks construction (fuzz-found).
- Prover: direct assignments must start with the constant one; malformed QAP dimensions return errors instead of panicking.
- Prover: proof and verification-key JSON use snarkjs's canonical identity encoding; the size-one H query is no longer empty.
- SPARROW: authentication is checked before a proof begins, a failed stream aborts, and a failed zkey digest can be retried.
- Browser cache adapter: artifact reads are size-capped; entries failing authentication are evicted and refetched.
- Native CLI keeps batch limits through graph decoding.
- SIGNET: system zstd pipe deadlock on large graphs; `decode_sha256` rejects non-hex input instead of panicking.
- Witness: JSON `-0` is accepted as zero; echoed names in `InputLength` errors are bounded to 128 bytes.
- Node: panics in the async initializer are caught.

### Security

- BabyJubjub signing, nonce/response arithmetic and `ephemeral_pub_key` use fixed-width `crypto-bigint` 0.7.5 and complete projective formulas.
- Poseidon and decimal-to-field conversion use fixed-width BN254 arithmetic.
- The default zkey reader rechecks every buffered chunk against the authenticated digest.
- Streaming domains are bounded to 2^22 and to the authenticated zkey length / 64 before allocation.
- Node artifact reads, batch sizes, C decimals and witness JSON are bounded before parsing.
- Errors no longer echo secrets or invalid field values; guarded C panics record only the source location.
- C secret-bearing JSON and byte outputs are built in exact-size buffers so no partial copies are left behind.
- Best-effort zeroization covers signing, hashing, cipher, witness, QAP and MSM-scalar buffers (complete erasure is not claimed).
- Random nonzero scalars use masked rejection sampling instead of reduction.
- Node loader ignores library-path overrides, spawns no subprocess and checks package and binary versions.
- Release path uses `--ignore-scripts` and digest-pinned Docker images.

### Changed

- `curvy-core`: `poseidon-optimized` is the default; `default-features = false` keeps the direct schedule.
- `curvy-core`: `imt::verify_proof` is deprecated in favor of `verify_proof_at_depth`.
- `curvy-core`: `ShardedNotesTree::rewind_live_to` returns unmarked owned ids in ascending leaf order.
- `curvy-prover`: serial MSM windows follow ln(points) + 2, capped at 16.
- `curvy-prover`: with `parallel`, SPARROW bucket window reduction runs on the Rayon pool.
- `curvy-prover`: the default serial build (no `parallel`/`compact-matrix`: default Rust, C FFI, portable and Node WASM) uses Curvy's proof assembly and batch-affine MSMs instead of stock `ark-groth16`; serial proofs 16–22% faster natively and 14–23% in portable browsers.
- `curvy-prover`: BN254 MSMs from 4,096 points (and every SPARROW query) accumulate batch-affine buckets with one shared inversion per batch; parallel and SPARROW adaptive windows widened. Resident G1 21–37% and G2 34–50% faster, SPARROW query MSM 37–53% faster; whole production proofs 18–32% faster (`docs/benchmarks.md` §9).
- `curvy-prover`: shared artifact authentication lives in `artifacts`; WASM bindings moved to `wasm_api.rs`.
- Node: compact matrices are the default; tree operations remain serial.
- CI builds and proves the shipped threaded and portable WASM packages and runs browser proofs.
- CI lints and tests serial, parallel and default-only feature sets separately.
- CI runs Rust checks as parallel matrix jobs, tests the Node binding natively on Windows and macOS, fuzzes the nested-matrix zkey parser, runs the SIGNET generator smoke and lints workflows with actionlint.
- Release workflow (still disabled) derives the npm dist-tag, waits for CI, runs the 160k Poseidon gate and publishes the smoke-tested tarball.
- Node release staging pins `cargo-xwin` and flags the Windows binary as untested.
- Documentation moved to `docs/`; the handover document was removed and raw benchmark results are no longer tracked.

### Migrating from rc.5

Merkle verification takes the depth you expect (production notes trees use
depth 30, `NOTES_TREE_DEPTH`):

```c
int ok = 0;
/* rc.5: curvy_verify_merkle_proof(leaf, 32, index, siblings, siblings_len, root, 32, &ok); */
CurvyStatus status = curvy_verify_merkle_proof(30, leaf, 32, index,
                                               siblings, siblings_len, root, 32, &ok);
```

```js
// rc.5: verifyMerkleProof(leaf, index, packedSiblings, root)
const ok = verifyMerkleProof(30, leaf, index, packedSiblings, root);
```

```rust
// rc.5: imt::verify_proof(&proof)
let ok = curvy_core::imt::verify_proof_at_depth(&proof, curvy_core::imt::NOTES_TREE_DEPTH);
```

C status codes: check the return of every `*_free`, and treat
`InvalidArgument` as a caller input error where rc.5 returned `Error`:

```c
if (curvy_merkle_free(tree) == CurvyStatus_InvalidHandle) {
  /* stale, wrong-type or double free */
}

char *out = NULL;
switch (curvy_poseidon(inputs_json, &out)) {
  case CurvyStatus_Ok: /* use out, then */ curvy_string_free(out); break;
  case CurvyStatus_InvalidArgument: /* malformed input (rc.5: Error) */ break;
  case CurvyStatus_Error: /* well-formed but rejected, or internal failure */ break;
  default: /* InvalidHandle or Panic */ break;
}
/* copy curvy_last_error() before the next call: any fallible call invalidates it */
```

Rename `CircuitProver` to `ResidentProver` (Rust and Node) and
`curvy_circuit_prover_*` to `curvy_resident_prover_*` (C). In Node, prefer
`await ResidentProver.create(options)` and `await prover.close()` when replacing
a key.

[0.1.0-rc.6]: https://github.com/0xCurvy/rs-core/compare/v0.1.0-rc.5...HEAD
