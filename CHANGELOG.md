# Changelog

All notable changes to the `rs-core` crates, bindings and packages are recorded
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Every crate, binding and package shares one workspace version. The 0.1.0 release
candidates could break APIs from one candidate to the next.

## [0.1.5] - 2026-11-05

Changes since `v0.1.4` (`58d6abd`, 28 October 2026). Every crate and both npm packages are released at
0.1.5.

### Security

- A pinned witness graph can no longer make a client evaluate for tens of seconds. `Limits` has an
  `evaluation_cost` budget, charged per node while the graph is decoded, before anything is evaluated:
  1 unit (about 16 ns) for an input, a constant or a field operation, 3 for a comparison, 24 for a
  shift or bitwise operation, 48 for an integer division, 256 for an inverse or field division and 768
  for an exponentiation. Over budget is `WitnessError::EvaluationCostLimit`. `Limits::client()` allows
  32 million units and `Limits::batch_prover()` 128 million; the costliest shipped graph, pending(10,30),
  needs 6.5 million. Before, a client-sized graph of two million exponentiations evaluated for about
  23 s. Both evaluators, both SIGNET body versions and compiled SAGE programs are charged.

### Added

- Rust: compact zkeys (`.czkey`), behind the opt-in `curvy-prover` feature `compact-zkey`. A compact
  zkey stores each curve point as `x` and a sign bit, and the coefficient section as columns, in one zstd
  frame behind a 48-byte header: `CVYZKC01`, then the SHA-256 and length of the zkey it decodes to. It
  decodes to that zkey byte for byte; `verifyPixAggregationBound_2_9_30` is 9,621,660 bytes instead of
  39,980,468. `Prover::from_compact_zkey_bytes`, `Prover::from_compact_zkey_reader` and
  `ResidentProver::from_compact_artifacts` check the compact file's pin before decoding it, and the
  decoded zkey against the digest in the header before parsing it. Loading computes a square root per
  point: that key loads in 990 ms instead of 30 ms, or 144 ms with `parallel` on 14 threads. Proving is
  unchanged. The `compact_zkey` module also has `encode`, `inflate`, `describe` and `is_compact`, and the
  `compact_zkey` example encodes, decodes, inspects and benchmarks compact zkeys.
- WASM: `WasmResidentProver` takes a compact zkey as well as a raw one, under the pin of the file it is
  given, and `@0xcurvy/rs-core-wasm` is built with it. Single-threaded, the 2_9_30 key loads in 2.9 s
  from its compact form and 0.1 s from the raw one. The Node.js and C bindings take raw zkeys only.
- WASM: `@0xcurvy/rs-core-wasm` is built with `signet-v2`, so both prover entries load SIGNET version-2
  witness graphs as well as version-1 ones, raw or zstd-compressed, under the pin of the bytes passed.
  Version 1 loads exactly as before. The decoder adds about 2 KB to each prover module, and SAGE and
  SPARROW stay out of the package.
- SIGNET: `signet transcode` rewrites an artifact in the other body version from the artifact alone. The
  header, and with it the R1CS digest, is kept byte for byte apart from the version field. The result must
  transcode back to the source and load with the source's signal count before it is written; `--input`
  and `--reference` add evaluation parity. Version 2 at zstd -9 is 48-66% smaller than the shipped bound
  v1 graphs.
- `scripts/build.sh npm-web` and `npm-web-threads` build the modules the npm package ships, with
  `--signet-v2 --compact-zkey`; `scripts/build.sh npm`, CI and the release workflow all build through
  them. `scripts/check.sh browser` takes `--signet-v2` and `--compact-zkey` like `scripts/check.sh wasm`.
- `scripts/build.sh` WASM targets and `scripts/check.sh wasm` take `--compact-zkey`, and
  `tools/artifacts/validate_release.py --compact-zkey` requires a shipped compact zkey to decode to the
  validated zkey.

### Fixed

- The `@0xcurvy/rs-core-wasm` modules and the `@0xcurvy/rs-core-node` binaries no longer contain
  absolute paths of the machine that built them. They name dependency sources `/cargo-home/...` and Rust
  standard-library sources `/rustc/<commit>/...`.
- The install name of the macOS `@0xcurvy/rs-core-node` binary is `@rpath/curvy_rs_core_node.node`
  instead of the path it was linked at.

### Changed

- `curvy-witness` refuses an input-mapping table in which two ranges partially overlap
  (`WitnessError::InputMappingOverlap`). Ranges may still nest, as a bus or struct input's fields do in
  18 of the 21 shipped graphs. Every shipped graph loads.
- SIGNET tooling: `export` refuses a constant at or above the BN254 modulus
  (`SignetError::NonCanonicalConstant`); `transcode` without `--input` compares the source and the
  result on an all-zero input (`parity=zero-input`, was `unchecked`); `--compressor zstd` refuses the
  ruzstd fallback before writing; `export`, `reseal`, `transcode` and `inspect` print `client_limits=`;
  and a failed write removes its partial output.
- CI tests the C library with its `signet-v2` feature.
- `scripts/build.sh node-release` and `scripts/build.sh npm` stop if a binary contains the build
  machine's home directory or the checkout's path.
- SIGNET version 2 has more coverage: generated graphs over all 23 operations must evaluate as in version
  1 and as an independent oracle computes, in both evaluators; CI fuzzes the two versions against each
  other (`signet_parity`) and the transcoder against the decoder (`signet_transcode`); and
  `WasmResidentProver` proves from a version-2 graph in Node (`scripts/check.sh wasm --signet-v2`), in
  Chromium and Firefox single-threaded and on Rayon workers (`scripts/check.sh browser`), and from the
  packed npm tarball (`scripts/check.sh npm`), which also proves from a compact zkey.

## [0.1.4] - 2026-10-28

Changes since `v0.1.3` (`305fa0a`, 19 October 2026). 0.1.3 was tagged but not published, so 0.1.4
follows 0.1.2 on crates.io and npm and includes the 0.1.3 changes. Every crate and both npm packages
are released at 0.1.4.

### Security

- `crypto-bigint` 0.7.10 (was 0.7.5); at least 0.7.9 is required. Versions 0.7.0 to 0.7.8 are yanked.
  0.7.6 removed secret-dependent branches from Montgomery multiplication and `borrowing_sub`, which the
  BabyJubjub signing arithmetic runs on secret keys and nonces. The WASM and Node packages and the C
  library are built with 0.7.10.

### Added

- Rust: `Imt::depth`.

### Changed

- WASM: `bindCalldata` takes only an array of strings, and `buildBoundPendingCommitment` on
  `MerkleTree` and `NotesFrontier` takes `batchSize` only as a number. Every field, packed-field and
  snapshot input of `MerkleTree`, `OrderedMerkleTree`, `NotesFrontier`, `ShardedNotesTree` and
  `verifyMerkleProof` takes only a `Uint8Array` (a Node `Buffer` is one). A string, another
  array-like, another typed array or a value of another type is refused instead of converted.
- Node: `bindCalldata` refuses more than 8,192 words, and `buildBoundPendingCommitment` and
  `buildPendingCommitment` more ids than the batch size, before parsing any of them.
- Rust: `build_pending_commitment` panics before it allocates or inserts anything when the batch size
  exceeds `MAX_PENDING_BATCH_SIZE`, `tree_depth` is not the tree's depth, or the ids do not fit in the
  tree.
- The WASM package is optimized with `wasm-opt` from binaryen 133, the release CI's browser proofs use.
- `scripts/publish.sh crates` builds every crate from its packaged sources before it publishes any, as
  CI does. CI runs for changes to the four crate READMEs, which are their docs, and runs the 160,000-case
  Poseidon comparison on every commit.

## [0.1.3] - 2026-10-19

Tagged, not published; its changes are part of 0.1.4.

Changes since `v0.1.2` (`256f9bf`, 16 October 2026).

Only the Rust crates change. `@0xcurvy/rs-core-wasm` and `@0xcurvy/rs-core-node` 0.1.3 are a sync-only
publish that keeps every package on one version: they are built from the same code as 0.1.2 and differ only
in the version they report. Upgrading them from 0.1.2 is optional.

### Changed

- Minimum Rust version 1.97 (was 1.99): 0.1.2 builds on 1.97.
- CI checks and tests `curvy-core`, `curvy-witness` and `curvy-prover` on the minimum Rust version.

## [0.1.2] - 2026-10-16

Changes since `v0.1.1` (`fa3ce61`, 8 October 2026).

### Added

- Rust: `calldata` module with `bind_calldata` and `bind_calldata_packed` (commitment, challenge `x`, evaluation `y`), at most `MAX_CALLDATA_WORDS` (8,192) words. `CalldataBinding::public_signals()` returns `[commitment, y, x]`.
- Rust: `build_bound_pending_commitment` and `build_bound_pending_commitment_packed` for the calldata-bound pending-notes circuit, on an `IndexedMerkleTree` or a `NotesFrontier`, with a batch size of at most `MAX_PENDING_BATCH_SIZE` (4,096). `PendingCommitmentError::is_caller_error()`.
- Rust: `next_leaf_frontier` on `Imt`, `IndexedMerkleTree` and `NotesFrontier`.
- Rust: `Imt::insert_many`, `field::fr_from_be_32_packed`, `field::fr_to_be_32_packed` and `PackedFieldsError`.
- Node: `bindCalldata` and `bindCalldataPacked`; `buildBoundPendingCommitment`, `buildBoundPendingCommitmentPacked` and `nextLeafFrontier` on `IndexedMerkleTree` and `NotesFrontier`.
- WASM: `bindCalldata` (`CalldataBinding`); `buildBoundPendingCommitment` (`BoundPendingCommitment`) and `nextLeafFrontier` on `MerkleTree` and `NotesFrontier`.
- C: `curvy_bind_calldata`, returning `[commitment, y, x]`; `curvy_merkle_build_bound_pending_commitment` and `curvy_frontier_build_bound_pending_commitment`, returning `[circuitInputJson, newNotesRoot, newNoteIndex, commitment, y, x]`; `curvy_merkle_next_leaf_frontier` and `curvy_frontier_next_leaf_frontier`.
- Test vectors for calldata bindings and bound pending commitments.
- `scripts/publish.sh` publishes the crates, the WASM npm package or the native Node packages; `RELEASING.md` lists the release steps.

### Changed

- Minimum Rust version 1.99 (was 1.94); toolchain 1.99.0 (was 1.94.0), including the Node release image.
- Threaded WASM build and fuzz targets use `nightly-2026-08-15` (was `nightly-2026-07-03`).
- New dependency: `sha3` 0.12.
- `IndexedMerkleTree::insert_many` and `OrderedMerkleTree::insert_many` are about 25 times faster for 256-leaf batches.
- Node and WASM: `batchSize` must be an integer from 1 to 4,096, also in Node `buildPendingCommitment` and `buildPendingCommitmentPacked`.
- Node: a JSON value that is not a canonical field element is `InvalidArg` (was `GenericFailure`).
- Packed-field decode errors have the same messages in every binding.
- `build_pending_commitment` and Node `buildPendingCommitment` name `build_bound_pending_commitment` as their successor.
- SIGNET: `build-graph.sh` builds graphs with `curvy-signet-ir-builder`, at the commit and lockfile digest in `crates/signet/scripts/ir-builder.pin`; `SIGNET_IR_BUILDER` overrides it, and `ir-builder.sh` runs it directly. Without `PROVING_KEY_R1CS`, `build-graph.sh` reports the digest of its own compilation's R1CS. Its `generator=` and `generator_checksum=` output lines are now `builder=`, `builder_version=`, `builder_sha256=` and `r1cs=`.
- SIGNET: `scripts/smoke-generator.sh` is now `scripts/smoke-graph.sh` and needs node; its CI job is `signet-graph`.
- `scripts/build.sh` builds every target (`native`, `wasm-*` with build options such as `--simd`, `npm`, `node-release`, `ffi-header`, `kernels`, `graph`) and `scripts/check.sh` runs every check. The other scripts moved to `scripts/lib/`; `build-native.sh`, `build-wasm.sh`, `build-npm.mjs`, `generate-ffi-header.sh` and the `check-*` scripts are no longer entry points.
- Development tools moved out of `crates/prover/js`: the mobile harness to `tools/mobile-harness`, the browser benchmarks to `tools/browser/bench`, the Node SPARROW benchmark to `tools/benchmarks`.
- CI builds the Linux x64 Node release image.

### Fixed

- SIGNET: `signet export` accepts graphs whose last inputs no node reads.

### Removed

- SIGNET: the C++ graph generator (`crates/signet/generator`) and `crates/signet/patches/circomlib-iszero-bbf.patch`.
- The `--poseidon-optimized` WASM build option, which had no effect.
- The `poc/` WASM field and FFT prototypes.

### Security

- `ruzstd` 0.9.1 (RUSTSEC-2026-0344).

## [0.1.1] - 2026-10-08

The first release after the 0.1.0 release candidates; there was no 0.1.0. The
library is the same as `0.1.0-rc.7`.

### Fixed

- Node release image: the pinned `cargo-xwin` is on `PATH`, so the Windows binary builds.

## [0.1.0-rc.7] - 2026-10-08

Changes since `v0.1.0-rc.6` (`49c62e7`, 2 September 2026), which was `v0.1.0-rc.5`
with the one change listed under it.

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
- Tools: release bundle validator (`tools/artifacts`), timing test harness (`tools/leakage`), browser proof checks (`tools/browser`).
- Tools: parser fuzz workspace (`fuzz/`) reaching authenticated parsers, the SAGE compiler and compressed programs.
- Docs: `CHANGELOG.md`.

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

### Changed

- `curvy-core`: `poseidon-optimized` is the default; `default-features = false` keeps the direct schedule.
- `curvy-core`: `imt::verify_proof` is deprecated in favor of `verify_proof_at_depth`.
- `curvy-core`: `ShardedNotesTree::rewind_live_to` returns unmarked owned ids in ascending leaf order.
- `curvy-prover`: serial MSM windows follow ln(points) + 2, capped at 16.
- `curvy-prover`: with `parallel`, SPARROW bucket window reduction runs on the Rayon pool.
- `curvy-prover`: the default serial build (no `parallel`/`compact-matrix`: default Rust, C FFI, portable and Node WASM) uses Curvy's proof assembly and batch-affine MSMs instead of stock `ark-groth16`; serial proofs 16–22% faster natively and 14–23% in portable browsers.
- `curvy-prover`: BN254 MSMs from 4,096 points (and every SPARROW query) accumulate batch-affine buckets with one shared inversion per batch; parallel and SPARROW adaptive windows widened. Resident G1 21–37% and G2 34–50% faster, SPARROW query MSM 37–53% faster; whole production proofs 18–32% faster.
- `curvy-prover`: shared artifact authentication lives in `artifacts`; WASM bindings moved to `wasm_api.rs`.
- Node: compact matrices are the default; tree operations remain serial.
- Node: the loader ignores `NAPI_RS_NATIVE_LIBRARY_PATH` and loads only the published platform packages.
- Prover: streaming domains above 2^22 are rejected.
- Error messages no longer include the rejected input.
- CI builds and proves the shipped threaded and portable WASM packages and runs browser proofs.
- CI lints and tests serial, parallel and default-only feature sets separately.
- CI runs Rust checks as parallel matrix jobs, tests the Node binding natively on Windows and macOS, fuzzes the nested-matrix zkey parser, runs the SIGNET generator smoke and lints workflows with actionlint.
- Release workflow (still disabled) derives the npm dist-tag, waits for CI, runs the 160k Poseidon gate and publishes the smoke-tested tarball.
- Node release staging pins `cargo-xwin` and flags the Windows binary as untested.
- Raw benchmark results are no longer tracked.

### Migrating from rc.5 or rc.6

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

## [0.1.0-rc.6] - 2026-09-02

### Changed

- Dependency requirements are caret ranges instead of exact pins, so the crates resolve next to a consumer that needs a newer patch of a shared dependency. `Cargo.lock` still fixes what this repository builds; `wasm-bindgen` and the napi crates stay exact.

[0.1.5]: https://github.com/0xCurvy/rs-core/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/0xCurvy/rs-core/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/0xCurvy/rs-core/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/0xCurvy/rs-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/0xCurvy/rs-core/compare/v0.1.0-rc.7...v0.1.1
[0.1.0-rc.7]: https://github.com/0xCurvy/rs-core/compare/v0.1.0-rc.6...v0.1.0-rc.7
[0.1.0-rc.6]: https://github.com/0xCurvy/rs-core/compare/v0.1.0-rc.5...v0.1.0-rc.6
