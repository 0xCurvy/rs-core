# Security model and audit history

What `rs-core` defends, what it relies on the host for, what was reviewed, and
what is still open. Measurements behind the timing statements are in
[benchmarks.md](benchmarks.md#8-leakage-and-constant-time-testing); per-binding
contracts are in the crate and binding READMEs.

**Claims.** The repository has had internal engineering reviews and one
independent review (Fable, September 2026). It has **not** had a formal external
security audit, a formal proof of the prover, or a side-channel certification.
Timing results are finite measurements on recorded binaries and platforms.

## Trust boundaries

### Deployment artifacts

A pin is a trust anchor only when it comes from trusted deployment metadata. A
digest sent next to untrusted bytes authenticates nothing.

| Artifact | Root of trust | Enforced where |
|---|---|---|
| Witness graph (SIGNET/CVYWIT, raw or zstd) | Graph SHA-256, checked before any graph-controlled count, reference or field is parsed. For zstd artifacts the pin covers the compressed bytes as supplied | `curvy_witness::WitnessGraph` (`crates/witness/src/lib.rs`) |
| zkey, whole-file paths | zkey SHA-256. Native readers hash the file, then recheck every buffered chunk before the parser sees it (`AuthenticatedReader`), so a concurrent file change cannot substitute bytes | `crates/prover/src/authenticated_reader.rs`, `ResidentProver::from_artifacts_reader`, SPARROW `prove_reader` |
| zkey, manifest paths | **The manifest pin is the sole trust root.** Each complete chunk is checked against the manifest before parsing; the supplied zkey pin is only compared with the whole-file digest the manifest claims and is not recomputed. Publication must run `ZkeyChunkManifest::verify_reader`, the only check that recomputes it | `crates/prover/src/artifacts/manifest.rs`; Node `zkeyManifestPath`/`zkeyManifestSha256`; `Prover::from_zkey_manifest_reader`; SPARROW |
| Compiled SAGE program (`SAGEPC01`) | Derived, origin-local data, never a root. Reuse requires a separately trusted program pin plus the source graph pin; without `expectedSageProgramSha256` the browser adapter recompiles and neither reads nor writes the cache | `crates/witness/src/sage.rs`, `crates/prover/js/sparrow-cache-api.mjs`, Node `sageProgramSha256`, C `curvy_resident_prover_new_compiled_sage` |
| Browser two-response SPARROW fallback | 64 KiB chunk hashes recorded privately during the first, fully authenticated response; the second response is checked chunk by chunk before reaching Rust | `crates/prover/js/sparrow-cache-api.mjs` |

Bulk zkey points are built without a per-point subgroup check. That is only
sound behind the boundaries above. Low-level entry points that bypass them
require the caller to authenticate first: `read_zkey`, `StreamingProofBuilder`
and the raw WASM framing methods.

**Self-verification** of every high-level proof (`prove_json`,
`prove_assignment`, `prove_wtns`, SPARROW, Node, C) is defense in depth. It uses
the loaded key, so it cannot detect an attacker-chosen key/pin pair; compare
`verifyingKeyDigest` with the deployed verifier. `Prover::prove` and
`prove_with_workspace` return unverified proofs. C is reconstructed from `A·B`
because Circom zkeys omit the C matrix, so a trusted, circuit-correct key is
essential.

### Resource limits

| Limit | Value | Where |
|---|---|---|
| Graph profile `Limits::client()` (default) | 2,000,000 nodes, 64 MiB raw graph, 32 MiB compressed, 8 MiB zstd window, 64 MiB SAGE program, 16 MiB input JSON | `crates/witness/src/lib.rs` |
| Graph profile `Limits::batch_prover()` | 8,000,000 nodes, 96 MiB raw graph; only for deliberately provisioned processes | same |
| zstd framing | One strict frame: no dictionaries, skippable frames, extra frames or trailing data | `crates/witness` |
| Groth16 domain | SPARROW headers ≤ 2^22 and ≤ authenticated zkey length / 64 before QAP allocation; resident keys whose domain differs from the circuit's are rejected | `crates/prover/src/sparrow.rs`, `crates/prover/src/zkey.rs` (`check_domain_size`) |
| Node | zkey a regular file ≤ 4 GiB (enforced while reading); manifest ≤ 4 MiB; pending batch 1–4096 checked before parsing; proof input ≤ 16 MiB; queue 1–64 | `bindings/node/src/lib.rs` |
| C | Field strings ≤ 4096 chars; raw integers ≤ 2^256 − 1 (78 digits); byte lengths > `isize::MAX` or wrapping address ranges rejected | `bindings/ffi/src/lib.rs`, `bindings/ffi/src/abi.rs` |

### Release artifacts

`tools/artifacts/validate_release.py` stages private copies, requires an
independently trusted PTAU SHA-256, verifies the ceremony transcript and
zkey/R1CS/PTAU/WTNS consistency, checks every key point and the published VK,
compares graph, SAGE and compiled-SAGE witnesses with the reference WTNS, and
re-checks all pins before writing a bundle. It was exercised only with a
test-only ceremony; production ceremony verification is not claimed.
`artifact_manifest_check` does not replace `snarkjs zkey verify` and
`snarkjs wtns check`.

### Protocol-level caller obligations

- Note encryption is an additive field one-time pad with no tag: recompute and
  check `noteId` after decryption, and never reuse an ephemeral key.
- A view-tag match is a ~1/256 candidate, not ownership; confirm by recomputing
  the note commitment.
- Seed-backed and direct-scalar BabyJubjub keys are different accounts; never
  reinterpret one as the other.
- Verify Merkle proofs against a known depth (`imt::verify_proof_at_depth`, C
  `curvy_verify_merkle_proof`, WASM `verifyMerkleProof`); the depth-free
  `imt::verify_proof` is deprecated.

## Constant-time scope

| Covered by a fixed schedule | Not covered (variable time or observable) |
|---|---|
| Secret BabyJubjub base multiplication: 256 rounds, complete projective formulas (EFD `add-2008-bbjlp`), both candidates computed, constant-time selection (`crates/core/src/secret_arithmetic.rs`) | Public signature verification, including the self-check inside scalar signing |
| Nonce reduction and response arithmetic on fixed-width `crypto-bigint` 0.7.5 | Nonce rejection-sampling retries (negligible probability) |
| Poseidon (both schedules) and decimal-to-field conversion on fixed-width BN254 arithmetic (`crates/core/src/secret_field.rs`) | Digit count, sign, syntax and validity results; formatting of returned values |
| `ephemeral_pub_key` (via `base_mul`) and secret decimal scalar import into fixed 32-byte storage | Stealth pairing and scanning; prover MSM bucket access and witness evaluation |

**Results** (details in [benchmarks.md](benchmarks.md#8-leakage-and-constant-time-testing)):

- Native dudect on Apple M4 Pro (8 Sep build): no signal above `|t| > 10` in
  secret base multiplication, private-input Poseidon, decimal conversion or
  complete seed signing; the affine-multiplier controls were detected.
- Valgrind Memcheck taint (Linux arm64): no secret-dependent branches or
  addresses in Poseidon (all 16 arities), decimal conversion, or complete seed
  and scalar signing.
- Complete scalar signing still shows a timing difference. Stage profiling and a
  public-transcript replay attribute it to public signature verification (the
  work depends on public scalars). This does not establish confidentiality of a
  secret signing message.
- Browser engines (best effort): Chromium and Firefox detect scalar signing;
  neither detected Poseidon, decimal conversion or seed signing on 8 Sep.
- Not measured: native x86-64, physical side channels, compiler/JIT
  independence. `.github/workflows/leakage.yml` runs weekly on hosted Linux
  x86-64 and arm64; no run is recorded here.

## Zeroization scope (best effort)

Owned buffers are wiped where their types allow. **Complete erasure is not
claimed.**

| Wiped | Not covered |
|---|---|
| Signing keys, nonces and intermediates; BLAKE-512 state; cipher state; Poseidon state buffers | Caller and JavaScript copies of inputs and outputs |
| Witness input and evaluation buffers; QAP and MSM-scalar buffers this crate allocates on the default proof path; `scratch` workspaces on success, error, unwind and drop | Copies inside arkworks, including the stock serial assembly's own scalar conversions |
| Node queued proof JSON and assignments; owned WASM input strings | Exposed legacy `BigUint` values, compiler/register spills, third-party temporaries |
| C: strings and byte buffers wiped by `curvy_string_free` / `curvy_bytes_free`; secret-bearing outputs built in exact-size buffers; signer handles erase key storage on free | wasm-bindgen output conversion; intermediate strings built inside the core before the C boundary |

Secret-bearing compatibility outputs remain: C/WASM `get_meta`, `new_meta` and
`scan` return private keys. Prefer the byte-input signer handles (see
[bindings/SIGNER_MIGRATION.md](../bindings/SIGNER_MIGRATION.md)). Proof timings
depend on the private witness; keep them out of untrusted telemetry.

## Binding and supply-chain boundaries

- `#![forbid(unsafe_code)]` in `curvy-core`, `curvy-witness`, `curvy-prover`,
  `curvy-signet` and `curvy-wasm`. The C ABI (`bindings/ffi`) is the only unsafe
  boundary: review null pointers, lengths, ownership, panic catching, handle
  lifetimes and thread-local teardown there with extra care.
- C ABI: panics are caught; the process panic hook records only the source
  location for guarded panics; handles come from one process-wide counter and
  are never reused; malformed input returns `InvalidArgument`, unknown or
  wrong-type handles `InvalidHandle`; error state survives thread-local
  destructors (`try_with`).
- Node loader: only published targets, ignores `NAPI_RS_NATIVE_LIBRARY_PATH`,
  spawns no subprocess, checks package and binary versions.
- Dependencies are exact-pinned with a committed `Cargo.lock`. `cargo deny`
  enforces RustSec advisories, a permissive-license allowlist, no wildcard
  versions, crates.io only and no unknown git sources. One documented exception:
  `RUSTSEC-2024-0388` (`derivative`, build-time only, via arkworks 0.6).
- GitHub Actions are pinned to commits; release Dockerfile images are pinned by
  digest; release-path `npm` installs and packs use `--ignore-scripts`.
- Development servers (`tools/browser/serve.mjs`,
  `crates/prover/js/serve-browser-bench.mjs`) bind to loopback and check
  Host/Origin. The debug CLI prints keys by design; keep developer tools out of
  production images.

## Review checklist for crypto, format and proving changes

- Authenticate artifacts against trusted pins before unchecked parsing or
  graph-controlled allocation; keep self-verification as a release gate.
- Never weaken `Limits` or zstd rules to accept one artifact.
- Use canonical checked types (`Bn254Fr`, `BabyJubSecretScalar`,
  `BabyJubPoint`) for storage, RPC, user, FFI and JavaScript input; reduce
  modulo the field only at intentional arithmetic boundaries.
- Preserve endianness choices, Poseidon input order, tree padding and witness
  flattening order. Golden vectors are protocol oracles: change one only with
  a documented upstream reference change.
- SIGNET operation tags are append-only and the postcard `Operation` enum order
  is wire data (`crates/signet/src/postcard.rs`). Validate every exported graph
  against a reference WTNS.
- Keep SAGE caches derived and source-bound; never promote their digest to a
  deployment root.
- Keep BN254 arithmetic, randomness and final Groth16 verification in arkworks.
- When shared code changes, re-run native, portable WASM, threaded WASM and C/WASM
  parity checks.

## Audit and remediation history

| Date | Review | Outcome |
|---|---|---|
| 17 Aug 2026 | `v0.1.0-rc.5` (`e17b711`) | Baseline for everything below |
| 25 Aug | Internal performance audit (proving, witness, Node, C, WASM) | Allocation removals, compact matrices, optimized Poseidon, packed boundaries; see [optimizations.md](optimizations.md) |
| 4 Sep | zkey reader fix | Default reader rechecks each buffered chunk; the previous hash/parse/hash reader allowed transient file substitution |
| 5 Sep | Resident follow-up | Manifest-authenticated resident loading; bounded Node queue; bounded Node artifact reads |
| 6 Sep | Internal whole-repository security, performance and organization audit | Fixed: release validator re-opening paths (now hashes owned snapshots), unbounded Node artifact reads, non-canonical Montgomery field encodings (fuzz-found), unchecked assignment constant, QAP dimension panics, VK identity encoding, empty size-one H query. QAP and MSM recoding equations reviewed against independent oracles; no discrepancy |
| 7 Sep | Independent review (Fable): 2 High, 7 Medium, 10 Low | All mechanisms confirmed and remediated (below). No key-recovery exploit was demonstrated; the scalar-dependent schedule was confirmed and replaced |
| 7 Sep | Ephemeral-scalar follow-up | `ephemeral_pub_key` moved onto the fixed `base_mul` schedule |
| 7–8 Sep | Secret-handling and leakage assessment | dudect, Memcheck and browser runs; Poseidon and decimal conversion moved to fixed-width arithmetic |
| 19 Sep | Consolidation (`eec4d60`) | All of the above committed |
| 1 Oct | Audit-fix commits from `250116e` on | Identity/canonical stealth inputs, Merkle depth pinning, C ABI status and TLS fixes, typed auth errors, domain check, streaming abort/reset, Node `close()`, parser edge cases, fuzz reach, CI feature isolation. See [CHANGELOG.md](../CHANGELOG.md) |

Fable findings (7 Sep):

| ID | Remediation |
|---|---|
| H1 | C crypto entry points use fallible, bounded decimal parsers; panic/error text never echoes input; redacting panic hook |
| H2 | The reported WASM exports validate decimals, 256-bit integers and Poseidon arity, returning ordinary JS errors instead of traps |
| M1 | Stealth spend/view keys must be exactly 64 unprefixed hex characters |
| M2 | Witness decimals parsed in linear time (19-digit Horner chunks) |
| M3 | Invalid field values and secrets are not retained in witness, C, Node or WASM errors |
| M4 | Native `prove_reader` paths use `AuthenticatedReader`; streaming domains bounded by authenticated length / 64 and 2^22 |
| M5 | Node pending-commitment batch size 1–4096 checked before any parsing or allocation |
| M6 | One process-wide C handle counter; every `*_free` returns a status |
| M7 | Signing on fixed-width arithmetic with complete formulas and constant-time selection |
| L1 | Zeroization extended (best effort, see above) |
| L2 | Compiled SAGE reuse requires an independently trusted program pin |
| L3 | SPARROW fallbacks authenticate chunks before parsing (native and browser) |
| L4 | Opt-in single-pass parser placed behind `AuthenticatedReader` |
| L5 | Compact CSR second pass checks every row's expected end |
| L6 | Streaming JSON visitor: duplicates, excess values, fractions, exponents, `+`, `_` and whitespace in decimals rejected |
| L7 | Random nonzero scalars by masked rejection sampling, not reduction |
| L8 | Generated keys always 64 hex digits (`0x` + 64 for spending keys) |
| L9 | Node loader hardening and zkey file limits; C slice validation and unaligned out-pointers |
| L10 | Release supply chain: `--ignore-scripts`, digest-pinned images, safe npm output directories, OIDC provenance without `NPM_TOKEN` in the (disabled) release workflow |

Ongoing evidence:

- Parser fuzzing (`fuzz/`, cargo-fuzz with AddressSanitizer) covers graph, SAGE
  (raw and compressed), WTNS/zkey/manifest/SPARROW parsing and input JSON, with
  digests recomputed so mutations reach post-authentication code. CI runs
  seeded smoke runs. The 7 Sep campaign ran 25.9 million executions without a
  new crash; the 6 Sep noncanonical-G2 crash is kept as a seed.
- QAP output is checked against an independent quadratic-interpolation oracle;
  MSM recoding is checked against naive scalar multiplication for every window
  width 3–16, carry chains and unequal lengths; fixed-randomizer proofs are
  compared with stock `ark-groth16`.
- Golden vectors pin Poseidon, BabyJubjub, signing, notes, trees and stealth
  flows to the TypeScript/Go references; C/WASM parity vectors cover the
  bindings.

## Known limitations and open items

- No formal external audit; no constant-time proof; native x86-64 and mobile
  timing and performance unmeasured.
- Production ceremony verification needs the real PTAU/R1CS and reviewed pins.
- npm trusted-publisher setup and revocation of any existing npm token are
  account-side work. The WASM release workflow is still
  `.github/workflows/release.yml.disabled`; native Node and crates.io releases are
  manual.
- CI builds and tests the Node binding natively on Linux x64, macOS arm64 and
  Windows x64, but the published Windows binary is cross-compiled with
  cargo-xwin and never executed in CI or the release container; smoke-test it
  on Windows before publishing.
- CI runs the SIGNET generator smoke with circom v2.2.3 on a three-signal
  circuit; production graphs are still built and checked by hand with
  `crates/signet/scripts/build-graph.sh`.
- SPARROW and SAGE are opt-in and less stable than the resident path; run their
  feature-specific native, WASM and browser gates before distribution.
- Low-level APIs (`read_zkey`, `StreamingProofBuilder`, raw WASM framing,
  `Prover::prove`) leave authentication or verification to the caller.
- Trusted-graph semantics are retained: input-mapping overlap, omitted inputs as
  zero, inverse-of-zero variants and shift bounds follow the evaluator's
  documented behavior.
- The native prover writes its public output files with ordinary overwrite and
  symlink semantics.
- WASM hash maps use the target standard library's seeding; no project-level
  hash-flooding hardening is claimed there.
