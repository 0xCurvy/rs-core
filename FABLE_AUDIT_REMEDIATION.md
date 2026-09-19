# Fable audit follow-up — 7 September 2026

Reviewed against `e17b71116bcd8c68795df3c1a4f7cec32b3068a8` plus the existing working tree. The earlier optimization work was preserved. This follow-up checks the reported mechanisms, fixes the reachable failures, and records changes that affect integrators. It is an engineering review, not a formal proof or side-channel certification.

All two High and seven Medium mechanisms check out. The Low findings also identify real mechanisms, although zeroization, local cache trust, and some binding/tooling items require explicit ownership or deployment assumptions. No exploit recovering a signing key from timing was demonstrated; the scalar-dependent schedule itself was confirmed and replaced.

## High and Medium findings

| ID | Verification and change | Regression evidence |
|---|---|---|
| H1 | C crypto entry points now use fallible, bounded decimal parsers. Panic/error text no longer includes the supplied decimal. The C guard installs a hook that records only the source location for guarded panics, chaining the host hook for unrelated panics. It discards panic payloads. | C subprocess regression exercises malformed secret arguments and checks both returned errors and stderr; a guard test forces a secret-bearing panic and checks redaction. |
| H2 | All nine reported WASM exports validate decimals, 256-bit raw integers, and Poseidon arity before arithmetic and return `Result`/ordinary JS errors. | Fourteen malformed-input checks against rebuilt WASM require an ordinary error, no `RuntimeError`, no secret echo, and a subsequent successful call. Existing 381 parity checks still pass. |
| M1 | Stealth spend/view keys require exactly 32 decoded bytes of unprefixed hex. Lossy decoding is no longer used for private keys. | Mid-string typos, missing nibbles, prefixes, wrong lengths and generated-key round trips. Existing Go/TS vectors pass. |
| M2 | Witness decimals use field Horner evaluation in 19-digit chunks. Work is linear in input length, with the existing JSON byte cap. | Independent BigUint differential tests and 1–15 MiB decimal measurements through the real graph JSON boundary. |
| M3 | Invalid field values are no longer retained in witness errors. The streaming JSON visitor rejects values with static errors, including malformed root values. FFI/Node JSON-array errors are also sanitized. | Witness, C, Node and WASM sentinel/redaction regressions. |
| M4 | Native `prove_reader`/`prove_reader_owned` now authenticate through the same chunk-rechecking reader as resident proving. Native, manifest and WASM adapters bound the domain by authenticated file length / 64. All streaming headers also reject domains above 2^22 before QAP allocation. The low-level builder prominently requires preauthenticated bytes. | Forged large-domain, authenticated-length, identity-anchor, mutation and manifest tests. |
| M5 | Both Node pending-commitment adapters reject batch sizes outside 1–4096 before JSON/packed parsing, padding, tree work or sibling allocation. Synchronous N-API exports opt into unwind catching. | Sizes 0, 4097, 200000 and `u32::MAX` reject without changing the tree. Allocation aborts are prevented by bounds, not by `catch_unwind`. |
| M6 | The eight registries share one process-wide monotonic handle counter. Every object free returns `CurvyStatus`, reporting stale/wrong-type handles. The C header was regenerated. | Cross-registry, wrong-type, double-free, and independent-handle concurrency tests. |
| M7 | Both signing profiles use fixed-width RustCrypto modular arithmetic for secret multiplication, nonce reduction and response calculation. BabyJubjub multiplication runs all 256 rounds, calculates both candidates, and uses constant-time selection. Public verification keeps the independent variable-time implementation. | Seed/scalar golden vectors; complete projective formula vs affine oracle for zero, order, all-ones, limb/high-bit boundaries and patterned scalars; wide reduction/response vs BigUint. |

M7 uses pinned `crypto-bigint` 0.7.5 and the complete [EFD twisted-Edwards projective addition formula](https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html), `add-2008-bbjlp`. Tests check that BabyJubjub's `a` is a square and `d` a nonsquare, the completeness conditions used here. The fixed schedule includes field inversion and response arithmetic: changing only the outer point loop would leave variable-time bigint/field operations. Nonce rejection sampling can repeat with negligible probability. Compiler output and physical side channels still warrant specialist review for a high-value signing service.

## Low findings

| ID | Disposition |
|---|---|
| L1 | Expanded wiping to owned signing/BLAKE/cipher intermediates, fixed-size key decoding, ordinary witness input/evaluation buffers, resident proving assignments, queued Node JSON/assignments, owned WASM input strings, C JSON string arrays and C output frees. Removed the witness JSON DOM and secret signing BigUint arithmetic. Complete erasure is **not** claimed: caller/JS copies, compiler/register copies, exposed legacy BigUint values, wasm-bindgen output conversion, and all third-party/shared arithmetic temporaries remain outside the guarantee. Compatibility `get_meta` still deliberately returns `[k,v,K,V]`; this secret-bearing contract is now documented. |
| L2 | Cached SAGE is reused only with an independently trusted `expectedSageProgramSha256`. Without one, the browser adapter recompiles the authenticated source graph each session. Cached bytes cannot supply their own trust root. Cold compilation also checks a supplied program pin. |
| L3 | Native SPARROW uses `AuthenticatedReader`. The JS two-response fallback privately records chunk hashes during successful authentication and checks second-response chunks before passing them to Rust. A response-substitution regression checks rejection before `beginZkey`. |
| L4 | The optional forward parser now also sits behind `AuthenticatedReader`. No header is interpreted or large parser allocation made before the first authentication pass. Its second-pass digest remains an additional check. This prototype no longer promises one total I/O pass. |
| L5 | CSR pass two checks each insertion against that row's immutable expected end and then checks every row's final cursor. Equal total counts and an unchanged final row no longer hide an inconsistent reader. Regressions move the middle record into a preceding row and into a discarded row. These checks protect structure; unauthenticated `read_zkey` still does not establish artifact authenticity. |
| L6 | A streaming visitor writes directly into the bounded graph input buffer. No `serde_json::Value` tree/flattened copies; duplicate signal names and excess values reject. Strings accept ASCII decimal digits with an optional minus, without plus/underscores/whitespace. JSON fractions/exponents reject. Omitted inputs remain zero and nested arrays retain ordered flattening. |
| L7 | Random BN254 and secp256k1 nonzero scalars use masked rejection sampling instead of reducing a 32-byte draw. |
| L8 | Generated private keys are always 64 hex digits; scanned spending keys are `0x` plus 64 digits. |
| L9 | Repository-owned Node loader ignores the environment library override, invokes no subprocess, supports only published targets and always checks package and compiled binary versions. Node zkeys must be regular files within 4 GiB, with an enforced read/seek bound even after growth. C slices reject impossible lengths/address wrap and all out-pointer stores support unaligned storage. |
| L10 | npm release-path installs/packing use `--ignore-scripts`. The release Dockerfile uses digest-pinned official Rust and Node images instead of a remote rustup shell installer; Docker context excludes repository metadata and common secret files. WASM npm packaging stages output and only replaces empty or previously marked packaging directories, refusing repositories/ancestors/metadata/unowned directories/symlinks. The disabled npm release workflow uses Node 24 and OIDC provenance without `NPM_TOKEN`. **Account-side trusted-publisher setup and revocation of an existing npm token remain operational work.** The documented build-only `derivative` advisory exception remains until arkworks removes it. |

The CSR consistency check adds two transient `u32` row-end arrays: eight bytes per retained constraint. It preserves the compact representation and sequential coefficient reads. The low-level streaming builder can still allocate within its documented hard ceiling if an integrator violates its authentication precondition; use the authenticated native or manifest adapters for untrusted sources.

## Informational follow-up

Additional changes from the detailed report:

- Stealth point coordinates reject negative and above-modulus values instead of reducing them.
- Legacy seed witness builders verify that a separately stored public key matches the seed.
- Streaming builders reject a non-one constant assignment up front, and reject identity verification-key anchors consistently with resident loading.
- Proof serialization emits canonical snarkjs projective identity encodings for the negligible-probability identity case.
- Nested matrix parsing validates the coefficient count against section 4's exact byte size before allocating rows.
- SAGE differential tests now gate v2 coverage on the actual `signet-v2` feature.
- Input JSON has its own fuzz target, exercised in CI alongside graph, SAGE and prover-format parsing.
- C/WASM version exports report the compiled workspace version. Successful guarded C calls clear stale errors; error pointer lifetime and blocking object frees are documented.
- The strict hex error display no longer includes an offending key character.
- A reverse owned-leaf index removes the repeated full scans in snapshot restoration, marking, frozen-path adoption and append validation. Snapshot format and note ordering are unchanged; restoration is O(n log n) for ownership checks. A restore/unmark/rewind regression checks index consistency.
- Both development servers check loopback Host/Origin; served paths are resolved through symlinks before containment checks.
- Protocol docs state the note cipher's integrity requirement and pad-reuse risk. Binding docs identify full private witness/key outputs and witness-dependent timings.

Deliberate contracts or remaining limits: the low-level prover arithmetic and stealth scans remain variable-time; WASM hash-map seeding is still the target standard library's implementation. Trusted graph mapping overlap, omitted-zero inputs, inverse-zero variants and shift bounds retain the documented evaluator semantics. Manifest chunk tables are the independently pinned trust root; a resident chunk mismatch can surface through the I/O error wrapper. The debug CLI deliberately prints keys, and the native prover's public output-file writes retain ordinary overwrite/symlink semantics. Keep developer tooling out of production images and avoid private-input telemetry.

## Compatibility changes

- Spend/view key imports must be 64 unprefixed hex characters. Previously valid short keys can be explicitly left-padded; never infer recovery from a previously truncated typo.
- Derived spending-key strings are consistently padded. Point coordinates must be canonical.
- Object `*_free` functions now return a status. Existing binary callers that ignored the old void return can ignore the return register, but source bindings should regenerate their declarations and check the status.
- A C error pointer is invalidated by the next fallible call, including success. The first guarded call installs the scoped redacting process panic hook; hosts replacing it later must preserve its behavior.
- `prove_reader` helpers require `Read + Seek`; nonseekable sources use manifests.
- Cache users supply a program digest from the deployment's trusted channel to retain warm compiled-cache reuse.
- Node batch and zkey resource limits apply even if the host previously passed larger values. Build scripts use `napi --no-js` to preserve the owned loader.
- Duplicate/lenient witness JSON that previously parsed ambiguously now rejects.
- `version()` / `curvy_version` report `0.1.0-rc.5` instead of the unrelated hard-coded `v1.0.2`.
- Existing unmarked npm output directories must be replaced manually or a fresh `--out` chosen; the packager will not silently delete them.

## Validation and measurements

Raw results and commands are in [the validation directory](tools/benchmarks/results/fable-2026-09-07/). The final validation summary is recorded there in `validation.json`: 225 workspace tests passed (one existing ignored test), 17 Node tests on macOS and 17 in the Linux arm64 release container, 395 WASM checks, 25 C/WASM golden vectors, six JavaScript cache/packaging tests, and successful two-worker proofs in Chromium and Firefox. Clippy, rustdoc and dependency policy passed. The final fuzz rerun adds 11,442,288 executions, bringing the task total to 25,906,006, without a new crash.

The long-decimal benchmark measures five runs at each size through `WitnessGraph::calculate_json` on Apple M4 Pro, release Rust 1.94.0. Median times were about 4.31 ms (1 MiB), 5.65 ms (2 MiB), 8.75 ms (4 MiB), 16.36 ms (8 MiB), and 30.60 ms (15 MiB). This establishes linear scaling for the input path; it is not a Groth16 proof-time benchmark. Fable's reported 0.72 s / 2.74 s figures measured the old bigint conversion separately.

The signing boundary comparison checks identical outputs before timing 500 calls
per operation (five samples of 100). In portable WASM on Node 22.22.3, median
seed signing improved from 6.62 ms to 1.21 ms (5.49×); scalar signing including
public self-verification improved from 13.00 ms to 8.35 ms (1.56×). Public-key
derivation improved from 3.18 to 0.582 ms for seeds and from 1.56 to 0.570 ms for
the tested scalar. These are throughput measurements, not evidence of constant
time. Raw inputs are fixed test keys and before/after WASM hashes are recorded in
`signing-boundary.json`.

The initial AddressSanitizer fuzz pass completed 14,463,718 executions across four targets without a new crash. Subsequent final-code checks, binding rebuilds, native feature configurations, Clippy/rustdoc, dependency policy, browser proof checks and release tooling validation are recorded with their individual outcomes. Existing arithmetic differential tests against arkworks, including the custom QAP/MSM cases, remain enabled.

## Ephemeral-scalar follow-up

The subsequent review correctly identified that `eddsa::ephemeral_pub_key`
still called the variable-time multiplier. It now hands a zeroized 32-byte
little-endian scalar buffer to `secret_arithmetic::base_mul`, covering both
WASM `ephemeralPubKey` and C `curvy_ephemeral_pub_key` through their shared core
helper. The multiplication follows the signing paths' fixed 256-round schedule.

Raw zero and all 256-bit scalars retain their mathematical outputs. Direct Rust
calls with larger integers now panic with a static error, matching the already
enforced WASM/C input limit; no high bits are silently discarded. Tests compare
against the independent affine routine at subgroup-order, limb, high-bit and
maximum-u256 boundaries, and check binding rejection of `2^256`.

The earlier validation counts and artifact hashes above describe the initial
remediation. Follow-up validation is recorded separately under
`tools/benchmarks/results/fable-ephemeral-2026-09-07/`. This correction does not
expand the assurance claim: BigUint encoding is outside the fixed arithmetic
schedule, scalar-buffer zeroization is not complete memory erasure, and no
timing-distribution measurement was included in that follow-up. Subsequent
measurements and their limits are recorded in
[the secret-handling assessment](tools/benchmarks/results/leakage-2026-09-07/README.md).
The [hashing and signing-stage assessment](tools/benchmarks/results/leakage-2026-09-08/README.md)
records the subsequent Poseidon hardening and identifies the remaining
scalar-signing timing difference in public signature verification.
