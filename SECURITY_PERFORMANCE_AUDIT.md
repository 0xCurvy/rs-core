# Security, performance, and organization audit — 6 September 2026

The 7 September follow-up to Fable’s independent review is recorded in
[FABLE_AUDIT_REMEDIATION.md](FABLE_AUDIT_REMEDIATION.md), including fixes, compatibility changes, validation, and remaining operational work.

This is the current follow-up to the whole-repository review, including the uncommitted changes. I performed the QAP/MSM review and arithmetic checks directly. This is an engineering audit, not an external security certification or a formal proof of the full prover.

## Findings and fixes

| Finding | Impact and fix | Regression evidence |
| --- | --- | --- |
| Release validation reopened paths when calculating final pins | A file replacement could produce a manifest claiming validation of different bytes. The validator now parses, validates, describes, and hashes owned snapshots. | A FIFO pauses the validator after key validation while the source key/VK are replaced. The emitted pins still identify the validated snapshots. |
| Unbounded Node artifact reads | An oversized graph, compiled program, or manifest could allocate before authentication rejected it. Reads now enforce raw/compressed graph limits of 64/32 MiB, a 64 MiB SAGE limit, and a 4 MiB manifest limit, including growing files. | Sparse oversized files are rejected by synchronous and asynchronous constructors; bounded-reader tests cover streams and exact limits. |
| Noncanonical Montgomery field encodings | Fuzzing found an out-of-range G2 coordinate reaching unchecked arkworks field arithmetic and triggering a debug assertion during curve checking. Fq and coefficient Fr encodings now reject values at or above their modulus before construction. Resident and streaming parsing share these decoders. Normal runtime digest authentication remains an additional boundary. | Saved reproducer, modulus/maximum-limb tests, every G2 limb, forward-reader regression, and further sanitizer fuzzing. |
| Direct assignment constant was unchecked | Direct Rust callers could provide a leading signal other than one. Every proving/public-input entry point now rejects it before arithmetic. | Zero/two constants tested, including scratch proving. |
| Public QAP dimension arithmetic could panic | Missing matrices, inconsistent row counts, invalid signal references, oversized public prefixes, and domain-size overflows now return errors. Both base and doubled FFT domains are checked before allocation. | Malformed-dimension and integer-overflow cases. |
| Verification-key infinity encoding differed from snarkjs | The release validator now uses the canonical projective identity encoding, so a valid zero IC entry is compared correctly. | Explicit G1/G2 identity serialization checks. |
| Constant-size setup H query was empty | The generic reduction now uses the two-point domain for the size-one case. Production imported keys were unaffected. | Independent polynomial identity tests include domain size one. |

## QAP audit

For `m` constraints and `l` instance variables (including one), the domain has `N = next_power_of_two(m + l)` elements. The A and B arrays first evaluate the constraint rows. A additionally contains the public prefix at rows `m..m+l`; B is zero there. C contains the rowwise A·B products at constraint rows and zero elsewhere.

The kernel interpolates those three polynomials and evaluates them at `eta * omega^j`, where `omega` has order N and `eta` has order 2N. Its output is `A(x)B(x) - C(x)` on the odd coset. These are the values required by the Circom HZ query, rather than quotient-polynomial coefficients. The kernel is now shared by nested, CSR, scratch, and streaming proving.

The independent oracle uses quadratic scalar interpolation and Horner evaluation, without the production FFT or row evaluator. It covers empty/cancelling/duplicate/zero terms, random field coefficients, public padding, and boundaries around powers of two. It also checks that the dot product with `h_query_scalars` equals `(A(t)B(t)-C(t))/delta`. The existing fixed-randomizer comparison checks complete A/B/C proof elements against ark-groth16, including zero randomizers. Authenticated production fixtures and the new browser runtime tests provide additional end-to-end coverage.

C is reconstructed from A·B because Circom zkeys omit the C matrix used by a generic R1CS evaluator. This does not establish witness satisfaction by itself. High-level proof APIs self-verify; low-level `Prover::prove` and `prove_with_workspace` require the caller to verify. A trusted, circuit-correct key remains essential.

## MSM audit

The recoding is balanced radix 2^w. For raw digit `u_j` and carry `c_j`, `d_j = u_j + c_j - 2^w c_(j+1)`, with `c_0 = 0`. A carry is ambiguous only when the preceding raw digit is `2^(w-1)-1`; the parallel implementation walks backward over that run. Resident proving uses the same recoding in serial and parallel. SPARROW also has a forward carry implementation for its serial, bounded point batches.

For canonical BN254 Fr integers and every allowed width 3–16, the padded top window consumes the final carry. Tests reconstruct the exact integer without reducing modulo Fr, so a discarded carry cannot hide behind group order. Positive and negative bucket indices stay in range, including the i16 minimum at width 16. Reverse bucket prefix sums produce the digit-weighted sum; high-to-low window reduction supplies the radix weights.

Tests compare G1 and G2 against a naive sum of independent scalar multiplications. Cases include zero, one, modulus minus one, limb boundaries, long carry chains, independent random bases, infinity, opposite bases, and unequal input lengths. Production calls provide canonical `Fr::into_bigint()` scalars and parser-validated query lengths. The private helper retains arkworks' truncation behavior for unequal slices.

No discrepancy was found in the audited QAP or MSM equations under these assumptions. The parser and boundary defects above were fixed; this conclusion is not a claim that the entire cryptographic system has been proved secure.

## Release and runtime boundaries

`tools/artifacts/validate_release.py` stages private copies, requires an independently trusted PTAU SHA-256, verifies the ceremony transcript, checks zkey/R1CS/PTAU consistency, checks the WTNS against R1CS, validates all key points and CRS relations, compares the published VK, and compares every graph/SAGE/compiled-SAGE witness signal with the reference WTNS. It checks all staged pins again before writing a local release bundle. Failed validation does not produce a bundle.

The pipeline was exercised with a fresh **test-only** ceremony and rejected an invalid witness and a wrong ceremony pin. Production PTAU/R1CS files were not available in this checkout or the local key package, so production ceremony verification is not claimed. A release must run this command using its reviewed ceremony pin and intended production inputs.

Authentication establishes identity relative to a trusted pin. Self-verification uses the key loaded from that artifact and cannot establish the authenticity of an attacker-chosen key/pin pair. Continue comparing the verifying-key digest with the deployed verifier.

MSM bucket access and witness evaluation are variable-time. Neither the arithmetic review nor scratch zeroization provides a constant-time or complete memory-erasure guarantee. Scratch clears its owned buffers on success, error, unwind, and drop; it does not erase caller copies or third-party temporaries. Scratch remains opt-in.

## Organization and CI

- Shared authentication lives in `artifacts`, with manifests behind `zkey-manifest`; Node no longer enables SPARROW merely to load resident manifests.
- The old streaming manifest type path remains a re-export. Manifest construction now returns `artifacts::manifest::ArtifactError`; streaming operations continue returning `StreamingError`.
- WASM bindings moved from the main prover module to `wasm_api.rs`.
- Resident and streaming QAP FFTs and point/field decoders are shared.
- CI executes scratch tests in serial and parallel, standalone manifest tests, the release race/full-pipeline tests, seeded parser fuzzing, and actual threaded Chromium/Firefox proofs.
- Browser and release development tools have separate exact lockfiles. The release tools use snarkjs 0.7.6 and override Underscore to patched 1.13.8; npm audit reports no vulnerabilities. See the [upstream release](https://github.com/iden3/snarkjs/releases/tag/v0.7.6) and [Underscore advisory](https://github.com/advisories/GHSA-qpx9-hpmf-5gmw).

## Measurements and validation

Raw results and final validation metadata are in `tools/benchmarks/results/hardening-2026-09-06/`. Earlier measurements remain historical evidence; use this report for current status.

Five measured proofs after one warm-up per native process; all proofs self-verified. On the Apple M4 Pro host (48 GiB RAM, Rust 1.94.0), serial results were:

| Notes | Stock serial ms / MiB | Previous compact ms / MiB | Final compact ms / MiB |
| --- | ---: | ---: | ---: |
| 2 | 1580.3 / 483.8 | 1863.6 / 184.1 | 1662.4 / 188.8 |
| 5 | 2354.3 / 847.5 | 2678.2 / 244.4 | 2236.1 / 248.2 |
| 10 | 4342.5 / 1401.8 | 5029.8 / 440.5 | 4120.5 / 446.4 |

The retained change increases serial window widths using an approximate ln(points)+2 policy, capped at the audited width 16. Parallel and SPARROW window policies stay as measured previously. The final serial compact path improved 11–18% over the previous compact path here. A precomputed-i16-digit candidate offered little further benefit and used more memory, so it was not retained. The smallest circuit remains about 5% slower than stock serial; compact defaults therefore remain specific to Node. These small samples describe this machine, not a universal speed guarantee.

Linux ARM64 was measured in a Docker VM on the same Apple Silicon host, with a six-CPU quota, an 8 GiB limit, and four workers for the parallel profile. This is a separate virtualized environment:

| Notes | Stock serial ms / MiB | Compact serial ms / MiB | Compact, 4 workers ms / MiB |
| --- | ---: | ---: | ---: |
| 2 | 1709.1 / 276.7 | 1779.6 / 155.5 | 571.6 / 164.4 |
| 5 | 2399.0 / 341.9 | 2410.1 / 211.3 | 802.4 / 220.4 |
| 10 | 4487.3 / 588.5 | 4471.9 / 390.3 | 1441.8 / 371.7 |

Linux memory comes from `/proc/self/status` VmHWM; macOS native memory is per-child `wait4` maximum RSS. The emulated Linux x86-64 two-note diagnostic measured 2451.0 ms stock serial, 2602.5 ms compact serial, and 819.1 ms compact with four workers. Those emulated timings are not native x86-64 performance evidence.

The Node concurrency run used the production ten-note graph, 13 workers, 32 proofs per concurrency level, and one shared prover. Service time stayed near 600–610 ms, with throughput around 1.6 proofs/s. Response p95 was 630 ms at concurrency one, 1276 ms at two, 2553 ms at four, and 4820 ms at eight. Queueing more work improves neither the capacity of a single serialized prover nor its individual service time; the admission bound keeps that waiting work finite.

Chromium 143 production runs use a fresh browser process tree per case, one warm-up, and five measured proofs. All expected public signals and self-verification checks passed. Both Chromium 143 and Firefox 144 also passed the two-worker runtime/malformed-input checks. Browser memory is sampled aggregate process RSS, including browser overhead and per-process shared-page accounting; it should not be compared directly with native per-child RSS.

| Notes | Portable default median ms / peak aggregate MiB | Threaded compact, 4 workers median ms / peak aggregate MiB |
| --- | ---: | ---: |
| 2 | 4478.8 / 776.4 | 1451.6 / 746.7 |
| 5 | 6275.7 / 965.6 | 2071.5 / 923.5 |
| 10 | 11709.5 / 1420.4 | 3728.1 / 1360.6 |

The separate portable-compact run isolates matrix storage from threading:

| Notes | Portable compact median ms / peak aggregate MiB |
| --- | ---: |
| 2 | 4681.9 / 735.6 |
| 5 | 6308.4 / 909.4 |
| 10 | 11595.5 / 1319.5 |

Compared with portable defaults, this saves about 41–101 MiB of aggregate browser RSS, with proving time ranging from 4.5% slower to 1% faster. The default portable build was restored after the experiment. These desktop results do not justify changing mobile defaults before device measurements.

The browser calls here execute synchronously on the page and measure proving throughput and memory, not application responsiveness. Product integrations should keep synchronous proving in a dedicated worker.

Validation passed: 200 workspace tests (one pre-existing ignored test), isolated default/manifest/scratch suites, 53 all-feature prover checks, 48 checks on each Linux architecture, 11 Node tests, 381 WASM parity checks, JavaScript cache tests, FFI surface checks, Clippy with warnings denied, and rustdoc with warnings denied. The release example additionally covers canonical infinity output. Seeded AddressSanitizer fuzzing exercised graph, SAGE, WTNS, zkey, and manifest parsing; the saved field-encoding crash was fixed and the subsequent runs completed without crashes. Full counts, logs, binary digests, and environment details accompany the raw results.

## Remaining external gates

Physical x86-64 and mobile-device performance cannot be inferred from Apple Silicon or emulation. Linux x86-64 compatibility was exercised under Docker emulation; native x86-64 CI is configured but was not remotely triggered. Production ceremony verification needs the actual PTAU/R1CS artifacts and reviewed pins. Those environment/release gates remain explicit; no change here promotes compact matrices globally or enables retained scratch by default.
