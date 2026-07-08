# M1 spike — Rust proofs accepted by Curvy's three real verifiers

**The kill-shot test for the PoC (plan §M1, risks 1–2), now covering ALL THREE deployed
circuit configs.** Produces a Groth16 proof for each of Curvy's deployed circuits
**entirely in Rust** (pure-Rust witness generation — no JS/node/snarkjs at runtime) and
gets it accepted (a) off-chain against the verifying key and (b) on-chain by the
*deployed* verifier bytecode on a local anvil, plus corrupted-proof negatives.

The v3-e2e Ignition `Devenv` deploy registers exactly three verifier configs; this spike
exercises every one:

| key           | circuit template & instance                          | deployed verifier                     | publics |
|---------------|------------------------------------------------------|---------------------------------------|---------|
| `withdrawal`  | `VerifySingleWithdrawalNoHashing(2,30)`              | `CurvyWithdrawalVerifier`             | `uint256[6]`  |
| `aggregation` | `VerifySingleAggregationNoHashing(2,3,30,6)`         | `CurvyAggregationVerifier`            | `uint256[31]` |
| `pending`     | `VerifyPendingNotesCommitment(5,30)`                 | `CurvyPendingNotesCommitmentVerifier` | `uint256[1]`  |

*(The registry also lists an aggregation `(5,3,30)` variant; the deployed/used config is
`(2,3,30)` — the `maxInputs=2,maxOutputs=3,depth=30,gasTreeDepth=6` instance above.)*

## Verdict (per circuit)

| Exit criterion | withdrawal(2,30) | aggregation(2,3,30,6) | pending(5,30) |
|---|---|---|---|
| Pure-Rust witness (no JS/node at runtime) | **PASS** | **PASS** | **PASS** |
| Evaluation graph builds from real sources | **PASS** | **PASS** | **PASS** |
| Graph deterministic (rebuild byte-identical) | **PASS** | **PASS** | **PASS** |
| Witness **byte-identical** to snarkjs golden `.wtns` | **PASS** `b57d069…` | **PASS** `5c8156e4…` | **PASS** `e91726d9…` |
| Off-chain Groth16 verify (arkworks pvk) | **PASS** | **PASS** | **PASS** |
| Public signals == snarkjs ref + independent recompute | **PASS** (6) | **PASS** (31) | **PASS** (1) |
| On-chain `verifyProof(valid) == true` (deployed bytecode) | **PASS** | **PASS** | **PASS** |
| On-chain negatives (corrupt statement + corrupt proof) | **PASS** | **PASS** | **PASS** |
| zkey/wasm/vkey provenance (risk #2) | **CLEAN** | **CLEAN** | **CLEAN** |

One `cargo run` proves and verifies all three (~2.3 s wall incl. anvil spawn ×3):

```
cd spikes/m1-prove-verify
./run.sh            # or: cargo run --release --bin prove-verify
./run.sh test       # cargo test --release --test e2e
```

Requires: the `anvil` binary on PATH (spawned in-process by alloy) and the deployed
`.zkey`s (read from the v3-e2e assets by default; override per circuit with
`CURVY_WITHDRAWAL_ZKEY` / `CURVY_AGGREGATION_ZKEY` / `CURVY_PENDING_ZKEY`). A circuit
whose graph or zkey is absent is **SKIPPED, not failed** (see pending note below).

## circom-witnesscalc compatibility verdict (plan Q6 — now confirmed across the family)

**iden3 `circom-witnesscalc` handles all three of Curvy's bus-typed circuits with full
fidelity.** All are `pragma circom 2.2.0` and use the same buses (`Note()`, `Owner()`,
`Signature()`, `NoteInclusionProof()`, `EncryptedNoteData()`) plus circomlib EdDSA-Poseidon,
Merkle inclusion/insertion, and (pending) a 256-bit SHA-256 sub-circuit. The vendored
`build-circuit` frontend compiled each real instance into a `wtns.graph.002` evaluation
graph, and the pure-Rust `calc_witness` runtime produced witnesses **byte-for-byte
identical** to snarkjs from the committed `.wasm`. Non-circular confirmation: each golden
`.wtns` was independently regenerated with `snarkjs wtns calculate` and matches both the
committed golden and the pure-Rust output.

| circuit | graph nodes (post-opt) | signals / witness elems | constraints | graph build | witness calc | graph size | golden size |
|---|---|---|---|---|---|---|---|
| withdrawal | ~88k | 21 502 | 21 498 | few s | ~7 ms | 1.1 MB | 688 KB |
| aggregation | 112 720 | 27 444 | 27 412 | ~2.5 s | ~7 ms | 1.47 MB | 878 KB |
| pending | 1 106 587 | 224 505 | 226 236 | ~13 s | ~28 ms | 13.3 MB | 7.18 MB |

Each graph is **deterministic** — rebuilding from source with `build-circuit` reproduces
the same sha256 byte-for-byte (verified by a full `./run.sh regen-fixtures`), so graphs are
committed/pinned by content hash (except pending's 13 MB blob — sha-pinned, see below).

**Recommendation for plan §3 (witness-calc end-state): option 1 (the `circom-witnesscalc`
evaluation graph) is confirmed across the whole deployed circuit family.** Pure-Rust,
snarkjs-identical witnesses today, no JS runtime, no wasm interpreter. Graphs are built
offline from the `curvy-circuits` sources (like compiling) and pinned by content hash;
the only runtime library dependency is `circom-witnesscalc`. Option 3 (embedded wasmi) is
unnecessary; option 2 (hand-written native builders) stays a long-term nicety with no
urgency — the graph path is template/bus/arity-agnostic and already exact.

The witness calculator lives behind a `WitnessCalculator` trait (`src/lib.rs`) — the seam
the SDK's `curvy-witnesscalc` (L0.5) crate will expose.

## Provenance evidence (risk #2 — re-verified independently, all three)

For every circuit the artifacts are **byte-identical between `packages/zk-keys/v2` and
`packages/zk-circuits/build/v2`** (same trusted-setup build), and each zkey is a real
multi-MB binary (not an LFS stub):

| circuit | `_0001.zkey` sha256 | `.wasm` sha256 | `verification_key.json` sha256 |
|---|---|---|---|
| withdrawal | `c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716` | `2334759a70…` | `b243688bce…` |
| aggregation | `88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6` | `7abae4a1f6…` | `e5f5479b78…` |
| pending | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` | `9af72950c1…` | `e32430501c…` |

And the **deployed verifier == the circuit's generated verifier** for each: the `uint256`
verifying-key constants in
`packages/contracts/evm/src/v2/aggregator-alpha/verifiers/Curvy{Withdrawal,Aggregation,PendingNotesCommitment}Verifier.sol`
are identical (normalized) to `build/v2/<circuit>/…_verifier.sol` produced by
`snarkjs zkey export solidityverifier` from the same `_0001.zkey` — **75/75** constants for
aggregation, **15/15** for pending (only the contract name differs: `Groth16Verifier` →
`Curvy…Verifier`). The on-chain leg deploys the compiled artifact bytecode directly, so
"accepted on-chain" is the definitive check against the committed verifying key.

## Committed fixtures (`fixtures/`)

Withdrawal fixtures are flat in `fixtures/` (M1 layout, unchanged); aggregation/pending
live in `fixtures/<circuit>/`. Per circuit: `input.json`, `expected-public.json`,
`snarkjs-proof.json`, `snarkjs-public.json`, `<Verifier>.bytecode.txt`, `<Verifier>.abi.json`.
Graphs + goldens: committed for withdrawal + aggregation; **pending's 13 MB graph and
7 MB golden are gitignored** and sha256-pinned in `src/lib.rs` (`graph_sha256`,
`golden_sha256`) — regenerate with `./run.sh regen-fixtures`.

- `input.json` — rs-core parity vector (`crates/core/testdata/witness_vectors.json`)
  rebuilt at treeDepth=30 by the `gen-input` bin (see below).
- `expected-public.json` — the public signals in on-chain order, **recomputed
  independently** from rs-core primitives (not extracted from snarkjs). For aggregation
  this 31-signal recomputation matches `snarkjs-public.json` exactly.
- `snarkjs-proof.json` — a `snarkjs groth16 prove` cross-reference (evidence only; not read
  at runtime, and randomized per run, so it is not re-asserted).

Not committed (read from v3-e2e; `.gitignore`d): the `.zkey`s (13 / 16 / 129 MB), the
`.wasm`s, `vendor/`, and pending's graph + golden.

### Input construction (`src/bin/gen-input.rs`)

All inputs are derived from the **committed rs-core witness-parity vectors**, rebuilt at the
deployed dimensions so they are real and circuit-satisfiable:

- **withdrawal** — the two committed notes, IMT rebuilt at depth 30 (unchanged from M1).
- **aggregation** — the committed `(2,2,·)` vector is a *balanced* aggregation (inputs
  10000, outputs 9965, feeNote 35 = gasFee 5 + protocolFeeQ 30). To fit the deployed
  `maxOutputs=3`, one **zero-amount sender-owned output note** is appended (same token) —
  it changes neither the total nor the protocol-fee base, so value conservation holds while
  its noteId + encrypted data still enter the signed input hash. Inclusion proofs rebuilt at
  depth 30; gas-fee tree stays depth 6 (matches the instance's `gasTreeDepth=6`, token 42 < 2⁶).
- **pending** — a full batch of 5 real note ids (the aggregation's inputs+outputs+fee) into a
  depth-30 IMT pre-seeded with the two withdrawal note ids.

## Witness-builder findings (`curvy_core::witness`) — flagged for the real crate

The core builders (`build_withdrawal` / `build_aggregation`) emit the circuit input object
directly. **`build_pending_commitment` does not** — its serialized object is a *superset*
that needs two adjustments to be circuit-consumable (handled in `gen-input`, **no
`crates/core` change**; the workarounds are localized and documented in-code):

1. **Extra `newNotesRoot` field.** The deployed `VerifyPendingNotesCommitment(5,30)` declares
   exactly five input signals `[currentNoteIndex, inputHash, currentNotesRoot, pendingNoteIds,
   siblings]`. The builder additionally emits the computed `newNotesRoot`, which is **not a
   circuit signal** — feeding it raises snarkjs `Error: Too many values for input signal
   newNotesRoot` (and the pure-Rust calc rejects the object). Must be dropped.
2. **Unreduced `inputHash`.** `build_pending_commitment` emits `sha256BigInt(...)` as the
   **raw 256-bit digest**, which can exceed the BN254 field modulus (the observed vector's is
   ~8.0e76 > p). The circuit's `MultiInputSha256` output is `Bits2Num(256) mod p`, so the
   input signal is that digest **reduced mod p**. The raw value is rejected by both snarkjs
   ("Too many values") and circom-witnesscalc (`BaseConvertError(Overflow)`); the reduced
   value (`fr_from_dec`) is what the circuit and the on-chain public signal actually use.
   The `sha256_bigint` doc-comment ("*no field reduction … the digest the pending-commit
   circuit verifies against*") is therefore misleading for the deployed circuit: the circuit
   verifies against the **reduced** digest.

For the SDK's `curvy-witnesscalc`, `build_pending_commitment` should either return a struct
split into "circuit inputs" vs "computed outputs (newNotesRoot)" and reduce `inputHash`, or
ship an explicit `to_circuit_input()` adapter.

## Reproduce from scratch (independent verification)

```bash
cd spikes/m1-prove-verify

# 0. Build the offline graph tool (once). protoc + clang required by its build.rs.
( cd vendor/circom-witnesscalc && cargo build --release --bin build-circuit --bin calc-witness )

# 1. Regenerate ALL offline golden fixtures for the three circuits (input, graph,
#    golden .wtns, snarkjs cross-ref, verifier bytecode). Needs v3-e2e + its pnpm snarkjs.
#    Prints the graph+golden sha256s — they match the pins in src/lib.rs byte-for-byte.
./run.sh regen-fixtures

# 2. The kill-shot: pure-Rust witness -> proof -> off-chain + on-chain verify, ×3.
./run.sh            # bin, or `./run.sh test` for the integration test
```

Spot re-checks:

```bash
# provenance: zkey byte-identical across zk-keys/v2 and zk-circuits/build/v2 (per circuit)
shasum -a 256 \
  $V3E2E/packages/zk-keys/v2/aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey \
  $V3E2E/packages/zk-circuits/build/v2/aggregation/keys/verifySingleAggregationNoHashing_2_3_30_0001.zkey

# deployed verifier constants == snarkjs-generated verifier constants
diff <(grep -oE 'constant [A-Za-z0-9_]+ = (uint256\()?[0-9]+' \
        $V3E2E/.../verifiers/CurvyAggregationVerifier.sol | sed -E 's/.*= (uint256\()?//;s/\)//' | sort) \
     <(grep -oE 'constant [A-Za-z0-9_]+ = (uint256\()?[0-9]+' \
        $V3E2E/packages/zk-circuits/build/v2/aggregation/verifySingleAggregationNoHashing_2_3_30_verifier.sol | sed -E 's/.*= (uint256\()?//;s/\)//' | sort)

# pure-Rust witness == snarkjs golden, byte-for-byte (aggregation shown)
./vendor/circom-witnesscalc/target/release/calc-witness \
    fixtures/aggregation/aggregation_2_3_30.graph.bin fixtures/aggregation/input.json /tmp/r.wtns
cmp /tmp/r.wtns fixtures/aggregation/golden.wtns && echo IDENTICAL
```

## Toolchain / pins

- `circom-witnesscalc` — crate `0.3.0` (runtime dep); vendored clone `vendor/circom-witnesscalc`
  at commit `d48eb7c97857d46b8a75c94ab96f769207263245` (tag `v0.3.0`) for the
  `build-circuit`/`calc-witness` offline tools.
- circom 2.2.x (bus era), snarkjs 0.7.5 (v3-e2e pnpm store), foundry (anvil 1.2.1),
  alloy 1.x, arkworks 0.5.0 (matches `curvy-prover`).
- Detached cargo workspace (own `[workspace]`); does **not** touch rs-core's root
  `Cargo.toml`/`deny.toml`, `crates/core`, or `crates/prover`.

## Key implementation notes

- **Per-circuit `uint256[N]`.** The three verifiers differ in public-signal arity
  (6 / 31 / 1). `OnchainCallData.pubs` is a `Vec<U256>`; three `sol!` bindings + an
  `onchain_verifier!` macro generate one typed `verifyProof` driver each, dispatched on
  `Circuit::num_public`. Public signals pass through in witness order unchanged — the
  deployed verifier defines that same order, so no per-arity reordering is needed.
- **G2 coordinate swap** (`calldata_from_snarkjs`): each `pi_b` coordinate pair is reversed
  (`[c0,c1] -> [c1,c0]`), matching the Ethereum pairing-precompile convention that
  `snarkjs generatecall` encodes. G1 points (`pi_a`,`pi_c`) pass through unchanged. Same for
  all three circuits (the classic footgun — get it wrong and off-chain passes, on-chain reverts).
- **Public-signal order (circom):** outputs first (declaration order), then public inputs
  (declaration order). For aggregation that is
  `[nullifiers[2], outputNoteIds[4] (incl. feeNote), encryptedNoteData[4×5], notesRoot,
  protocolFeePerThousand, commitPendingNotesGasFeeRoot, feeNotePublicKey[2]]` = 31 — the
  independent recomputation matches snarkjs exactly. Withdrawal:
  `[withdrawnAmount, nullifiers[2], notesRoot, destinationAddress, tokenId]`. Pending: `[inputHash]`.
- The on-chain bool is decoded from the raw 32-byte `eth_call` output; a proof-point
  corruption may return `false` **or** revert (off-curve precompile failure) — both counted
  as rejection.

## Open issues for the real `curvy-witnesscalc` (L0.5) crate

1. **`build_pending_commitment` output is not a circuit input** — see *Witness-builder
   findings*: drop `newNotesRoot`, reduce `inputHash` mod p. The other two builders are clean.
2. **`.zkey` residency.** The 13 / 16 / 129 MB proving keys stay in v3-e2e. The SDK needs a
   decision on shipping/loading proving keys (embed, fetch, or path-pin by content hash — the
   prover already assumes a pre-verified zkey). Pending's 129 MB key is the outlier.
3. **Graph artifact lifecycle.** Decide where the per-circuit `*.graph.bin` live and how they
   regenerate on circuit changes (offline `build-circuit` step in `curvy-circuits`, pinned by
   hash). Runtime never needs the circom toolchain — only the committed graph +
   `circom-witnesscalc`. Pending's 13 MB graph argues for a fetch/cache rather than embed.
4. **Alloy weight.** The on-chain leg pulls the full alloy tree; in the real SDK this is the
   `curvy-chain-rpc`/`curvy-chain-blokli` (L4) concern, not L0.5 witness-calc.
