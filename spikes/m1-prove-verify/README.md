# M1 spike — a Rust proof accepted by Curvy's real verifier

**The kill-shot test for the PoC (plan §M1, risks 1–2).** Produces a Groth16 proof
for Curvy's `verifySingleWithdrawalNoHashing(2,30)` circuit **entirely in Rust**
(pure-Rust witness generation — no JS/node/snarkjs at runtime) and gets it accepted
(a) off-chain against the verifying key and (b) on-chain by the *deployed*
`CurvyWithdrawalVerifier.sol` on a local anvil, plus corrupted-proof negatives.

## Verdict

| Exit criterion | Result |
|---|---|
| Pure-Rust witness generation (no JS/node at runtime) | **PASS** — iden3 `circom-witnesscalc` evaluation graph, executed natively |
| Witness **byte-identical** to the snarkjs golden `.wtns` | **PASS** — sha256 `b57d069…` from both paths |
| Off-chain Groth16 verify (arkworks pvk from the zkey) | **PASS** |
| Public signals == snarkjs reference + expected fixture | **PASS** — 6 signals identical |
| On-chain `verifyProof(valid) == true` (deployed bytecode) | **PASS** |
| On-chain negatives (corrupted statement + corrupted proof point) rejected | **PASS** |
| zkey/verifier provenance (risk #2) | **CLEAN** — see below |

Run it:

```
cd spikes/m1-prove-verify
./run.sh            # or: cargo run --release --bin prove-verify
./run.sh test       # cargo test --release --test e2e
```

Requires: the `anvil` binary on PATH (spawned in-process by alloy), and the deployed
withdrawal(2,30) `.zkey` — read from the v3-e2e asset by default, override with
`CURVY_WITHDRAWAL_ZKEY=/path/to/..._0001.zkey`. Nothing else external at runtime.

## circom-witnesscalc compatibility verdict (the open technical unknown, plan Q6)

**iden3 `circom-witnesscalc` handles Curvy's bus-typed circuits with full fidelity.**
`verifySingleWithdrawalNoHashing` is `pragma circom 2.2.0` and uses buses (`Note()`,
`Signature()`, `NoteInclusionProof()`) — the exact feature that was the compatibility
question. The crate's `build-circuit` frontend (circom master, 2.2.x bus era) compiled
the real circuit sources into an evaluation graph, and the pure-Rust `calc_witness`
runtime produced a witness that is **byte-for-byte identical** to the witness snarkjs
computes from the committed circuit `.wasm`. Non-circular confirmation: the golden
`.wtns` was independently regenerated with `snarkjs wtns calculate` from the committed
`.wasm` and matches both the committed golden and the pure-Rust output (all sha256
`b57d069…`).

- Graph format: `wtns.graph.002` (native graph, not the CVM/wasm path). ~88k nodes,
  21502 signals; witness calc ≈ 8 ms; graph build ≈ a few seconds, offline, once.
- The graph is **deterministic**: rebuilding it from source with `build-circuit`
  reproduces sha256 `3a7c7a5…` byte-for-byte, so it is committed as a fixture with a
  documented regeneration command (`./run.sh regen-fixtures`).

**Recommendation for plan §3 (witness-calc end-state): adopt option 1 (the
`circom-witnesscalc` evaluation graph).** It gives pure-Rust, snarkjs-identical
witnesses today with no JS runtime and no wasm interpreter. The graph artifacts are
built offline from the `curvy-circuits` sources (like compiling) and committed/pinned
by content hash. Option 3 (embedded wasmi) is unnecessary — not needed as a fallback.
Option 2 (hand-written native builders) stays a *long-term* nicety (zero circom
toolchain anywhere) but carries no urgency now: the graph path is
template/bus-agnostic and already exact.

The witness calculator lives behind a `WitnessCalculator` trait (`src/lib.rs`) — the
seam the SDK's `curvy-witnesscalc` (L0.5) crate will expose. Graph build stays an
offline tool; the runtime library dependency is `circom-witnesscalc` only.

## Provenance evidence (risk #2 — re-verified independently)

All hashes below re-verified this run (`shasum -a 256`). Withdrawal(2,30) artifacts
are **byte-identical between `packages/zk-keys/v2` and `packages/zk-circuits/build/v2`**
(same trusted-setup build), and the zkey is a real 13 MB binary (magic `zkey…`), not
an LFS stub:

| Artifact | sha256 | Notes |
|---|---|---|
| `..._2_30_0001.zkey` | `c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716` | identical in zk-keys/v2 and build/v2 |
| `..._2_30.wasm` | `2334759a70baa546d20c0d7488e0ba5b0ee2af563e960257bd30786a95f94e23` | identical in both locations |
| `..._2_30_verification_key.json` | `b243688bce1680a9e13ec9dc0ed18a2b8124a98d9b817f47bdd41d41105fb635` | identical in both locations |

And the **deployed verifier == the circuit's generated verifier**: the 30 `uint256`
verifying-key constants in
`packages/contracts/evm/src/v2/aggregator-alpha/verifiers/CurvyWithdrawalVerifier.sol`
are identical (normalized) to `build/v2/withdrawal/…_2_30_verifier.sol` produced by
`snarkjs zkey export solidityverifier` from that same `_0001.zkey`. The on-chain leg
deploys the compiled artifact's bytecode directly, so "accepted on-chain" is the
definitive check against the committed verifying key.

## Committed fixtures (`fixtures/`)

| File | sha256 | Origin |
|---|---|---|
| `input.json` | `2d1dc3106b…` | rs-core parity vector, rebuilt at treeDepth=30 (`gen-input` bin) |
| `withdrawal_2_30.graph.bin` | `3a7c7a5ad4…` | `build-circuit` from the circuit sources (pure-Rust graph) |
| `golden.wtns` | `b57d06927c…` | `snarkjs wtns calculate` from the committed `.wasm` |
| `snarkjs-proof.json` / `snarkjs-public.json` | `8d921ba4…` / `172b33bc…` | `snarkjs groth16 prove` cross-reference |
| `expected-public.json` | `b2cfc00a…` | 6 public signals in on-chain order |
| `CurvyWithdrawalVerifier.bytecode.txt` / `.abi.json` | `43a59e62…` / `7cb75086…` | extracted from the contracts artifact |

Not committed (read from v3-e2e, `.gitignore`d build/vendor): the 13 MB `.zkey`, the
3 MB `.wasm`, and `vendor/` (the `circom-witnesscalc` clone).

## Reproduce from scratch (independent verification)

```bash
cd spikes/m1-prove-verify

# 0. Build the offline graph tool (once). protoc + clang required by its build.rs.
( cd vendor/circom-witnesscalc && cargo build --release --bin build-circuit --bin calc-witness )

# 1. Regenerate all offline golden fixtures (input, graph, golden .wtns, snarkjs
#    cross-ref, verifier bytecode). Needs v3-e2e + its pnpm snarkjs.
./run.sh regen-fixtures

# 2. The kill-shot: pure-Rust witness -> proof -> off-chain + on-chain verify.
./run.sh            # bin, or `./run.sh test` for the integration test
```

Spot re-checks used during the spike:

```bash
# pure-Rust witness == snarkjs golden, byte-for-byte
./vendor/circom-witnesscalc/target/release/calc-witness \
    fixtures/withdrawal_2_30.graph.bin fixtures/input.json /tmp/r.wtns
cmp /tmp/r.wtns fixtures/golden.wtns && echo IDENTICAL

# snarkjs regenerates the same golden from the committed .wasm (non-circular)
$SNARKJS wtns calculate .../verifySingleWithdrawalNoHashing_2_30.wasm \
    fixtures/input.json /tmp/g.wtns && cmp /tmp/g.wtns fixtures/golden.wtns

# graph is reproducible from source
( cd $V3E2E/packages/zk-circuits && build-circuit \
    ./circuits/v2/instances/verifySingleWithdrawalNoHashing_2_30.circom /tmp/g.bin )
cmp /tmp/g.bin fixtures/withdrawal_2_30.graph.bin && echo GRAPH REPRODUCIBLE
```

## Toolchain / pins

- `circom-witnesscalc` — crate `0.3.0` (runtime dep); vendored clone
  `vendor/circom-witnesscalc` at commit `d48eb7c97857d46b8a75c94ab96f769207263245`
  (tag `v0.3.0`) for the `build-circuit`/`calc-witness` offline tools.
- circom 2.2.3, snarkjs 0.7.5 (v3-e2e pnpm store), foundry (anvil 1.2.1), alloy 1.8.3,
  arkworks 0.5.0 (matches `curvy-prover`).
- Detached cargo workspace (own `[workspace]`); does **not** touch rs-core's root
  `Cargo.toml`/`deny.toml`, `crates/core`, or `crates/prover`.

## Key implementation notes

- **G2 coordinate swap** (`calldata_from_snarkjs`): the on-chain verifier expects each
  `pi_b` coordinate pair reversed (`[c0,c1] -> [c1,c0]`), matching the Ethereum pairing
  precompile convention that `snarkjs generatecall` encodes. Verified numerically
  against `snarkjs generatecall` on the golden proof. G1 points (`pi_a`,`pi_c`) pass
  through unchanged. This is the classic footgun — get it wrong and off-chain passes
  while on-chain reverts.
- **Public-signal order**: `[withdrawnAmount, nullifiers[0], nullifiers[1], notesRoot,
  destinationAddress, tokenId]` — outputs first (declaration order), then public
  inputs. Matches `prover.public_inputs()`, the snarkjs `public.json`, and the
  verifier's `uint256[6]`.
- The on-chain bool is decoded from the raw 32-byte `eth_call` output; a proof-point
  corruption may `false` **or** revert (off-curve precompile failure) — both counted
  as rejection.

## Open issues for M2

1. **Aggregation circuits not yet exercised.** M1 fully proves withdrawal(2,30). The
   `verifySingleAggregationNoHashing(2,3,30)` / `(5,3,30)` and
   `verifyPendingNotesCommitment` circuits use the same buses/templates, so the graph
   path is expected to carry with zero new machinery — the remaining work is a second
   input fixture (an aggregation `witness::build_*` vector) + deploying the matching
   verifier. Fast-follow, not a risk; do it early in M2 to close the circuit family.
2. **`.zkey` residency.** The 13 MB proving keys stay in v3-e2e for the spike. The SDK
   needs a decision on shipping/loading proving keys (embed, fetch, or path-pin by
   content hash — the prover already assumes a pre-verified zkey).
3. **Graph artifact lifecycle.** For the SDK, decide where the per-circuit
   `*.graph.bin` artifacts live and how they're regenerated on circuit changes
   (offline build step in `curvy-circuits`, pinned by hash). The runtime never needs
   the circom toolchain — only the committed graph + `circom-witnesscalc` lib.
4. **Alloy weight.** The on-chain leg pulls the full alloy tree; in the real SDK this
   is the `curvy-chain-rpc`/`curvy-chain-blokli` (L4) concern, not L0.5 witness-calc.
