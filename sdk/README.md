# Curvy Rust SDK — M2 slice (`sdk/`)

The first real slice of the full Curvy Rust SDK: a **detached cargo workspace**
instantiating the plan's L2/L3/L4 seams (`plans/hopr-blokli-poc.md` §2–3) at PoC
scale, driving a **real end-to-end flow on the `poc/blokli-env` stack, entirely from
Rust**:

> **shield → commit → aggregate → scan → withdraw**

Rust-built, Rust-proved (pure-Rust witness + arkworks Groth16), submitted through
**blokli's `sendTransactionSync`** for the aggregation, events read back over direct
RPC, and the aggregation's output note **discovered by a second account via real ECDH
stealth scan**.

> Repo location is provisional (plan open-question 3: a detached `curvy-rs-sdk`
> workspace path-depending on rs-core, vs growing inside rs-core). It lives under
> `sdk/` for now; nothing here touches rs-core's root `Cargo.toml`/`deny.toml`.

## Crate map (one-liners)

| crate | layer | what it is |
|---|---|---|
| `curvy-types` | L1 | neutral domain types crossing the seams — decimal-string field elements, `RawTx`, decoded events, `FeeConfig`. No alloy/blokli. |
| `curvy-chain-api` | L2 | the load-bearing seam: `TxSubmitter`, `NoteIndexSource`, `RootAnchor`, `FeeConfigSource`, `BalanceReader`, `PortalDirectory` (`#[async_trait]`) + one `ChainError`. |
| `curvy-abi` | L3 | alloy `sol!` bindings from **vendored** ABI JSONs (compile-time; v3-e2e never read at runtime), calldata encoders, local raw-tx signer, snarkjs→on-chain proof transform (the G2 swap), event decoders. Neutral public API. |
| `curvy-witnesscalc` | L0.5 | `WitnessCalculator` trait + graph impl (iden3 `circom-witnesscalc`) + `curvy-prover`; per-circuit graph/zkey pinned by sha256; the interim `build_pending_commitment` massaging. |
| `curvy-chain-blokli` | L4 | `TxSubmitter` over bloklid GraphQL (`sendTransactionSync`, conf=1), typed union errors. |
| `curvy-chain-rpc` | L4 | `NoteIndexSource`/`RootAnchor`/`FeeConfigSource`/`BalanceReader`/`PortalDirectory` over alloy against anvil + a direct-submit `TxSubmitter` fallback. |
| `curvy-sdk` | L5 | the `CurvyClient` facade: keccak-KDF accounts, note build/send via `curvy-core` stealth, the shield/commit/aggregate/scan orchestration over the trait objects, minimal in-memory storage. **No direct alloy/blokli/reqwest dependency.** |
| `curvy-e2e` | L6 | the runnable end-to-end (bin + integration test); per-step PASS/FAIL ledger. |
| `curvy-deployer` | legacy | frozen deployment path; retained until the native Blokli image passes Linux acceptance. |

Dependency flow is one-directional and L0–L3 never name a concrete backend. The seam
is real, not decorative: `curvy-sdk`'s `Cargo.toml` lists no alloy/blokli/reqwest —
chain access is only via the adapter crates behind the L2 traits.

## Reproduce

```bash
# 1. Prerequisite: bring up the M2 substrate (anvil + HOPR + Curvy + bloklid).
#    ≈6–8 min cold, ≈2–3 min warm. Writes poc/blokli-env/curvy_deployed_addresses.json.
cd /Users/vanja/Projects/rs-core/poc/blokli-env && ./run.sh image-up

# 2. Run the e2e (release — arkworks proving is far faster than debug).
cd /Users/vanja/Projects/rs-core/sdk && cargo run --locked --release -p curvy-e2e
# The integration test is strict and fails when the stack is unavailable:
cargo test --locked --release -p curvy-e2e

# 3. Tear the stack down when done.
cd /Users/vanja/Projects/rs-core/poc/blokli-env && ./run.sh image-down
```

Expected wall time for step 2 once the stack is up: a few seconds of chain round-trips
plus the two heavy proofs (aggregation ≈ a couple s, pending ≈ a few s in release).

## What each step does (and the load-bearing details)

1. **shield** — pre-fund the deterministic entry portal (Portal forwards its own
   balance to `autoShield`), then `deployShieldPortal(note, recovery)`. The note owner
   is a full Curvy account's BabyJubJub key; `netAmount = gross − (gross·depositFee/1e4
   + portalDeployment + pendingNoteCommitment)` is recomputed exactly as the contract
   does (fees read from chain via `FeeConfigSource`). Verified by reading back the
   `PendingNotes` event.
2. **commit** — build the batch-5 pending-notes-commitment input (the interim
   `to_circuit_input` drops `newNotesRoot` and field-reduces `inputHash`), prove with
   the graph+prover pipeline, `commitPendingNotes(5, noteIds, newRoot, a, b, c)`. The
   contract recomputes `inputHash = sha256(noteIds‖currentRoot‖newRoot‖currentIndex‖
   newIndex) mod p` — matched exactly. Verified by the chain root advancing.
3. **aggregate** — spend the committed note against the new root: real IMT inclusion
   (`curvy-core::imt` mirroring on-chain leaves), EdDSA-Poseidon owner signature,
   encrypted output notes, fee/gas signals consistent with chain (`protocolFeePerThousand`,
   the **real** depth-6 gas-fee tree bound under `commitmentFeeRoot`, `feeNotePublicKey`).
   The output to Bob is a **real stealth send** (`curvy-core::stealth::send`); change
   goes back to Alice; the fee note is owned by the on-chain `feeNotePublicKey`. Encoded
   as `submitAggregationRequest`, signed locally, submitted **through blokli
   `sendTransactionSync`**.
4. **scan** — pull `PendingNotes` via `eth_getLogs`, run `stealth::scan` (ECDH +
   view-tag prefilter), `decrypt_amount_token`, and the integrity gate (recompute
   `noteId`, drop mismatches). Asserts Bob discovers the aggregation output with the
   right amount/token.
5. **withdraw** — commit Bob's note, submit the withdrawal through Blokli, and require
   the destination balance delta to match the delivered amount.

See `../spikes/m1-prove-verify` (the proven pure-Rust proving pipeline) and
`../poc/blokli-env` (the running stack) — this workspace is built ON TOP of both and
modifies neither.
