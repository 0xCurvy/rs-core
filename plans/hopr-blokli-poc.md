# Curvy full Rust SDK × HOPR/blokli — PoC plan

*Status: research synthesis, 2026-07-08. Branch: `plan/hopr-blokli-poc`.*
*Sources: local repos (`v3-e2e` @ `v3-backend`, `rs-core`, `v3-backend-rust-core`), shallow clones of `hoprnet/hoprnet` and `hoprnet/blokli`, hoprnet org/web research.*

## 0. Goal

A PoC composed of:

1. a **full Curvy Rust SDK** built on rs-core (`curvy-core` + `curvy-prover`),
2. **hoprnet/blokli** used for transaction submission and chain indexing,
3. Curvy logic running as a **hoprd strategy**,
4. everything running against **blokli's anvil image** with Curvy's contracts deployed.

Later phases (not this PoC, but the design must not preclude them): the "pix protocol",
HOPR connectors/edge nodes as Curvy infrastructure.

---

## 1. What we learned (condensed)

### 1.1 Curvy today (reference: `v3-e2e` on branch `v3-backend`)

- The canonical SDK is `packages/@0xcurvy/sdk` (`@0xcurvy/curvy-sdk`, ~280 src files).
  Functional wagmi-style API: `createCurvyConfig()` + standalone actions
  (`login/register`, `refreshBalances`, `estimateIntent/executePlan`,
  `buildAggregateRequest/buildWithdrawRequest`, `syncNotes`, …). `AGENTS.md` in that
  package is the canonical map; its `README.md` documents a deleted legacy API.
- **The crypto core the TS SDK loads today is a Go-compiled wasm**
  (`assets/core/curvy-core-v1.0.2.wasm`, go1.24.5). rs-core is its intended Rust
  successor and already exposes a *superset* of the Go core's surface
  (`crates/wasm/src/lib.rs` additionally exports poseidon/ownerHash/noteId/nullifier/
  sign/cipher — things the TS SDK currently re-implements in JS).
- Flow model: dual-key stealth notes (`stealth::send/scan`), client-side notes-tree
  sync (indexer delta + **chain-root trust anchor via direct RPC**, gap detection,
  integrity gate recomputing `noteId`), client-side Groth16 proving (snarkjs),
  submission either direct (`submitAggregationRequest`/`submitWithdrawalRequest` on
  `CurvyAggregatorAlphaV2`) or via relayer + Privacy Pass anonymous tokens.
- Six REST services: metadata, indexer (`/v3/sync/{notes,nullifiers,meta}`), relayer,
  portal-broadcaster, batch-prover (legacy v2 path), ens-resolver.
- Contracts (`packages/contracts/evm/src/v2`): `CurvyVaultV2` (custody, UUPS),
  `CurvyAggregatorAlphaV2` (zk settlement; verifier registry keyed by circuit dims;
  events `PendingNotes` / `CommittedNotes` / `CommittedNullifiers` — the only events
  the indexer consumes), `PortalFactory` (CreateX/EIP-1167, entry/exit portals),
  3 snarkjs Groth16 verifiers. Deploy = Hardhat Ignition (`Devenv.ts`) + two
  **mandatory** post-deploy calls: `initPerTokenGasFees`, `initFeeNotePublicKey`
  (aggregation/withdrawal revert without them). zk artifacts are pre-built and
  checked in (`packages/zk-keys/v2`, git-lfs). Localnet chain id 31337; CreateX is
  only needed for `PortalFactory`.

### 1.2 rs-core (this repo)

- `curvy-core` is **pure, sync, IO-free and fully usable as a native Rust library**
  (typed `Fr`/`BigUint` API; decimal strings exist only in `curvy-wasm`). `stealth`
  returns typed `Result<_, StealthError>`; the commitment-layer modules panic on
  malformed input by design (callers pre-validate).
- `curvy-prover` (detached workspace) proves natively from `.zkey` + `.wtns` and emits
  snarkjs-shaped JSON accepted by the on-chain verifiers. ~6–8× snarkjs native.
- **Gap #1 (the critical one): no witness calculator.** `witness.rs` builds flat
  circuit *input* objects; `curvy-prover` needs the *full assignment* (`.wtns`).
  The wasmer calculator from ark-circom was deliberately dropped. Nothing in any
  repo fills this seam today.
- Everything else a full SDK needs is absent by design: chain clients, contract
  bindings, HTTP clients, key derivation from wallet signatures, storage, async
  orchestration, unified error model.
- `v3-backend-rust-core` / `rust-core-sdk` checkouts = earlier/later snapshots of the
  same "vendored core-rs + wasm-in-SDK + hybridProver worker" integration that
  rs-core was extracted from. Consumption pattern there is wasm; **a native Rust SDK
  should skip the wasm/decimal-string boundary entirely.**

### 1.3 HOPR / blokli

- hoprd v3 is mid-modularization: `hoprnet/hoprnet` (main) now contains only the
  `hopr-lib` layer; the chain stack is **already fully extracted to blokli**, consumed
  through `hopr-chain-connector` → crates.io `blokli-client 0.29.1`, abstracted
  behind `hopr-api 1.14.0` traits. The hoprd binary/REST/strategy-YAML wiring lives
  in the separate `hoprnet/hoprd` repo. Related: `hoprnet/edge-client` (`edgli`) — a
  light HOPR protocol client that takes an optional blokli URL (the future
  "connectors" direction), `hoprnet/blokli-client` (Rust GraphQL client crate).
- **Strategy framework** (`impls/strategy`): `#[async_trait] trait Strategy { async fn
  run(&mut self) }` — each strategy owns its own timer/event loop; `MultiStrategy`
  composes `Vec<Box<dyn Strategy + Send>>` with failure isolation and **provably
  accepts out-of-crate strategies** (`test_multi_strategy_accepts_external_strategy`).
  A Curvy strategy is drop-in with zero HOPR code changes; only the composition site
  (hoprd) must include it. Built-ins (AutoFunding, AutoRedeeming, ClosureFinalizer,
  ChannelLifecycle) reach the node via `hopr_api::node` traits — a Curvy strategy
  needs none of them (it talks to its own chain API), so its bounds are just
  `Strategy + Send`.
- **blokli** (GraphQL on :8080, SSE subscriptions, temporal SeaORM DB, Alloy RPC with
  finality windows):
  - **Tx submission**: `sendTransaction` / `sendTransactionAsync` /
    `sendTransactionSync(confirmations)` — all take a **hex pre-signed raw tx**.
    Caller holds all keys and pays gas; blokli never signs. The contract/function
    allowlist validator is a stub (rejects only empty txs) → **Curvy txs can be
    submitted through blokli today with zero blokli changes.**
  - **Indexing**: hardcoded to the HOPR contract set (`chain/indexer/src/constants.rs`
    topic lists, if/else dispatch on fixed addresses in `handlers/mod.rs`). **No
    config for extra ABIs/addresses.** Indexing Curvy events in blokli = a fork:
    new topics + handler + DB entity + migration + GraphQL query/subscription types.
  - **Anvil image**: `bloklid-anvil` (Nix, `nix build .#docker-bloklid-anvil-…`),
    single container: anvil (chain id 31337, 1s blocks, 10 std accounts) + HOPR
    contracts via `blokli-contract-deployer` + bloklid; **only :8080 exposed**
    (anvil :8545 internal). The smoke-test compose
    (`tests/smoke/docker-compose.yml`) instead runs anvil as a *separate service
    with :8545 exposed* + a cast seed one-shot — the easiest base to fork for
    adding Curvy contracts. No auth on the API; no published anvil image found
    (build-it-yourself).
- **"pix protocol"**: empty public footprint in HOPR and Curvy context (publicly only
  Brazil's payment rail). Treated as an internal codename; a seam is reserved
  (§3, L6) but semantics need owner input.
- No public HOPR↔Curvy collaboration exists. The layers are complementary:
  HOPR = network/metadata privacy (mixnet, sessions, RPCh/GnosisVPN pattern),
  Curvy = on-chain transaction-graph privacy (stealth addresses + ZK). The natural
  long-term fit: Curvy's network calls (relay submission, note-delta fetch, handle
  resolution) tunneled over HOPR sessions; Curvy node-side logic living as hoprd
  strategies; blokli as the shared chain backend for Curvy light clients.

---

## 2. Where the Curvy Rust SDK fits in the HOPR stack

```
                 ┌────────────────────────────── hoprd (separate repo) ─────────────┐
                 │  MultiStrategy: [AutoFunding, …, ★CurvyStrategy]                  │
                 │  hopr-lib (transport/sessions)     hopr-chain-connector           │
                 └──────────────┬────────────────────────────┬──────────────────────┘
                                │ Strategy trait              │ blokli-client (GraphQL)
   ★ curvy-hopr-strategy ───────┘                             ▼
   ★ curvy-sdk (CurvyClient)                        ┌──────────────────┐
       ├─ TxSubmitter ────────── blokli GraphQL ───▶│  bloklid  :8080  │
       ├─ NoteIndexSource ──┐                       │  (indexes HOPR;  │
       ├─ RootAnchor        ├── direct RPC (PoC) ──▶│  Curvy events    │
       └─ FeeConfigSource ──┘        │              │  = later fork)   │
   ★ curvy-core / curvy-prover       ▼              └────────┬─────────┘
     (rs-core, native link)   anvil :8545  ◀── HOPR contracts + ★Curvy v2 contracts
```

Key structural decisions this diagram encodes:

1. **Blokli is one adapter, not a hard dependency.** Chain access sits behind
   Curvy-owned traits split *by capability*, because no single backend covers all of
   them today: `TxSubmitter` (blokli ✅ today), `NoteIndexSource` (blokli ❌ — direct
   RPC in the PoC, blokli fork or Curvy indexer later), `RootAnchor` (**always** a
   direct chain read — the trust anchor is never delegated to an indexer, mirroring
   the TS `rpcRootVerifier` seam), `FeeConfigSource`, `BalanceReader`. This is the
   same seam HOPR itself uses (`hopr-api` traits, blokli behind a connector).
2. **The strategy is a thin policy shell** around `Arc<CurvyClient>` — it needs no
   HOPR chain/ticket traits, so it composes with just `Strategy + Send` and stays
   insulated from hoprd's toolchain except in one crate.
3. **Native linking, no wasm boundary.** The TS SDK's decimal-string glue and its
   duplicated JS crypto are artifacts of the JS runtime; the Rust SDK calls
   `curvy-core`'s typed API directly. `curvy-wasm` remains the JS-boundary shim and
   later becomes the TS SDK's core replacement (one Rust core, compiled twice).

## 3. Target architecture (crate layers)

One-directional dependency flow; **L0–L3 never name a concrete backend**:

```
L0  curvy-core, curvy-prover                      [EXIST — rs-core, unchanged]
L1  curvy-types, curvy-keys                        pure domain, serde, no IO
L2  curvy-chain-api, curvy-services-api,           trait boundaries only
    curvy-storage (Storage + SecretStore)
L3  curvy-abi (alloy sol!), curvy-notes (sync      pure algorithms over L2 seams
    engine), curvy-planner, curvy-privacy-pass
L4  curvy-chain-blokli, curvy-chain-rpc,           concrete adapters (the only
    curvy-services-http, curvy-storage-{mem,sled}  crates naming a backend)
L5  curvy-sdk (CurvyClient facade: builder,        what wallets/CLIs/strategies call
    actions, typed broadcast/watch event bus)
L6  curvy-sdk-wasm | curvy-hopr-strategy |         consumers
    curvy-pix (future) | curvy-connector (future)
```

- New workspace (working name `curvy-rs-sdk`) **path-depending on rs-core** —
  don't fold into rs-core's workspace: the prover is already detached, and
  `curvy-hopr-strategy` must track hoprnet's toolchain (edition 2024, rustc 1.96,
  `hopr-strategy`/`hopr-api` from crates.io) while everything else stays on stable.
- Plus `curvy-witnesscalc` (L0.5): one trait (`WitnessCalculator`), v0 = snarkjs
  `wtns.calculate` subprocess with the circuit `.wasm`, v1 = pure-Rust calculator
  (spike iden3 `circom-witnesscalc` against Curvy's circuits' custom templates/bus
  types). Callers stay calculator-agnostic; "pure-Rust, no-JS" is earned
  incrementally without rework.
- Async model: tokio for IO; crypto/proving stay sync and run under
  `spawn_blocking`/rayon; typed enum events over `tokio::sync::broadcast` + `watch`;
  keyring is `Zeroizing`, never serialized; `SecretStore` trait for at-rest secrets
  (OS keychain / encrypted opt-in) — the browser XOR-split keystore trick stays a
  wasm-adapter concern.
- **Deliberately NOT copied from the TS SDK**: the ambient global config singleton;
  the second in-host-language crypto implementation; the decimal-string boundary for
  native callers; the mega `CurvyConfig` value-bag (→ narrow injected `Arc<dyn Trait>`
  fields); closure-injected seams (→ trait objects); string-keyed events; the
  assumption that "the indexer" is the note-delta source.

## 4. PoC milestones

Ordering principle: **kill the riskiest assumption first**, and make every milestone
independently demoable. PoC cuts (all stubbed/deferred, none blocked by the design):
portals/CreateX, Solana, LiFi bridging, relayer + Privacy Pass (direct submit only),
ENS/metadata handle resolution (pass pubkeys directly), sharded lean-client engine,
passkeys/EIP-712 UI flows (private-key login path only).

### M1 — A Rust proof accepted by Curvy's real verifier  ← the kill-shot test
The single riskiest assumption is that rs-core's prover output verifies against
Curvy's *deployed* snarkjs verifiers, because the witness-calc seam is unfilled and
zkey provenance is unconfirmed.
- Build `curvy-witnesscalc` v0 (snarkjs subprocess over `packages/zk-keys/v2`
  artifacts). Feed `witness::build_withdrawal` (2,30 — smallest circuit) →
  `.wtns` → `curvy-prover` → snarkjs-JSON proof.
- Verify (a) off-chain against the checked-in vkey (fast inner loop), then
  (b) on-chain: deploy only `CurvyWithdrawalVerifier.sol` to a bare anvil and get
  `verifyProof(...) == true`. Repeat for aggregation (2,3,30).
- Prerequisite check: the zkey proved against is byte-identical to the artifact
  whose verifier is deployed (same trusted-setup build).
- **Exit:** `cargo run -p curvy-poc --bin prove-verify` passes both checks. A failure
  localizes to {witness-calc, field/endianness, zkey/verifier mismatch} before any
  SDK scaffolding exists.

### M2 — Curvy contracts on blokli's anvil; first tx through blokli
- Fork `blokli/tests/smoke/docker-compose.yml` (anvil as separate service, :8545
  exposed, HOPR deployer one-shot) and add a Curvy deploy one-shot running the
  existing Ignition `Devenv.ts` graph trimmed to vault + aggregator + 3 verifiers
  (+ Multicall3 + ERC20Mock; skip PortalFactory/CreateX/ENS), then
  `initPerTokenGasFees` + `initFeeNotePublicKey`. Chain id stays 31337 (matches both
  worlds' defaults). Alternative for later single-container UX: extend
  `blokli-contract-deployer.rs`.
- `curvy-chain-api` traits + two adapters: `curvy-chain-blokli::TxSubmitter`
  (via `blokli-client` `sendTransactionSync`; fall back to a ~50-line reqwest
  GraphQL client if the crate drags in too much) and `curvy-chain-rpc`
  (alloy: `NoteIndexSource`/`RootAnchor`/`FeeConfigSource`/`BalanceReader`).
  `curvy-abi` from `packages/contracts/evm/artifacts/src/v2/**`.
- Drive one self-shielded aggregation end-to-end: keys (keccak-KDF from raw
  private keys) → `stealth::send` → M1 proving path → alloy-encode
  `submitAggregationRequest` → sign raw tx → **blokli `sendTransactionSync`** →
  read back `PendingNotes`/`CommittedNotes` via direct `eth_getLogs`.
- **Exit:** a Rust-built, Rust-proved Curvy aggregation is mined on blokli's anvil,
  submitted through blokli's GraphQL, events read back over RPC.

### M3 — Receive path: sync, scan, discover
- `curvy-notes` global-IMT engine over the seams: delta pull → gap-detect →
  `curvy-core::imt` fold → `RootAnchor` reconcile (tolerate index-ahead-of-root
  on 1s blocks + blokli finality lag; retry, don't throw) → `stealth::scan`/
  `viewer_scan` + `cipher::decrypt_amount_token` → integrity gate (recompute
  `note_id`, drop mismatches) → `curvy-storage-mem` balance entries.
- **Exit:** a second account syncs from chain, discovers and correctly values its
  owned note; a forged-ciphertext leaf is rejected in a test.

### M4 — Two-party e2e through the CurvyClient facade
- Assemble `CurvyClient` (builder injecting the adapter mix), actions:
  login-with-private-keys, refreshBalances, aggregate(A→B), withdraw.
- **Exit:** integration test: fund → shield → A sends to B → B syncs, sees the note
  → B withdraws to a plain address whose balance increases — entirely from Rust,
  submission via blokli.

### M5 — CurvyStrategy in MultiStrategy
- `curvy-hopr-strategy`: `impl hopr_strategy::Strategy for CurvyStrategy` owning
  `Arc<CurvyClient>`; internal timer loop; policy v0 = sync notes + auto-aggregate
  when owned-note count exceeds circuit `maxInputs` (or threshold-triggered settle).
- Run via a standalone `MultiStrategy::new(vec![Box::new(curvy), …])` runner bin —
  the hoprd composition site lives in the separate `hoprnet/hoprd` repo and a full
  node needs Safe/staking/registry infra; API-level compatibility is what the PoC
  proves (exactly what HOPR's own out-of-crate-strategy test demonstrates).
- **Exit:** compiles against crates.io `hopr-strategy`/`hopr-api`; the runner
  triggers a real settle via blokli on schedule; a failing CurvyStrategy does not
  abort a sibling strategy (isolation test).

### Phase 2+ (post-PoC, seams already in place)
1. **Blokli indexes Curvy events** — fork or upstream: topics + handler + DB entity
   + migration + GraphQL types for `PendingNotes`/`CommittedNotes`/
   `CommittedNullifiers`; then `curvy-chain-blokli` also implements
   `NoteIndexSource` and the RPC adapter becomes fallback. Worth an early
   conversation with the HOPR team about generic extensibility upstream.
2. **In-node strategy**: wire CurvyStrategy into the real `hoprnet/hoprd`
   composition site; assess a dev-net hoprd against the same anvil.
3. **Relayer + Privacy Pass** (`curvy-privacy-pass`), portals/recovery, Solana,
   bridging — per parity checklist (29 capabilities catalogued in research).
4. **`curvy-sdk-wasm`**: wrap CurvyClient for the browser; retire the Go wasm core
   and the TS SDK's duplicated JS crypto (one Rust core compiled twice).
   Prerequisite: rs-core↔Go-core conformance vectors.
5. **Connectors / pix**: Curvy service traffic over HOPR sessions via
   `edge-client`/session targets (RPCh pattern) behind `curvy-services-api`;
   `curvy-pix` slots in at L6 once its semantics are defined.

## 5. Risks (ranked)

1. **Witness-calculator gap** — no Rust path from circuit inputs to full assignment;
   v0 subprocess undercuts "pure Rust" until the circom-witnesscalc spike lands.
   Compatibility of Curvy's custom templates/bus types with pure-Rust calculators
   is unverified. *Mitigated by M1 ordering + trait seam.*
2. **zkey/verifier provenance** — a mismatch produces proofs that verify locally but
   revert on-chain. *M1 pins artifact provenance; golden vectors per circuit config.*
3. **Blokli indexer can't see Curvy events** — "blokli for indexing" is a fork, not
   config. *PoC uses direct RPC; trait split keeps the swap cheap; upstream talk.*
4. **Blokli's permissive validator may tighten** — a future allowlist release could
   block Curvy calls. *Keep `curvy-chain-rpc` direct-submit as fallback TxSubmitter.*
5. **hoprd composition site not in the lib repo** — M5 proves the trait contract via
   a standalone runner; a true in-node demo needs `hoprnet/hoprd` + node infra
   (possibly HOPR-team involvement, permissioned registry).
6. **Toolchain split** — rs-core (2021/stable) vs hoprnet (2024/1.96) + exact
   crates.io dep pins. *Contained in the single `curvy-hopr-strategy` crate.*
7. **Deploy-init foot-guns** — missing `initPerTokenGasFees`/`initFeeNotePublicKey`,
   or empty-root constant drift between the aggregator's `initialize` and the SDK
   IMT → silent reverts. *Deploy one-shot runs both; SDK pins the depth-30 root.*
8. **Root/index height races** on 1s blocks + finality windows → sync must tolerate
   and retry, or balances flap.
9. **Panic-prone core boundary** — commitment-layer functions panic on bad input;
   the SDK needs a validating shim + one `thiserror` error enum at L5.
10. **Chain-flavor drift** (Gnosis 100/xDai/hardfork vs anvil 31337/Cancun) — pinned
    to 31337 for the PoC; Gnosis-flavor is a deliberate later step.

## 6. Open questions (need owner input)

1. **pix protocol** — no public footprint; what is it, and does it ride on sessions
   (transport) or on HOPR ticket economics (settlement)? The two imply different
   L6 crates.
2. **PoC scope cuts** — confirm: stubbed handle registration (no metadata service),
   direct submit only (no relayer/Privacy Pass), no portals/Solana/bridging.
3. **Blokli indexing end-state** — fork blokli for Curvy events, run a Curvy-owned
   indexer beside it, or pursue upstream generic extensibility with the HOPR team?
4. **Witness-calc end-state** — is a temporary snarkjs subprocess acceptable, or is
   pure-Rust witness generation a hard requirement (and on what timeline)?
5. **Strategy depth** — is CurvyStrategy purely a scheduler around CurvyClient
   (current design), or should it eventually react to HOPR node state
   (channels/tickets), which would add `hopr-api` node-trait bounds?
6. **zkey provenance** — confirm `packages/zk-keys/v2` artifacts are the same
   trusted-setup build as the deployed verifier bytecode.
7. **Repo layout** — new `curvy-rs-sdk` workspace path-depending on rs-core
   (recommended), or grow inside rs-core?
8. **Chain flavor** — vanilla 31337 anvil for the whole PoC (recommended), Gnosis-
   flavored later?
