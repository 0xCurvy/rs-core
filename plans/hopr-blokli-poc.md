# Curvy full Rust SDK × HOPR/blokli — PoC plan

*Status: research synthesis, 2026-07-08. Branch: `plan/hopr-blokli-poc`.*
*Sources: local repos (`v3-e2e` @ `v3-backend`, `rs-core`, `v3-backend-rust-core`), shallow clones of `hoprnet/hoprnet` and `hoprnet/blokli`, hoprnet org/web research.*

## 0. Goal

A PoC composed of:

1. a **full Curvy Rust SDK** built on rs-core (`curvy-core` + `curvy-prover`),
2. **hoprnet/blokli** used for transaction submission and chain indexing,
3. Curvy logic running as a **hoprd strategy**,
4. everything running against **blokli's anvil image** with Curvy's contracts deployed.

Later phases (not this PoC, but the design must not preclude them): PIX (RFC-0012 —
Curvy as the privacy pool for HOPR exit-node incentives, see §1.4), HOPR
connectors/edge nodes as Curvy infrastructure.

Decisions locked in with Vanja (2026-07-08):
- **Pure-Rust witness generation from day one** — no snarkjs/JS subprocess, ever
  (see §3 witness-calc and M1).
- **Blokli indexing of Curvy events is a later modification; Curvy's own indexer
  stays for now.** The PoC reads events via direct RPC; the existing Curvy indexer
  REST is the interim production `NoteIndexSource`; a blokli extension comes later.
- PoC scope cuts (§4 preamble) approved in principle.

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
- No public HOPR↔Curvy collaboration exists yet (the PIX Appendix-3 PR is the first
  concrete artifact). The layers are complementary:
  HOPR = network/metadata privacy (mixnet, sessions, RPCh/GnosisVPN pattern),
  Curvy = on-chain transaction-graph privacy (stealth addresses + ZK). The natural
  long-term fit: Curvy's network calls (relay submission, note-delta fetch, handle
  resolution) tunneled over HOPR sessions; Curvy node-side logic living as hoprd
  strategies; blokli as the shared chain backend for Curvy light clients.

### 1.4 PIX — RFC-0012 and Curvy's role (the "pix protocol")

PIX = **Protocol for Incentivization of eXits** (`hoprnet/rfc` RFC-0012, Draft
v0.3.0 on branch `pix`; authors Pohanka/Yu). It pays Exit nodes for serving Entry
nodes, conditionally on actually delivering return traffic, without the Exit
learning anything about the Entry:

- The Entry deposits into an abstract **privacy pool `W`** ahead of time
  (`Deposit(Amount) → Deposit_Handle`).
- Per agreement round `i`, Entry and Exit jointly derive a **Session Stealth
  Address**: `SSA_i = Σ constant-term commitments of m Entry polynomials +
  ExitCommitment_i` (Exit's `b_i·BP`). Neither side alone knows `SSA_Priv_i`.
  The Entry runs `Allocate(ChunkPrice, Deposit_Handle, SSA_i)` against `W`.
- The Entry attaches **encrypted Shamir-style shares** of its polynomial constants
  to SURBs; a share only becomes decryptable by the Exit after the Exit *uses* that
  SURB to send reply traffic (the ack-secret from the first return-path relayer
  keys the decryption — that's the traffic-conditionality trick). After `t+1`
  verified shares per polynomial the Exit Lagrange-interpolates, adds `b_i`,
  obtains `SSA_Priv_i`, and runs `Withdraw(SSA_i, PkPoP, WithdrawalAddress)`.
- Appendix 2: PIX messages ride the Session/Start protocols (RFC-0008/0009),
  bound to a Session ID; `UsePIX` capability bit in `StartSession`.

**PR #89 (Aleksandar, open against the `pix` branch) adds Appendix 3: `W` = the
Curvy protocol with curve `C` = BabyJubJub** (Appendix 1's secp256k1 is
ZK-inefficient). The mapping onto Curvy is remarkably direct:

| RFC-0012 op | Curvy realization |
|---|---|
| `Deposit(Amount)` | shield into the aggregator; the note + inclusion proof is the `Deposit_Handle` |
| `Allocate(amount, handle, SSA_i)` | aggregation output note **owned by the SSA_i BabyJubJub pubkey** (ephemeral, single-note) |
| `Withdraw(SSA, PkPoP, dest)` | Curvy withdrawal/aggregation — PoP *is* the EdDSA-Poseidon owner signature already enforced in the circuits |

Consequences for the SDK design (why the architecture already fits):
- Exit-side PIX = exactly the CurvyClient spend path: discover note owned by a
  known key → prove → aggregate/withdraw via `TxSubmitter`. New pieces are small
  and pure-math: polynomial eval/commitment and Lagrange interpolation over the
  BabyJubJub subgroup scalar field (`curvy-core::babyjubjub` already has
  `add_point`/`mul_point_escalar`/`BASE8`/`SUB_ORDER`), plus share
  verification (`y·BP == Σ xʳ·M_r_u`).
- PIX note discovery is **by known owner key**, not trial-decrypt stealth scanning
  — the Exit knows each `SSA_i` it awaits. `curvy-notes` should expose a
  "watch specific owner keys" mode alongside the scan path (cheap addition, worth
  keeping in mind now).
- Share encryption/transport (Blake3 KDF, ChaCha20, SURB attachment, ack-secrets)
  lives in the **HOPR node/session layer**, not the Curvy SDK — the natural home is
  the hoprd side (strategy/session integration), consuming `curvy-pix` (L6) for the
  pool operations.
- Spec gap to raise on the PR: Appendix 3 doesn't yet pin the exact note
  construction for SSA-owned notes (Curvy's `ownerHash = Poseidon(pub.x, pub.y,
  sharedSecret)` needs a defined `sharedSecret` convention the Exit can compute,
  e.g. from the session/agreement transcript).

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
   RPC in the PoC, the existing Curvy indexer REST as the interim production
   source, a blokli extension later), `RootAnchor` (**always** a
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
- Plus `curvy-witnesscalc` (L0.5): one trait (`WitnessCalculator`), **pure Rust
  from day one** (decision: no snarkjs/JS subprocess, ever). Candidate paths, to be
  settled by the M1 spike:
  1. **iden3 `circom-witnesscalc`** — compiles the circom *sources* (the
     `curvy-circuits` package) into an evaluation graph executed natively in Rust.
     Fastest route to full fidelity if Curvy's custom templates/bus types are
     supported; needs the circuit sources + a compatible circom version.
  2. **Native witness builders in Rust** — hand-implement full-assignment
     generation for the three fixed circuit families (aggregation, withdrawal,
     pending-commitment). Every primitive the circuits use already exists in
     `curvy-core` (Poseidon, EdDSA verify, IMT paths, cipher); the work is wire
     ordering fidelity. The long-term ideal (zero circom toolchain anywhere), most
     effort, brittle against circuit changes.
  3. **Embedded wasm runtime fallback** — execute the circom-generated witness
     `.wasm` inside `wasmi`/`wasmtime` from Rust (re-vendor ark-circom's approach).
     No JS/node anywhere — an all-Rust process executing a circom-built artifact.
     Acceptable stopgap only if 1 fails and before 2 lands.
  In every path, conformance is pinned by **golden `.wtns` fixtures generated once
  offline with snarkjs** (committed test vectors, not a runtime dependency) —
  byte-compare full assignments per circuit config.
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
> **✅ PASSED 2026-07-08** — spike at `spikes/m1-prove-verify/` (commit `e1b9bd5`),
> independently re-verified by the orchestrator (fresh proof, all 6 checks).
> Verdict: iden3 `circom-witnesscalc` **handles Curvy's bus-typed circom 2.2.0
> circuits with full fidelity** — pure-Rust witness byte-identical to snarkjs
> (sha256 `b57d069…`, ~6 ms calc), arkworks proof verified off-chain and accepted
> by the deployed `CurvyWithdrawalVerifier` bytecode on anvil; corrupted statement
> and corrupted proof point both rejected. Provenance CLEAN: zkey `c91d9fdb…`
> byte-identical across `zk-keys/v2` and `zk-circuits/build/v2`; verifier constants
> match the snarkjs-generated verifier from that zkey. **§3 decision: option 1
> (evaluation graph) adopted**; option 3 unnecessary, option 2 remains a long-term
> nicety.
>
> **Fast-follow ✅ DONE (same day, commits `cc84433`+`122cf8f`, reviewer-verified):**
> all THREE deployed circuit configs now pass the identical pipeline —
> aggregation(2,3,30): 31 public signals, graph `f757ba00…`, witness `5c8156e4…`;
> pending-notes-commitment(5,30): 226k constraints, 1.1M-node graph, witness
> `e91726d9…`; both provenance-CLEAN (75/75 and 15/15 verifier constants match).
> Findings for the real crates: (a) `witness::build_pending_commitment`'s output
> is not directly circuit-consumable — it serializes a `newNotesRoot` the circuit
> doesn't declare and emits `inputHash` as the RAW sha256 digest (> field modulus)
> where the circuit's public signal is the mod-p reduction; needs a
> `to_circuit_input()` view in core (worked around in the spike's gen-input).
> (b) Artifact sizes force a fetch/cache-by-hash design: pending's zkey is 129 MB,
> its graph 13 MB (gitignored + sha-pinned; `run.sh regen-fixtures` rebuilds
> byte-identically).
The single riskiest assumption is that rs-core's prover output verifies against
Curvy's *deployed* snarkjs verifiers, because the witness-calc seam is unfilled and
zkey provenance is unconfirmed. Pure-Rust witness generation is a day-one
requirement, so M1 *starts* with the calculator spike:
- **Spike `circom-witnesscalc` against the real `curvy-circuits` sources** (custom
  templates/bus types are the compatibility question). If it fails, fall back to
  the embedded-wasmi path while scoping native builders (§3 options 2/3). Generate
  golden `.wtns` fixtures offline with snarkjs and byte-compare.
- Feed `witness::build_withdrawal` (2,30 — smallest circuit) through the calculator
  → full assignment → `curvy-prover` → snarkjs-JSON proof.
- Verify (a) off-chain against the checked-in vkey (fast inner loop), then
  (b) on-chain: deploy only `CurvyWithdrawalVerifier.sol` to a bare anvil and get
  `verifyProof(...) == true`. Repeat for aggregation (2,3,30).
- Prerequisite check: the zkey proved against is byte-identical to the artifact
  whose verifier is deployed (same trusted-setup build).
- **Exit:** `cargo run -p curvy-poc --bin prove-verify` passes both checks. A failure
  localizes to {witness-calc, field/endianness, zkey/verifier mismatch} before any
  SDK scaffolding exists.

### M2 — Curvy contracts on blokli's anvil; first tx through blokli
> **✅ ENVIRONMENT LAYER DONE 2026-07-08** — `poc/blokli-env/` (commits `a991044`,
> `849b51b`), reviewer-verified with a full independent down/up cycle. One anvil
> (automine, 31337) carries the HOPR suite (deployed by the bloklid image's own
> `blokli-contract-deployer`) AND the full Curvy Devenv graph (CreateX bootstrap
> replayed + Ignition `blokli_anvil_poc`); bloklid `0.23.3` (digest-pinned prod
> image) serves GraphQL on :8080; `curvy-init` (alloy) ports the two mandatory
> init calls with read-back verification (root `3185275…50464` matches the SDK
> canonical value; fee-note key == `DEV_FEE_COLLECTOR` in
> `packages/services/common/src/fee-collector.ts`); `blokli-smoke` submits a
> locally-signed raw tx through `sendTransactionSync(conf=1)` → CONFIRMED in ~5 ms,
> RPC cross-checked; garbage submissions rejected cleanly. Review found+fixed one
> flake: Ignition's 5-confirmation interference check raced against hardhat boot
> time (fixed by `anvil_mine 6` pre-deploy). Operational notes: anvil must run
> AUTOMINE (the HOPR deployer's alloy `.watch()` stalls under interval mining);
> `deploy-curvy.sh` flips to interval mining only for the Ignition run;
> anvil-localhost finality = 1 → use `conf=1`; Curvy deploy runs host-side (needs
> v3-e2e's pnpm/hardhat toolchain); addresses hand off via
> `curvy_deployed_addresses.json` (git-ignored, regenerated per run).
>
> **✅ M2 COMPLETE (same day, commit `b668017` — `sdk/` workspace), reviewer-verified
> on a fresh chain**: shield → commitPendingNotes (client plays batch-prover) →
> aggregate to a second account **via blokli `sendTransactionSync`** → real ECDH
> scan-discovery (decrypt + integrity gate) → **withdrawal stretch** to an EOA via
> blokli, balance exact to the wei (cast-verified independently). The `sdk/`
> workspace instantiates the plan's layering at PoC scale: `curvy-types`,
> `curvy-chain-api` (5 traits + `PortalDirectory`), `curvy-abi` (vendored ABIs),
> `curvy-witnesscalc` (real L0.5 crate), `curvy-chain-blokli`, `curvy-chain-rpc`
> (+ direct-submit fallback), `curvy-sdk` (`CurvyClient`, no direct
> alloy/blokli/reqwest — seam verified), `curvy-e2e`. Load-bearing discoveries
> recorded in `sdk/` docs: note-owner BabyJubJub key is account-level (`s`) with
> unlinkability from the stealth `sharedSecret`; shield = pre-fund entry portal
> address then `deployShieldPortal` (non-payable); aggregation `gasFee` must bind
> the real on-chain `commitmentFeeRoot` (core's `build_aggregation` synthesizes
> its own — override needed); `netAmount` = gross − depositFee − portal − commit
> gas. M3 residue: promote `sync()` into the real `curvy-notes` engine (gap
> detection + forged-leaf test); swap the PoC keccak KDF stand-in for the exact
> TS signature-KDF; raw-vs-reduced sharedSecret cross-impl conformance check vs
> the Go core.
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
1. **Blokli indexes Curvy events** (decision: later, not now — the existing Curvy
   indexer stays in the interim). When it happens: topics + handler + DB entity +
   migration + GraphQL types for `PendingNotes`/`CommittedNotes`/
   `CommittedNullifiers`; then `curvy-chain-blokli` also implements
   `NoteIndexSource` and RPC/Curvy-indexer adapters become fallbacks. Meanwhile,
   add a `NoteIndexSource` impl over the Curvy indexer's `/v3/sync/*` REST in
   `curvy-services-http`. Worth an early conversation with the HOPR team about
   generic extensibility upstream.
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

1. ~~**Witness-calculator gap**~~ **RESOLVED (M1, 2026-07-08)**: `circom-witnesscalc`
   evaluation graphs handle the bus-typed circuits with byte-identical output —
   pure-Rust witness generation works today — now proven on ALL THREE deployed
   circuit configs. Residual: artifact lifecycle design (129 MB pending zkey /
   13 MB graph → fetch/cache pinned by hash), and a `to_circuit_input()` fix for
   `build_pending_commitment` (extraneous `newNotesRoot`, unreduced `inputHash`).
2. ~~**zkey/verifier provenance**~~ **RESOLVED for withdrawal(2,30) (M1)**:
   zkey/wasm/vkey byte-identical across `zk-keys/v2` and `zk-circuits/build/v2`;
   deployed verifier constants match the snarkjs-generated verifier from that zkey.
   Repeat the hash check per circuit config as each is brought up.
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

## 6. Open questions

Answered 2026-07-08: ~~pix protocol~~ (= RFC-0012 PIX + Curvy Appendix 3, §1.4),
~~blokli indexing end-state~~ (modify blokli later; Curvy indexer stays for now),
~~witness-calc end-state~~ (pure Rust from day one), ~~PoC scope cuts~~ (approved
in principle).

Still open:

1. **Strategy depth** — is CurvyStrategy purely a scheduler around CurvyClient
   (current design), or should it eventually react to HOPR node state
   (channels/tickets), which would add `hopr-api` node-trait bounds? PIX suggests
   the eventual exit-side strategy *will* need session-layer hooks (share
   verification lives near the SURB machinery) — worth deciding the seam early.
2. ~~**zkey provenance**~~ — answered by M1 for withdrawal(2,30): same trusted-setup
   build; hashes recorded in `spikes/m1-prove-verify/README.md`.
3. **Repo layout** — new `curvy-rs-sdk` workspace path-depending on rs-core
   (recommended), or grow inside rs-core?
4. **Chain flavor** — vanilla 31337 anvil for the whole PoC (recommended), Gnosis-
   flavored later?
5. **PIX (for the Appendix-3 PR / later phase)** — (a) the SSA-owned note
   construction needs a spec'd `sharedSecret`/`ownerHash` convention the Exit can
   compute; (b) which component owns share generation/verification plumbing —
   hoprd session layer consuming `curvy-pix`, or a session-service sidecar; (c)
   shares live over the BabyJubJub *subgroup scalar field* — pin the exact field
   (vs BN254 Fr) in the appendix to avoid an implementation mismatch.
6. ~~**circom-witnesscalc compatibility**~~ — answered by M1: **yes**, full
   fidelity on the bus-typed withdrawal circuit (graph build from sources, ~6 ms
   pure-Rust evaluation, byte-identical to snarkjs). Aggregation/pending-commitment
   fixtures are the fast-follow.
