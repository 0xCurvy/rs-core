# Curvy × HOPR/blokli — M2 environment

> **Current delivery path:** run `./run.sh image-up`. It builds and starts Blokli's
> native `docker-bloklid-anvil-curvy-x86_64-linux` image, then runs the transaction
> smoke test and strict Curvy E2E. Run `./run.sh image-down` to stop it. Nix/image
> validation must run in the Linux VM. The compose and standalone-deployer sections
> below are retained temporarily as rollback documentation until that acceptance run
> passes; they are not the release path. `./run.sh e2e` re-runs just the strict Curvy
> E2E against an already-running stack. A system Cargo installation is optional:
> `run.sh` uses the host toolchain only when it is complete (cargo **and** libclang —
> `bindgen` needs the latter); otherwise it falls back to Blokli's Nix shell for Blokli
> builds and rs-core's Nix shell (which provides libclang/libffi) for the smoke and
> SDK builds. The strict E2E also needs the three
> proving keys, which ship in this repo under `zk-keys/v2` via Git LFS — run
> `git lfs pull` and `run.sh` discovers them automatically. `CURVY_ZK_KEYS_DIR` can
> still point at an external `packages/zk-keys/v2` checkout to override.

A reproducible local stack that puts **Curvy's v2 contracts and the HOPR contract
suite on one anvil**, runs **hoprnet/blokli (`bloklid`)** against it, and proves a
**pre-signed raw tx flows through blokli's `sendTransactionSync` GraphQL mutation**
and mines. This is the substrate the Curvy Rust SDK e2e (M2 body) runs on next.

See `../../plans/hopr-blokli-poc.md` §4 (M2) for the milestone this delivers.

```
                          docker compose network "curvy-blokli"
  ┌────────────────────────────────────────────────────────────────────────┐
  │  anvil (foundry)               bloklid (hoprnet/blokli, prod image)      │
  │  :8545  chain 31337            :8080  GraphQL /graphql  +  /healthz /readyz│
  │  1s blocks, 10 accts   ◀──rpc──  indexes the HOPR contract set           │
  │     ▲     ▲                          (Curvy events = later fork)         │
  └─────┼─────┼──────────────────────────────────────────────────────────────┘
        │     │
  HOPR suite  Curvy v2 suite            Rust deployers/tools:
  (blokli-    (vault+aggregator+3         curvy-bindings (v3-e2e contracts pkg) — the
   contract-   verifiers+PortalFactory      hopr-bindings mirror whose deploy_for_testing
   deployer)   +Multicall3+ERC20)           deploys+wires+inits the whole Curvy suite
                                          blokli-smoke  (rs/)  — raw tx → sendTransactionSync
```

> **BOTH suites are now deployed by ONE binary: a fork of blokli's own
> `blokli-contract-deployer`.** `run.sh up` builds that fork on the host and runs it once
> with `--with-curvy`; it deploys the HOPR suite (stock `ContractInstances::deploy_for_testing`)
> then calls `curvy_bindings::config::CurvyContractInstances::deploy_for_testing` on the
> SAME provider/signer (the `curvy-bindings` crate is the structural mirror of
> `hopr-bindings`, living in the v3-e2e monorepo at
> `packages/contracts/evm/bindings/curvy-bindings/`; it supersedes the
> `sdk/curvy-deployer` lib for this path), emitting the HOPR `[contracts]` config,
> Curvy's Ignition JSON, and a `[curvy_contracts]` TOML — no node/pnpm/hardhat toolchain
> at deploy time. The old two-step flow (image `blokli-contract-deployer` for HOPR +
> host `sdk/curvy-deployer` bin for Curvy) is kept behind `CURVY_LEGACY_DEPLOY=1`. The
> ENS stack is skipped (the PoC passes pubkeys directly). NOTE: with curvy-bindings the
> deterministic PortalFactory CREATE2 address is
> `0x410607362be76701CcE07841281e7352E63f2072` (not the Hardhat-era `0x3c0C…8125`):
> CREATE2 hashes the full init code incl. the solc CBOR metadata blob, which differs
> between the Hardhat and forge builds of the same source; the executable bytecode is
> byte-identical (see the parity gate in the curvy-bindings README). No consumer
> hardcodes the address — it flows through the Ignition JSON.
>
> **Fork provenance:** `/Users/vanja/Projects/blokli`, branch `curvy-deployer`, forked
> from `hoprnet/blokli` `main` @ `7b2b00c` ("feat: Add deployment annotations to
> helm-chart (#397)"). The fork adds `--with-curvy` + a `curvy-bindings` path dependency
> (v3-e2e `packages/contracts/evm/bindings/curvy-bindings`, interim until the crate is
> hosted) to `bloklid/src/bin/blokli-contract-deployer.rs`; nothing else changes — the
> Curvy block reads exactly like the HOPR `deploy_for_testing` lines above it. Override
> the fork location with `BLOKLI_FORK=…`.

## What is HOPR-side vs Curvy-side

| Layer | Who | How it gets there |
|---|---|---|
| anvil dev chain | shared | foundry image, `--block-time 1`, chain id **31337** (both worlds' default) |
| HOPR contract suite | HOPR | **forked** `blokli-contract-deployer` (host build) — stock `ContractInstances::deploy_for_testing`; emits the `[contracts]` TOML that bloklid consumes |
| bloklid indexer + GraphQL | HOPR | production image, `network = "anvil-localhost"`, SQLite, single container |
| Curvy v2 contracts + init | Curvy | the **same** forked deployer's `--with-curvy` path calls **`curvy-bindings`**' `CurvyContractInstances::deploy_for_testing` — CreateX bootstrap + deploy/wire the whole suite + `setPerTokenGasFees`/`setFeeNotePublicKey` + read-back (committed forge-bind codegen, parity-gated against the Hardhat artifacts) |
| tx-submission smoke | Curvy | `rs/blokli-smoke` — the exact `TxSubmitter` path (raw tx → `sendTransactionSync`) |

blokli's indexer is hardcoded to the HOPR contract set; it neither needs nor sees
the Curvy contracts. We use blokli purely for **transaction submission** here (its
allowlist validator is a stub, so arbitrary contracts relay) — exactly the PoC
stance in the plan (§1.3, §2, risk #3).

## Port map

| Port | Service | Purpose |
|---|---|---|
| `8545` | anvil | JSON-RPC (Curvy deploy, curvy-init, smoke RPC cross-check) |
| `8080` | bloklid | GraphQL `POST /graphql`, `GET /healthz`, `GET /readyz` |

## Reproduce

Prereqs on host: **docker**, **foundry** (`cast`/`forge`/`anvil`), **cargo**, **jq**,
**curl**. (No node/pnpm/hardhat/v3-e2e toolchain — Curvy is deployed by the Rust
`sdk/curvy-deployer`, which vendors its own creation bytecode + ABIs.)

```bash
cd /Users/vanja/Projects/rs-core/poc/blokli-env
./run.sh up          # full stack + all checks   (≈6–8 min cold, ≈2–3 min warm)
./run.sh smoke       # re-run blokli-smoke only
./run.sh e2e         # re-run the strict Curvy E2E only (stack must be up)
./run.sh deploy      # re-run the Curvy deploy+init only (curvy-deployer)
./run.sh logs        # follow bloklid logs
./run.sh down        # tear down + wipe volumes
```

`run.sh up` is idempotent. Cold time is dominated by the first foundry-image pull
(~200 MB) + the Rust build (~1 min). The Curvy deploy is a few seconds of direct alloy
txs under automine (no more Ignition confirmation waits on 1s blocks).

### What `run.sh up` does, in order
1. Build the forked `blokli-contract-deployer` on the host if missing (`BLOKLI_FORK`,
   rustc 1.96 via blokli's `rust-toolchain.toml`).
2. `docker compose up -d anvil`, wait healthy.
3. **ONE forked deployer invocation, `--with-curvy`** — deploys the HOPR suite, then (same
   provider/signer) CreateX bootstrap + the whole Curvy suite + the two mandatory init
   calls + read-back verify. Writes `generated/contracts.toml` (HOPR `[contracts]`),
   `curvy_deployed_addresses.json` (Ignition JSON), and `generated/curvy_contracts.toml`
   (`[curvy_contracts]`). run.sh then assembles `generated/config.toml` = base +
   `[contracts]` (Curvy stays in its own file — see the deny-unknown-fields note below).
4. `docker compose run --rm seed-tx` — one plain tx so bloklid's
   `verify_rpc_capabilities()` has a transaction to trace (mirrors blokli's smoke compose).
5. `docker compose up -d bloklid`; **drain the indexer** — the whole HOPR+Curvy deploy
   burst (~29 txs) happened under automine before bloklid started, so run.sh mines blocks
   one-per-second until `/readyz` is ready (empty blocks are harmless; each later SDK/smoke
   tx keeps it fed).
6. `rs/blokli-smoke` — chainInfo + raw tx through `sendTransactionSync` + negatives.

> **bloklid config rejects extra sections.** bloklid's top-level `Config` (and all nested
> structs) are `#[serde(deny_unknown_fields)]`, so appending `[curvy_contracts]` to
> `config.toml` would make bloklid **fail to start**. The Curvy addresses are therefore
> written to their OWN files (`curvy_deployed_addresses.json` + `generated/curvy_contracts.toml`),
> never merged into bloklid's config. This is why the forked deployer takes separate
> `--curvy-json-out` / `--curvy-toml-out` paths rather than folding Curvy into `--output`.

Set `CURVY_LEGACY_DEPLOY=1` to instead use the old two-step flow: the bloklid image's
own `blokli-contract-deployer` for HOPR (steps 2–4 as before), then the host
`sdk/curvy-deployer` bin for Curvy after bloklid is up.

## Image provenance

| Image | Tag / digest | Notes |
|---|---|---|
| `europe-west3-docker.pkg.dev/hoprassociation/docker-images/bloklid` | `latest@sha256:b76b2a142a2fa161c2dc79cb9f01c3cb6f668eb841c6206748ad3259330147fc` | **pinned by digest** in compose; publicly pullable (no auth). Ships `/bin/bloklid` + `/bin/blokli-contract-deployer`; **no curl/wget** (so bloklid has no container healthcheck — run.sh polls `/readyz` from the host). |
| `ghcr.io/foundry-rs/foundry` | `latest` → resolved `sha256:8347b728d5d393dac1c018691b36f506d23b9dcd78341d40ea0fcb11c3a19cdd` (2026-07-08; **mutable tag**) | anvil + cast + seed-tx. Re-check with `docker images --digests ghcr.io/foundry-rs/foundry`. |

bloklid version at this digest: **0.23.3** (from `/healthz`).

## Deployed addresses & init read-back

`curvy_deployed_addresses.json` is written by the forked deployer's `--curvy-json-out`
(git-ignored). The `curvy-deployer` lib's init + read-back step sets and verifies:
- `vault.setPerTokenGasFees(gasFees, root)` where `root` is the depth-6 Poseidon2
  merkle root over a full 64-leaf set (`leaf[1]=1e17`, `leaf[2]=2e17`), computed in
  Rust with `curvy-core`'s Poseidon (== the SDK's poseidon-lite `poseidon2` / @zk-kit IMT).
- `aggregator.setFeeNotePublicKey(x, y)` with the dev BabyJubJub fee-collector key
  (`DEV_FEE_COLLECTOR` from devenv.ts).
- Read-back asserts `aggregator.commitmentFeeRoot()`, `aggregator.feeNotePublicKey(0/1)`,
  and `vault.perTokenGasFees(1/2)` match what was written.

(Concrete run values are printed by `run.sh up`; see the RESULTS section below —
addresses change per fresh chain but are deterministic for a given deploy order.)

## RESULTS (reference run, 2026-07-08, all tiers T1–T3 PASSED)

Warm wall time (images already pulled): anvil→smoke ≈ **2–3 min** (HOPR deploy ≈35s,
bloklid ready ≈20s, Curvy Ignition deploy ≈30s, curvy-init ≈15s, smoke <1s). Cold
(first foundry pull ≈200 MB + Rust build ≈1 min): ≈ **6–8 min**.

**T1 — bloklid healthy + chainInfo against anvil (HOPR suite deployed):**
```
GET /healthz  200  {"status":"healthy","version":"0.23.3"}
GET /readyz    200  {"status":"ready", ...,"indexer":{"last_indexed_block":81,"lag":1}}
chainInfo:     network="anvil-localhost" chainId=31337 blockNumber=81 finality=1
```
HOPR suite deployed by `blokli-contract-deployer`; bloklid indexes it (via the emitted
`[contracts]` override). HOPR token proxy e.g. `0x9A676e781A523b5d0C0e43731313A708CB607508`.

**T2 — Curvy contracts + curvy-init read-back (same anvil):**
```
CurvyVault#ERC1967Proxy       = 0x0E801D84Fa97b50751Dbf25036d067dCf18858bF
CurvyAggregator#ERC1967Proxy  = 0x9d4454B023096f34B160D6B654540c56A1F81688
  CurvyWithdrawalVerifier              = 0xE6E340D132b5f46d1e472DebcD681B2aBc16e57E
  CurvyAggregationVerifier             = 0xc5a5C42992dECbae36851359345FE25997F5C42d
  CurvyPendingNotesCommitmentVerifier  = 0x67d269191c92Caf3cD7723F116c85e6E9bf55933
  PoseidonT4                           = 0xc3e53F4d16Ae77Db1c982e75a937B9f60FE63690
PortalFactory#PortalFactory   = 0x3c0C573B618D88F1a370bf18000f437c450D8125  (via CreateX 0xba5Ed0…ba5Ed)
Multicall3 / ERC20Mock / LocalENS…     = see curvy_deployed_addresses.json (17 entries)

read-back:
  aggregator.commitmentFeeRoot()  = 318527533646335451640559730256624356987889861989382757516685243934603950464
  aggregator.feeNotePublicKey(0/1)= 5509…440004 / 5125…838760   (DEV_FEE_COLLECTOR)
  vault.perTokenGasFees(1)        = (portal 5e16, commit 1e17, withdraw 5e16)
  vault.perTokenGasFees(2)        = (portal 5e16, commit 2e17, withdraw 5e16)
```
The `commitmentFeeRoot` computed in Rust (`curvy-core` Poseidon2) is **byte-identical**
to the SDK's canonical value (independently reproduced with `poseidon-lite`).

**T3 — blokli-smoke (raw tx through `sendTransactionSync`):**
```
positive: signed 0.001 ETH transfer (acct1→acct2) → sendTransactionSync(conf=1)
          → Transaction{status:CONFIRMED, hash:0xe76c18…41eb} in 4.9 ms
          → RPC cross-check: receipt block 84, status=true, hash matches
negative: "0xdeadbeef" → RpcError "Failed to decode transaction" in 1.1 ms   (clean, no hang)
          "nothex!!"   → top-level "Invalid hex string" in 0.6 ms            (clean, no hang)
```

## Key design decisions

- **SQLite, single bloklid container** (not the smoke compose's postgres) — mirrors
  blokli's own `docker/blokli-anvil-entrypoint.sh`, fewer moving parts.
- **HOPR + Curvy deploy in ONE forked `blokli-contract-deployer`** (host build), rather
  than an image one-shot + a separate host bin. The fork adds `--with-curvy`, which after
  the stock HOPR deploy calls `curvy_deployer::deploy_and_init` on the same alloy provider.
  It emits the HOPR `[contracts]` section run.sh assembles onto `config/bloklid.base.toml`,
  plus the Curvy JSON/TOML to their own files. The transplant was mechanical: blokli is
  alloy-meta 2.1.0 and `curvy-deployer` is provider-generic + SolCall-only, so it compiles
  against blokli's alloy 2.1 with **no logic changes** (only its `alloy` version range was
  widened to `>=1,<3`; alloy-core is a shared 1.6.0 in both worlds).
- **Curvy deploy is pure Rust (`sdk/curvy-deployer`) under automine.** Direct alloy
  deploys mine per-tx and `get_receipt` returns after 1 confirmation, so the old
  Hardhat/Ignition machinery is gone: **no interval-mining toggle, no `anvil_mine 6`
  5-confirmation dance, no `CURVY_ENVIRONMENT`/`CURVY_NETWORK` parameter-resolver env**.
  The deploy config is `CurvyDeployConfig::local()` (the ignition `"local"`/`"anvil"`
  values, baked in). anvil stays on automine the whole time.
- **`blokli-smoke` stays in the detached `rs/` workspace** (own `[workspace]`), which
  no longer needs `curvy-core` (the gas-fee-tree logic moved into `curvy-deployer`).

## Known limitations / open issues for the SDK e2e (M2 body)

1. **blokli does not index Curvy events** (by design — plan risk #3). The SDK e2e must
   read `PendingNotes`/`CommittedNotes`/`CommittedNullifiers` via **direct `eth_getLogs`**
   (`curvy-chain-rpc`), not blokli. blokli is the `TxSubmitter` only.
2. **`sendTransactionSync` confirmations**: on `anvil-localhost` finality is 1 block;
   the smoke uses `confirmations: 1`. The SDK should not assume >1.
3. **Root/index height race** (plan risk #8): bloklid readiness allows up to
   `max_indexer_lag` blocks (set to 20 here). Curvy's own root-anchor reconcile still
   goes through direct RPC, so this does not affect Curvy correctness — but the SDK's
   sync loop must tolerate index-ahead-of-root on 1s blocks.
4. **foundry image tag is mutable** (`latest`). Pin by digest for CI reproducibility.
5. **Indexer drain after the deploy burst**: `curvy-deployer` mines ~24 txs under
   automine, briefly outrunning bloklid's indexer (it advances a few blocks per new-head
   event, then stalls when the chain freezes). `run.sh` mines blocks one-per-second
   until `/readyz` is ready. Alternative: run the deploy under `--block-time`. This is
   the deploy-time face of plan risk #8 (root/index height race).
6. **ENS stack skipped** by `curvy-deployer` (`LocalENSRegistry`/`SimpleOffchainResolver`
   /`LocalUniversalResolver`) — the PoC passes pubkeys directly and no consumer reads
   those keys. PortalFactory/CreateX/Multicall3/ERC20Mock are all still deployed.
7. **~~Single-container UX~~ DONE**: the transplant into blokli's own
   `blokli-contract-deployer` is now the default path — one host-built deployer emits HOPR
   + Curvy. Fork at `/Users/vanja/Projects/blokli` (branch `curvy-deployer`, off `main`
   @ `7b2b00c`). The `sdk/curvy-deployer` bin is still available standalone via
   `./run.sh deploy` and the `CURVY_LEGACY_DEPLOY=1` fallback. Upstreaming needs the
   `curvy-deployer` crate published to crates.io or git-hosted (it is a `path` dep here).
8. **Indexer burst-stall is a fork-time issue too** (plan risk #8). The one-shot deployer
   mines ~29 txs under automine before bloklid starts; bloklid then needs new heads to
   finish its historical sync, so run.sh's `drain_indexer` mines empty blocks until ready.
   Worth raising upstream alongside the transplant: blokli's anvil entrypoint should drain
   its own indexer after a deploy burst, or the deployer should run under `--block-time`.
