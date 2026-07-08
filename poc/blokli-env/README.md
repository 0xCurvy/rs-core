# Curvy × HOPR/blokli — M2 environment

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
  HOPR suite  Curvy v2 suite            host-side Rust (poc/blokli-env/rs):
  (blokli-    (vault+aggregator+3         curvy-init    — the 2 mandatory post-deploy calls
   contract-   verifiers+PortalFactory    blokli-smoke  — raw tx → sendTransactionSync → mined
   deployer)   +Multicall3+ERC20+ENS)
```

## What is HOPR-side vs Curvy-side

| Layer | Who | How it gets there |
|---|---|---|
| anvil dev chain | shared | foundry image, `--block-time 1`, chain id **31337** (both worlds' default) |
| HOPR contract suite | HOPR | `blokli-contract-deployer` (shipped **inside** the bloklid image) — one-shot `hopr-deploy`; emits the `[contracts]` TOML that bloklid consumes |
| bloklid indexer + GraphQL | HOPR | production image, `network = "anvil-localhost"`, SQLite, single container |
| Curvy v2 contracts | Curvy | `deploy-curvy.sh` — CreateX bootstrap + Hardhat Ignition `Devenv.ts` from the v3-e2e checkout |
| Curvy on-chain init | Curvy | `rs/curvy-init` — `setPerTokenGasFees` + `setFeeNotePublicKey`, verified by read-back |
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

Prereqs on host: **docker**, **foundry** (`cast`/`forge`/`anvil`), **node** + **pnpm**
(with `/Users/vanja/Projects/v3-e2e` deps already installed), **cargo**, **jq**, **curl**.

```bash
cd /Users/vanja/Projects/rs-core/poc/blokli-env
./run.sh up          # full stack + all checks   (≈8–12 min cold, ≈3–4 min warm)
./run.sh smoke       # re-run blokli-smoke only
./run.sh init        # re-run curvy-init only
./run.sh logs        # follow bloklid logs
./run.sh down        # tear down + wipe volumes
```

`run.sh up` is idempotent. Cold time is dominated by the first foundry-image pull
(~200 MB) + the Rust build (~1 min) + the Ignition deploy (~2–4 min on 1s blocks).

### What `run.sh up` does, in order
1. `docker compose up -d anvil`, wait healthy.
2. `docker compose run --rm hopr-deploy` — deploys the HOPR suite on the fresh chain
   (anvil account 0, deterministic addresses) and writes `generated/config.toml`
   (base config + emitted `[contracts]`).
3. `docker compose run --rm seed-tx` — one plain tx so bloklid's
   `verify_rpc_capabilities()` has a transaction to trace (mirrors blokli's smoke compose).
4. `docker compose up -d bloklid`, poll `/readyz` until `"status":"ready"`.
5. `./deploy-curvy.sh` — CreateX bootstrap + Ignition `Devenv.ts`; copies
   `deployed_addresses.json` → `curvy_deployed_addresses.json`.
6. `rs/curvy-init` — the two mandatory calls + read-back verification.
7. `rs/blokli-smoke` — chainInfo + raw tx through `sendTransactionSync` + negatives.

## Image provenance

| Image | Tag / digest | Notes |
|---|---|---|
| `europe-west3-docker.pkg.dev/hoprassociation/docker-images/bloklid` | `latest@sha256:b76b2a142a2fa161c2dc79cb9f01c3cb6f668eb841c6206748ad3259330147fc` | **pinned by digest** in compose; publicly pullable (no auth). Ships `/bin/bloklid` + `/bin/blokli-contract-deployer`; **no curl/wget** (so bloklid has no container healthcheck — run.sh polls `/readyz` from the host). |
| `ghcr.io/foundry-rs/foundry` | `latest` → resolved `sha256:8347b728d5d393dac1c018691b36f506d23b9dcd78341d40ea0fcb11c3a19cdd` (2026-07-08; **mutable tag**) | anvil + cast + seed-tx. Re-check with `docker images --digests ghcr.io/foundry-rs/foundry`. |

bloklid version at this digest: **0.23.3** (from `/healthz`).

## Deployed addresses & init read-back

`curvy_deployed_addresses.json` is written by `deploy-curvy.sh` (git-ignored).
`curvy-init` sets and reads back:
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
- **HOPR deploy uses the image's own `blokli-contract-deployer`**, run as a one-shot,
  rather than reimplementing HOPR deployment. It emits the `[contracts]` section the
  bloklid config needs; run.sh assembles `config/bloklid.base.toml` + that section.
- **`CURVY_ENVIRONMENT=local CURVY_NETWORK=anvil`** are set for the Ignition deploy so
  the module's parameter resolver reads `ignition/{network,environment}-parameters.json`
  under keys `anvil`/`local` (the requested `--deployment-id blokli_anvil_poc` is not a
  valid `environment_network` pair on its own).
- **Detached Rust workspace** (`rs/`, own `[workspace]`) path-depending on `curvy-core`
  — never touches rs-core's root manifest / cargo-deny policy (mirrors `spikes/m1-*`).

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
5. **Full `Devenv.ts` graph is deployed** (incl. PortalFactory/CreateX/ENS), not the
   trimmed vault+aggregator+verifiers set the plan floats — chosen to avoid modifying
   the read-only v3-e2e module. Deploy is correspondingly a bit slower.
6. **Curvy deploy runs from the host** (needs the v3-e2e pnpm/hardhat toolchain), not
   from a container. A later single-container UX could extend `blokli-contract-deployer`
   (plan M2 note) — out of scope here.
