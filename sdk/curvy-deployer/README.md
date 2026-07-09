# curvy-deployer

Deploy **and** initialise the entire Curvy v2 contract suite from ONE Rust binary,
against any RPC. This replaces `poc/blokli-env/deploy-curvy.sh`'s Hardhat/Ignition leg
**and** the separate `curvy-init` bin — so `poc/blokli-env/run.sh up` needs **no
node / pnpm / hardhat / v3-e2e toolchain** at deploy time.

It replicates `v3-e2e`'s `ignition/modules/deployments/dev/Devenv.ts` (+ its building
blocks) exactly, **minus the ENS stack** (see Deviations), and folds in `curvy-init`'s
two mandatory post-deploy calls + read-back verification.

## Lib-first (built for transplant into blokli)

The end state is that blokli's own `blokli-contract-deployer` deploys HOPR **and**
Curvy in one shot. So all logic lives in the **library**; the bin is a thin clap
wrapper. Public surface:

```rust
pub async fn deploy_curvy_suite<P: Provider>(provider: &P, cfg: &CurvyDeployConfig) -> Result<CurvyAddresses>;
pub async fn init_gas_fees_and_fee_key<P: Provider>(provider: &P, addrs: &CurvyAddresses, cfg: &CurvyDeployConfig) -> Result<()>;
pub async fn verify_readback<P: Provider>(provider: &P, addrs: &CurvyAddresses, cfg: &CurvyDeployConfig) -> Result<()>;
pub async fn deploy_and_init<P: Provider>(provider: &P, cfg: &CurvyDeployConfig) -> Result<CurvyAddresses>; // all three
pub async fn ensure_createx<P: Provider>(provider: &P) -> Result<Address>;                                  // CreateX bootstrap
```

`CurvyAddresses::to_ignition_json()` emits the Ignition-style
`deployed_addresses.json` (downstream `curvy-e2e` / `curvy-hopr-runner` depend on its
keys); `CurvyAddresses::to_toml()` emits a `[curvy_contracts]` TOML section in the
spirit of blokli's `[contracts]` block.

Chain interaction uses only the `Provider` trait's `&self` methods (`send_transaction`,
`call`, `send_raw_transaction`, `get_code_at`) with `SolCall`-built calldata — **no
`alloy-contract` instances** — so the only alloy-version-sensitive surface is the
`Provider` trait itself.

## How the deploy maps to Devenv.ts

| step | what | source of truth |
|---|---|---|
| 0 | CreateX bootstrap (fund keyless EOA + publish pre-signed raw tx) — idempotent | `scripts/devenv.ts` |
| 1 | PoseidonT4 lib → **CurvyAggregatorAlphaV2 impl (PoseidonT4 linked)** → `ERC1967Proxy(impl, initialize(owner))` → 3 verifiers → register `(pending 5)`,`(agg 2,3)`,`(withdrawal 2)` | `building-blocks/CurvyAggregator.ts` |
| 2 | CurvyVaultV2 impl → `ERC1967Proxy(impl, initialize(owner))` | `building-blocks/CurvyVault.ts` |
| 3 | PortalFactory via `createX.deployCreate2(create2_salt, bytecode ++ abi.encode(owner))`, address parsed from the `ContractCreation` event | `building-blocks/PortalFactory.ts` + ignition `"local".create2_salt` |
| 4 | Multicall3, ERC20Mock | `Devenv.ts` |
| 5 | wire: `vault.setCurvyAggregatorAddress`, `aggregator.updateConfig{vault,portalFactory}`, `portalFactory.updateConfig(vault,aggregator,0x0 lifi)`, `vault.registerToken(erc20Mock)` | `Devenv.ts` |
| 6 | dev-address funding: 1000 ETH + `mockMint` 1000 mock ERC20 to `0x0eeCE…97779` | `Devenv.ts` |
| 7 | init: `setPerTokenGasFees(gasFees, commitmentGasFeeRoot)` + `setFeeNotePublicKey(x,y)`, then read-back | `scripts/devenv.ts` (was `curvy-init`) |

**Library linking**: the aggregator creation bytecode carries the unlinked
`__$da668b34bdb7a81662c478d887f0e664bc$__` PoseidonT4 placeholder (solc
`linkReferences`: length 20 at byte 6783). `Artifact::creation_code_linked` substitutes
the 40-hex library address for that placeholder (asserting exactly one occurrence and
none remaining). All other artifacts are placeholder-free (asserted).

**Determinism cross-check**: PortalFactory always lands at
`0x3c0C573B618D88F1a370bf18000f437c450D8125` — byte-identical to the old Ignition path,
confirming our CreateX salt + owner + PortalFactory init-code match. The other
addresses differ from the old run (different deploy/nonce order; no ENS), which is fine
— consumers read them from the emitted JSON, and the **read-back values are identical**
(`commitmentFeeRoot = 318527533646335451640559730256624356987889861989382757516685243934603950464`,
`feeNotePublicKey = DEV_FEE_COLLECTOR`, per-token gas fees as before).

## Usage

```bash
# via the M2 stack (what run.sh calls):
cd sdk && cargo run --release -p curvy-deployer -- \
  --rpc-url http://127.0.0.1:8545 \
  --json-out ../poc/blokli-env/curvy_deployed_addresses.json \
  --toml-out ../poc/blokli-env/generated/curvy_contracts.toml
```

CLI (mirrors `blokli-contract-deployer`): `--rpc-url` (env `RPC_URL`),
`--private-key` (env `CURVY_DEPLOYER_PRIVATE_KEY`, default anvil acct 0), `--json-out`
(env `CURVY_ADDRESSES`), `--toml-out` (optional). Requires the chain on **automine**
(each `get_receipt` needs its tx mined). **Idempotency**: CreateX bootstrap is skipped
if already present; the Curvy suite is deployed FRESH every run
(fresh-deploy-per-fresh-chain, matching the old pipeline).

## Feature flags

- `gas-fee-tree` (**default**): pulls in `curvy-core` (arkworks) for the depth-6
  Poseidon2 commitment-gas-fee tree — the **one heavy dependency**. Isolated in
  `src/gasfee.rs`. Build `--no-default-features` to drop arkworks entirely and instead
  pass a precomputed `commitment_fee_root` in `CurvyDeployConfig` (verified: the crate
  compiles with no `curvy-core` in the tree).

## Alloy version (the blokli-transplant friction)

| | `alloy` meta-crate | `alloy-core` family (`-primitives`/`-sol-types`/`-json-abi`) |
|---|---|---|
| this crate (rs-core sdk) | **1.8.3** (`alloy-provider` 1.8.3) | **1.6.0** |
| blokli / hopr-bindings | **2.1.0** | **1.6.0** |

The **core type + `sol!` layer is identical (1.6.0)** in both worlds — `Address`,
`U256`, `Bytes`, `B256`, all `SolCall`/`SolValue`/`SolEvent`-generated calldata types,
and `JsonAbi` unify across the boundary. Only the `alloy` **meta-crate** diverges
(providers/network/rpc/contract: 1.8.x vs 2.x), i.e. the `Provider` **trait** our
public fns are generic over. So the transplant friction is exactly: **align the `alloy`
provider version** (bump this crate to alloy 2.x, or the fork stays on the version it
needs). The 1.x→2.x provider surface we use (`ProviderBuilder`, `send_transaction`,
`get_receipt`, `call`, `send_raw_transaction`, `get_code_at`, `TransactionRequest` +
`TransactionBuilder`) is source-stable, so the bump is expected to be mechanical. We
deliberately avoid `alloy-contract` instances to keep this surface minimal.

## Integrating into `blokli-contract-deployer` (mechanical fork sketch)

Target: `bloklid/src/bin/blokli-contract-deployer.rs` deploys HOPR then Curvy, emitting
`[contracts]` + `[curvy_contracts]` in one config.

1. **Dependency** (blokli `bloklid/Cargo.toml`):
   ```toml
   curvy-deployer = { git = "https://…/rs-core", package = "curvy-deployer" }
   # if blokli stays on alloy 2.x, bump this crate's alloy to 2.x first (see table above);
   # alloy-core is already shared at 1.6.0, so only the provider bump is needed.
   ```
2. **Imports** (add to the deployer bin):
   ```rust
   use curvy_deployer::{deploy_and_init, CurvyDeployConfig};
   ```
3. **Call site** — after `ContractInstances::deploy_for_testing(provider, …)` and the
   existing HOPR wiring, reuse the SAME `provider` (it already wraps the anvil signer):
   ```rust
   let mut curvy_cfg = CurvyDeployConfig::local();
   curvy_cfg.owner = signer_address;                     // = ChainKeypair pubkey's address
   let curvy = deploy_and_init(&provider, &curvy_cfg).await?;   // deploy + init + read-back
   ```
   (`deploy_curvy_suite` runs the CreateX bootstrap itself; no separate step needed.)
4. **Config plumbing** — extend the emitted TOML doc with the Curvy section:
   ```rust
   #[derive(Serialize)]
   struct ContractsOutput {
       contracts: BlokliContractAddresses,
       // curvy addresses as a second table:
       curvy_contracts: /* mirror CurvyAddresses::to_toml’s Section, or */ toml::Value,
   }
   // simplest: append curvy.to_toml()? (already a full `[curvy_contracts]` doc) to the
   // HOPR toml string before writing --output.
   ```
   The Ignition-style JSON stays available via `curvy.to_ignition_json()` for the SDK
   consumers that read `curvy_deployed_addresses.json`.
5. **Anvil note** — the deployer bursts ~24 txs under automine; blokli's own anvil
   entrypoint should drain the indexer (mine until `/readyz` ready) exactly as
   `poc/blokli-env/run.sh`'s `drain_indexer` does, OR run the deploy under `--block-time`.

## Artifacts

Creation bytecode + ABI for every deployed contract are **vendored** under
[`artifacts/`](artifacts/) (see [`artifacts/README.md`](artifacts/README.md) for the
per-file provenance + sha256 manifest). Refresh from the read-only v3-e2e checkout with
[`refresh-artifacts.sh`](refresh-artifacts.sh) (`--check` verifies against
`SHA256SUMS`). v3-e2e is never read at build or run time.

## Deviations from Devenv.ts

- **ENS stack skipped** (`LocalENSRegistry` / `SimpleOffchainResolver` /
  `LocalUniversalResolver` + the `setSubnodeOwner`/`setSubnodeRecord` calls). The PoC
  passes pubkeys directly (plan §4 cut: "ENS/metadata handle resolution"), and no
  downstream consumer reads those keys. Everything else matches Devenv.ts exactly.
