//! `curvy-deployer` — deploy + initialise the entire Curvy v2 suite from ONE Rust
//! binary, against any RPC, mirroring how blokli's own `blokli-contract-deployer`
//! works (deploy → wire → emit an addresses artifact). This is the Rust replacement
//! for `poc/blokli-env/deploy-curvy.sh`'s Hardhat/Ignition leg **and** the separate
//! `curvy-init` bin.
//!
//! **Lib-first, transplant-ready.** All logic lives here as `pub async fn`s generic
//! over `P: Provider`; the bin is a thin clap wrapper. A fork of blokli's
//! `blokli-contract-deployer` can `use curvy_deployer::{deploy_curvy_suite,
//! init_gas_fees_and_fee_key, verify_readback}` and call them after its own HOPR
//! deploy, then emit our `[curvy_contracts]` TOML alongside its `[contracts]`. See
//! README.md §"Integrating into blokli-contract-deployer".
//!
//! It replicates `v3-e2e`'s `ignition/modules/deployments/dev/Devenv.ts` (+ its
//! building blocks) exactly, MINUS the ENS stack (skipped — see below). The two
//! mandatory post-deploy calls (`setPerTokenGasFees` / `setFeeNotePublicKey`) are
//! folded in from `curvy-init`, with the same read-back verification.
//!
//! ## Chain-interaction style
//! Calldata is built from `SolCall` types (reusing `curvy-abi`'s vendored bindings +
//! a tiny local `sol!` for CreateX/ERC20Mock) and sent as plain `TransactionRequest`s
//! through the `Provider` trait's `&self` methods (`send_transaction`, `call`,
//! `send_raw_transaction`, `get_code_at`). No `alloy-contract` instances are used, so
//! the only alloy-version-sensitive surface is the `Provider` trait itself — keeping
//! the blokli transplant (alloy 2.x vs our 1.8.x) minimal.

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::sol_types::{SolCall, SolEvent, SolValue};
use anyhow::{bail, Context, Result};

use curvy_abi::bindings::aggregator::{CurvyAggregatorAlphaV2 as Agg, CurvyTypes as AggTypes};
use curvy_abi::bindings::portal_factory::PortalFactory as PF;
use curvy_abi::bindings::vault::{CurvyTypes as VaultTypes, CurvyVaultV2 as Vault};

pub mod artifact;
#[cfg(feature = "gas-fee-tree")]
pub mod gasfee;

use artifact::*;

// ── canonical constants (from v3-e2e devenv.ts / ignition parameters "local"/"anvil") ─

/// Canonical CreateX address (immutable, Nick's method).
pub const CREATEX_ADDR: &str = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";
/// CreateX keyless-deployment EOA (funded, then it publishes the pre-signed deploy tx).
pub const CREATEX_DEPLOYER_EOA: &str = "0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5";
/// Deployer/owner for the local devenv: anvil account 0 == ignition `"local".owner`.
pub const LOCAL_OWNER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
/// PortalFactory CreateX salt: ignition `"local".create2_salt` (NOT `_v2`; the
/// PortalFactory building block reads plain `create2_salt`).
pub const LOCAL_CREATE2_SALT: &str = "0x7374616765206d696861696c6f2c76616e6a6120637572767920706f77657200";
/// Dev auto-shielding recipient funded by Devenv.ts (1000 ETH + 1000 mock ERC20).
pub const DEV_SHIELDING_ADDR: &str = "0x0eeCE19240e3A8826d92da5f4D31581a1DC97779";

/// DEV_FEE_COLLECTOR BabyJubJub key (devenv.ts). `x.y`, decimal.
pub const FEE_PK_X: &str = "5509359784107808046541889973707062912186356978136525798140528612444721440004";
pub const FEE_PK_Y: &str = "5125768395023217094469327424244994953312297627197683956739233494456001838760";

/// Per-token gas-fee placeholders (devenv.ts), decimal wei. Also the gas-fee tree leaves.
pub const TOKEN1_PENDING_COMMITMENT: &str = "100000000000000000"; // 0.1 ETH (token 1)
pub const TOKEN2_PENDING_COMMITMENT: &str = "200000000000000000"; // 0.2 ETH (token 2)
pub const GAS_LEG_5E16: &str = "50000000000000000"; // 0.05 ETH portalDeployment / withdrawal

/// A tiny local interface for the two things `curvy-abi` doesn't bind: CreateX's
/// `deployCreate2` + `ContractCreation` event, and ERC20Mock's `mockMint`. Declared
/// by hand (not from the vendored ICreateX ABI) because that ABI overloads
/// `ContractCreation`, which `sol!` cannot disambiguate.
mod iface {
    alloy::sol! {
        #[allow(missing_docs)]
        event ContractCreation(address indexed newContract, bytes32 indexed salt);
        #[allow(missing_docs)]
        function deployCreate2(bytes32 salt, bytes initCode) external payable returns (address newContract);
        #[allow(missing_docs)]
        function mockMint(address _address, uint256 _amount) external;
    }
}

// ── config ──────────────────────────────────────────────────────────────────────────

/// A per-token gas-fee row (one `GasFees` struct on the vault).
#[derive(Clone, Debug)]
pub struct GasFeeLeg {
    pub token_id: U256,
    pub portal_deployment: U256,
    pub pending_note_commitment: U256,
    pub withdrawal: U256,
}

/// The dev-address funding step (Devenv.ts sends 1000 ETH + mints 1000 mock ERC20).
#[derive(Clone, Debug)]
pub struct DevFunding {
    pub address: Address,
    pub eth_wei: U256,
    pub erc20_amount: U256,
}

/// Everything the suite deploy + init needs. [`CurvyDeployConfig::local`] fills in the
/// devenv/anvil defaults; a blokli fork overrides `owner`, salt, fee key, etc.
#[derive(Clone, Debug)]
pub struct CurvyDeployConfig {
    /// Owner of vault + aggregator + PortalFactory (also the tx signer's address).
    pub owner: Address,
    /// CreateX salt for the deterministic PortalFactory deploy.
    pub create2_salt: B256,
    /// PortalFactory's LiFi diamond (anvil devenv: `address(0)`).
    pub lifi_diamond: Address,
    /// Aggregator fee-note BabyJubJub public key `(x, y)`.
    pub fee_note_pubkey: (U256, U256),
    /// Per-token gas fees written by `setPerTokenGasFees`.
    pub per_token_gas_fees: Vec<GasFeeLeg>,
    /// Commitment-gas-fee tree root. `None` ⇒ computed via the `gas-fee-tree` feature
    /// from [`TOKEN1_PENDING_COMMITMENT`]/[`TOKEN2_PENDING_COMMITMENT`]; required
    /// (`Some`) when that feature is disabled.
    pub commitment_fee_root: Option<U256>,
    /// Optional dev-address funding (kept to match Devenv.ts behaviour).
    pub dev_funding: Option<DevFunding>,
}

impl CurvyDeployConfig {
    /// The local devenv/anvil defaults — mirrors `Devenv.ts` + ignition `"local"`/`"anvil"`.
    pub fn local() -> Self {
        let e18 = U256::from(1_000_000_000_000_000_000u128);
        let thousand = U256::from(1000u64) * e18;
        Self {
            owner: LOCAL_OWNER.parse().expect("owner"),
            create2_salt: LOCAL_CREATE2_SALT.parse().expect("salt"),
            lifi_diamond: Address::ZERO,
            fee_note_pubkey: (u_dec(FEE_PK_X), u_dec(FEE_PK_Y)),
            per_token_gas_fees: vec![
                GasFeeLeg {
                    token_id: U256::from(1),
                    portal_deployment: u_dec(GAS_LEG_5E16),
                    pending_note_commitment: u_dec(TOKEN1_PENDING_COMMITMENT),
                    withdrawal: u_dec(GAS_LEG_5E16),
                },
                GasFeeLeg {
                    token_id: U256::from(2),
                    portal_deployment: u_dec(GAS_LEG_5E16),
                    pending_note_commitment: u_dec(TOKEN2_PENDING_COMMITMENT),
                    withdrawal: u_dec(GAS_LEG_5E16),
                },
            ],
            commitment_fee_root: None,
            dev_funding: Some(DevFunding {
                address: DEV_SHIELDING_ADDR.parse().expect("dev addr"),
                eth_wei: thousand,
                erc20_amount: thousand,
            }),
        }
    }
}

// ── deployed-address record + emitters ────────────────────────────────────────────────

/// Every address the deploy produced. [`Self::to_ignition_json`] emits the exact
/// Ignition-style keys the existing pipeline produced (downstream `curvy-e2e` /
/// `curvy-hopr-runner` read `CurvyAggregator#ERC1967Proxy`, `CurvyVault#ERC1967Proxy`,
/// `PortalFactory#PortalFactory`); [`Self::to_toml`] emits a `[curvy_contracts]` TOML
/// section in the spirit of blokli's `[contracts]`.
#[derive(Clone, Debug)]
pub struct CurvyAddresses {
    pub createx: Address,
    pub poseidon_t4: Address,
    pub aggregator_impl: Address,
    pub aggregator_proxy: Address,
    pub aggregation_verifier: Address,
    pub pending_notes_commitment_verifier: Address,
    pub withdrawal_verifier: Address,
    pub vault_impl: Address,
    pub vault_proxy: Address,
    pub portal_factory: Address,
    pub multicall3: Address,
    pub erc20_mock: Address,
}

impl CurvyAddresses {
    /// The Ignition-style `deployed_addresses.json` shape (EIP-55 checksummed values),
    /// with the SAME keys the Hardhat pipeline emitted (minus the skipped ENS keys —
    /// `Devenv#LocalENSRegistry` / `#SimpleOffchainResolver` / `#LocalUniversalResolver`,
    /// which no downstream consumer reads).
    pub fn to_ignition_json(&self) -> serde_json::Value {
        let cs = |a: &Address| a.to_checksum(None);
        serde_json::json!({
            "PortalFactory#CreateX": cs(&self.createx),
            "CurvyAggregator#PoseidonT4": cs(&self.poseidon_t4),
            "CurvyAggregator#CurvyAggregatorV2Implementation": cs(&self.aggregator_impl),
            "CurvyAggregator#ERC1967Proxy": cs(&self.aggregator_proxy),
            "CurvyAggregator#CurvyAggregatorAlphaV2": cs(&self.aggregator_proxy),
            "CurvyAggregator#CurvyAggregationVerifier": cs(&self.aggregation_verifier),
            "CurvyAggregator#CurvyPendingNotesCommitmentVerifier": cs(&self.pending_notes_commitment_verifier),
            "CurvyAggregator#CurvyWithdrawalVerifier": cs(&self.withdrawal_verifier),
            "CurvyVault#CurvyVaultV2Implementation": cs(&self.vault_impl),
            "CurvyVault#ERC1967Proxy": cs(&self.vault_proxy),
            "CurvyVault#CurvyVaultV2": cs(&self.vault_proxy),
            "PortalFactory#PortalFactory": cs(&self.portal_factory),
            "Devenv#Multicall3": cs(&self.multicall3),
            "Devenv#ERC20Mock": cs(&self.erc20_mock),
        })
    }

    /// A `[curvy_contracts]` TOML section (snake_case keys), for the blokli-fork path
    /// where one deployer emits HOPR `[contracts]` + Curvy `[curvy_contracts]` together.
    pub fn to_toml(&self) -> Result<String> {
        #[derive(serde::Serialize)]
        struct Section {
            createx: String,
            poseidon_t4: String,
            aggregator_impl: String,
            aggregator_proxy: String,
            aggregation_verifier: String,
            pending_notes_commitment_verifier: String,
            withdrawal_verifier: String,
            vault_impl: String,
            vault_proxy: String,
            portal_factory: String,
            multicall3: String,
            erc20_mock: String,
        }
        #[derive(serde::Serialize)]
        struct Doc {
            curvy_contracts: Section,
        }
        let cs = |a: &Address| a.to_checksum(None);
        let doc = Doc {
            curvy_contracts: Section {
                createx: cs(&self.createx),
                poseidon_t4: cs(&self.poseidon_t4),
                aggregator_impl: cs(&self.aggregator_impl),
                aggregator_proxy: cs(&self.aggregator_proxy),
                aggregation_verifier: cs(&self.aggregation_verifier),
                pending_notes_commitment_verifier: cs(&self.pending_notes_commitment_verifier),
                withdrawal_verifier: cs(&self.withdrawal_verifier),
                vault_impl: cs(&self.vault_impl),
                vault_proxy: cs(&self.vault_proxy),
                portal_factory: cs(&self.portal_factory),
                multicall3: cs(&self.multicall3),
                erc20_mock: cs(&self.erc20_mock),
            },
        };
        Ok(toml::to_string(&doc)?)
    }
}

// ── small chain helpers (only `Provider` trait `&self` methods — version-robust) ──────

fn u_dec(s: &str) -> U256 {
    U256::from_str_radix(s, 10).expect("decimal U256")
}

/// Deploy `code` (a full creation-tx payload) and return the new contract address.
async fn deploy_code<P: Provider>(provider: &P, label: &str, code: Bytes) -> Result<Address> {
    let tx = TransactionRequest::default().with_deploy_code(code);
    let receipt = provider
        .send_transaction(tx)
        .await
        .with_context(|| format!("deploy {label}: send"))?
        .get_receipt()
        .await
        .with_context(|| format!("deploy {label}: receipt"))?;
    if !receipt.status() {
        bail!("deploy {label} reverted (tx {})", receipt.transaction_hash);
    }
    let addr = receipt
        .contract_address
        .with_context(|| format!("deploy {label}: receipt had no contract_address"))?;
    println!("    deploy {label:<38} = {}", addr.to_checksum(None));
    Ok(addr)
}

/// Send a state-changing call (`to`+calldata+value) and return the receipt.
async fn send_call<P: Provider>(
    provider: &P,
    to: Address,
    data: Vec<u8>,
    value: U256,
    label: &str,
) -> Result<TransactionReceipt> {
    let tx = TransactionRequest::default()
        .with_to(to)
        .with_input(Bytes::from(data))
        .with_value(value);
    let receipt = provider
        .send_transaction(tx)
        .await
        .with_context(|| format!("{label}: send"))?
        .get_receipt()
        .await
        .with_context(|| format!("{label}: receipt"))?;
    if !receipt.status() {
        bail!("{label} reverted (tx {})", receipt.transaction_hash);
    }
    Ok(receipt)
}

/// `eth_call` returning the raw return bytes.
async fn read_bytes<P: Provider>(provider: &P, to: Address, data: Vec<u8>) -> Result<Bytes> {
    let tx = TransactionRequest::default().with_to(to).with_input(Bytes::from(data));
    provider.call(tx).await.context("eth_call")
}

/// `eth_call` returning a single `uint256` (first word of the return data).
async fn read_u256<P: Provider>(provider: &P, to: Address, data: Vec<u8>) -> Result<U256> {
    let out = read_bytes(provider, to, data).await?;
    if out.len() < 32 {
        bail!("read: short return ({} bytes)", out.len());
    }
    Ok(U256::from_be_slice(&out[..32]))
}

// ── CreateX bootstrap ─────────────────────────────────────────────────────────────────

/// Ensure CreateX is live at its canonical address; if absent, fund the keyless
/// deployer with 1 ETH and publish the pre-signed (Nick's-method) raw deploy tx.
/// Idempotent: returns immediately if CreateX code is already present.
pub async fn ensure_createx<P: Provider>(provider: &P) -> Result<Address> {
    let createx: Address = CREATEX_ADDR.parse()?;
    if !provider.get_code_at(createx).await.context("get_code_at CreateX")?.is_empty() {
        println!("    CreateX already present at {} — skipping bootstrap", createx.to_checksum(None));
        return Ok(createx);
    }
    let deployer: Address = CREATEX_DEPLOYER_EOA.parse()?;
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    println!("    CreateX absent — funding keyless deployer {} with 1 ETH", deployer.to_checksum(None));
    send_call(provider, deployer, Vec::new(), one_eth, "fund CreateX deployer").await?;

    let raw_hex = CREATEX_BOOTSTRAP_TX.trim();
    let raw = hex::decode(raw_hex.strip_prefix("0x").unwrap_or(raw_hex)).context("decode CreateX raw tx")?;
    println!("    publishing pre-signed CreateX deploy tx ({} bytes)", raw.len());
    let receipt = provider
        .send_raw_transaction(&raw)
        .await
        .context("publish CreateX raw tx")?
        .get_receipt()
        .await
        .context("CreateX deploy receipt")?;
    if !receipt.status() {
        bail!("CreateX deploy tx reverted");
    }
    if provider.get_code_at(createx).await?.is_empty() {
        bail!("CreateX not deployed at {createx} after publishing raw tx");
    }
    println!("    CreateX live at {}", createx.to_checksum(None));
    Ok(createx)
}

// ── the full suite deploy ─────────────────────────────────────────────────────────────

/// Deploy + wire the entire Curvy v2 suite (mirrors `Devenv.ts` minus ENS). Does NOT
/// run the two mandatory init calls — call [`init_gas_fees_and_fee_key`] after.
///
/// Behaviour: CreateX bootstrap is idempotent (skipped if present); the Curvy suite
/// itself is deployed FRESH every call (fresh-deploy-per-fresh-chain, matching the old
/// pipeline). Requires `provider` to sign+fund from `cfg.owner` (a wallet+filler
/// provider) and the chain to be on automine (each `get_receipt` needs its tx mined).
pub async fn deploy_curvy_suite<P: Provider>(provider: &P, cfg: &CurvyDeployConfig) -> Result<CurvyAddresses> {
    // 0. CreateX
    println!("==> [curvy-deployer] CreateX bootstrap");
    let createx = ensure_createx(provider).await?;

    // 1. CurvyAggregator module: PoseidonT4 → impl(linked) → proxy → 3 verifiers → register
    println!("==> [curvy-deployer] aggregator module");
    let poseidon_t4 = deploy_code(provider, "PoseidonT4", POSEIDON_T4.creation_code()?).await?;

    let agg_code = AGGREGATOR_IMPL.creation_code_linked(POSEIDON_T4_PLACEHOLDER, poseidon_t4)?;
    let aggregator_impl = deploy_code(provider, "CurvyAggregatorAlphaV2(impl)", agg_code).await?;

    let agg_init = Agg::initializeCall { initialOwner: cfg.owner }.abi_encode();
    let agg_proxy_code = proxy_creation_code(aggregator_impl, &agg_init)?;
    let aggregator_proxy = deploy_code(provider, "CurvyAggregator#ERC1967Proxy", agg_proxy_code).await?;

    let aggregation_verifier = deploy_code(provider, "CurvyAggregationVerifier", AGGREGATION_VERIFIER.creation_code()?).await?;
    let pending_notes_commitment_verifier =
        deploy_code(provider, "CurvyPendingNotesCommitmentVerifier", PENDING_NOTES_COMMITMENT_VERIFIER.creation_code()?).await?;
    let withdrawal_verifier = deploy_code(provider, "CurvyWithdrawalVerifier", WITHDRAWAL_VERIFIER.creation_code()?).await?;

    // register verifiers (pending(5), aggregation(2,3), withdrawal(2)) — matches CurvyAggregator.ts
    send_call(
        provider,
        aggregator_proxy,
        Agg::setPendingNotesCommitmentVerifierCall { batchSize: U256::from(5), verifier: pending_notes_commitment_verifier }.abi_encode(),
        U256::ZERO,
        "aggregator.setPendingNotesCommitmentVerifier(5)",
    )
    .await?;
    send_call(
        provider,
        aggregator_proxy,
        Agg::setAggregationVerifierCall { maxInputs: U256::from(2), maxOutputs: U256::from(3), verifier: aggregation_verifier }.abi_encode(),
        U256::ZERO,
        "aggregator.setAggregationVerifier(2,3)",
    )
    .await?;
    send_call(
        provider,
        aggregator_proxy,
        Agg::setWithdrawalVerifierCall { maxInputs: U256::from(2), verifier: withdrawal_verifier }.abi_encode(),
        U256::ZERO,
        "aggregator.setWithdrawalVerifier(2)",
    )
    .await?;

    // 2. CurvyVault module: impl → proxy (no ERC20 registered here — anvil.erc20Addresses is [])
    println!("==> [curvy-deployer] vault module");
    let vault_impl = deploy_code(provider, "CurvyVaultV2(impl)", VAULT_IMPL.creation_code()?).await?;
    let vault_init = Vault::initializeCall { initialOwner: cfg.owner }.abi_encode();
    let vault_proxy_code = proxy_creation_code(vault_impl, &vault_init)?;
    let vault_proxy = deploy_code(provider, "CurvyVault#ERC1967Proxy", vault_proxy_code).await?;

    // 3. PortalFactory via CreateX.deployCreate2(salt, PortalFactory.bytecode ++ abi.encode(owner))
    println!("==> [curvy-deployer] PortalFactory (via CreateX deployCreate2)");
    let mut init_code = PORTAL_FACTORY.creation_code()?.to_vec();
    init_code.extend_from_slice(&cfg.owner.abi_encode()); // ctor(address initialOwner)
    let deploy_create2 = iface::deployCreate2Call { salt: cfg.create2_salt, initCode: Bytes::from(init_code) }.abi_encode();
    let receipt = send_call(provider, createx, deploy_create2, U256::ZERO, "createX.deployCreate2(PortalFactory)").await?;
    let portal_factory = parse_contract_creation(&receipt, createx)?;
    println!("    PortalFactory (CreateX)                = {}", portal_factory.to_checksum(None));

    // 4. Multicall3 + ERC20Mock
    println!("==> [curvy-deployer] devenv utilities");
    let multicall3 = deploy_code(provider, "Multicall3", MULTICALL3.creation_code()?).await?;
    let erc20_mock = deploy_code(provider, "ERC20Mock", ERC20_MOCK.creation_code()?).await?;

    // 5. Wire (matches Devenv.ts exactly)
    println!("==> [curvy-deployer] wiring");
    send_call(
        provider,
        vault_proxy,
        Vault::setCurvyAggregatorAddressCall { curvyAggregator: aggregator_proxy }.abi_encode(),
        U256::ZERO,
        "vault.setCurvyAggregatorAddress",
    )
    .await?;
    send_call(
        provider,
        aggregator_proxy,
        Agg::updateConfigCall {
            _update: AggTypes::AggregatorConfigurationUpdate { curvyVault: vault_proxy, portalFactory: portal_factory },
        }
        .abi_encode(),
        U256::ZERO,
        "aggregator.updateConfig{vault,portalFactory}",
    )
    .await?;
    send_call(
        provider,
        portal_factory,
        PF::updateConfigCall {
            curvyVaultProxyAddress: vault_proxy,
            curvyAggregatorAlphaProxyAddress: aggregator_proxy,
            lifiDiamondAddress: cfg.lifi_diamond,
        }
        .abi_encode(),
        U256::ZERO,
        "portalFactory.updateConfig(vault,aggregator,lifi)",
    )
    .await?;
    send_call(
        provider,
        vault_proxy,
        Vault::registerTokenCall { tokenAddress: erc20_mock }.abi_encode(),
        U256::ZERO,
        "vault.registerToken(erc20Mock)",
    )
    .await?;

    // 6. Dev-address funding (kept to match Devenv.ts): 1000 ETH + mint 1000 mock ERC20
    if let Some(f) = &cfg.dev_funding {
        println!("==> [curvy-deployer] dev-address funding {}", f.address.to_checksum(None));
        send_call(provider, f.address, Vec::new(), f.eth_wei, "fund dev address (ETH)").await?;
        send_call(
            provider,
            erc20_mock,
            iface::mockMintCall { _address: f.address, _amount: f.erc20_amount }.abi_encode(),
            U256::ZERO,
            "erc20Mock.mockMint(dev, 1000e18)",
        )
        .await?;
    }

    Ok(CurvyAddresses {
        createx,
        poseidon_t4,
        aggregator_impl,
        aggregator_proxy,
        aggregation_verifier,
        pending_notes_commitment_verifier,
        withdrawal_verifier,
        vault_impl,
        vault_proxy,
        portal_factory,
        multicall3,
        erc20_mock,
    })
}

/// ERC1967Proxy creation code = proxy creation bytecode ++ abi.encode(impl, initCalldata).
fn proxy_creation_code(implementation: Address, init_calldata: &[u8]) -> Result<Bytes> {
    let mut code = ERC1967_PROXY.creation_code()?.to_vec();
    let args = (implementation, Bytes::from(init_calldata.to_vec())).abi_encode_params();
    code.extend_from_slice(&args);
    Ok(Bytes::from(code))
}

/// Extract the `newContract` address from a CreateX `ContractCreation(address,bytes32)`
/// log emitted by `createx` in the given receipt.
fn parse_contract_creation(receipt: &TransactionReceipt, createx: Address) -> Result<Address> {
    for log in receipt.logs() {
        if log.inner.address == createx && log.topic0() == Some(&iface::ContractCreation::SIGNATURE_HASH) {
            let word = log.topics().get(1).context("ContractCreation: missing newContract topic")?;
            return Ok(Address::from_word(*word));
        }
    }
    bail!("no ContractCreation(address,bytes32) log from CreateX {createx} in receipt")
}

// ── the two mandatory init calls (folded from curvy-init) ─────────────────────────────

/// Resolve the commitment-gas-fee-tree root: `cfg.commitment_fee_root` if set, else
/// (with the `gas-fee-tree` feature) compute it from the token-1/2 commitment leaves.
pub fn resolve_commitment_fee_root(cfg: &CurvyDeployConfig) -> Result<U256> {
    if let Some(r) = cfg.commitment_fee_root {
        return Ok(r);
    }
    #[cfg(feature = "gas-fee-tree")]
    {
        Ok(gasfee::commitment_fee_root(TOKEN1_PENDING_COMMITMENT, TOKEN2_PENDING_COMMITMENT))
    }
    #[cfg(not(feature = "gas-fee-tree"))]
    {
        bail!("commitment_fee_root must be supplied in CurvyDeployConfig when the `gas-fee-tree` feature is disabled")
    }
}

/// `setPerTokenGasFees(gasFees, root)` + `setFeeNotePublicKey(x, y)` — the two calls
/// aggregation/withdrawal proofs revert without. Folded from `curvy-init`.
pub async fn init_gas_fees_and_fee_key<P: Provider>(
    provider: &P,
    addrs: &CurvyAddresses,
    cfg: &CurvyDeployConfig,
) -> Result<()> {
    let root = resolve_commitment_fee_root(cfg)?;
    println!("==> [curvy-deployer] init: setPerTokenGasFees (commitmentGasFeeRoot = {root})");
    let gas_fees: Vec<VaultTypes::GasFees> = cfg
        .per_token_gas_fees
        .iter()
        .map(|g| VaultTypes::GasFees {
            tokenId: g.token_id,
            portalDeployment: g.portal_deployment,
            pendingNoteCommitment: g.pending_note_commitment,
            withdrawal: g.withdrawal,
        })
        .collect();
    send_call(
        provider,
        addrs.vault_proxy,
        Vault::setPerTokenGasFeesCall { gasFees: gas_fees, commitmentGasFeeRoot: root }.abi_encode(),
        U256::ZERO,
        "vault.setPerTokenGasFees",
    )
    .await?;

    let (fx, fy) = cfg.fee_note_pubkey;
    println!("==> [curvy-deployer] init: setFeeNotePublicKey (x={fx} y={fy})");
    send_call(
        provider,
        addrs.aggregator_proxy,
        Agg::setFeeNotePublicKeyCall { x: fx, y: fy }.abi_encode(),
        U256::ZERO,
        "aggregator.setFeeNotePublicKey",
    )
    .await?;
    Ok(())
}

/// The read-back verification `curvy-init` did: `commitmentFeeRoot`, `feeNotePublicKey`,
/// and every `perTokenGasFees` row must match what was written. Bails on any mismatch.
pub async fn verify_readback<P: Provider>(
    provider: &P,
    addrs: &CurvyAddresses,
    cfg: &CurvyDeployConfig,
) -> Result<()> {
    println!("==> [curvy-deployer] read-back verification");
    let mut ok = true;

    let want_root = resolve_commitment_fee_root(cfg)?;
    let got_root = read_u256(provider, addrs.aggregator_proxy, Agg::commitmentFeeRootCall {}.abi_encode()).await?;
    println!("    aggregator.commitmentFeeRoot() = {got_root}");
    if got_root != want_root {
        eprintln!("    MISMATCH: expected commitmentFeeRoot {want_root}");
        ok = false;
    }

    let (fx, fy) = cfg.fee_note_pubkey;
    let px = read_u256(provider, addrs.aggregator_proxy, Agg::feeNotePublicKeyCall(U256::from(0)).abi_encode()).await?;
    let py = read_u256(provider, addrs.aggregator_proxy, Agg::feeNotePublicKeyCall(U256::from(1)).abi_encode()).await?;
    println!("    aggregator.feeNotePublicKey(0/1) = {px} / {py}");
    if px != fx || py != fy {
        eprintln!("    MISMATCH: expected feeNotePublicKey ({fx}, {fy})");
        ok = false;
    }

    let fee_thousand = read_u256(provider, addrs.aggregator_proxy, Agg::protocolFeePerThousandCall {}.abi_encode()).await?;
    println!("    aggregator.protocolFeePerThousand() = {fee_thousand}");

    for g in &cfg.per_token_gas_fees {
        // perTokenGasFees returns a static GasFees tuple → 4 contiguous words:
        // [tokenId, portalDeployment, pendingNoteCommitment, withdrawal].
        let out = read_bytes(provider, addrs.vault_proxy, Vault::perTokenGasFeesCall { tokenId: g.token_id }.abi_encode()).await?;
        if out.len() < 128 {
            bail!("perTokenGasFees({}): short return ({} bytes)", g.token_id, out.len());
        }
        let word = |i: usize| U256::from_be_slice(&out[i * 32..i * 32 + 32]);
        let (portal, commit, withdraw) = (word(1), word(2), word(3));
        println!(
            "    vault.perTokenGasFees({}) = (portal {portal}, commit {commit}, withdraw {withdraw})",
            g.token_id
        );
        if portal != g.portal_deployment || commit != g.pending_note_commitment || withdraw != g.withdrawal {
            eprintln!("    MISMATCH on token {}", g.token_id);
            ok = false;
        }
    }

    if ok {
        println!("    read-back OK — all values match.");
        Ok(())
    } else {
        bail!("read-back verification FAILED")
    }
}

/// Convenience: deploy the suite, run both init calls, and verify the read-back.
pub async fn deploy_and_init<P: Provider>(provider: &P, cfg: &CurvyDeployConfig) -> Result<CurvyAddresses> {
    let addrs = deploy_curvy_suite(provider, cfg).await?;
    init_gas_fees_and_fee_key(provider, &addrs, cfg).await?;
    verify_readback(provider, &addrs, cfg).await?;
    Ok(addrs)
}
