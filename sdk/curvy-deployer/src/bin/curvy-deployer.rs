//! Thin clap wrapper over the `curvy_deployer` library — all logic lives in the lib
//! (so blokli's `blokli-contract-deployer` fork can call it directly). CLI shapes
//! mirror `blokli-contract-deployer` (`--rpc-url`, `--private-key`, `--output`).

use std::path::PathBuf;

use alloy::network::EthereumWallet;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use clap::Parser;
use curvy_deployer::{deploy_and_init, CurvyDeployConfig};

// anvil dev account 0 — the ignition `"local".owner` (0xf39Fd6…92266).
const DEFAULT_ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Parser, Debug)]
#[command(
    name = "curvy-deployer",
    about = "Deploy + initialise the Curvy v2 suite against an RPC (Rust replacement for deploy-curvy.sh + curvy-init)"
)]
struct Args {
    /// RPC endpoint URL for the chain.
    #[arg(long, env = "RPC_URL", default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    /// Deployer/owner private key (its address becomes the vault/aggregator owner).
    #[arg(long, env = "CURVY_DEPLOYER_PRIVATE_KEY", default_value = DEFAULT_ANVIL_KEY)]
    private_key: String,

    /// Output path for the Ignition-style deployed_addresses.json (downstream
    /// `curvy-e2e` / `curvy-hopr-runner` read this).
    #[arg(long, env = "CURVY_ADDRESSES", default_value = "../poc/blokli-env/curvy_deployed_addresses.json")]
    json_out: PathBuf,

    /// Optional path to ALSO emit the `[curvy_contracts]` TOML section (blokli-fork style).
    #[arg(long)]
    toml_out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let signer: PrivateKeySigner = args.private_key.parse().context("parse deployer private key")?;
    let owner = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(args.rpc_url.parse().context("parse rpc url")?);

    let mut cfg = CurvyDeployConfig::local();
    // The deployer key IS the owner (on anvil this key == the ignition "local".owner).
    cfg.owner = owner;

    println!("curvy-deployer: rpc={} owner={}", args.rpc_url, owner.to_checksum(None));
    let addrs = deploy_and_init(&provider, &cfg).await?;

    // Ignition-style JSON (the contract downstream consumers depend on).
    let json = serde_json::to_string_pretty(&addrs.to_ignition_json())?;
    if let Some(parent) = args.json_out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&args.json_out, format!("{json}\n"))
        .with_context(|| format!("write {}", args.json_out.display()))?;
    println!("\n==> wrote Ignition addresses → {}", args.json_out.display());
    println!("{json}");

    if let Some(toml_path) = &args.toml_out {
        std::fs::write(toml_path, addrs.to_toml()?)
            .with_context(|| format!("write {}", toml_path.display()))?;
        println!("==> wrote [curvy_contracts] TOML → {}", toml_path.display());
    }

    println!("\ncurvy-deployer: OK — suite deployed, initialised, and read-back verified.");
    Ok(())
}
