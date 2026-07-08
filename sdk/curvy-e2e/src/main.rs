//! curvy-e2e — runs the M2 flow against the live `poc/blokli-env` stack and exits
//! non-zero if any step fails. See `curvy_e2e::run` for the flow.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let all_passed = curvy_e2e::run().await?;
    if all_passed {
        println!("\ncurvy-e2e: ALL STEPS PASSED");
        Ok(())
    } else {
        std::process::exit(1);
    }
}
