//! Runs the strict Curvy flow against the Blokli local-development stack.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    curvy_e2e::run().await?;
    println!("\ncurvy-e2e: ALL STEPS PASSED");
    Ok(())
}
