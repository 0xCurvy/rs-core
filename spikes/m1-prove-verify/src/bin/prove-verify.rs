//! M1 kill-shot end-to-end: pure-Rust witness -> curvy-prover proof -> off-chain
//! verify -> on-chain `CurvyWithdrawalVerifier.verifyProof` (accept + negatives).
//!
//!   cargo run -p m1-prove-verify --bin prove-verify --release
//!
//! Requires the deployed zkey (default: v3-e2e path, override CURVY_WITHDRAWAL_ZKEY)
//! and the `anvil` binary on PATH. Exits non-zero if any check fails.

use anyhow::Result;
use m1_prove_verify::{calldata_from_snarkjs, run_offchain, run_onchain};

fn check(label: &str, ok: bool) -> bool {
    println!("  [{}] {label}", if ok { "PASS" } else { "FAIL" });
    ok
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("== M1: pure-Rust prove + verify vs Curvy withdrawal(2,30) ==\n");

    println!("-- off-chain leg --");
    let off = run_offchain()?;
    println!(
        "  circuit: {} constraints, {} public signals, {} witness elements",
        off.num_constraints, off.num_public, off.full_assignment_len
    );
    println!("  zkey sha256:    {}", off.zkey_sha256);
    println!("  witness sha256: {}", off.wtns_sha256);
    println!("  public signals: {:?}", off.publics_dec);

    let mut all = true;
    all &= check(
        "pure-Rust witness == snarkjs golden .wtns (byte-identical)",
        off.witness_matches_golden,
    );
    all &= check("off-chain Groth16 verify (arkworks pvk)", off.offchain_verified);
    all &= check(
        "public signals == snarkjs reference + expected fixture",
        off.publics_match_reference,
    );

    println!("\n-- on-chain leg (anvil + deployed CurvyWithdrawalVerifier) --");
    let cd = calldata_from_snarkjs(&off.proof_json, &off.public_json)?;
    let on = run_onchain(&cd).await?;
    println!("  verifier deployed at {}", on.verifier_addr);
    all &= check("verifyProof(valid) == true", on.valid_accepted);
    all &= check(
        "verifyProof(corrupted statement) rejected",
        on.corrupted_statement_rejected,
    );
    all &= check(
        "verifyProof(corrupted proof point) rejected",
        on.corrupted_proof_rejected,
    );

    println!("\n{}", if all { "ALL CHECKS PASSED" } else { "FAILURES PRESENT" });
    if !all {
        std::process::exit(1);
    }
    Ok(())
}
