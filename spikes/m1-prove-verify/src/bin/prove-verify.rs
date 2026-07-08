//! M1 kill-shot end-to-end for **all three deployed Curvy circuit configs**:
//! pure-Rust witness -> curvy-prover proof -> off-chain verify -> on-chain
//! `verifyProof` (accept + corrupted-statement + corrupted-proof negatives).
//!
//!   cargo run -p m1-prove-verify --bin prove-verify --release
//!
//! Requires the deployed zkeys (default: v3-e2e paths, override CURVY_<CIRCUIT>_ZKEY)
//! and the `anvil` binary on PATH. A circuit whose evaluation graph or zkey is absent
//! (e.g. pending before `./run.sh regen-fixtures`) is SKIPPED, not failed. Exits
//! non-zero if any executed check fails.

use anyhow::Result;
use m1_prove_verify::{calldata_from_snarkjs, run_offchain, run_onchain, Circuit};

fn check(label: &str, ok: bool) -> bool {
    println!("    [{}] {label}", if ok { "PASS" } else { "FAIL" });
    ok
}

async fn run_circuit(circuit: &Circuit) -> Result<Option<bool>> {
    println!("\n══════ {} — {} public signals ══════", circuit.label, circuit.num_public);

    if !circuit.graph_path().exists() {
        println!("  SKIP: graph {} absent (run `./run.sh regen-fixtures`)", circuit.graph_path().display());
        return Ok(None);
    }
    if !circuit.zkey_path().exists() {
        println!("  SKIP: zkey {} absent (set {})", circuit.zkey_path().display(), circuit.zkey_env);
        return Ok(None);
    }

    println!("  -- off-chain leg --");
    let off = run_offchain(circuit)?;
    println!(
        "  circuit: {} constraints, {} public signals, {} witness elements",
        off.num_constraints, off.num_public, off.full_assignment_len
    );
    println!("  zkey sha256:    {}", off.zkey_sha256);
    println!("  witness sha256: {}", off.wtns_sha256);
    if off.publics_dec.len() <= 6 {
        println!("  public signals: {:?}", off.publics_dec);
    } else {
        println!("  public signals: [{} values] first={}", off.publics_dec.len(), off.publics_dec[0]);
    }

    let mut all = true;
    all &= check("evaluation graph sha256 == pinned (deterministic build)", off.graph_matches_pin);
    all &= check("pure-Rust witness == snarkjs golden .wtns", off.witness_matches_golden);
    all &= check("off-chain Groth16 verify (arkworks pvk)", off.offchain_verified);
    all &= check("public signals == snarkjs reference + independent recompute", off.publics_match_reference);

    println!("  -- on-chain leg (anvil + deployed verifier bytecode) --");
    let cd = calldata_from_snarkjs(&off.proof_json, &off.public_json)?;
    let on = run_onchain(circuit, &cd).await?;
    println!("  verifier deployed at {}", on.verifier_addr);
    all &= check("verifyProof(valid) == true", on.valid_accepted);
    all &= check("verifyProof(corrupted statement) rejected", on.corrupted_statement_rejected);
    all &= check("verifyProof(corrupted proof point) rejected", on.corrupted_proof_rejected);

    Ok(Some(all))
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("== M1: pure-Rust prove + verify vs Curvy's three deployed circuits ==");

    let mut any_fail = false;
    let mut ran = 0usize;
    let mut skipped: Vec<&str> = Vec::new();
    for circuit in Circuit::all() {
        match run_circuit(&circuit).await? {
            Some(ok) => {
                ran += 1;
                any_fail |= !ok;
            }
            None => skipped.push(circuit.label),
        }
    }

    println!("\n────────────────────────────────────────");
    println!("circuits run: {ran}, skipped: {}", skipped.len());
    if !skipped.is_empty() {
        println!("skipped (missing graph/zkey): {}", skipped.join(", "));
    }
    println!("{}", if any_fail { "FAILURES PRESENT" } else { "ALL EXECUTED CHECKS PASSED" });
    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}
