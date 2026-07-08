//! M1 end-to-end integration test across **all three deployed Curvy circuit configs**
//! (withdrawal(2,30), aggregation(2,3,30,6), pending-notes-commitment(5,30)): drives
//! the same three legs as the `prove-verify` bin and asserts every exit criterion.
//!
//! Needs the deployed zkeys (default v3-e2e paths, override CURVY_<CIRCUIT>_ZKEY) and
//! `anvil` on PATH. A circuit whose evaluation graph or zkey is absent (e.g. pending
//! before `./run.sh regen-fixtures`) is SKIPPED with an eprintln, not failed.

use m1_prove_verify::{calldata_from_snarkjs, run_offchain, run_onchain, Circuit};

async fn assert_circuit(circuit: &Circuit) -> bool {
    if !circuit.graph_path().exists() {
        eprintln!("SKIP {}: graph absent ({}) — run `./run.sh regen-fixtures`", circuit.key, circuit.graph_path().display());
        return false;
    }
    if !circuit.zkey_path().exists() {
        eprintln!("SKIP {}: zkey absent ({}) — set {}", circuit.key, circuit.zkey_path().display(), circuit.zkey_env);
        return false;
    }

    let off = run_offchain(circuit).unwrap_or_else(|e| panic!("{}: off-chain leg: {e:?}", circuit.key));
    assert!(off.graph_matches_pin, "{}: evaluation graph sha256 must equal the pin", circuit.key);
    assert!(off.witness_matches_golden, "{}: pure-Rust witness must match the snarkjs golden .wtns", circuit.key);
    assert_eq!(off.wtns_sha256, circuit_golden_sha(circuit), "{}: witness sha256 pin", circuit.key);
    assert_eq!(off.zkey_sha256, circuit_zkey_sha(circuit), "{}: zkey sha256 pin", circuit.key);
    assert_eq!(off.num_public, circuit.num_public, "{}: public-signal count", circuit.key);
    assert!(off.offchain_verified, "{}: arkworks Groth16 verify must pass", circuit.key);
    assert!(off.publics_match_reference, "{}: public signals must equal snarkjs + independent recompute", circuit.key);

    let cd = calldata_from_snarkjs(&off.proof_json, &off.public_json).expect("calldata");
    let on = run_onchain(circuit, &cd).await.unwrap_or_else(|e| panic!("{}: on-chain leg: {e:?}", circuit.key));
    assert!(on.valid_accepted, "{}: deployed verifier must accept the valid proof", circuit.key);
    assert!(on.corrupted_statement_rejected, "{}: deployed verifier must reject a corrupted statement", circuit.key);
    assert!(on.corrupted_proof_rejected, "{}: deployed verifier must reject a corrupted proof point", circuit.key);
    true
}

// The pins live in the Circuit config; re-read them here so a drift fails the test.
fn circuit_golden_sha(c: &Circuit) -> String {
    // `run_offchain` already asserts wtns_sha256 == c.golden_sha256 via witness_matches_golden;
    // this mirrors it explicitly for a hard equality assertion.
    match c.key {
        "withdrawal" => "b57d06927c8ce5afd9ca4100a87f0fe2da7f398ecf47dfe2b54bdad7114d2f28",
        "aggregation" => "5c8156e4ca34ab10a10af6f2e38141c44b9c02aa930f59253e90ee29e3a1d666",
        "pending" => "e91726d9f5e9ea2bc3981c32cb490cd5ab5d1eeb2f5a3dc825d7abfdd78729d5",
        k => panic!("unknown circuit {k}"),
    }
    .to_string()
}
fn circuit_zkey_sha(c: &Circuit) -> String {
    match c.key {
        "withdrawal" => "c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716",
        "aggregation" => "88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6",
        "pending" => "efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847",
        k => panic!("unknown circuit {k}"),
    }
    .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn m1_prove_verify_end_to_end_all_circuits() {
    let mut ran = 0usize;
    for circuit in Circuit::all() {
        if assert_circuit(&circuit).await {
            ran += 1;
        }
    }
    // Withdrawal + aggregation are self-contained (committed graph + golden); their
    // zkeys default to the canonical v3-e2e assets. At minimum those two must run.
    assert!(ran >= 2, "expected at least withdrawal + aggregation to run (ran {ran}); ensure the zkeys are present");
}
