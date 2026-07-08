//! M1 end-to-end integration test: drives the same three legs as the
//! `prove-verify` bin and asserts every exit criterion.
//!
//! Needs the deployed zkey (default v3-e2e path, override CURVY_WITHDRAWAL_ZKEY)
//! and `anvil` on PATH.

use m1_prove_verify::{calldata_from_snarkjs, run_offchain, run_onchain};

#[tokio::test(flavor = "multi_thread")]
async fn m1_prove_verify_end_to_end() {
    let off = run_offchain().expect("off-chain leg");
    assert!(
        off.witness_matches_golden,
        "pure-Rust witness must be byte-identical to the snarkjs golden .wtns"
    );
    assert_eq!(off.wtns_sha256, m1_prove_verify::GOLDEN_WTNS_SHA256);
    assert_eq!(off.zkey_sha256, m1_prove_verify::ZKEY_SHA256);
    assert!(off.offchain_verified, "arkworks Groth16 verify must pass");
    assert!(
        off.publics_match_reference,
        "public signals must equal the snarkjs reference + expected fixture"
    );

    let cd = calldata_from_snarkjs(&off.proof_json, &off.public_json).expect("calldata");
    let on = run_onchain(&cd).await.expect("on-chain leg");
    assert!(on.valid_accepted, "deployed verifier must accept the valid proof");
    assert!(
        on.corrupted_statement_rejected,
        "deployed verifier must reject a corrupted public statement"
    );
    assert!(
        on.corrupted_proof_rejected,
        "deployed verifier must reject a corrupted proof point"
    );
}
