use ark_bn254::Fr;
use curvy_prover::{HAWK_PROFILE, ProverError, ProverMode, ResidentProver};
mod common;
use common::{digest, multiplier_graph};

const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");
const ZKEY_SHA256: &str = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

#[test]
fn assignment_constant_must_be_one_in_every_proving_entry_point() {
    let prover = curvy_prover::Prover::from_zkey_bytes(ZKEY, ZKEY_SHA256).unwrap();
    for first in [0, 2] {
        let assignment = [Fr::from(first), Fr::from(33), Fr::from(3), Fr::from(11)];
        assert!(matches!(
            prover.prove(&assignment),
            Err(ProverError::AssignmentConstant)
        ));
        assert!(matches!(
            prover.public_inputs(&assignment),
            Err(ProverError::AssignmentConstant)
        ));
        assert!(matches!(
            prover.prove_assignment(&assignment),
            Err(ProverError::AssignmentConstant)
        ));
        #[cfg(feature = "scratch")]
        assert!(matches!(
            prover.prove_with_workspace(&assignment, &mut curvy_prover::ProofWorkspace::new(1024)),
            Err(ProverError::AssignmentConstant)
        ));
    }
}

#[test]
fn proves_and_self_verifies_an_authenticated_graph() {
    let graph = multiplier_graph();
    let prover = ResidentProver::from_artifacts(ZKEY, ZKEY_SHA256, &graph, &digest(&graph))
        .expect("authenticated fixtures must parse");

    assert_eq!(prover.num_constraints(), 1);
    assert_eq!(prover.num_public(), 1);
    assert_eq!(prover.mode(), ProverMode::Resident);
    assert_eq!(prover.mode().to_string(), "resident");
    assert_eq!(prover.profile(), HAWK_PROFILE);

    let assignment = prover
        .calculate_witness_json(r#"{"a":"3","b":"11"}"#)
        .expect("graph evaluation must succeed");
    assert_eq!(
        assignment,
        [Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)]
    );

    let bundle = prover
        .prove_assignment(&assignment)
        .expect("valid witness must prove and self-verify");
    assert_eq!(bundle.public_signals_json, r#"["33"]"#);
    assert!(bundle.proof_json.contains(r#""protocol":"groth16""#));

    let mut invalid_assignment = assignment;
    invalid_assignment[1] += Fr::from(1);
    assert!(matches!(
        prover.prove_assignment(&invalid_assignment),
        Err(ProverError::SelfVerificationFailed)
    ));
}

/// A tampered proving key must never reach a proof.
///
/// The pinned digest is the defence: it refuses the artifact before the
/// unchecked point parser sees a coordinate. Self-verification is the backstop
/// behind it, and only a backstop - it verifies against the verifying key
/// carried by the same artifact, so it catches corruption, not a coherent
/// substitution. Both are exercised here.
#[test]
fn a_tampered_zkey_is_refused_and_cannot_produce_a_verifying_proof() {
    let graph = multiplier_graph();
    let graph_digest = digest(&graph);

    // Section 9 (the H query) spans 1044..1300 and holds four G1 points, so
    // this byte belongs to the second one - interior, past the first and last
    // that `spot_check` inspects. Nothing but the digest notices it.
    let mut tampered = ZKEY.to_vec();
    tampered[1044 + 64] ^= 0x01;
    assert_ne!(tampered.as_slice(), ZKEY);

    // With the real pin the load is refused outright.
    assert!(matches!(
        ResidentProver::from_artifacts(&tampered, ZKEY_SHA256, &graph, &graph_digest),
        Err(ProverError::ZkeyHashMismatch { .. })
    ));

    // Even where an attacker also controls the pin, the corrupted H basis
    // cannot produce a proof that verifies.
    let prover =
        ResidentProver::from_artifacts(&tampered, &digest(&tampered), &graph, &graph_digest)
            .expect("a self-consistent pin still loads: the digest is the only gate");
    let assignment = prover
        .calculate_witness_json(r#"{"a":"3","b":"11"}"#)
        .expect("graph evaluation is unaffected by the zkey");
    assert!(matches!(
        prover.prove_assignment(&assignment),
        Err(ProverError::SelfVerificationFailed)
    ));
}

/// The verifying-key digest pins what a verifier encodes, so it must be stable
/// across artifact churn that leaves the verifier alone. Rebuilding a zkey with
/// a different contributions section moves the zkey digest but must not move
/// this one - that is exactly what makes it usable as a long-lived constant.
#[test]
fn verifying_key_digest_is_pinned_and_survives_artifact_churn() {
    const FIXTURE_VK: &str = "b550c07c390e3122b682edc04afb8c590bbc66172f19d1a42ac7051f15442838";

    let graph = multiplier_graph();
    let graph_digest = digest(&graph);
    let prover = ResidentProver::from_artifacts(ZKEY, ZKEY_SHA256, &graph, &graph_digest)
        .expect("authenticated fixtures must parse");
    assert_eq!(prover.verifying_key_digest(), FIXTURE_VK);

    // Section 10 holds the contributions transcript at 2512..2580: not part of
    // the proving key and not part of the verifier.
    let mut rebuilt = ZKEY.to_vec();
    rebuilt[2512] ^= 0xff;
    let rebuilt_digest = digest(&rebuilt);
    assert_ne!(rebuilt_digest, ZKEY_SHA256, "the artifact digest must move");

    let rebuilt_prover =
        ResidentProver::from_artifacts(&rebuilt, &rebuilt_digest, &graph, &graph_digest)
            .expect("a differently attested artifact still parses");
    assert_eq!(
        rebuilt_prover.verifying_key_digest(),
        FIXTURE_VK,
        "the verifier did not change, so its digest must not either",
    );
}
