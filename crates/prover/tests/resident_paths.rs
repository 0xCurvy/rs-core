#![cfg(any(feature = "zkey-manifest", feature = "sage", feature = "scratch"))]

mod common;
use common::{digest, multiplier_graph};
use curvy_prover::{Prover, ResidentProver};

const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

#[cfg(feature = "zkey-manifest")]
#[test]
fn manifest_reader_loads_without_seek_and_rejects_every_changed_chunk() {
    use curvy_prover::artifacts::manifest::ZkeyChunkManifest;
    let mut bytes = ZKEY.to_vec();
    bytes.resize(3 * 65536 + 7, 0); // Also authenticate bytes outside parsed sections.
    let (encoded, pin) = ZkeyChunkManifest::generate(&mut bytes.as_slice(), 65536).unwrap();
    let manifest = ZkeyChunkManifest::from_bytes(&encoded, &pin, &digest(&bytes)).unwrap();
    let baseline = Prover::from_zkey_bytes(ZKEY, &digest(ZKEY)).unwrap();
    let key = Prover::from_zkey_manifest_reader(&mut bytes.as_slice(), &manifest).unwrap();
    assert_eq!(key.verifying_key_digest(), baseline.verifying_key_digest());
    let graph = multiplier_graph();
    let resident = ResidentProver::with_graph(
        key,
        curvy_witness::WitnessGraph::from_bytes(&graph, &digest(&graph)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        resident
            .prove_json(r#"{"a":"3","b":"11"}"#)
            .unwrap()
            .public_signals_json,
        "[\"33\"]"
    );

    for offset in [0, 65536, 131072, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let error = Prover::from_zkey_manifest_reader(&mut changed.as_slice(), &manifest)
            .err()
            .unwrap();
        assert!(error.to_string().contains("SHA-256 mismatch"));
    }
    assert!(Prover::from_zkey_manifest_reader(&mut &bytes[..bytes.len() - 1], &manifest).is_err());
    bytes.push(0);
    assert!(Prover::from_zkey_manifest_reader(&mut bytes.as_slice(), &manifest).is_err());
    assert!(ZkeyChunkManifest::from_bytes(&encoded, &pin, &"00".repeat(32)).is_err());
    assert!(ZkeyChunkManifest::from_bytes(&encoded, &"00".repeat(32), &digest(&bytes)).is_err());
}

#[cfg(feature = "sage")]
#[test]
fn resident_sage_matches_graph_and_authenticates_compiled_programs() {
    use curvy_witness::{Limits, sage::SageGraph};
    let graph = multiplier_graph();
    let source_pin = digest(&graph);
    let reference =
        ResidentProver::from_artifacts(ZKEY, &digest(ZKEY), &graph, &source_pin).unwrap();
    let sage = SageGraph::from_bytes(&graph, &source_pin).unwrap();
    let program = sage.to_compiled_bytes().unwrap();
    let resident =
        ResidentProver::with_sage(Prover::from_zkey_bytes(ZKEY, &digest(ZKEY)).unwrap(), sage)
            .unwrap();
    let cached = ResidentProver::from_compiled_sage(
        Prover::from_zkey_bytes(ZKEY, &digest(ZKEY)).unwrap(),
        &program,
        &digest(&program),
        &source_pin,
        Limits::client(),
    )
    .unwrap();
    assert_eq!(resident.witness_backend(), "sage");
    assert_eq!(cached.r1cs_sha256(), reference.r1cs_sha256());
    for input in [r#"{"a":"3","b":"11"}"#, r#"{"a":"7","b":"5"}"#] {
        let assignment = reference.calculate_witness_json(input).unwrap();
        assert_eq!(resident.calculate_witness_json(input).unwrap(), assignment);
        assert_eq!(cached.calculate_witness_json(input).unwrap(), assignment);
        assert_eq!(
            cached.prove_json(input).unwrap().public_signals_json,
            reference.prove_json(input).unwrap().public_signals_json
        );
    }
    for (program_pin, graph_pin) in [
        ("00".repeat(32), source_pin.clone()),
        (digest(&program), "00".repeat(32)),
    ] {
        assert!(
            ResidentProver::from_compiled_sage(
                Prover::from_zkey_bytes(ZKEY, &digest(ZKEY)).unwrap(),
                &program,
                &program_pin,
                &graph_pin,
                Limits::client()
            )
            .is_err()
        );
    }
    let mut wrong_size = graph;
    wrong_size[52..56].copy_from_slice(&3_u32.to_le_bytes());
    wrong_size.drain(101..105);
    let sage = SageGraph::from_bytes(&wrong_size, &digest(&wrong_size)).unwrap();
    assert!(matches!(
        ResidentProver::with_sage(Prover::from_zkey_bytes(ZKEY, &digest(ZKEY)).unwrap(), sage),
        Err(curvy_prover::ProverError::AssignmentLength { .. })
    ));
}

#[cfg(feature = "scratch")]
#[test]
fn bounded_workspaces_reuse_and_recover_after_invalid_inputs() {
    use curvy_prover::ProofWorkspace;
    use curvy_witness::WitnessWorkspace;
    let graph = multiplier_graph();
    let resident =
        ResidentProver::from_artifacts(ZKEY, &digest(ZKEY), &graph, &digest(&graph)).unwrap();
    for limit in [0, 1024 * 1024] {
        let mut witness = WitnessWorkspace::new(limit);
        let mut proof = ProofWorkspace::new(limit);
        for input in [r#"{"a":"3","b":"11"}"#, r#"{"a":"7","b":"5"}"#] {
            let actual = resident
                .prove_json_with_workspace(input, &mut witness, &mut proof)
                .unwrap();
            assert_eq!(
                actual.public_signals_json,
                resident.prove_json(input).unwrap().public_signals_json
            );
            assert!(witness.retained_bytes() <= limit);
            assert!(proof.retained_bytes() <= limit);
            assert!(
                resident
                    .prove_json_with_workspace("{", &mut witness, &mut proof)
                    .is_err()
            );
        }
        if limit > 0 {
            assert!(proof.retained_bytes() > 0);
        }
    }
}
