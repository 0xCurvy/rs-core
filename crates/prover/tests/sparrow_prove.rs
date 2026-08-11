#![cfg(feature = "sparrow")]

use std::io::Cursor;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::Proof;
use curvy_prover::Prover;
use curvy_prover::sparrow::{
    SparrowConfig, SparrowError, SparrowProofBuilder, SparrowProver,
    manifest::{ManifestProofStream, ZkeyChunkManifest, prove_reader_with_manifest_owned},
};
use curvy_witness::Limits;
use sha2::{Digest, Sha256};

const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");
const ZKEY_SHA256: &str = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

#[test]
fn release_validator_accepts_every_fixture_point() {
    let (key, _) = curvy_prover::zkey::read_zkey(&mut Cursor::new(ZKEY)).expect("parse fixture");
    curvy_prover::zkey::validate_proving_key(&key).expect("validate every proving-key point");
}

#[test]
fn release_validator_rejects_identity_anchor_points() {
    let (key, _) = curvy_prover::zkey::read_zkey(&mut Cursor::new(ZKEY)).expect("parse fixture");

    let mut changed = key.clone();
    changed.vk.alpha_g1 = G1Affine::identity();
    assert!(curvy_prover::zkey::validate_proving_key(&changed).is_err());

    let mut changed = key.clone();
    changed.beta_g1 = G1Affine::identity();
    assert!(curvy_prover::zkey::validate_proving_key(&changed).is_err());

    let mut changed = key.clone();
    changed.delta_g1 = G1Affine::identity();
    assert!(curvy_prover::zkey::validate_proving_key(&changed).is_err());

    let mut changed = key.clone();
    changed.vk.beta_g2 = G2Affine::identity();
    assert!(curvy_prover::zkey::validate_proving_key(&changed).is_err());

    let mut changed = key.clone();
    changed.vk.gamma_g2 = G2Affine::identity();
    assert!(curvy_prover::zkey::validate_proving_key(&changed).is_err());

    let mut changed = key;
    changed.vk.delta_g2 = G2Affine::identity();
    assert!(curvy_prover::zkey::validate_proving_key(&changed).is_err());
}

#[test]
fn sage_and_sparrow_queries_produce_a_valid_proof() {
    let graph = multiplier_graph();
    let prover = SparrowProver::from_signet_bytes(
        &graph,
        &digest(&graph),
        ZKEY_SHA256,
        Limits::client(),
        SparrowConfig {
            window_bits: 6,
            msm_chunk_points: 2,
            io_chunk_bytes: 17,
        },
    )
    .expect("authenticated SAGE graph must compile");
    assert!(prover.sage_slot_count() <= 3);

    let program = prover
        .compiled_sage_bytes()
        .expect("serialize authenticated SAGE graph");
    let cached = SparrowProver::from_compiled_sage_bytes(
        &program,
        &digest(&program),
        &digest(&graph),
        ZKEY_SHA256,
        Limits::client(),
        SparrowConfig {
            window_bits: 6,
            msm_chunk_points: 2,
            io_chunk_bytes: 17,
        },
    )
    .expect("load locally derived SAGE cache");
    assert_eq!(
        cached
            .calculate_witness_json(r#"{"a":"3","b":"11"}"#)
            .expect("evaluate cached SAGE program"),
        prover
            .calculate_witness_json(r#"{"a":"3","b":"11"}"#)
            .expect("evaluate source-compiled SAGE program")
    );

    let mut zkey = Cursor::new(ZKEY);
    let bundle = prover
        .prove_json(r#"{"a":"3","b":"11"}"#, &mut zkey)
        .expect("SPARROW proof must self-verify");
    assert_eq!(bundle.public_signals_json, r#"["33"]"#);
    let foreign_verifier = Prover::from_zkey_bytes(ZKEY, ZKEY_SHA256).expect("load verifier");
    assert!(
        foreign_verifier
            .verify(&parse_proof(&bundle.proof_json), &[Fr::from(33)])
            .expect("foreign verification")
    );
}

#[test]
fn incremental_builder_accepts_unaligned_chunks_and_rechecks_the_digest() {
    let assignment = vec![Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
    let config = SparrowConfig {
        window_bits: 6,
        msm_chunk_points: 2,
        io_chunk_bytes: 17,
    };
    let mut builder = SparrowProofBuilder::new(assignment, ZKEY_SHA256, config).unwrap();
    builder.begin_zkey(&ZKEY[..12]).unwrap();
    let mut offset = 12;
    for _ in 0..10 {
        let header = &ZKEY[offset..offset + 12];
        let length = u64::from_le_bytes(header[4..12].try_into().unwrap()) as usize;
        builder.begin_section(header).unwrap();
        offset += 12;
        for chunk in ZKEY[offset..offset + length].chunks(7) {
            builder.push_section_chunk(chunk).unwrap();
        }
        builder.end_section().unwrap();
        offset += length;
    }
    assert_eq!(offset, ZKEY.len());
    assert!(builder.finish().is_ok());

    let mut corrupted = ZKEY.to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut builder = SparrowProofBuilder::new(
        vec![Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)],
        ZKEY_SHA256,
        config,
    )
    .unwrap();
    builder.begin_zkey(&corrupted[..12]).unwrap();
    let mut offset = 12;
    for _ in 0..10 {
        let header = &corrupted[offset..offset + 12];
        let length = u64::from_le_bytes(header[4..12].try_into().unwrap()) as usize;
        builder.begin_section(header).unwrap();
        offset += 12;
        builder
            .push_section_chunk(&corrupted[offset..offset + length])
            .unwrap();
        builder.end_section().unwrap();
        offset += length;
    }
    assert!(matches!(
        builder.finish(),
        Err(SparrowError::ZkeyHashMismatch { .. })
    ));
}

#[test]
fn authenticated_chunk_manifest_enables_a_single_zkey_pass() {
    let (manifest_bytes, manifest_sha) =
        ZkeyChunkManifest::generate(&mut Cursor::new(ZKEY), 64 * 1024).unwrap();
    assert!(matches!(
        ZkeyChunkManifest::from_bytes(&manifest_bytes, &"00".repeat(32), ZKEY_SHA256),
        Err(SparrowError::ManifestHashMismatch { .. })
    ));
    assert!(matches!(
        ZkeyChunkManifest::from_bytes(&manifest_bytes, &manifest_sha, &"00".repeat(32)),
        Err(SparrowError::ManifestZkeyHashMismatch { .. })
    ));
    let manifest =
        ZkeyChunkManifest::from_bytes(&manifest_bytes, &manifest_sha, ZKEY_SHA256).unwrap();
    let assignment = vec![Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
    let config = SparrowConfig {
        window_bits: 6,
        msm_chunk_points: 2,
        io_chunk_bytes: 17,
    };
    let graph = multiplier_graph();
    let prover = SparrowProver::from_signet_bytes(
        &graph,
        &digest(&graph),
        ZKEY_SHA256,
        Limits::client(),
        config,
    )
    .unwrap();
    let bundle = prover
        .prove_json_with_manifest(
            r#"{"a":"3","b":"11"}"#,
            &mut Cursor::new(ZKEY),
            &manifest_bytes,
            &manifest_sha,
        )
        .expect("manifest-authenticated single pass must prove");
    assert_eq!(bundle.public_signals_json, r#"["33"]"#);

    let mut corrupted = ZKEY.to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut stream = ManifestProofStream::new(assignment, manifest, config).unwrap();
    for chunk in corrupted.chunks(7) {
        stream.push(chunk).unwrap();
    }
    assert!(matches!(
        stream.finish(),
        Err(SparrowError::ZkeyChunkHashMismatch { index: 0, .. })
    ));
}

#[test]
fn manifest_advances_across_multiple_chunks_and_batches_authentication() {
    let zkey = padded_zkey();
    assert!(zkey.len() > 2 * 64 * 1024);
    let zkey_sha = digest(&zkey);
    let (manifest_bytes, manifest_sha) =
        ZkeyChunkManifest::generate(&mut Cursor::new(&zkey), 64 * 1024).unwrap();
    // Header plus three SHA-256 chunk entries proves this fixture actually
    // crosses two boundaries rather than retesting the one-chunk path.
    assert_eq!(manifest_bytes.len(), 60 + 3 * 32);
    let manifest =
        ZkeyChunkManifest::from_bytes(&manifest_bytes, &manifest_sha, &zkey_sha).unwrap();
    manifest
        .verify_reader(&mut Cursor::new(&zkey))
        .expect("chunk table and whole digest agree");
    let assignment = vec![Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
    let config = SparrowConfig {
        window_bits: 6,
        msm_chunk_points: 2,
        io_chunk_bytes: 17,
    };

    // This is the ownership-taking entry point used by the browser adapter.
    let mut exact_stream =
        ManifestProofStream::new(assignment.clone(), manifest.clone(), config).unwrap();
    for chunk in zkey.chunks(64 * 1024) {
        exact_stream
            .push_complete_chunk(chunk.to_vec())
            .expect("authenticate an exact manifest chunk");
    }
    exact_stream
        .finish()
        .expect("exact-chunk entry point must produce a proof");

    let mut truncated =
        ManifestProofStream::new(assignment.clone(), manifest.clone(), config).unwrap();
    truncated
        .push(&zkey[..zkey.len() - 1])
        .expect("all complete chunks authenticate before the truncated tail");
    assert!(matches!(
        truncated.finish(),
        Err(SparrowError::UnexpectedEof)
    ));

    let bundle = prove_reader_with_manifest_owned(
        &mut Cursor::new(&zkey),
        assignment.clone(),
        manifest.clone(),
        config,
    )
    .expect("batched multi-chunk manifest proof");

    let foreign_verifier = Prover::from_zkey_bytes(&zkey, &zkey_sha).expect("load padded zkey");
    assert!(
        foreign_verifier
            .verify(&parse_proof(&bundle.proof_json), &[Fr::from(33)])
            .expect("foreign verification")
    );

    let mut corrupted = zkey;
    corrupted[64 * 1024 + 17] ^= 1;
    let mut stream = ManifestProofStream::new(assignment, manifest, config).unwrap();
    let error = stream
        .push(&corrupted)
        .expect_err("corruption in the second chunk must fail before parsing it");
    assert!(matches!(
        error,
        SparrowError::ZkeyChunkHashMismatch { index: 1, .. }
    ));
}

fn multiplier_graph() -> Vec<u8> {
    let mut graph = Vec::new();
    graph.extend_from_slice(b"SIGNET01");
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&64_u32.to_le_bytes());
    graph.extend_from_slice(&[0_u8; 32]);
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());
    graph.extend_from_slice(&3_u32.to_le_bytes());
    for input in 0_u32..=2 {
        graph.push(0);
        graph.extend_from_slice(&input.to_le_bytes());
    }
    graph.push(2);
    graph.push(0);
    graph.extend_from_slice(&1_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());
    for signal in [0_u32, 3, 1, 2] {
        graph.extend_from_slice(&signal.to_le_bytes());
    }
    for (name, signal) in [("a", 1_u32), ("b", 2_u32)] {
        graph.extend_from_slice(&fnv1a(name).to_le_bytes());
        graph.extend_from_slice(&signal.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
    }
    graph
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn padded_zkey() -> Vec<u8> {
    let mut zkey = ZKEY.to_vec();
    let mut offset = 12_usize;
    for _ in 0..10 {
        let id = u32::from_le_bytes(zkey[offset..offset + 4].try_into().unwrap());
        let length = u64::from_le_bytes(zkey[offset + 4..offset + 12].try_into().unwrap()) as usize;
        let body = offset + 12;
        let end = body + length;
        if id == 10 {
            assert_eq!(
                end,
                zkey.len(),
                "contributions must be the final fixture section"
            );
            let target = 2 * 64 * 1024 + 1;
            let padding = target - zkey.len();
            let new_length = length + padding;
            zkey[offset + 4..offset + 12].copy_from_slice(&(new_length as u64).to_le_bytes());
            zkey.resize(target, 0);
            return zkey;
        }
        offset = end;
    }
    panic!("fixture has no contributions section")
}

fn parse_proof(json: &str) -> Proof<Bn254> {
    let value: serde_json::Value = serde_json::from_str(json).expect("proof JSON");
    let fq = |value: &serde_json::Value| {
        value
            .as_str()
            .expect("decimal coordinate")
            .parse::<Fq>()
            .expect("canonical Fq")
    };
    let a = &value["pi_a"];
    let b = &value["pi_b"];
    let c = &value["pi_c"];
    Proof {
        a: G1Affine::new(fq(&a[0]), fq(&a[1])),
        b: G2Affine::new(
            Fq2::new(fq(&b[0][0]), fq(&b[0][1])),
            Fq2::new(fq(&b[1][0]), fq(&b[1][1])),
        ),
        c: G1Affine::new(fq(&c[0]), fq(&c[1])),
    }
}
