//! Encode → authenticate → evaluate, in both encodings.
//!
//! The operation-tag test in `encode` proves the two sides share one table. This
//! proves the bytes in between are right: a graph exported here is accepted by the
//! shipped evaluator and computes what the graph says it computes. Without it, a
//! header field written at the wrong offset or a varint emitted with the wrong sign
//! would pass every unit test and fail only when a real artifact is published.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use curvy_signet::postcard::{Graph, InputMapping, Node, Operation};
use curvy_signet::{Compression, Envelope, FormatVersion, encode, hex};
use curvy_witness::WitnessGraph;
use ruint::aliases::U256;
use sha2::{Digest, Sha256};

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF2_9CE4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

/// `signal[1] = (a * a) + 7`, with a black-box inverse and an unread node so the
/// exporter has to handle every node kind it supports.
fn graph() -> Graph {
    Graph {
        nodes: vec![
            Node::Constant(U256::from(1_u64)),          // 0: the constant one
            Node::Input(1),                             // 1: a
            Node::Op(Operation::Mul, 1, 1),             // 2: a * a
            Node::Constant(U256::from(7_u64)),          // 3
            Node::Op(Operation::Add, 2, 3),             // 4: a*a + 7
            Node::Bbf("bbf_inv_3".to_owned(), vec![1]), // 5: 1/a, never read
        ],
        signals: vec![0, 4],
        input_mapping: vec![
            // Upstream's zero-hash placeholder; the exporter drops it.
            InputMapping {
                hash: 0,
                signal_id: 0,
                signal_size: 1,
            },
            InputMapping {
                hash: fnv1a("a"),
                signal_id: 1,
                signal_size: 1,
            },
        ],
    }
}

fn evaluate(envelope: Envelope, version: FormatVersion) -> Vec<Fr> {
    let bytes = encode(&graph(), [0xAB; 32], envelope, version).expect("encode");
    let digest = hex(&Sha256::digest(&bytes));
    WitnessGraph::from_bytes(&bytes, &digest)
        .expect("the shipped evaluator must accept what we export")
        .calculate_json(r#"{"a":"6"}"#)
        .expect("evaluate")
}

#[test]
fn every_encoding_round_trips_through_the_evaluator() {
    for envelope in [Envelope::Cvywit, Envelope::Signet] {
        for version in [FormatVersion::V1, FormatVersion::V2] {
            let assignment = evaluate(envelope, version);
            assert_eq!(
                assignment.len(),
                2,
                "{envelope:?}/{version:?}: signal count"
            );
            assert_eq!(
                assignment[0],
                Fr::from(1_u64),
                "{envelope:?}/{version:?}: assignment must begin with one"
            );
            assert_eq!(
                assignment[1].into_bigint().0[0],
                43,
                "{envelope:?}/{version:?}: 6*6 + 7"
            );
        }
    }
}

/// The two encodings are the same graph, so they must produce the same witness -
/// and version 2 must actually be denser, or it is not worth its decoder.
#[test]
fn the_two_encodings_agree_and_v2_is_smaller() {
    assert_eq!(
        evaluate(Envelope::Cvywit, FormatVersion::V1),
        evaluate(Envelope::Cvywit, FormatVersion::V2),
    );
    let v1 = encode(&graph(), [0; 32], Envelope::Cvywit, FormatVersion::V1).expect("v1");
    let v2 = encode(&graph(), [0; 32], Envelope::Cvywit, FormatVersion::V2).expect("v2");
    assert!(v2.len() < v1.len(), "v2 {} !< v1 {}", v2.len(), v1.len());
}

/// The default is the only combination a client without the `signet` feature
/// accepts, so an artifact built with no flags has to be publishable as-is.
#[test]
fn the_default_encoding_is_the_publishable_one() {
    assert_eq!(Envelope::default(), Envelope::Signet);
    assert_eq!(FormatVersion::default(), FormatVersion::V1);
    assert_eq!(Compression::default(), Compression::Zstd);
    let bytes = encode(
        &graph(),
        [0; 32],
        Envelope::default(),
        FormatVersion::default(),
    )
    .expect("encode");
    assert_eq!(&bytes[..8], b"SIGNET01");
}

/// The placeholder mapping must not reach the artifact: the evaluator rejects a
/// zero `signal_id`, so leaving it in would make every graph unloadable.
#[test]
fn the_upstream_placeholder_mapping_is_dropped() {
    let bytes = encode(&graph(), [0; 32], Envelope::Cvywit, FormatVersion::V1).expect("encode");
    assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 1);
}

/// A graph the exporter cannot faithfully represent must fail loudly rather than
/// emit something that evaluates differently.
#[test]
fn unknown_black_box_functions_are_refused() {
    let mut graph = graph();
    graph.nodes[5] = Node::Bbf("bbf_sqrt_1".to_owned(), vec![1]);
    let Err(error) = encode(&graph, [0; 32], Envelope::Cvywit, FormatVersion::V1) else {
        panic!("unknown black box must fail");
    };
    assert!(error.to_string().contains("bbf_sqrt_1"), "{error}");
}

/// A compressed artifact must survive the consumer's whole zstd policy: the window
/// cap, the declared-size check, the dictionary and trailing-frame refusals, and the
/// checksum. Producing frames our own evaluator rejects is the obvious way for a
/// generator to be quietly useless.
#[test]
fn zstd_artifacts_round_trip_through_the_evaluator() {
    for envelope in [Envelope::Cvywit, Envelope::Signet] {
        for version in [FormatVersion::V1, FormatVersion::V2] {
            let raw = encode(&graph(), [0x11; 32], envelope, version).expect("encode");
            let (artifact, _) =
                curvy_signet::compress(&raw, curvy_signet::DEFAULT_COMPRESSION_LEVEL);

            assert_eq!(
                &artifact[..4],
                &[0x28, 0xb5, 0x2f, 0xfd],
                "{envelope:?}/{version:?}: not a zstd frame"
            );

            // The digest to pin is the compressed one - that is what the evaluator
            // is handed and therefore what it authenticates.
            let digest = hex(&Sha256::digest(&artifact));
            let assignment = WitnessGraph::from_bytes(&artifact, &digest)
                .expect("the evaluator must accept our compressed artifact")
                .calculate_json(r#"{"a":"6"}"#)
                .expect("evaluate");

            assert_eq!(
                assignment[1].into_bigint().0[0],
                43,
                "{envelope:?}/{version:?}"
            );
        }
    }
}

/// Compressing changes which digest authenticates the artifact. Pinning the
/// uncompressed one against a compressed file must fail, not silently pass.
#[test]
fn a_compressed_artifact_is_pinned_by_its_compressed_digest() {
    let raw = encode(&graph(), [0; 32], Envelope::Cvywit, FormatVersion::V1).expect("encode");
    let (artifact, _) = curvy_signet::compress(&raw, curvy_signet::DEFAULT_COMPRESSION_LEVEL);
    let uncompressed_digest = hex(&Sha256::digest(&raw));

    let Err(error) = WitnessGraph::from_bytes(&artifact, &uncompressed_digest) else {
        panic!("the raw digest must not authenticate the compressed file");
    };
    assert!(error.to_string().contains("mismatch"), "{error}");
}

/// Compression has to actually pay for the decoder it costs.
#[test]
fn compression_shrinks_a_realistic_graph() {
    // Repetitive structure, like a real circuit's fan-out.
    let mut nodes = vec![Node::Constant(U256::from(1_u64)), Node::Input(1)];
    for index in 2..4_000 {
        nodes.push(Node::Op(Operation::Add, index - 1, index - 2));
    }
    let graph = Graph {
        nodes,
        signals: vec![0, 3_999],
        input_mapping: vec![InputMapping {
            hash: fnv1a("a"),
            signal_id: 1,
            signal_size: 1,
        }],
    };

    let raw = encode(&graph, [0; 32], Envelope::Signet, FormatVersion::V2).expect("encode");
    let (artifact, _) = curvy_signet::compress(&raw, curvy_signet::DEFAULT_COMPRESSION_LEVEL);
    assert!(
        artifact.len() < raw.len(),
        "compressed {} !< raw {}",
        artifact.len(),
        raw.len()
    );

    let digest = hex(&Sha256::digest(&artifact));
    WitnessGraph::from_bytes(&artifact, &digest).expect("compressed large graph must load");
}

/// Whatever compressor ran, the frame has to stay inside the consumer's window cap.
/// A generator that silently produced un-loadable artifacts would be worse than one
/// that produced none.
#[test]
fn the_default_level_stays_within_the_consumer_window_cap() {
    let mut nodes = vec![Node::Constant(U256::from(1_u64)), Node::Input(1)];
    for index in 2..50_000 {
        nodes.push(Node::Op(Operation::Add, index - 1, index - 2));
    }
    let graph = Graph {
        nodes,
        signals: vec![0, 49_999],
        input_mapping: vec![InputMapping {
            hash: fnv1a("a"),
            signal_id: 1,
            signal_size: 1,
        }],
    };

    let raw = encode(&graph, [0; 32], Envelope::Signet, FormatVersion::V2).expect("encode");
    let (artifact, compressor) =
        curvy_signet::compress(&raw, curvy_signet::DEFAULT_COMPRESSION_LEVEL);
    let digest = hex(&Sha256::digest(&artifact));

    let loaded = WitnessGraph::from_bytes(&artifact, &digest)
        .unwrap_or_else(|e| panic!("{compressor:?} produced an artifact we cannot load: {e}"));
    assert_eq!(loaded.assignment_size(), 2);
}
