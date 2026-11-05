#![no_main]
//! Graphs built from the fuzz input, encoded as SIGNET versions 1 and 2.
//!
//! The two encodings must transcode into each other byte for byte, be accepted or
//! refused together with the same error, and evaluate to the same assignment - or
//! fail at the same node - in both evaluators, raw and zstd-compressed.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use curvy_signet::postcard::{ALL_OPERATIONS, Graph, InputMapping, Node};
use curvy_signet::{Envelope, FormatVersion, encode, transcode};
use curvy_witness::{Limits, WitnessGraph, sage::SageGraph};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use ruint::aliases::U256;
use sha2::{Digest, Sha256};

const MAX_NODES: usize = 96;
const MAX_SIGNALS: usize = 48;

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF2_9CE4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn limits() -> Limits {
    let mut limits = Limits::client();
    limits.graph_bytes = 65536;
    limits.compressed_graph_bytes = 65536;
    // ruzstd's fastest level declares a 128 KiB window.
    limits.zstd_window_bytes = 128 * 1024;
    limits.nodes = MAX_NODES + 1;
    limits.signals = MAX_SIGNALS + 1;
    limits.input_mappings = 4;
    limits.input_values = 64;
    limits
}

/// A scalar: small, at the field's top, or any 32 bytes - so the encoder also
/// meets constants at or above the modulus, which it must refuse alike.
fn scalar(u: &mut Unstructured) -> Result<U256> {
    Ok(match u.int_in_range(0..=3)? {
        0 => U256::from(u.int_in_range(0..=300_u64)?),
        1 => {
            let modulus = U256::from_limbs(Fr::MODULUS.0);
            modulus - U256::from(u.int_in_range(0..=300_u64)?)
        }
        2 => U256::from_le_bytes(u.arbitrary::<[u8; 32]>()?),
        _ => {
            let field = Fr::from_le_bytes_mod_order(&u.arbitrary::<[u8; 32]>()?);
            U256::from_le_slice(&field.into_bigint().to_bytes_le())
        }
    })
}

fn graph_and_input(u: &mut Unstructured) -> Result<(Graph, String)> {
    let width = u.int_in_range(1..=4_usize)?;
    let buffer = 1 + width + usize::from(u.arbitrary::<bool>()?);
    let mut nodes = vec![Node::Constant(U256::from(1_u64))];
    for index in 1..=u.int_in_range(0..=MAX_NODES - 1)? {
        nodes.push(match u.int_in_range(0..=9)? {
            0 | 1 => Node::Input(u.choose_index(buffer)?),
            2 => Node::Constant(scalar(u)?),
            3 => Node::Bbf(format!("bbf_inv_{index}"), vec![u.choose_index(index)?]),
            _ => Node::Op(
                *u.choose(&ALL_OPERATIONS)?,
                u.choose_index(index)?,
                u.choose_index(index)?,
            ),
        });
    }
    let mut signals = Vec::new();
    for _ in 0..u.int_in_range(1..=MAX_SIGNALS)? {
        signals.push(u.choose_index(nodes.len())?);
    }
    let graph = Graph {
        nodes,
        signals,
        input_mapping: vec![InputMapping {
            hash: fnv1a("x"),
            signal_id: 1,
            signal_size: width as u64,
        }],
    };
    let mut values = Vec::new();
    for _ in 0..width {
        values.push(if u.ratio(1, 8)? {
            format!("\"-{}\"", u.int_in_range(0..=1000_u32)?)
        } else {
            format!("\"{}\"", scalar(u)? % U256::from_limbs(Fr::MODULUS.0))
        });
    }
    Ok((graph, format!("{{\"x\":[{}]}}", values.join(","))))
}

/// Acceptance and every evaluator's outcome, as comparable strings.
fn outcome(bytes: &[u8], input: &str) -> std::result::Result<String, String> {
    let pin = hex(&Sha256::digest(bytes));
    let graph = WitnessGraph::from_bytes_with_limits(bytes, &pin, limits());
    let sage = SageGraph::from_bytes_with_limits(bytes, &pin, limits());
    assert_eq!(
        graph.as_ref().map(|_| ()).map_err(|e| e.to_string()),
        sage.as_ref().map(|_| ()).map_err(|e| e.to_string()),
        "the evaluators disagree on acceptance"
    );
    let (graph, sage) = (graph.map_err(|e| e.to_string())?, sage.expect("accepted"));
    let assignment = graph.calculate_json(input).map_err(|e| e.to_string());
    assert_eq!(
        sage.calculate_json(input).map_err(|e| e.to_string()),
        assignment,
        "SAGE evaluates differently"
    );
    Ok(format!("{assignment:?}"))
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok((graph, input)) = graph_and_input(&mut u) else {
        return;
    };
    let envelope = if data.first().is_some_and(|b| b & 1 == 1) {
        Envelope::Cvywit
    } else {
        Envelope::Signet
    };
    // A constant at or above the modulus is refused by the encoder, in either version.
    let (v1, v2) = match (
        encode(&graph, [0x5E; 32], envelope, FormatVersion::V1),
        encode(&graph, [0x5E; 32], envelope, FormatVersion::V2),
    ) {
        (Ok(v1), Ok(v2)) => (v1, v2),
        (Err(v1), Err(v2)) => {
            assert_eq!(
                v1.to_string(),
                v2.to_string(),
                "the encoder refused differently"
            );
            return;
        }
        (v1, v2) => panic!(
            "the encoder refused one version only: {:?} / {:?}",
            v1.err(),
            v2.err()
        ),
    };

    assert_eq!(transcode(&v1, FormatVersion::V2).expect("transcode v1"), v2);
    assert_eq!(transcode(&v2, FormatVersion::V1).expect("transcode v2"), v1);

    let expected = outcome(&v1, &input);
    assert_eq!(
        outcome(&v2, &input),
        expected,
        "version 2 differs from version 1"
    );
    if data.last().is_some_and(|b| b & 1 == 1) {
        let compressed = ruzstd::encoding::compress_to_vec(
            v2.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert_eq!(
            outcome(&compressed, &input),
            expected,
            "compressed version 2 differs"
        );
    }
});
