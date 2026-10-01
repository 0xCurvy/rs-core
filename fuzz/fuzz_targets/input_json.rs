#![no_main]
use std::sync::LazyLock;
use curvy_witness::{WitnessError, WitnessGraph, wire};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
fn authenticated(bytes: &[u8]) -> WitnessGraph {
    let pin = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    WitnessGraph::from_bytes(bytes, &pin).unwrap()
}
fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3))
}
static GRAPH: LazyLock<WitnessGraph> =
    LazyLock::new(|| authenticated(include_bytes!("../corpus/graph/multiplier")));
// Scalar `a`, one-dimensional `b[3]` and two-dimensional `c[2][2]`, so lengths,
// nesting and flattening are exercised beyond the scalar-only multiplier.
static ARRAYS: LazyLock<WitnessGraph> = LazyLock::new(|| {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(wire::MAGIC);
    bytes.extend_from_slice(&wire::FORMAT_VERSION_V1.to_le_bytes());
    bytes.extend_from_slice(&wire::FIELD_BN254_FR.to_le_bytes());
    bytes.extend_from_slice(&wire::HEADER_SIZE.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    for count in [10_u32, 10, 3, 9] { bytes.extend_from_slice(&count.to_le_bytes()); }
    for input in 0_u32..9 { bytes.push(0); bytes.extend_from_slice(&input.to_le_bytes()); }
    bytes.extend_from_slice(&[2, wire::MUL]);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    for output in [0_u32, 9, 1, 2, 3, 4, 5, 6, 7, 8] { bytes.extend_from_slice(&output.to_le_bytes()); }
    for (name, signal, size) in [("a", 1_u32, 1_u32), ("b", 2, 3), ("c", 5, 4)] {
        bytes.extend_from_slice(&fnv1a(name).to_le_bytes());
        bytes.extend_from_slice(&signal.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
    }
    authenticated(&bytes)
});
/// Errors never repeat input values. Signal names (keys) are the one thing they
/// may echo, and only up to 128 bytes.
fn check_redaction(json: &str, error: &WitnessError) {
    let message = error.to_string();
    // Only an echoed key can contain `{`, and never followed by the rest of an
    // object, so an object input can never appear whole in an error.
    if json.starts_with('{') {
        assert!(!message.contains(json), "error repeats the input: {message:?}");
    }
    let echoed = match error {
        WitnessError::UnknownInput(name) | WitnessError::InputLength { name, .. } => Some(name),
        _ => None,
    };
    let unechoed = match echoed {
        Some(name) => {
            assert!(name.len() <= 128, "error echoes an oversized key");
            message.replacen(&format!("{name:?}"), "", 1)
        }
        None => message,
    };
    // Seeds plant this sentinel in values; mutations keep it in many positions.
    assert!(!unechoed.contains("PRIVATE"), "error repeats an input value: {unechoed:?}");
}
fuzz_target!(|data: &[u8]| {
    if data.len() <= 65536 {
        if let Ok(json) = std::str::from_utf8(data) {
            for graph in [&*GRAPH, &*ARRAYS] {
                match graph.calculate_json(json) {
                    Ok(assignment) => assert_eq!(assignment.len(), graph.assignment_size()),
                    Err(error) => check_redaction(json, &error),
                }
            }
        }
    }
});
