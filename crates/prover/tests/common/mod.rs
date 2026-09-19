use sha2::{Digest, Sha256};

pub fn multiplier_graph() -> Vec<u8> {
    let mut graph = Vec::new();

    graph.extend_from_slice(b"CVYWIT01");
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

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
