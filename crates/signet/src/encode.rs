//! Upstream graph → SIGNET artifact.
//!
//! The tag values come from [`curvy_witness::wire`], so producer and consumer read
//! one table. That is the reason this crate lives beside the evaluator rather than
//! in the circuit repository.

use ark_ff::{BigInteger, PrimeField};
use curvy_witness::wire;

use crate::postcard::{Graph, Node, Operation};
use crate::{Envelope, FormatVersion, SignetError};

/// Encode one graph into an authenticated-artifact body.
///
/// `r1cs_sha256` is provenance: it records which optimised R1CS the graph was
/// compiled from. It is not a second trust root - the artifact's own digest,
/// pinned in protocol metadata, is what authenticates these bytes.
pub fn encode(
    graph: &Graph,
    r1cs_sha256: [u8; 32],
    envelope: Envelope,
    version: FormatVersion,
) -> Result<Vec<u8>, SignetError> {
    // Upstream leaves a zero-hash placeholder in the mapping table; it maps no
    // name, and the consumer rejects a zero `signal_id`, so drop it here.
    let input_mapping = graph
        .input_mapping
        .iter()
        .filter(|mapping| mapping.hash != 0)
        .collect::<Vec<_>>();

    let mut bytes = Vec::with_capacity(64 + graph.nodes.len() * 10);
    bytes.extend_from_slice(envelope.magic());
    push_u16(&mut bytes, version.tag());
    push_u16(&mut bytes, wire::FIELD_BN254_FR);
    push_u32(&mut bytes, wire::HEADER_SIZE);
    bytes.extend_from_slice(&r1cs_sha256);
    push_u32(&mut bytes, checked_u32(graph.nodes.len(), "nodes")?);
    push_u32(&mut bytes, checked_u32(graph.signals.len(), "signals")?);
    push_u32(
        &mut bytes,
        checked_u32(input_mapping.len(), "input mappings")?,
    );
    push_u32(
        &mut bytes,
        checked_u32(graph.input_buffer_len(), "input buffer")?,
    );

    for (index, node) in graph.nodes.iter().enumerate() {
        match version {
            FormatVersion::V1 => encode_v1_node(&mut bytes, node)?,
            FormatVersion::V2 => encode_v2_node(&mut bytes, index, node)?,
        }
    }

    match version {
        FormatVersion::V1 => {
            for signal in &graph.signals {
                push_u32(&mut bytes, checked_u32(*signal, "signal reference")?);
            }
        }
        FormatVersion::V2 => {
            let mut previous = 0_i64;
            for signal in &graph.signals {
                let signal = i64::try_from(*signal).map_err(|_| SignetError::TooLarge {
                    what: "signal reference",
                })?;
                push_var_u64(&mut bytes, zigzag(signal - previous));
                previous = signal;
            }
        }
    }

    for mapping in input_mapping {
        push_u64(&mut bytes, mapping.hash);
        push_u32(
            &mut bytes,
            checked_u64(mapping.signal_id, "input signal id")?,
        );
        push_u32(
            &mut bytes,
            checked_u64(mapping.signal_size, "input signal size")?,
        );
    }
    Ok(bytes)
}

fn encode_v1_node(bytes: &mut Vec<u8>, node: &Node) -> Result<(), SignetError> {
    match node {
        Node::Input(index) => {
            bytes.push(0);
            push_u32(bytes, checked_u32(*index, "input index")?);
        }
        Node::Constant(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&constant_bytes(*value));
        }
        Node::MontConstant(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&montgomery_bytes(*value));
        }
        Node::Op(operation, left, right) => {
            bytes.push(2);
            bytes.push(operation_tag(*operation));
            push_u32(bytes, checked_u32(*left, "left reference")?);
            push_u32(bytes, checked_u32(*right, "right reference")?);
        }
        Node::Bbf(name, parameters) => {
            bytes.push(3);
            push_u32(
                bytes,
                checked_u32(inverse_source(name, parameters)?, "inverse reference")?,
            );
        }
    }
    Ok(())
}

fn encode_v2_node(bytes: &mut Vec<u8>, index: usize, node: &Node) -> Result<(), SignetError> {
    match node {
        Node::Input(input) => {
            bytes.push(wire::V2_INPUT_TAG);
            push_var_u64(bytes, u64::from(checked_u32(*input, "input index")?));
        }
        Node::Constant(value) => {
            bytes.push(wire::V2_CONSTANT_TAG);
            bytes.extend_from_slice(&constant_bytes(*value));
        }
        Node::MontConstant(value) => {
            bytes.push(wire::V2_CONSTANT_TAG);
            bytes.extend_from_slice(&montgomery_bytes(*value));
        }
        Node::Op(operation, left, right) => {
            bytes.push(operation_tag(*operation));
            push_var_u64(bytes, backward_distance(index, *left, "left reference")?);
            push_var_u64(bytes, backward_distance(index, *right, "right reference")?);
        }
        Node::Bbf(name, parameters) => {
            let source = inverse_source(name, parameters)?;
            bytes.push(wire::V2_INVERSE_TAG);
            push_var_u64(
                bytes,
                backward_distance(index, source, "inverse reference")?,
            );
        }
    }
    Ok(())
}

/// The only black-box function the exporter understands.
///
/// `patches/circomlib-iszero-bbf.patch` moves circomlib's dynamic `IsZero`
/// ternary into a named closure so the graph can carry it as one node. Anything
/// else is a circuit the exporter has not been shown to handle, and guessing at
/// its semantics would produce a graph that evaluates to the wrong witness.
fn inverse_source(name: &str, parameters: &[usize]) -> Result<usize, SignetError> {
    if strip_suffix_number(name) != "bbf_inv" || parameters.is_empty() {
        return Err(SignetError::UnsupportedBlackBox {
            name: name.to_owned(),
            arity: parameters.len(),
        });
    }
    // The parity-tested closure consumes only its first argument.
    Ok(parameters[0])
}

fn operation_tag(operation: Operation) -> u8 {
    match operation {
        Operation::Mul => wire::MUL,
        Operation::MMul => wire::MONTGOMERY_MUL,
        Operation::Add => wire::ADD,
        Operation::Sub => wire::SUB,
        Operation::Eq => wire::EQ,
        Operation::Neq => wire::NEQ,
        Operation::Lt => wire::LT,
        Operation::Gt => wire::GT,
        Operation::Leq => wire::LEQ,
        Operation::Geq => wire::GEQ,
        Operation::Lor => wire::LOGICAL_OR,
        Operation::Shl => wire::SHL,
        Operation::Shr => wire::SHR,
        Operation::Band => wire::BIT_AND,
        Operation::Bor => wire::BIT_OR,
        Operation::Bxor => wire::BIT_XOR,
        Operation::Neg => wire::NEG,
        Operation::Inv => wire::INV,
        Operation::Div => wire::DIV,
        Operation::Mod => wire::MOD,
        Operation::Pow => wire::POW,
        Operation::Land => wire::LOGICAL_AND,
        Operation::IDiv => wire::INTEGER_DIV,
    }
}

/// A plain constant is already the canonical integer; take its little-endian bytes.
fn constant_bytes(value: ruint::aliases::U256) -> [u8; 32] {
    value.to_le_bytes()
}

/// A Montgomery constant has to leave Montgomery form first.
fn montgomery_bytes(value: ark_bn254::Fr) -> [u8; 32] {
    let encoded = value.into_bigint().to_bytes_le();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&encoded);
    bytes
}

fn backward_distance(
    index: usize,
    reference: usize,
    what: &'static str,
) -> Result<u64, SignetError> {
    let distance = index
        .checked_sub(reference)
        .filter(|distance| *distance != 0)
        .ok_or(SignetError::NotAPriorNode { what, index })?;
    u64::try_from(distance).map_err(|_| SignetError::TooLarge { what })
}

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn push_var_u64(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

/// Upstream appends a numeric suffix to each black-box instance.
fn strip_suffix_number(value: &str) -> &str {
    if let Some(position) = value.rfind('_') {
        let (prefix, suffix) = value.split_at(position);
        if suffix[1..]
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            return prefix;
        }
    }
    value
}

fn checked_u32(value: usize, what: &'static str) -> Result<u32, SignetError> {
    u32::try_from(value).map_err(|_| SignetError::TooLarge { what })
}

fn checked_u64(value: u64, what: &'static str) -> Result<u32, SignetError> {
    u32::try_from(value).map_err(|_| SignetError::TooLarge { what })
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postcard::ALL_OPERATIONS;

    /// Every upstream operation must map to a distinct shipped tag, and every
    /// shipped tag must be produced by exactly one operation.
    ///
    /// The two arrays are deliberately not compared elementwise: `ALL_OPERATIONS`
    /// is in upstream's postcard declaration order, which puts `Bor`/`Bxor` at 14
    /// and 15, while the wire table assigns them 22 and 21. A positional
    /// comparison would encode that coincidence instead of the invariant.
    #[test]
    fn exporter_covers_the_consumer_operation_contract_exactly() {
        let mut produced = ALL_OPERATIONS.map(operation_tag);
        produced.sort_unstable();
        let mut shipped = wire::ALL_OPERATION_TAGS;
        shipped.sort_unstable();
        assert_eq!(
            produced, shipped,
            "the exporter and curvy-witness disagree about which tags exist"
        );

        let distinct = produced.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            distinct.len(),
            produced.len(),
            "two upstream operations share one wire tag"
        );
    }

    /// The mapping the drift test above cannot see: these four are where upstream
    /// order and wire order actually diverge.
    #[test]
    fn bitwise_operations_map_to_their_shipped_tags() {
        assert_eq!(operation_tag(Operation::Band), wire::BIT_AND);
        assert_eq!(operation_tag(Operation::Bxor), wire::BIT_XOR);
        assert_eq!(operation_tag(Operation::Bor), wire::BIT_OR);
        assert_eq!(operation_tag(Operation::Neg), wire::NEG);
    }

    /// postcard encodes a variant by declaration index, so this order is part of
    /// the input format, not a stylistic choice.
    #[test]
    fn upstream_variant_order_is_pinned() {
        assert_eq!(ALL_OPERATIONS[13], Operation::Band);
        assert_eq!(ALL_OPERATIONS[14], Operation::Bor);
        assert_eq!(ALL_OPERATIONS[15], Operation::Bxor);
        assert_eq!(ALL_OPERATIONS[16], Operation::Neg);
    }

    #[test]
    fn black_box_names_tolerate_instance_suffixes() {
        assert_eq!(inverse_source("bbf_inv_17", &[3]).expect("suffixed"), 3);
        assert_eq!(inverse_source("bbf_inv", &[9, 1]).expect("bare"), 9);
        assert!(inverse_source("bbf_sqrt_2", &[3]).is_err());
        assert!(inverse_source("bbf_inv_1", &[]).is_err());
    }
}
