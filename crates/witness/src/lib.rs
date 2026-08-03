#![doc = include_str!("../README.md")]
//!
//! ## Security model
//!
//! Graph bytes are deployment artifacts, not executable code. The parser hashes
//! the complete artifact before decoding and validates every size and reference.
//! Use this crate when an integration needs a full BN254 witness assignment but
//! performs proving elsewhere. [`curvy-prover`](https://docs.rs/curvy-prover)
//! builds on this evaluator when local Groth16 proving is required.

use std::cmp::Ordering;
use std::collections::HashSet;

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, Zero};
use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"CVYWIT01";
const FORMAT_VERSION: u16 = 1;
const FIELD_BN254_FR: u16 = 1;
const HEADER_SIZE: u32 = 64;
const MAX_GRAPH_BYTES: usize = 64 * 1024 * 1024;
const MAX_INPUT_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 2_000_000;
const MAX_SIGNALS: usize = 2_000_000;
const MAX_INPUT_MAPPINGS: usize = 4_096;
const MAX_INPUT_VALUES: usize = 2_000_000;

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("expected graph SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("witness graph SHA-256 mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("witness graph exceeds the {maximum}-byte limit")]
    GraphTooLarge { maximum: usize },
    #[error("witness input JSON exceeds the {maximum}-byte limit")]
    InputTooLarge { maximum: usize },
    #[error("witness graph is truncated")]
    Truncated,
    #[error("invalid witness graph magic")]
    InvalidMagic,
    #[error("unsupported witness graph format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported witness graph field identifier {0}")]
    UnsupportedField(u16),
    #[error("invalid witness graph header size {0}")]
    InvalidHeaderSize(u32),
    #[error("witness graph {section} count {actual} exceeds limit {maximum}")]
    CountLimit {
        section: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("witness graph contains no nodes or signals")]
    EmptyGraph,
    #[error("invalid witness graph node tag {tag} at node {index}")]
    InvalidNodeTag { index: usize, tag: u8 },
    #[error("invalid witness graph operation tag {tag} at node {index}")]
    InvalidOperation { index: usize, tag: u8 },
    #[error("node {index} references non-prior node {reference}")]
    ForwardReference { index: usize, reference: usize },
    #[error("node {index} references input {input}, but the input buffer has length {length}")]
    InputReference {
        index: usize,
        input: usize,
        length: usize,
    },
    #[error("constant at node {0} is not a canonical BN254 scalar")]
    NonCanonicalConstant(usize),
    #[error("witness output {index} references missing node {reference}")]
    OutputReference { index: usize, reference: usize },
    #[error("duplicate input hash {0:#018x} in witness graph")]
    DuplicateInputHash(u64),
    #[error("input mapping {index} range exceeds the graph input buffer")]
    InputMappingRange { index: usize },
    #[error("witness graph has trailing bytes")]
    TrailingBytes,
    #[error("invalid witness input JSON: {0}")]
    InvalidInputJson(serde_json::Error),
    #[error("witness input must be a JSON object")]
    InputNotObject,
    #[error("unknown witness input signal {0:?}")]
    UnknownInput(String),
    #[error("two input names resolve to the same graph signal hash {0:#018x}")]
    InputHashCollision(u64),
    #[error("witness input {name:?} expects {expected} values, got {actual}")]
    InputLength {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("witness input {name:?} contains an unsupported JSON value")]
    InvalidInputValue { name: String },
    #[error("witness input {name:?} contains invalid decimal field value {value:?}")]
    InvalidFieldValue { name: String, value: String },
    #[error("division or modulus by zero at graph node {0}")]
    DivisionByZero(usize),
    #[error("shift at graph node {0} is not in 0..256")]
    InvalidShift(usize),
    #[error("witness assignment must begin with the constant one")]
    InvalidAssignmentOne,
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    Mul,
    MontgomeryMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    LogicalOr,
    Shl,
    Shr,
    BitAnd,
    Neg,
    Inv,
    Div,
    Mod,
    Pow,
    LogicalAnd,
    IntegerDiv,
}

impl Operation {
    fn from_tag(tag: u8, index: usize) -> Result<Self, WitnessError> {
        let operation = match tag {
            0 => Self::Mul,
            1 => Self::MontgomeryMul,
            2 => Self::Add,
            3 => Self::Sub,
            4 => Self::Eq,
            5 => Self::Neq,
            6 => Self::Lt,
            7 => Self::Gt,
            8 => Self::Leq,
            9 => Self::Geq,
            10 => Self::LogicalOr,
            11 => Self::Shl,
            12 => Self::Shr,
            13 => Self::BitAnd,
            14 => Self::Neg,
            15 => Self::Inv,
            16 => Self::Div,
            17 => Self::Mod,
            18 => Self::Pow,
            19 => Self::LogicalAnd,
            20 => Self::IntegerDiv,
            _ => return Err(WitnessError::InvalidOperation { index, tag }),
        };
        Ok(operation)
    }

    fn evaluate(self, index: usize, left: Fr, right: Fr) -> Result<Fr, WitnessError> {
        let value = match self {
            Self::Mul | Self::MontgomeryMul => left * right,
            Self::Add => left + right,
            Self::Sub => left - right,
            Self::Eq => Fr::from(left == right),
            Self::Neq => Fr::from(left != right),
            Self::Lt => Fr::from(compare_balanced(left, right).is_lt()),
            Self::Gt => Fr::from(compare_balanced(left, right).is_gt()),
            Self::Leq => Fr::from(compare_balanced(left, right).is_le()),
            Self::Geq => Fr::from(compare_balanced(left, right).is_ge()),
            Self::LogicalOr => Fr::from(!left.is_zero() || !right.is_zero()),
            Self::LogicalAnd => Fr::from(!left.is_zero() && !right.is_zero()),
            Self::Neg => -left,
            Self::Inv => left.inverse().ok_or(WitnessError::DivisionByZero(index))?,
            Self::Div => left * right.inverse().ok_or(WitnessError::DivisionByZero(index))?,
            Self::Pow => left.pow(right.into_bigint().0),
            Self::Shl => shift(index, left, right, true)?,
            Self::Shr => shift(index, left, right, false)?,
            Self::BitAnd => bigint_to_field(left.into_bigint() & right.into_bigint()),
            Self::Mod | Self::IntegerDiv => {
                let left = field_to_biguint(left);
                let right = field_to_biguint(right);
                if right == BigUint::from(0_u8) {
                    return Err(WitnessError::DivisionByZero(index));
                }
                let value = if matches!(self, Self::Mod) {
                    left % right
                } else {
                    left / right
                };
                Fr::from_le_bytes_mod_order(&value.to_bytes_le())
            }
        };
        Ok(value)
    }
}

#[derive(Debug, Clone)]
enum Node {
    Input(usize),
    Constant(Fr),
    Operation(Operation, usize, usize),
    Inverse(usize),
}

#[derive(Debug, Clone, Copy)]
struct InputMapping {
    hash: u64,
    signal_id: usize,
    signal_size: usize,
}

/// Parsed, reusable graph for one circuit revision.
pub struct WitnessGraph {
    nodes: Vec<Node>,
    signals: Vec<usize>,
    input_mapping: Vec<InputMapping>,
    input_buffer_len: usize,
    r1cs_sha256: [u8; 32],
}

impl WitnessGraph {
    /// Authenticate and parse an immutable graph artifact.
    pub fn from_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self, WitnessError> {
        if bytes.len() > MAX_GRAPH_BYTES {
            return Err(WitnessError::GraphTooLarge {
                maximum: MAX_GRAPH_BYTES,
            });
        }
        verify_sha256(bytes, expected_sha256)?;
        parse_graph(bytes)
    }

    /// Evaluate JSON circuit signals directly into the arkworks assignment.
    pub fn calculate_json(&self, input_json: &str) -> Result<Vec<Fr>, WitnessError> {
        let inputs = self.parse_inputs(input_json)?;
        let mut values = Vec::with_capacity(self.nodes.len());
        for (index, node) in self.nodes.iter().enumerate() {
            let value = match *node {
                Node::Input(input) => inputs[input],
                Node::Constant(value) => value,
                Node::Operation(operation, left, right) => {
                    operation.evaluate(index, values[left], values[right])?
                }
                Node::Inverse(source) => values[source].inverse().unwrap_or_else(Fr::zero),
            };
            values.push(value);
        }
        let assignment = self
            .signals
            .iter()
            .map(|index| values[*index])
            .collect::<Vec<_>>();
        if assignment.first().copied() != Some(Fr::from(1_u64)) {
            return Err(WitnessError::InvalidAssignmentOne);
        }
        Ok(assignment)
    }

    pub fn assignment_size(&self) -> usize {
        self.signals.len()
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        self.r1cs_sha256
    }

    fn parse_inputs(&self, input_json: &str) -> Result<Vec<Fr>, WitnessError> {
        if input_json.len() > MAX_INPUT_JSON_BYTES {
            return Err(WitnessError::InputTooLarge {
                maximum: MAX_INPUT_JSON_BYTES,
            });
        }
        let value: Value =
            serde_json::from_str(input_json).map_err(WitnessError::InvalidInputJson)?;
        let object = value.as_object().ok_or(WitnessError::InputNotObject)?;
        // Circom graph evaluation leaves omitted input signals at zero.
        let mut inputs = vec![Fr::from(0_u64); self.input_buffer_len];
        inputs[0] = Fr::from(1_u64);
        let mut matched = vec![false; self.input_mapping.len()];

        for (name, value) in object {
            let hash = fnv1a(name);
            let Some((mapping_index, mapping)) = self
                .input_mapping
                .iter()
                .enumerate()
                .find(|(_, mapping)| mapping.hash == hash)
            else {
                return Err(WitnessError::UnknownInput(name.clone()));
            };
            if matched[mapping_index] {
                return Err(WitnessError::InputHashCollision(hash));
            }
            let mut flattened = Vec::with_capacity(mapping.signal_size);
            flatten_input(name, value, mapping.signal_size, &mut flattened)?;
            if flattened.len() != mapping.signal_size {
                return Err(WitnessError::InputLength {
                    name: name.clone(),
                    expected: mapping.signal_size,
                    actual: flattened.len(),
                });
            }
            let end = mapping.signal_id + mapping.signal_size;
            inputs[mapping.signal_id..end].copy_from_slice(&flattened);
            matched[mapping_index] = true;
        }

        Ok(inputs)
    }
}

fn parse_graph(bytes: &[u8]) -> Result<WitnessGraph, WitnessError> {
    let mut reader = Reader::new(bytes);
    if reader.array::<8>()? != *MAGIC {
        return Err(WitnessError::InvalidMagic);
    }
    let version = reader.u16()?;
    if version != FORMAT_VERSION {
        return Err(WitnessError::UnsupportedVersion(version));
    }
    let field = reader.u16()?;
    if field != FIELD_BN254_FR {
        return Err(WitnessError::UnsupportedField(field));
    }
    let header_size = reader.u32()?;
    if header_size != HEADER_SIZE {
        return Err(WitnessError::InvalidHeaderSize(header_size));
    }
    let r1cs_sha256 = reader.array::<32>()?;
    let node_count = checked_count("node", reader.u32()? as usize, MAX_NODES)?;
    let signal_count = checked_count("signal", reader.u32()? as usize, MAX_SIGNALS)?;
    let input_mapping_count =
        checked_count("input mapping", reader.u32()? as usize, MAX_INPUT_MAPPINGS)?;
    let input_buffer_len = checked_count("input value", reader.u32()? as usize, MAX_INPUT_VALUES)?;
    if node_count == 0 || signal_count == 0 || input_buffer_len == 0 {
        return Err(WitnessError::EmptyGraph);
    }

    let mut nodes = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let tag = reader.u8()?;
        let node = match tag {
            0 => {
                let input = reader.u32()? as usize;
                if input >= input_buffer_len {
                    return Err(WitnessError::InputReference {
                        index,
                        input,
                        length: input_buffer_len,
                    });
                }
                Node::Input(input)
            }
            1 => {
                let encoded = reader.array::<32>()?;
                let value = Fr::from_bigint(bigint_from_le_bytes(encoded)?)
                    .ok_or(WitnessError::NonCanonicalConstant(index))?;
                Node::Constant(value)
            }
            2 => {
                let operation = Operation::from_tag(reader.u8()?, index)?;
                let left = reader.u32()? as usize;
                let right = reader.u32()? as usize;
                validate_reference(index, left)?;
                validate_reference(index, right)?;
                Node::Operation(operation, left, right)
            }
            3 => {
                let source = reader.u32()? as usize;
                validate_reference(index, source)?;
                Node::Inverse(source)
            }
            _ => return Err(WitnessError::InvalidNodeTag { index, tag }),
        };
        nodes.push(node);
    }

    let mut signals = Vec::with_capacity(signal_count);
    for index in 0..signal_count {
        let reference = reader.u32()? as usize;
        if reference >= nodes.len() {
            return Err(WitnessError::OutputReference { index, reference });
        }
        signals.push(reference);
    }

    let mut input_mapping = Vec::with_capacity(input_mapping_count);
    let mut hashes = HashSet::with_capacity(input_mapping_count);
    for index in 0..input_mapping_count {
        let hash = reader.u64()?;
        let signal_id = reader.u32()? as usize;
        let signal_size = reader.u32()? as usize;
        if !hashes.insert(hash) {
            return Err(WitnessError::DuplicateInputHash(hash));
        }
        if signal_id == 0
            || signal_size == 0
            || signal_id
                .checked_add(signal_size)
                .is_none_or(|end| end > input_buffer_len)
        {
            return Err(WitnessError::InputMappingRange { index });
        }
        input_mapping.push(InputMapping {
            hash,
            signal_id,
            signal_size,
        });
    }
    if !reader.is_empty() {
        return Err(WitnessError::TrailingBytes);
    }

    Ok(WitnessGraph {
        nodes,
        signals,
        input_mapping,
        input_buffer_len,
        r1cs_sha256,
    })
}

fn checked_count(
    section: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<usize, WitnessError> {
    if actual > maximum {
        return Err(WitnessError::CountLimit {
            section,
            actual,
            maximum,
        });
    }
    Ok(actual)
}

fn validate_reference(index: usize, reference: usize) -> Result<(), WitnessError> {
    if reference >= index {
        return Err(WitnessError::ForwardReference { index, reference });
    }
    Ok(())
}

fn flatten_input(
    name: &str,
    value: &Value,
    limit: usize,
    output: &mut Vec<Fr>,
) -> Result<(), WitnessError> {
    if output.len() >= limit {
        return Err(WitnessError::InputLength {
            name: name.to_owned(),
            expected: limit,
            actual: output.len() + 1,
        });
    }
    match value {
        Value::String(value) => output.push(parse_field(name, value)?),
        Value::Number(value) => output.push(parse_field(name, &value.to_string())?),
        Value::Array(values) => {
            for value in values {
                flatten_input(name, value, limit, output)?;
            }
        }
        _ => {
            return Err(WitnessError::InvalidInputValue {
                name: name.to_owned(),
            });
        }
    }
    Ok(())
}

fn parse_field(name: &str, value: &str) -> Result<Fr, WitnessError> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |digits| (true, digits));
    let integer = BigUint::parse_bytes(digits.as_bytes(), 10).ok_or_else(|| {
        WitnessError::InvalidFieldValue {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    })?;
    let field = Fr::from_be_bytes_mod_order(&integer.to_bytes_be());
    Ok(if negative { -field } else { field })
}

fn compare_balanced(left: Fr, right: Fr) -> Ordering {
    let left_integer = left.into_bigint();
    let right_integer = right.into_bigint();
    let half = Fr::MODULUS >> 1_u32;
    match (left_integer > half, right_integer > half) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => left_integer.cmp(&right_integer),
        (true, true) => (-right).into_bigint().cmp(&(-left).into_bigint()),
    }
}

fn shift(index: usize, left: Fr, right: Fr, is_left: bool) -> Result<Fr, WitnessError> {
    let shift = right.into_bigint();
    if shift.0[1..].iter().any(|limb| *limb != 0) || shift.0[0] >= 256 {
        return Err(WitnessError::InvalidShift(index));
    }
    let shift = shift.0[0] as u32;
    let value = if is_left {
        let mut value = left.into_bigint() << shift;
        // Circom masks left shifts to 254 bits before reducing into BN254 Fr.
        value.0[3] &= (1_u64 << 62) - 1;
        value
    } else {
        left.into_bigint() >> shift
    };
    Ok(bigint_to_field(value))
}

fn bigint_to_field(value: BigInt<4>) -> Fr {
    Fr::from_le_bytes_mod_order(&value.to_bytes_le())
}

fn field_to_biguint(value: Fr) -> BigUint {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le())
}

fn bigint_from_le_bytes(bytes: [u8; 32]) -> Result<BigInt<4>, WitnessError> {
    let mut limbs = [0_u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        let encoded: [u8; 8] = chunk.try_into().map_err(|_| WitnessError::Truncated)?;
        *limb = u64::from_le_bytes(encoded);
    }
    Ok(BigInt(limbs))
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

fn verify_sha256(bytes: &[u8], expected_sha256: &str) -> Result<(), WitnessError> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WitnessError::InvalidExpectedHash);
    }
    let expected = expected_sha256.to_ascii_lowercase();
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(WitnessError::HashMismatch { expected, actual });
    }
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WitnessError> {
        if self.remaining.len() < length {
            return Err(WitnessError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WitnessError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WitnessError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, WitnessError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WitnessError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WitnessError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WitnessError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};

    use super::{FIELD_BN254_FR, FORMAT_VERSION, MAGIC, WitnessError, WitnessGraph, fnv1a};

    fn graph_bytes(operation_reference: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&FIELD_BN254_FR.to_le_bytes());
        bytes.extend_from_slice(&64_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 32]);
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());

        bytes.push(1);
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(0);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&field_bytes(2));
        bytes.push(2);
        bytes.push(2);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&operation_reference.to_le_bytes());

        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&fnv1a("a").to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes
    }

    fn field_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn evaluates_an_authenticated_graph() {
        let bytes = graph_bytes(2);
        let graph = WitnessGraph::from_bytes(&bytes, &digest(&bytes)).expect("graph must parse");
        let assignment = graph
            .calculate_json(r#"{"a":"5"}"#)
            .expect("input must evaluate");
        assert_eq!(assignment[0].into_bigint().0[0], 1);
        assert_eq!(assignment[1].into_bigint().0[0], 7);
    }

    #[test]
    fn authenticates_before_parsing() {
        let error = WitnessGraph::from_bytes(b"not a graph", &"00".repeat(32))
            .err()
            .expect("digest must mismatch");
        assert!(matches!(error, WitnessError::HashMismatch { .. }));
    }

    #[test]
    fn rejects_forward_references_without_panicking() {
        let bytes = graph_bytes(3);
        let error = WitnessGraph::from_bytes(&bytes, &digest(&bytes))
            .err()
            .expect("self-reference must fail");
        assert!(matches!(
            error,
            WitnessError::ForwardReference {
                index: 3,
                reference: 3
            }
        ));
    }

    #[test]
    fn permits_omitted_zero_inputs_and_rejects_unknown_inputs() {
        let bytes = graph_bytes(2);
        let graph = WitnessGraph::from_bytes(&bytes, &digest(&bytes)).expect("graph must parse");
        graph
            .calculate_json("{}")
            .expect("omitted inputs remain zero");
        assert!(matches!(
            graph.calculate_json(r#"{"b":"5"}"#),
            Err(WitnessError::UnknownInput(name)) if name == "b"
        ));
    }
}
