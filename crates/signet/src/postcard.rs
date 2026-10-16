//! The upstream graph representation, as it exists on disk.
//!
//! `circom-witness-rs` serialises its optimised graph as a postcard-encoded
//! `(Vec<Node>, Vec<usize>, Vec<HashSignalInfo>)` tuple. These declarations are
//! reproduced from that project (MIT), via Curvy's fork at
//! <https://github.com/0xCurvy/circom-witness-rs>, because they *are* the input format
//! - they are not a second implementation of anything.
//!
//! Only the parts needed to read a graph are here. The upstream evaluator is not:
//! validation goes through `curvy-witness`, which is the implementation we ship.
//!
//! # Why variant order is load-bearing
//!
//! postcard encodes an enum variant as its *declaration index*. Reordering
//! [`Operation`] here - or letting it drift from the patched upstream enum -
//! silently remaps every operation in every graph rather than failing. The order
//! below is asserted against the shipped tag table in [`mod@crate::encode`]'s tests,
//! and `Bor`/`Bxor` sit between `Band` and `Neg` because that is where the patch
//! inserts them.

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use ruint::aliases::U256;
use serde::Deserialize;

use crate::SignetError;

/// Which upstream revision produced a postcard graph.
///
/// postcard encodes an enum variant as its *declaration index*, and the patch that
/// adds circom's bitwise operators inserts `Bor`/`Bxor` between `Band` and `Neg`.
/// Every index from 14 up therefore means something different depending on which
/// upstream built the file - and the file does not say which.
///
/// Choosing wrong does not fail: it silently remaps operations. `Neg` becomes
/// `Bor`, `Inv` becomes `Bxor`, and so on, producing a graph that parses, loads,
/// and computes the wrong witness. `signet validate` against a reference witness is
/// the only thing that catches it. Always validate before pinning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OperationSchema {
    /// Unpatched upstream: 21 operations, `Neg` at 14.
    Original,
    /// Patched: 23 operations, `Bor` and `Bxor` at 14 and 15. What the current
    /// pipeline produces.
    #[default]
    Patched,
}

impl OperationSchema {
    pub fn parse(value: &str) -> Result<Self, SignetError> {
        match value {
            "original" => Ok(Self::Original),
            "patched" => Ok(Self::Patched),
            other => Err(SignetError::UnknownSchema(other.to_owned())),
        }
    }
}

/// The canonical operation set this crate encodes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Mul,
    MMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
    Shl,
    Shr,
    Band,
    Bor,
    Bxor,
    Neg,
    Inv,
    Div,
    Mod,
    Pow,
    Land,
    IDiv,
}

/// Every operation, so a drift check can enumerate them.
pub const ALL_OPERATIONS: [Operation; 23] = [
    Operation::Mul,
    Operation::MMul,
    Operation::Add,
    Operation::Sub,
    Operation::Eq,
    Operation::Neq,
    Operation::Lt,
    Operation::Gt,
    Operation::Leq,
    Operation::Geq,
    Operation::Lor,
    Operation::Shl,
    Operation::Shr,
    Operation::Band,
    Operation::Bor,
    Operation::Bxor,
    Operation::Neg,
    Operation::Inv,
    Operation::Div,
    Operation::Mod,
    Operation::Pow,
    Operation::Land,
    Operation::IDiv,
];

/// Unpatched upstream, in its declaration order. Do not reorder.
#[derive(Debug, Clone, Copy, Deserialize)]
enum OriginalOperation {
    Mul,
    MMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
    Shl,
    Shr,
    Band,
    Neg,
    Inv,
    Div,
    Mod,
    Pow,
    Land,
    IDiv,
}

/// Patched upstream, in its declaration order. Do not reorder.
#[derive(Debug, Clone, Copy, Deserialize)]
enum PatchedOperation {
    Mul,
    MMul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
    Shl,
    Shr,
    Band,
    Bor,
    Bxor,
    Neg,
    Inv,
    Div,
    Mod,
    Pow,
    Land,
    IDiv,
}

impl From<OriginalOperation> for Operation {
    fn from(value: OriginalOperation) -> Self {
        use OriginalOperation as O;
        match value {
            O::Mul => Self::Mul,
            O::MMul => Self::MMul,
            O::Add => Self::Add,
            O::Sub => Self::Sub,
            O::Eq => Self::Eq,
            O::Neq => Self::Neq,
            O::Lt => Self::Lt,
            O::Gt => Self::Gt,
            O::Leq => Self::Leq,
            O::Geq => Self::Geq,
            O::Lor => Self::Lor,
            O::Shl => Self::Shl,
            O::Shr => Self::Shr,
            O::Band => Self::Band,
            O::Neg => Self::Neg,
            O::Inv => Self::Inv,
            O::Div => Self::Div,
            O::Mod => Self::Mod,
            O::Pow => Self::Pow,
            O::Land => Self::Land,
            O::IDiv => Self::IDiv,
        }
    }
}

impl From<PatchedOperation> for Operation {
    fn from(value: PatchedOperation) -> Self {
        use PatchedOperation as P;
        match value {
            P::Mul => Self::Mul,
            P::MMul => Self::MMul,
            P::Add => Self::Add,
            P::Sub => Self::Sub,
            P::Eq => Self::Eq,
            P::Neq => Self::Neq,
            P::Lt => Self::Lt,
            P::Gt => Self::Gt,
            P::Leq => Self::Leq,
            P::Geq => Self::Geq,
            P::Lor => Self::Lor,
            P::Shl => Self::Shl,
            P::Shr => Self::Shr,
            P::Band => Self::Band,
            P::Bor => Self::Bor,
            P::Bxor => Self::Bxor,
            P::Neg => Self::Neg,
            P::Inv => Self::Inv,
            P::Div => Self::Div,
            P::Mod => Self::Mod,
            P::Pow => Self::Pow,
            P::Land => Self::Land,
            P::IDiv => Self::IDiv,
        }
    }
}

fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    A::deserialize_with_mode(bytes.as_slice(), Compress::Yes, Validate::Yes)
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
pub enum WireNode<Op> {
    Input(usize),
    Constant(U256),
    #[serde(deserialize_with = "ark_de")]
    MontConstant(Fr),
    Op(Op, usize, usize),
    /// Black-box function: a name and its argument node indices. The only one the
    /// exporter accepts is `bbf_inv`, the inverse-or-zero that graphs built from an
    /// `IsZero`-patched circomlib carry.
    Bbf(String, Vec<usize>),
}

/// One node, normalised to the canonical operation set.
#[derive(Debug, Clone)]
pub enum Node {
    Input(usize),
    Constant(U256),
    MontConstant(Fr),
    Op(Operation, usize, usize),
    Bbf(String, Vec<usize>),
}

impl<Op: Into<Operation>> From<WireNode<Op>> for Node {
    fn from(value: WireNode<Op>) -> Self {
        match value {
            WireNode::Input(index) => Self::Input(index),
            WireNode::Constant(value) => Self::Constant(value),
            WireNode::MontConstant(value) => Self::MontConstant(value),
            WireNode::Op(operation, left, right) => Self::Op(operation.into(), left, right),
            WireNode::Bbf(name, parameters) => Self::Bbf(name, parameters),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct InputMapping {
    pub hash: u64,
    pub signal_id: u64,
    pub signal_size: u64,
}

/// One decoded upstream graph.
#[derive(Debug, Clone)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<InputMapping>,
}

impl Graph {
    /// Decode a `graph.bin` produced by upstream's `build_graph`.
    ///
    /// `schema` must match the upstream revision that wrote the file; see
    /// [`OperationSchema`] for why getting it wrong is silent.
    pub fn from_postcard(bytes: &[u8], schema: OperationSchema) -> Result<Self, SignetError> {
        match schema {
            OperationSchema::Original => Self::decode::<OriginalOperation>(bytes),
            OperationSchema::Patched => Self::decode::<PatchedOperation>(bytes),
        }
    }

    fn decode<Op>(bytes: &[u8]) -> Result<Self, SignetError>
    where
        Op: Into<Operation>,
        for<'a> Op: Deserialize<'a>,
    {
        let (nodes, signals, input_mapping): (Vec<WireNode<Op>>, Vec<usize>, Vec<InputMapping>) =
            postcard::from_bytes(bytes).map_err(SignetError::Postcard)?;
        Ok(Self {
            nodes: nodes.into_iter().map(Node::from).collect(),
            signals,
            input_mapping,
        })
    }

    /// Size of the input buffer the graph expects: one past the last signal any
    /// named input covers or any input node reads.
    ///
    /// The input table decides it, since callers write through it and the evaluator
    /// refuses a mapping that runs past the buffer. Optimization drops input nodes
    /// nothing reads, so a graph whose last inputs are unused has no node for them,
    /// and input nodes need not come first. The zero-hash placeholder `encode` drops
    /// does not count.
    pub fn input_buffer_len(&self) -> usize {
        let named = self
            .input_mapping
            .iter()
            .filter(|mapping| mapping.hash != 0)
            .map(|mapping| {
                usize::try_from(mapping.signal_id.saturating_add(mapping.signal_size))
                    .unwrap_or(usize::MAX)
            });
        let read = self.nodes.iter().filter_map(|node| match node {
            Node::Input(index) => Some(index.saturating_add(1)),
            _ => None,
        });
        named.chain(read).max().unwrap_or(1).max(1)
    }
}
