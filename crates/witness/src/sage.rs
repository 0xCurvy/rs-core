//! SAGE - the Slot-Allocated Graph Evaluator.
//!
//! **Experimental.** Behind the `sage` feature; the API may change without a major
//! version. The default [`WitnessGraph`](crate::WitnessGraph) is the supported
//! evaluator.
//!
//! # Why it exists
//!
//! [`WitnessGraph`](crate::WitnessGraph) keeps one `Fr` per graph node for the
//! whole evaluation, because any later node may reference any earlier one. Most
//! nodes are dead almost immediately, so that array is mostly waste: pending(50)
//! has 7,442,816 nodes (227 MiB of values) but never needs more than 16,436 of
//! them live at once (0.50 MiB).
//!
//! SAGE compiles the graph once into fixed-width instructions with
//! liveness-allocated value slots, then reuses a slot as soon as its last reader
//! has run. Outputs are copied into the assignment the moment they are produced,
//! so an output does not pin a slot to the end.
//!
//! Hosts that reuse a circuit may serialize those instructions as `SAGEPC01`
//! after the authenticated source graph compiles. This is derived cache state:
//! loading it authenticates the program digest, validates every dimension and
//! index, and requires the embedded source-graph digest to match. Bump
//! [`CACHE_VERSION`] when compiler semantics change without changing that wire
//! layout, so hosts cannot reuse stale derived output.
//!
//! # What it does not change
//!
//! The wire format, the authentication, and the arithmetic are shared with the
//! default evaluator - this module adds a storage strategy, not a second graph
//! format or a second decoder. `read_node_record` is the only wire-format reader
//! in the crate, so the two cannot drift.
//!
//! # The saving is empirical, not a bound
//!
//! Slot count depends on graph topology, and nothing forces it below the node
//! count: a graph whose late instructions read its earliest nodes keeps everything
//! live, and `slots` approaches `node_count`. Constants trade back too - 16 bytes
//! of instruction plus 32 in the constant pool, against 40 in the default
//! `Vec<Node>`.
//!
//! So at the configured maxima the two are comparable (roughly 625 MiB here against
//! roughly 720 MiB for the default evaluator), and the large measured wins come
//! from what real circuits actually look like. **Do not treat this evaluator as
//! justification for raising any limit** - the budget behind [`crate::Limits`]
//! must continue to hold for the default evaluator on its own.
//!
//! # Measured
//!
//! Peak RSS and warm witness time, macOS release build, against the pinned
//! artifacts and their snarkjs reference witnesses:
//!
//! | profile | nodes | live slots | default evaluator | SAGE |
//! |---|---:|---:|---:|---:|
//! | pending(5,30) | 1,106,576 | 4,916 | ~96 MB | ~50 MB |
//! | pending(50,30) | 7,442,816 | 16,436 | ~638 MB | ~332 MB |

use std::io::{BufReader, Cursor, Read};

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};

use crate::{
    Artifact, InputMapping, Limits, NodeRecord, Operation, WitnessError, authenticate,
    build_input_buffer, constant_from_bytes, preflight_body_size, read_header, read_input_mappings,
    read_node_record, read_output_references, reserved_vec, verify_sha256,
};
use crate::{ZSTD_MAGIC, decompress_graph};

// SAGE PreCompiled program, wire revision 1. Cache invalidation for compiler
// semantic changes is deliberately separate in `CACHE_VERSION` below.
const PROGRAM_MAGIC: &[u8; 8] = b"SAGEPC01";
const PROGRAM_VERSION: u32 = 1;
/// Version of the deterministic SAGE compiler output cached by hosts.
///
/// Increment this when a compiler change should invalidate locally derived
/// programs even if `PROGRAM_VERSION` can still decode their wire layout.
pub const CACHE_VERSION: u32 = 1;
const PROGRAM_HEADER_BYTES: usize = 108;
const PROGRAM_INSTRUCTION_BYTES: usize = 16;
const PROGRAM_CONSTANT_BYTES: usize = 32;
const PROGRAM_OUTPUT_BYTES: usize = 8;
const PROGRAM_INPUT_MAPPING_BYTES: usize = 16;

/// One compiled instruction: three `u32` operand slots plus an opcode.
///
/// `left` means different things per kind - an input index, a constant index, or a
/// value slot - which is why [`SageGraph::calculate_json`] dispatches on `kind`
/// before it indexes anything.
#[derive(Debug, Clone, Copy)]
struct Instruction {
    left: u32,
    right: u32,
    destination: u32,
    kind: Kind,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Input,
    Constant,
    Inverse,
    Operation(Operation),
}

/// Copy a produced value into its final assignment position.
#[derive(Debug, Clone, Copy)]
struct OutputWrite {
    node: u32,
    signal: u32,
}

/// A graph compiled for slot-allocated evaluation.
///
/// Construction cost is one extra pass over the wire bytes to compute liveness;
/// after that the graph is immutable and evaluation allocates only the value slots
/// and the assignment.
pub struct SageGraph {
    limits: Limits,
    instructions: Vec<Instruction>,
    constants: Vec<Fr>,
    outputs: Vec<OutputWrite>,
    input_mapping: Vec<InputMapping>,
    input_buffer_len: usize,
    signal_count: usize,
    slots: usize,
    r1cs_sha256: [u8; 32],
    source_graph_sha256: [u8; 32],
}

impl SageGraph {
    /// Authenticate, decode, and compile an immutable graph artifact.
    ///
    /// Accepts exactly the artifacts [`WitnessGraph::from_bytes`](crate::WitnessGraph::from_bytes)
    /// accepts, and enforces the same limits.
    pub fn from_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self, WitnessError> {
        Self::from_bytes_with_limits(bytes, expected_sha256, Limits::default())
    }

    /// Authenticate, decode and compile under explicit ceilings.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        expected_sha256: &str,
        limits: Limits,
    ) -> Result<Self, WitnessError> {
        // Same authentication, same size caps, same compression support as the
        // default evaluator - sharing the helper is what stops the two drifting.
        let source_graph_sha256 = decode_sha256(expected_sha256)?;
        match authenticate(bytes, expected_sha256, &limits)? {
            Artifact::Raw => compile(bytes, limits, source_graph_sha256),
            Artifact::Zstd => compile(
                &decompress_graph(bytes, &limits)?,
                limits,
                source_graph_sha256,
            ),
        }
    }

    /// Load the liveness-allocated instruction program produced by
    /// [`Self::to_compiled_bytes`].
    ///
    /// A locally derived cache records the digest produced immediately after
    /// compiling an authenticated SIGNET graph. The program header must also
    /// bind the expected source-graph digest. Callers that move these bytes to a
    /// different trust domain are responsible for publishing an independent
    /// program digest there.
    pub fn from_compiled_bytes(
        bytes: &[u8],
        expected_program_sha256: &str,
        expected_source_graph_sha256: &str,
    ) -> Result<Self, WitnessError> {
        Self::from_compiled_bytes_with_limits(
            bytes,
            expected_program_sha256,
            expected_source_graph_sha256,
            Limits::default(),
        )
    }

    pub fn from_compiled_bytes_with_limits(
        bytes: &[u8],
        expected_program_sha256: &str,
        expected_source_graph_sha256: &str,
        limits: Limits,
    ) -> Result<Self, WitnessError> {
        if bytes.len() > limits.sage_program_bytes {
            return Err(WitnessError::SageProgramTooLarge {
                maximum: limits.sage_program_bytes,
            });
        }
        verify_sha256(bytes, expected_program_sha256)?;
        if bytes.starts_with(&ZSTD_MAGIC) {
            decode_compressed_program(bytes, expected_source_graph_sha256, limits)
        } else {
            decode_program(
                Cursor::new(bytes),
                Some(bytes.len()),
                expected_source_graph_sha256,
                limits,
            )
        }
    }

    /// Serialize the immutable, already validated SAGE instruction program.
    /// Locally cached bytes use a digest recorded at derivation time and remain
    /// inside the authenticated source graph's trust boundary. Moving the bytes
    /// to a different trust domain requires an independent digest pin.
    pub fn to_compiled_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        encode_program(self)
    }

    pub fn source_graph_sha256(&self) -> [u8; 32] {
        self.source_graph_sha256
    }

    /// Evaluate JSON circuit signals into the arkworks assignment.
    ///
    /// Produces the identical assignment to
    /// [`WitnessGraph::calculate_json`](crate::WitnessGraph::calculate_json).
    pub fn calculate_json(&self, input_json: &str) -> Result<Vec<Fr>, WitnessError> {
        let inputs = build_input_buffer(
            &self.input_mapping,
            self.input_buffer_len,
            input_json,
            &self.limits,
        )?;
        let mut values = reserved_vec("evaluation slots", self.slots)?;
        values.resize(self.slots, Fr::zero());
        let mut assignment = reserved_vec("witness assignment", self.signal_count)?;
        assignment.resize(self.signal_count, Fr::zero());
        let mut output_index = 0_usize;

        for (index, instruction) in self.instructions.iter().copied().enumerate() {
            // Dispatch first: `left` is only a value slot for the last two kinds.
            let value = match instruction.kind {
                Kind::Input => *slot(&inputs, instruction.left, "input")?,
                Kind::Constant => *slot(&self.constants, instruction.left, "constant")?,
                Kind::Inverse => slot(&values, instruction.left, "inverse source")?
                    .inverse()
                    .unwrap_or_else(Fr::zero),
                Kind::Operation(operation) => {
                    let left = *slot(&values, instruction.left, "left source")?;
                    let right = *slot(&values, instruction.right, "right source")?;
                    operation.evaluate(index, left, right)?
                }
            };
            *slot_mut(&mut values, instruction.destination, "destination")? = value;

            // Outputs are sorted by node, so every write for this node is contiguous.
            // Copying `value` rather than re-reading the slot is load-bearing: it is
            // what lets this node's slot be recycled on the very next instruction.
            while let Some(output) = self
                .outputs
                .get(output_index)
                .filter(|output| output.node as usize == index)
            {
                *slot_mut(&mut assignment, output.signal, "output signal")? = value;
                output_index += 1;
            }
        }

        // Every output must have been consumed. Unwritten signals would stay zero
        // and produce a silently wrong witness rather than a failure.
        if output_index != self.outputs.len() {
            return Err(WitnessError::CompiledIndex {
                what: "output write",
            });
        }
        if assignment.first().copied() != Some(Fr::from(1_u64)) {
            return Err(WitnessError::InvalidAssignmentOne);
        }
        Ok(assignment)
    }

    pub fn assignment_size(&self) -> usize {
        self.signal_count
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        self.r1cs_sha256
    }

    /// Live value slots this graph needs. Diagnostic: the ratio against the node
    /// count is the whole point of this evaluator.
    pub fn slot_count(&self) -> usize {
        self.slots
    }
}

fn compile(
    bytes: &[u8],
    limits: Limits,
    source_graph_sha256: [u8; 32],
) -> Result<SageGraph, WitnessError> {
    let (header, mut reader) = read_header(bytes, &limits)?;

    // Pass one: the last instruction that reads each node. A node nobody reads
    // keeps its own index, so its slot is released immediately after it is written.
    // Declared counts are checked against the bytes actually present before any
    // of them drives an allocation.
    preflight_body_size(&header, reader.len())?;
    let mut last_use = reserved_vec("node liveness", header.node_count)?;
    last_use.extend((0..header.node_count).map(|index| index as u32));
    for index in 0..header.node_count {
        let mut mark = |reference: usize| -> Result<(), WitnessError> {
            *at_mut(&mut last_use, reference, "node liveness")? = index as u32;
            Ok(())
        };
        match read_node_record(&mut reader, header.version, index, header.input_buffer_len)? {
            NodeRecord::Operation { left, right, .. } => {
                mark(left)?;
                mark(right)?;
            }
            NodeRecord::Inverse(source) => mark(source)?,
            NodeRecord::Input(_) | NodeRecord::Constant(_) => {}
        }
    }
    let node_section_end = reader.remaining_len();

    let signals = read_output_references(&mut reader, &header)?;
    let input_mapping = read_input_mappings(&mut reader, &header)?;
    if !reader.is_empty() {
        return Err(WitnessError::TrailingBytes);
    }

    let mut outputs = signals
        .iter()
        .enumerate()
        .map(|(signal, node)| {
            Ok(OutputWrite {
                node: index_u32(*node, "output reference")?,
                signal: index_u32(signal, "output signal")?,
            })
        })
        .collect::<Result<Vec<_>, WitnessError>>()?;
    outputs.sort_unstable_by_key(|output| (output.node, output.signal));
    drop(signals);

    // Pass two: assign slots, recycling one as soon as its last reader has run.
    let (_, mut reader) = read_header(bytes, &limits)?;
    let mut instructions = reserved_vec("instructions", header.node_count)?;
    let mut constants = Vec::new();
    let mut node_slots = reserved_vec("node slots", header.node_count)?;
    node_slots.resize(header.node_count, 0_u32);
    let mut free_slots = Vec::<u32>::new();
    // Which node currently owns each slot, so reuse can be checked rather than
    // merely argued. `slot_owner.len()` is the number of slots minted so far.
    let mut slot_owner = Vec::<u32>::new();

    for index in 0..header.node_count {
        let record = read_node_record(&mut reader, header.version, index, header.input_buffer_len)?;
        let (left, right, kind, first_release, second_release) = match record {
            NodeRecord::Operation {
                operation,
                left,
                right,
            } => (
                at(&node_slots, left, "left operand slot")?,
                at(&node_slots, right, "right operand slot")?,
                Kind::Operation(operation),
                Some(left),
                // A node used twice by one instruction must only be released once.
                (left != right).then_some(right),
            ),
            NodeRecord::Input(input) => {
                (index_u32(input, "input index")?, 0, Kind::Input, None, None)
            }
            NodeRecord::Constant(encoded) => {
                let constant_index = index_u32(constants.len(), "constant index")?;
                constants.push(constant_from_bytes(encoded, index)?);
                (constant_index, 0, Kind::Constant, None, None)
            }
            NodeRecord::Inverse(source) => (
                at(&node_slots, source, "inverse operand slot")?,
                0,
                Kind::Inverse,
                Some(source),
                None,
            ),
        };

        // Release operands before choosing a destination, so an instruction may
        // legitimately overwrite one of its own inputs - evaluation reads both
        // operands before it writes.
        for reference in [first_release, second_release].into_iter().flatten() {
            if at(&last_use, reference, "operand liveness")? as usize == index {
                free_slots.push(at(&node_slots, reference, "released slot")?);
            }
        }
        let destination = match free_slots.pop() {
            Some(slot) => {
                // The whole design rests on never handing out a slot whose previous
                // owner can still be read. Check it rather than trust it: this is the
                // one bug class that would yield a wrong witness instead of an error.
                let owner = at(&slot_owner, slot as usize, "recycled slot owner")?;
                if at(&last_use, owner as usize, "recycled slot liveness")? as usize > index {
                    return Err(WitnessError::Invariant(
                        "recycled a slot that is still live",
                    ));
                }
                *at_mut(&mut slot_owner, slot as usize, "recycled slot owner")? = index as u32;
                slot
            }
            None => {
                let slot = index_u32(slot_owner.len(), "slot count")?;
                slot_owner.push(index as u32);
                slot
            }
        };
        *at_mut(&mut node_slots, index, "destination slot")? = destination;
        instructions.push(Instruction {
            left,
            right,
            destination,
            kind,
        });
        if at(&last_use, index, "node liveness")? as usize == index {
            free_slots.push(destination);
        }
    }

    // The two passes must have decoded the node section identically; pass two reads
    // `node_slots` positions that pass one's liveness was computed from.
    if reader.remaining_len() != node_section_end {
        return Err(WitnessError::Invariant(
            "the two decode passes disagreed on the node section",
        ));
    }

    Ok(SageGraph {
        limits,
        instructions,
        constants,
        outputs,
        input_mapping,
        input_buffer_len: header.input_buffer_len,
        signal_count: header.signal_count,
        slots: slot_owner.len(),
        r1cs_sha256: header.r1cs_sha256,
        source_graph_sha256,
    })
}

fn encode_program(graph: &SageGraph) -> Result<Vec<u8>, WitnessError> {
    let instruction_count = index_u32(graph.instructions.len(), "instruction count")?;
    let constant_count = index_u32(graph.constants.len(), "constant count")?;
    let output_count = index_u32(graph.outputs.len(), "output count")?;
    let mapping_count = index_u32(graph.input_mapping.len(), "input mapping count")?;
    let input_buffer_len = index_u32(graph.input_buffer_len, "input buffer length")?;
    let signal_count = index_u32(graph.signal_count, "signal count")?;
    let slots = index_u32(graph.slots, "slot count")?;
    let size = program_size(
        graph.instructions.len(),
        graph.constants.len(),
        graph.outputs.len(),
        graph.input_mapping.len(),
    )?;
    if size > graph.limits.sage_program_bytes {
        return Err(WitnessError::SageProgramTooLarge {
            maximum: graph.limits.sage_program_bytes,
        });
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| WitnessError::AllocationFailed {
            section: "compiled SAGE program",
        })?;
    bytes.extend_from_slice(PROGRAM_MAGIC);
    bytes.extend_from_slice(&PROGRAM_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(PROGRAM_HEADER_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(&graph.source_graph_sha256);
    bytes.extend_from_slice(&graph.r1cs_sha256);
    for value in [
        instruction_count,
        constant_count,
        output_count,
        mapping_count,
        input_buffer_len,
        signal_count,
        slots,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for instruction in &graph.instructions {
        bytes.extend_from_slice(&instruction.left.to_le_bytes());
        bytes.extend_from_slice(&instruction.right.to_le_bytes());
        bytes.extend_from_slice(&instruction.destination.to_le_bytes());
        let (kind, operation) = match instruction.kind {
            Kind::Input => (0, 0),
            Kind::Constant => (1, 0),
            Kind::Inverse => (2, 0),
            Kind::Operation(operation) => (3, operation_tag(operation)),
        };
        bytes.push(kind);
        bytes.push(operation);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
    }
    for constant in &graph.constants {
        let encoded = constant.into_bigint().to_bytes_le();
        if encoded.len() != PROGRAM_CONSTANT_BYTES {
            return Err(WitnessError::Invariant(
                "BN254 scalar serialization changed width",
            ));
        }
        bytes.extend_from_slice(&encoded);
    }
    for output in &graph.outputs {
        bytes.extend_from_slice(&output.node.to_le_bytes());
        bytes.extend_from_slice(&output.signal.to_le_bytes());
    }
    for mapping in &graph.input_mapping {
        bytes.extend_from_slice(&mapping.hash.to_le_bytes());
        bytes.extend_from_slice(&index_u32(mapping.signal_id, "input signal id")?.to_le_bytes());
        bytes
            .extend_from_slice(&index_u32(mapping.signal_size, "input signal size")?.to_le_bytes());
    }
    if bytes.len() != size {
        return Err(WitnessError::Invariant(
            "compiled SAGE size calculation disagreed with encoder",
        ));
    }
    Ok(bytes)
}

fn decode_program<R: Read>(
    source: R,
    declared_size: Option<usize>,
    expected_source_graph_sha256: &str,
    limits: Limits,
) -> Result<SageGraph, WitnessError> {
    let mut reader = ProgramReader::new(source);
    if reader.array::<8>()? != *PROGRAM_MAGIC {
        return Err(WitnessError::InvalidSageProgram("invalid header"));
    }
    if reader.u32()? != PROGRAM_VERSION || reader.u32()? as usize != PROGRAM_HEADER_BYTES {
        return Err(WitnessError::InvalidSageProgram("unsupported version"));
    }
    let source_graph_sha256 = reader.array::<32>()?;
    let expected_source = decode_sha256(expected_source_graph_sha256)?;
    if source_graph_sha256 != expected_source {
        return Err(WitnessError::SageSourceHashMismatch {
            expected: hex(&expected_source),
            actual: hex(&source_graph_sha256),
        });
    }
    let r1cs_sha256 = reader.array::<32>()?;
    let instruction_count = reader.u32()? as usize;
    let constant_count = reader.u32()? as usize;
    let output_count = reader.u32()? as usize;
    let input_mapping_count = reader.u32()? as usize;
    let input_buffer_len = reader.u32()? as usize;
    let signal_count = reader.u32()? as usize;
    let slots = reader.u32()? as usize;

    check_count("instructions", instruction_count, limits.nodes)?;
    check_count("constants", constant_count, limits.nodes)?;
    check_count("outputs", output_count, limits.signals)?;
    check_count("input mappings", input_mapping_count, limits.input_mappings)?;
    check_count("input buffer", input_buffer_len, limits.input_values)?;
    check_count("signals", signal_count, limits.signals)?;
    if instruction_count == 0
        || input_buffer_len == 0
        || signal_count == 0
        || slots == 0
        || slots > instruction_count
        || constant_count > instruction_count
        || output_count != signal_count
    {
        return Err(WitnessError::InvalidSageProgram("invalid dimensions"));
    }
    let expected_size = program_size(
        instruction_count,
        constant_count,
        output_count,
        input_mapping_count,
    )?;
    if expected_size > limits.sage_program_bytes {
        return Err(WitnessError::SageProgramTooLarge {
            maximum: limits.sage_program_bytes,
        });
    }
    if declared_size.is_some_and(|declared| expected_size != declared) {
        return Err(WitnessError::InvalidSageProgram("size mismatch"));
    }

    let mut instructions = reserved_vec("instructions", instruction_count)?;
    let mut defined_slots = reserved_vec("slot definition validation", slots)?;
    defined_slots.resize(slots, false);
    for index in 0..instruction_count {
        let left = reader.u32()?;
        let right = reader.u32()?;
        let destination = reader.u32()?;
        let kind_tag = reader.u8()?;
        let operation_tag = reader.u8()?;
        if reader.u16()? != 0 || destination as usize >= slots {
            return Err(WitnessError::InvalidSageProgram(
                "invalid instruction encoding",
            ));
        }
        let kind = match kind_tag {
            0 if operation_tag == 0 && (left as usize) < input_buffer_len && right == 0 => {
                Kind::Input
            }
            1 if operation_tag == 0 && (left as usize) < constant_count && right == 0 => {
                Kind::Constant
            }
            2 if operation_tag == 0 && (left as usize) < slots && right == 0 => Kind::Inverse,
            3 if (left as usize) < slots && (right as usize) < slots => {
                Kind::Operation(Operation::from_tag(operation_tag, index)?)
            }
            _ => {
                return Err(WitnessError::InvalidSageProgram(
                    "instruction operand is out of bounds",
                ));
            }
        };
        let reads_undefined_slot = match kind {
            Kind::Inverse => !defined_slots[left as usize],
            Kind::Operation(_) => !defined_slots[left as usize] || !defined_slots[right as usize],
            Kind::Input | Kind::Constant => false,
        };
        if reads_undefined_slot {
            return Err(WitnessError::InvalidSageProgram(
                "instruction reads a slot before it is written",
            ));
        }
        // Evaluation reads both operands before writing the destination, so an
        // instruction may legitimately reuse one of its source slots.
        defined_slots[destination as usize] = true;
        instructions.push(Instruction {
            left,
            right,
            destination,
            kind,
        });
    }

    let mut constants = reserved_vec("constants", constant_count)?;
    for index in 0..constant_count {
        constants.push(constant_from_bytes(reader.array::<32>()?, index)?);
    }

    let mut outputs = reserved_vec("outputs", output_count)?;
    let mut seen_signals = reserved_vec("output signal validation", signal_count)?;
    seen_signals.resize(signal_count, false);
    let mut previous = None;
    for _ in 0..output_count {
        let output = OutputWrite {
            node: reader.u32()?,
            signal: reader.u32()?,
        };
        if output.node as usize >= instruction_count
            || output.signal as usize >= signal_count
            || seen_signals[output.signal as usize]
            || previous.is_some_and(|previous| previous > (output.node, output.signal))
        {
            return Err(WitnessError::InvalidSageProgram("invalid output table"));
        }
        seen_signals[output.signal as usize] = true;
        previous = Some((output.node, output.signal));
        outputs.push(output);
    }
    if seen_signals.iter().any(|seen| !seen) {
        return Err(WitnessError::InvalidSageProgram(
            "output table omits a signal",
        ));
    }

    let mut input_mapping = reserved_vec("input mappings", input_mapping_count)?;
    let mut hashes = std::collections::HashSet::new();
    hashes
        .try_reserve(input_mapping_count)
        .map_err(|_| WitnessError::AllocationFailed {
            section: "input mapping hashes",
        })?;
    for index in 0..input_mapping_count {
        let mapping = InputMapping {
            hash: reader.u64()?,
            signal_id: reader.u32()? as usize,
            signal_size: reader.u32()? as usize,
        };
        if !hashes.insert(mapping.hash) {
            return Err(WitnessError::DuplicateInputHash(mapping.hash));
        }
        if mapping.signal_id == 0
            || mapping.signal_size == 0
            || mapping
                .signal_id
                .checked_add(mapping.signal_size)
                .is_none_or(|end| end > input_buffer_len)
        {
            return Err(WitnessError::InputMappingRange { index });
        }
        input_mapping.push(mapping);
    }
    if !reader.is_empty()? {
        return Err(WitnessError::InvalidSageProgram("trailing bytes"));
    }

    Ok(SageGraph {
        limits,
        instructions,
        constants,
        outputs,
        input_mapping,
        input_buffer_len,
        signal_count,
        slots,
        r1cs_sha256,
        source_graph_sha256,
    })
}

fn decode_compressed_program(
    bytes: &[u8],
    expected_source_graph_sha256: &str,
    limits: Limits,
) -> Result<SageGraph, WitnessError> {
    use ruzstd::decoding::StreamingDecoder;
    use ruzstd::decoding::errors::FrameDecoderError;

    let source = Cursor::new(bytes);
    let mut decoder = StreamingDecoder::new_with_max_window_size(source, limits.zstd_window_bytes)
        .map_err(|error| match error {
            FrameDecoderError::WindowSizeTooBig { requested, .. } => {
                WitnessError::ZstdWindowTooLarge {
                    requested,
                    maximum: limits.zstd_window_bytes,
                }
            }
            FrameDecoderError::DictNotProvided { .. } => WitnessError::ZstdDictionaryUnsupported,
            _ => WitnessError::InvalidZstd,
        })?;
    let content_size = usize::try_from(decoder.decoder.content_size()).map_err(|_| {
        WitnessError::ZstdOutputTooLarge {
            maximum: limits.sage_program_bytes,
        }
    })?;
    if content_size > limits.sage_program_bytes {
        return Err(WitnessError::ZstdOutputTooLarge {
            maximum: limits.sage_program_bytes,
        });
    }
    let declared_size = (content_size != 0).then_some(content_size);
    let graph = {
        let buffered = BufReader::with_capacity(1024 * 1024, &mut decoder);
        decode_program(
            buffered,
            declared_size,
            expected_source_graph_sha256,
            limits,
        )?
    };
    if let Some(expected) = decoder.decoder.get_checksum_from_data()
        && decoder.decoder.get_calculated_checksum() != Some(expected)
    {
        return Err(WitnessError::ZstdChecksumMismatch);
    }
    let (source, _) = decoder.into_parts();
    if source.position() != bytes.len() as u64 {
        return Err(WitnessError::ZstdTrailingData);
    }
    Ok(graph)
}

fn program_size(
    instructions: usize,
    constants: usize,
    outputs: usize,
    mappings: usize,
) -> Result<usize, WitnessError> {
    PROGRAM_HEADER_BYTES
        .checked_add(
            instructions
                .checked_mul(PROGRAM_INSTRUCTION_BYTES)
                .ok_or(WitnessError::InvalidSageProgram("size overflow"))?,
        )
        .and_then(|size| size.checked_add(constants.checked_mul(PROGRAM_CONSTANT_BYTES)?))
        .and_then(|size| size.checked_add(outputs.checked_mul(PROGRAM_OUTPUT_BYTES)?))
        .and_then(|size| size.checked_add(mappings.checked_mul(PROGRAM_INPUT_MAPPING_BYTES)?))
        .ok_or(WitnessError::InvalidSageProgram("size overflow"))
}

fn check_count(section: &'static str, actual: usize, maximum: usize) -> Result<(), WitnessError> {
    if actual > maximum {
        return Err(WitnessError::CountLimit {
            section,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn operation_tag(operation: Operation) -> u8 {
    match operation {
        Operation::Mul => crate::wire::MUL,
        Operation::MontgomeryMul => crate::wire::MONTGOMERY_MUL,
        Operation::Add => crate::wire::ADD,
        Operation::Sub => crate::wire::SUB,
        Operation::Eq => crate::wire::EQ,
        Operation::Neq => crate::wire::NEQ,
        Operation::Lt => crate::wire::LT,
        Operation::Gt => crate::wire::GT,
        Operation::Leq => crate::wire::LEQ,
        Operation::Geq => crate::wire::GEQ,
        Operation::LogicalOr => crate::wire::LOGICAL_OR,
        Operation::Shl => crate::wire::SHL,
        Operation::Shr => crate::wire::SHR,
        Operation::BitAnd => crate::wire::BIT_AND,
        Operation::Neg => crate::wire::NEG,
        Operation::Inv => crate::wire::INV,
        Operation::Div => crate::wire::DIV,
        Operation::Mod => crate::wire::MOD,
        Operation::Pow => crate::wire::POW,
        Operation::LogicalAnd => crate::wire::LOGICAL_AND,
        Operation::IntegerDiv => crate::wire::INTEGER_DIV,
        Operation::BitXor => crate::wire::BIT_XOR,
        Operation::BitOr => crate::wire::BIT_OR,
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], WitnessError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WitnessError::InvalidExpectedHash);
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WitnessError::InvalidExpectedHash)?;
    }
    Ok(decoded)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct ProgramReader<R> {
    source: R,
}

impl<R: Read> ProgramReader<R> {
    fn new(source: R) -> Self {
        Self { source }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WitnessError> {
        let mut bytes = [0_u8; N];
        self.source
            .read_exact(&mut bytes)
            .map_err(|_| WitnessError::InvalidSageProgram("truncated"))?;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, WitnessError> {
        Ok(self.array::<1>()?[0])
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

    fn is_empty(&mut self) -> Result<bool, WitnessError> {
        let mut byte = [0_u8; 1];
        self.source
            .read(&mut byte)
            .map(|count| count == 0)
            .map_err(|_| WitnessError::InvalidSageProgram("could not finish decoding"))
    }
}

fn index_u32(value: usize, what: &'static str) -> Result<u32, WitnessError> {
    u32::try_from(value).map_err(|_| WitnessError::CompiledIndex { what })
}

/// Compile-time bounds check. Every reference the decoder returns is already known
/// to be prior and in range, so these never fire - going through them anyway means
/// panic-freedom is a property of this function rather than of an argument that
/// spans two others.
fn at<T: Copy>(values: &[T], index: usize, what: &'static str) -> Result<T, WitnessError> {
    values
        .get(index)
        .copied()
        .ok_or(WitnessError::CompiledIndex { what })
}

fn at_mut<'a, T>(
    values: &'a mut [T],
    index: usize,
    what: &'static str,
) -> Result<&'a mut T, WitnessError> {
    values
        .get_mut(index)
        .ok_or(WitnessError::CompiledIndex { what })
}

fn slot<'a, T>(values: &'a [T], index: u32, what: &'static str) -> Result<&'a T, WitnessError> {
    values
        .get(index as usize)
        .ok_or(WitnessError::CompiledIndex { what })
}

fn slot_mut<'a, T>(
    values: &'a mut [T],
    index: u32,
    what: &'static str,
) -> Result<&'a mut T, WitnessError> {
    values
        .get_mut(index as usize)
        .ok_or(WitnessError::CompiledIndex { what })
}

#[cfg(test)]
mod differential;

#[cfg(test)]
mod tests {
    use super::{CACHE_VERSION, SageGraph};
    use crate::WitnessGraph;
    use ark_ff::PrimeField;
    use ruzstd::encoding::{CompressionLevel, compress_to_vec};
    use sha2::{Digest, Sha256};

    /// `a * a + 1`, written so nodes die at different points and slots get recycled.
    fn graph_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(crate::LEGACY_MAGIC);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&crate::FIELD_BN254_FR.to_le_bytes());
        bytes.extend_from_slice(&64_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 32]);
        bytes.extend_from_slice(&5_u32.to_le_bytes()); // nodes
        bytes.extend_from_slice(&2_u32.to_le_bytes()); // signals
        bytes.extend_from_slice(&1_u32.to_le_bytes()); // input mappings
        bytes.extend_from_slice(&2_u32.to_le_bytes()); // input buffer

        bytes.push(1); // node 0: constant one
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(0); // node 1: input a
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(2); // node 2: a * a
        bytes.push(0);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1); // node 3: constant one
        bytes.extend_from_slice(&field_bytes(1));
        bytes.push(2); // node 4: (a * a) + 1
        bytes.push(2);
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());

        bytes.extend_from_slice(&0_u32.to_le_bytes()); // signal 0 -> node 0
        bytes.extend_from_slice(&4_u32.to_le_bytes()); // signal 1 -> node 4

        bytes.extend_from_slice(&crate::fnv1a("a").to_le_bytes());
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

    /// The contract that matters: same artifact, same input, same assignment.
    #[test]
    fn reproduces_the_default_evaluator() {
        let bytes = graph_bytes();
        let sha = digest(&bytes);
        let input = r#"{"a":"5"}"#;

        let reference = WitnessGraph::from_bytes(&bytes, &sha)
            .expect("default graph")
            .calculate_json(input)
            .expect("default assignment");
        let candidate = SageGraph::from_bytes(&bytes, &sha)
            .expect("SAGE graph")
            .calculate_json(input)
            .expect("SAGE assignment");

        assert_eq!(candidate, reference);
        assert_eq!(candidate[1].into_bigint().0[0], 26);
    }

    /// Five nodes, but never five live at once.
    #[test]
    fn recycles_slots_below_the_node_count() {
        let bytes = graph_bytes();
        let graph = SageGraph::from_bytes(&bytes, &digest(&bytes)).expect("SAGE graph");
        assert!(
            graph.slot_count() < graph.instructions.len(),
            "expected slot reuse, got {} slots for {} nodes",
            graph.slot_count(),
            graph.instructions.len()
        );
    }

    #[test]
    fn rejects_an_unauthenticated_artifact_before_compiling() {
        let error = SageGraph::from_bytes(b"not a graph", &"00".repeat(32))
            .err()
            .expect("hash must mismatch");
        assert!(matches!(error, crate::WitnessError::HashMismatch { .. }));
    }

    #[test]
    fn authenticated_precompiled_program_skips_graph_compilation() {
        let bytes = graph_bytes();
        let graph_sha = digest(&bytes);
        let graph = SageGraph::from_bytes(&bytes, &graph_sha).expect("compile graph");
        let program = graph.to_compiled_bytes().expect("serialize program");
        assert_eq!(&program[..8], b"SAGEPC01");
        assert_eq!(CACHE_VERSION, 1);
        let program_sha = digest(&program);
        let loaded = SageGraph::from_compiled_bytes(&program, &program_sha, &graph_sha)
            .expect("load precompiled program");

        assert_eq!(loaded.source_graph_sha256(), graph.source_graph_sha256());
        assert_eq!(loaded.r1cs_sha256(), graph.r1cs_sha256());
        assert_eq!(loaded.slot_count(), graph.slot_count());
        assert_eq!(
            loaded.calculate_json(r#"{"a":"5"}"#).expect("evaluate"),
            graph.calculate_json(r#"{"a":"5"}"#).expect("evaluate")
        );

        let error = SageGraph::from_compiled_bytes(&program, &program_sha, &"00".repeat(32))
            .err()
            .expect("source pin must be checked");
        assert!(matches!(
            error,
            crate::WitnessError::SageSourceHashMismatch { .. }
        ));

        let compressed = compress_to_vec(program.as_slice(), CompressionLevel::Fastest);
        let compressed_sha = digest(&compressed);
        let compressed_loaded =
            SageGraph::from_compiled_bytes(&compressed, &compressed_sha, &graph_sha)
                .expect("load compressed precompiled program");
        assert_eq!(
            compressed_loaded
                .calculate_json(r#"{"a":"5"}"#)
                .expect("evaluate compressed program"),
            graph.calculate_json(r#"{"a":"5"}"#).expect("evaluate")
        );

        let mut corrupted = compressed;
        *corrupted
            .last_mut()
            .expect("compressed program is non-empty") ^= 1;
        let error = SageGraph::from_compiled_bytes(&corrupted, &compressed_sha, &graph_sha)
            .err()
            .expect("compressed program must authenticate before decoding");
        assert!(matches!(error, crate::WitnessError::HashMismatch { .. }));
    }

    #[test]
    fn compiled_program_rejects_an_empty_input_buffer() {
        let bytes = graph_bytes();
        let graph_sha = digest(&bytes);
        let graph = SageGraph::from_bytes(&bytes, &graph_sha).expect("compile graph");
        let mut program = graph.to_compiled_bytes().expect("serialize program");
        // Header layout: magic (8), version (4), header size (4), source hash
        // (32), R1CS hash (32), four preceding counts (16), then input buffer.
        program[96..100].copy_from_slice(&0_u32.to_le_bytes());
        let program_sha = digest(&program);

        let error = SageGraph::from_compiled_bytes(&program, &program_sha, &graph_sha)
            .err()
            .expect("an empty input buffer must fail during decode");
        assert!(matches!(
            error,
            crate::WitnessError::InvalidSageProgram("invalid dimensions")
        ));
    }

    #[test]
    fn compiled_program_rejects_a_slot_read_before_its_first_write() {
        let bytes = graph_bytes();
        let graph_sha = digest(&bytes);
        let graph = SageGraph::from_bytes(&bytes, &graph_sha).expect("compile graph");
        let mut program = graph.to_compiled_bytes().expect("serialize program");
        // Turn the first instruction into `inverse(slot 0)`. The operand is in
        // bounds but slot 0 has not been initialized by any earlier instruction.
        let first_instruction = super::PROGRAM_HEADER_BYTES;
        program[first_instruction..first_instruction + 4].copy_from_slice(&0_u32.to_le_bytes());
        program[first_instruction + 4..first_instruction + 8].copy_from_slice(&0_u32.to_le_bytes());
        program[first_instruction + 12] = 2;
        program[first_instruction + 13] = 0;
        let program_sha = digest(&program);

        let error = SageGraph::from_compiled_bytes(&program, &program_sha, &graph_sha)
            .err()
            .expect("read-before-write must fail during decode");
        assert!(matches!(
            error,
            crate::WitnessError::InvalidSageProgram(
                "instruction reads a slot before it is written"
            )
        ));
    }
}
