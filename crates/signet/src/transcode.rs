//! Re-encode an artifact's body in the other body version, from the artifact alone.
//!
//! [`reseal`](crate::reseal()) rewraps a body it copies verbatim. This module
//! decodes the body instead - node records, output references, input table - and
//! writes it again in the requested version. It needs no postcard `graph.bin`, no
//! circom and no circuit tree, so it runs on a file fetched from a release page.
//!
//! What it preserves:
//!
//! - every header byte except the two-byte body version, including the source
//!   R1CS digest and the four counts;
//! - every node, in order, with the same operation tag, constant bytes, input
//!   index and operand nodes;
//! - the output references and the input table, in order.
//!
//! The records are written through `push_record` and `SignalWriter`, the same
//! code [`encode`](crate::encode()) uses. A body transcoded to version 2 is
//! therefore byte-for-byte the body `signet export --version 2` writes from the
//! postcard source; `tests/roundtrip.rs` holds the two to that.
//!
//! What it cannot do is change what a graph computes. An artifact exported with
//! the wrong [`OperationSchema`](crate::OperationSchema) transcodes into an
//! artifact with the same wrong operations.

use curvy_witness::wire;

use crate::encode::{Record, SignalWriter, push_record};
use crate::reseal::describe;
use crate::{FormatVersion, SignetError};

/// Bytes per input-table entry: hash, signal id, signal size.
const INPUT_MAPPING_BYTES: usize = 8 + 4 + 4;

/// Rewrite a raw artifact's body in `target`'s encoding.
///
/// The input must be uncompressed; see [`crate::to_raw`]. The envelope stays as
/// it is. Transcoding to the version the artifact already has returns the input
/// unchanged, which is a property the tests check rather than a shortcut taken
/// here: the body is still decoded and written again.
///
/// This checks structure, not meaning: every reference must point at a prior
/// node, every operation tag must be one the evaluator knows, and nothing may
/// follow the input table. Load the result through `curvy_witness::WitnessGraph`
/// before shipping it, as `signet transcode` does.
pub fn transcode(artifact: &[u8], target: FormatVersion) -> Result<Vec<u8>, SignetError> {
    let described = describe(artifact)?;
    let source = match described.version {
        wire::FORMAT_VERSION_V1 => FormatVersion::V1,
        wire::FORMAT_VERSION_V2 => FormatVersion::V2,
        _ => return Err(SignetError::NotAnArtifact),
    };

    let mut body = Body::new(artifact);
    let header = body.take(wire::HEADER_SIZE as usize)?;
    if read_u32(header, 12) != wire::HEADER_SIZE {
        return Err(malformed("header size is not 64"));
    }
    let node_count = read_u32(header, 48) as usize;
    let signal_count = read_u32(header, 52) as usize;
    let mapping_count = read_u32(header, 56) as usize;
    let input_buffer_len = read_u32(header, 60) as usize;

    // Version 2 is the smaller encoding, so the larger of the two sizes bounds
    // either direction closely enough; this is a capacity hint, not a limit.
    let mut output = Vec::with_capacity(match target {
        FormatVersion::V1 => artifact.len().saturating_mul(3),
        FormatVersion::V2 => artifact.len(),
    });
    output.extend_from_slice(&header[..8]);
    output.extend_from_slice(&target.tag().to_le_bytes());
    output.extend_from_slice(&header[10..]);

    for index in 0..node_count {
        let record = body.record(source, index, input_buffer_len)?;
        push_record(&mut output, target, index, record)?;
    }

    let mut signals = SignalWriter::new(target);
    let mut previous = 0_usize;
    for index in 0..signal_count {
        let reference = body.signal(source, previous, node_count, index)?;
        signals.push(&mut output, reference)?;
        previous = reference;
    }

    let table_bytes = mapping_count
        .checked_mul(INPUT_MAPPING_BYTES)
        .ok_or_else(|| malformed("input table size overflows"))?;
    output.extend_from_slice(body.take(table_bytes)?);

    if !body.is_empty() {
        return Err(malformed("bytes follow the input table"));
    }
    Ok(output)
}

fn malformed(what: impl Into<String>) -> SignetError {
    SignetError::MalformedBody(what.into())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// A forward cursor over a raw artifact.
struct Body<'a> {
    remaining: &'a [u8],
}

impl<'a> Body<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], SignetError> {
        if self.remaining.len() < count {
            return Err(malformed("truncated"));
        }
        let (taken, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(taken)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn u8(&mut self) -> Result<u8, SignetError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SignetError> {
        Ok(read_u32(self.take(4)?, 0))
    }

    fn array32(&mut self) -> Result<[u8; 32], SignetError> {
        let mut value = [0_u8; 32];
        value.copy_from_slice(self.take(32)?);
        Ok(value)
    }

    /// LEB128, held to the evaluator's rules: at most ten bytes, no bits above
    /// 64, and no redundant trailing zero group. A non-canonical varint would
    /// load in neither place, and accepting it here would make a version-2 to
    /// version-1 to version-2 round trip lossy.
    fn var_u64(&mut self) -> Result<u64, SignetError> {
        let mut value = 0_u64;
        for position in 0..10 {
            let byte = self.u8()?;
            let payload = byte & 0x7f;
            if position == 9 && byte & 0xfe != 0 {
                return Err(malformed("varint exceeds 64 bits"));
            }
            value |= u64::from(payload) << (position * 7);
            if byte & 0x80 == 0 {
                if position != 0 && payload == 0 {
                    return Err(malformed("non-canonical varint"));
                }
                return Ok(value);
            }
        }
        Err(malformed("varint exceeds ten bytes"))
    }

    fn record(
        &mut self,
        version: FormatVersion,
        index: usize,
        input_buffer_len: usize,
    ) -> Result<Record, SignetError> {
        let tag = self.u8()?;
        let record = match version {
            FormatVersion::V1 => match tag {
                0 => Record::Input(self.u32()?),
                1 => Record::Constant(self.array32()?),
                2 => Record::Operation {
                    tag: operation(self.u8()?, index)?,
                    left: prior(self.u32()? as usize, index)?,
                    right: prior(self.u32()? as usize, index)?,
                },
                3 => Record::Inverse(prior(self.u32()? as usize, index)?),
                _ => return Err(malformed(format!("node {index}: unknown node tag {tag}"))),
            },
            FormatVersion::V2 => match tag {
                wire::V2_INPUT_TAG => {
                    let input = self.var_u64()?;
                    Record::Input(u32::try_from(input).map_err(|_| {
                        malformed(format!("node {index}: input index exceeds 32 bits"))
                    })?)
                }
                wire::V2_CONSTANT_TAG => Record::Constant(self.array32()?),
                wire::V2_INVERSE_TAG => Record::Inverse(self.distance(index)?),
                0..=0x7f => Record::Operation {
                    tag: operation(tag, index)?,
                    left: self.distance(index)?,
                    right: self.distance(index)?,
                },
                _ => return Err(malformed(format!("node {index}: unknown node tag {tag}"))),
            },
        };
        if let Record::Input(input) = record
            && input as usize >= input_buffer_len
        {
            return Err(malformed(format!(
                "node {index}: input {input} is outside the {input_buffer_len}-value input buffer"
            )));
        }
        Ok(record)
    }

    fn distance(&mut self, index: usize) -> Result<usize, SignetError> {
        let distance = self.var_u64()?;
        usize::try_from(distance)
            .ok()
            .filter(|distance| (1..=index).contains(distance))
            .map(|distance| index - distance)
            .ok_or_else(|| {
                malformed(format!(
                    "node {index}: backward distance {distance} does not reach a prior node"
                ))
            })
    }

    fn signal(
        &mut self,
        version: FormatVersion,
        previous: usize,
        node_count: usize,
        index: usize,
    ) -> Result<usize, SignetError> {
        let reference = match version {
            FormatVersion::V1 => i128::from(self.u32()?),
            FormatVersion::V2 => {
                let encoded = self.var_u64()?;
                let magnitude = i128::from(encoded >> 1);
                let delta = if encoded & 1 == 0 {
                    magnitude
                } else {
                    -magnitude - 1
                };
                previous as i128 + delta
            }
        };
        if reference < 0 || reference >= node_count as i128 {
            return Err(malformed(format!(
                "output {index} does not reference one of the {node_count} nodes"
            )));
        }
        Ok(reference as usize)
    }
}

/// Only operation tags the evaluator knows survive. In version 2 an operation
/// tag shares the first byte with the node kind, so an unknown version-1 tag of
/// `0x80` and up would come back as an input, constant or inverse node.
fn operation(tag: u8, index: usize) -> Result<u8, SignetError> {
    if wire::ALL_OPERATION_TAGS.contains(&tag) {
        Ok(tag)
    } else {
        Err(malformed(format!(
            "node {index}: unknown operation tag {tag}"
        )))
    }
}

/// Version 2 can only express a reference to an earlier node, and the evaluator
/// refuses anything else in version 1 too.
fn prior(reference: usize, index: usize) -> Result<usize, SignetError> {
    if reference < index {
        Ok(reference)
    } else {
        Err(malformed(format!(
            "node {index}: reference {reference} is not a prior node"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-node version-1 graph: the constant one, then input 1.
    fn v1_graph(extra: &[u8], signals: &[u32]) -> Vec<u8> {
        let mut graph = Vec::new();
        graph.extend_from_slice(b"SIGNET01");
        graph.extend_from_slice(&1_u16.to_le_bytes());
        graph.extend_from_slice(&1_u16.to_le_bytes());
        graph.extend_from_slice(&64_u32.to_le_bytes());
        graph.extend_from_slice(&[0x5A; 32]);
        let extra_nodes = u32::from(!extra.is_empty());
        graph.extend_from_slice(&(2 + extra_nodes).to_le_bytes());
        graph.extend_from_slice(&(signals.len() as u32).to_le_bytes());
        graph.extend_from_slice(&0_u32.to_le_bytes());
        graph.extend_from_slice(&2_u32.to_le_bytes());
        graph.push(1);
        let mut one = [0_u8; 32];
        one[0] = 1;
        graph.extend_from_slice(&one);
        graph.push(0);
        graph.extend_from_slice(&1_u32.to_le_bytes());
        graph.extend_from_slice(extra);
        for signal in signals {
            graph.extend_from_slice(&signal.to_le_bytes());
        }
        graph
    }

    #[test]
    fn a_minimal_graph_round_trips_through_both_versions() {
        let mut multiply = vec![2, wire::MUL];
        multiply.extend_from_slice(&1_u32.to_le_bytes());
        multiply.extend_from_slice(&0_u32.to_le_bytes());
        let v1 = v1_graph(&multiply, &[0, 2, 1]);
        let v2 = transcode(&v1, FormatVersion::V2).expect("v1 -> v2");
        assert_eq!(&v2[8..10], &2_u16.to_le_bytes());
        assert_eq!(v2[..8], v1[..8]);
        assert_eq!(v2[10..64], v1[10..64]);
        assert!(v2.len() < v1.len());
        assert_eq!(transcode(&v2, FormatVersion::V1).expect("v2 -> v1"), v1);
        assert_eq!(transcode(&v2, FormatVersion::V2).expect("v2 -> v2"), v2);
        assert_eq!(transcode(&v1, FormatVersion::V1).expect("v1 -> v1"), v1);
    }

    #[test]
    fn references_that_version_2_cannot_express_are_refused() {
        // Node 2 multiplies itself: a self reference, which neither the evaluator
        // nor a backward distance of zero can carry.
        let mut selfish = vec![2, wire::MUL];
        selfish.extend_from_slice(&2_u32.to_le_bytes());
        selfish.extend_from_slice(&0_u32.to_le_bytes());
        let error = transcode(&v1_graph(&selfish, &[0]), FormatVersion::V2)
            .expect_err("a self reference must be refused");
        assert!(error.to_string().contains("not a prior node"), "{error}");

        let mut forward = vec![3];
        forward.extend_from_slice(&7_u32.to_le_bytes());
        assert!(transcode(&v1_graph(&forward, &[0]), FormatVersion::V2).is_err());
    }

    #[test]
    fn unknown_operation_tags_are_refused_rather_than_reinterpreted() {
        for tag in [23_u8, 0x80, 0x81, 0x82, 0xff] {
            let mut node = vec![2, tag];
            node.extend_from_slice(&1_u32.to_le_bytes());
            node.extend_from_slice(&0_u32.to_le_bytes());
            let error = transcode(&v1_graph(&node, &[0]), FormatVersion::V2)
                .expect_err("unknown tag must be refused");
            assert!(
                error.to_string().contains("unknown operation tag"),
                "{error}"
            );
        }
    }

    #[test]
    fn out_of_range_inputs_and_outputs_are_refused() {
        let mut input = vec![0];
        input.extend_from_slice(&2_u32.to_le_bytes());
        assert!(transcode(&v1_graph(&input, &[0]), FormatVersion::V2).is_err());
        assert!(transcode(&v1_graph(&[], &[2]), FormatVersion::V2).is_err());
    }

    #[test]
    fn every_truncation_and_any_trailing_byte_is_refused() {
        let v1 = v1_graph(&[], &[0, 1]);
        let v2 = transcode(&v1, FormatVersion::V2).expect("v1 -> v2");
        for artifact in [&v1, &v2] {
            for length in 0..artifact.len() {
                assert!(
                    transcode(&artifact[..length], FormatVersion::V2).is_err(),
                    "accepted a {length}-byte prefix"
                );
            }
            let mut trailing = artifact.clone();
            trailing.push(0);
            assert!(transcode(&trailing, FormatVersion::V1).is_err());
        }
    }

    #[test]
    fn non_canonical_varints_are_refused() {
        let v2 = transcode(&v1_graph(&[], &[0, 1]), FormatVersion::V2).expect("v1 -> v2");
        // The first output delta is zero, encoded as the single byte 0x00 two
        // bytes from the end; spell it 0x80 0x00 instead.
        let at = v2.len() - 2;
        assert_eq!(v2[at], 0);
        let mut overlong = v2[..at].to_vec();
        overlong.extend_from_slice(&[0x80, 0x00]);
        overlong.extend_from_slice(&v2[at + 1..]);
        let error = transcode(&overlong, FormatVersion::V1).expect_err("overlong varint");
        assert!(error.to_string().contains("non-canonical"), "{error}");
    }
}
