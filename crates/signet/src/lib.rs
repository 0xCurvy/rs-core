//! Builds SIGNET witness-graph artifacts from `circom-witness-rs` output.
//!
//! This is the second half of the graph pipeline. The first half - running
//! `circom`, proving the black-box patch leaves the R1CS byte-identical, and
//! driving upstream's C++ backend - lives with the circuit sources and produces a
//! postcard `graph.bin`. Everything downstream of that file is here:
//!
//! ```text
//! graph.bin  ──encode──►  SIGNET artifact + SHA-256
//!            ──validate─►  assignment parity against a reference witness
//! ```
//!
//! # Why it lives beside the evaluator
//!
//! Operation tags, node tags and header layout come from [`curvy_witness::wire`],
//! the same table the evaluator reads. Producer and consumer therefore cannot
//! drift: a tag renumbered on one side fails this crate's own tests. Keeping the
//! exporter next to the circuits would have made that a coincidence rather than a
//! guarantee.
//!
//! # The one thing that can go silently wrong
//!
//! A postcard graph does not record which upstream built it, and the bitwise patch
//! shifted every operation index from 14 up. Decoding with the wrong
//! [`OperationSchema`] therefore produces a graph that parses and evaluates but
//! computes a different witness. `signet validate` against a reference witness is
//! what catches it - treat export-without-validate as an unfinished job.
//!
//! # Defaults
//!
//! [`Envelope::Cvywit`] and [`FormatVersion::V1`] are the defaults because they are
//! what `curvy-witness` accepts without any feature flag, and therefore the only
//! combination that is publishable today. `SIGNET01` and version 2 both require the
//! consumer's `signet` feature; emitting them by default would produce artifacts a
//! stock client refuses.

pub mod encode;
pub mod postcard;
pub mod wtns;

use curvy_witness::wire;
use thiserror::Error;

pub use encode::encode;
pub use postcard::{Graph, OperationSchema};

/// Which magic the artifact carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Envelope {
    /// `CVYWIT01` - every published artifact, accepted by every build.
    #[default]
    Cvywit,
    /// `SIGNET01` - the successor envelope; needs the consumer's `signet` feature.
    Signet,
}

impl Envelope {
    pub fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Cvywit => b"CVYWIT01",
            Self::Signet => wire::MAGIC,
        }
    }

    pub fn parse(value: &str) -> Result<Self, SignetError> {
        match value {
            "cvywit" => Ok(Self::Cvywit),
            "signet" => Ok(Self::Signet),
            other => Err(SignetError::UnknownEnvelope(other.to_owned())),
        }
    }
}

/// Whether the artifact ships raw or inside a zstd frame.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    /// Raw SIGNET bytes. What every published artifact is today.
    #[default]
    None,
    /// A zstd frame around those bytes. Needs the consumer's `signet` feature,
    /// and the digest to pin becomes the digest of the *compressed* file - that is
    /// what the evaluator is handed and therefore what it authenticates.
    Zstd,
}

impl Compression {
    pub fn parse(value: &str) -> Result<Self, SignetError> {
        match value {
            "none" => Ok(Self::None),
            "zstd" => Ok(Self::Zstd),
            other => Err(SignetError::UnknownCompression(other.to_owned())),
        }
    }
}

/// Default compression level.
///
/// Level 9 keeps the frame window at 4 MiB, half the consumer's 8 MiB cap. Level 19
/// is ~26% smaller again but lands the window on exactly 8 MiB, and shipping on the
/// boundary means a slightly larger graph - or a zstd release that picks a wider
/// window - produces artifacts our own evaluator refuses. Raising that cap is a
/// consumer-side decision, not something a generator flag should force.
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 9;

/// Wrap an encoded artifact in a zstd frame.
///
/// Prefers the system `zstd`, because ruzstd only implements level 1 - and its
/// level 1 is itself ~39% weaker than libzstd's. Compression runs once at build
/// time in a pipeline that already needs `circom`, `git` and a C++ toolchain, so
/// depending on `zstd` there costs nothing. The *decoder* stays pure Rust, which is
/// the constraint that actually matters: it ships to wasm.
///
/// Falls back to ruzstd when the binary is absent, and reports which was used so a
/// noticeably larger artifact is never a mystery.
pub fn compress(bytes: &[u8], level: i32) -> (Vec<u8>, Compressor) {
    match compress_with_system_zstd(bytes, level) {
        Some(compressed) => (compressed, Compressor::SystemZstd),
        None => (
            ruzstd::encoding::compress_to_vec(bytes, ruzstd::encoding::CompressionLevel::Fastest),
            Compressor::Ruzstd,
        ),
    }
}

/// Which compressor produced an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
    SystemZstd,
    /// Level 1 only. Usable, but not what publication-grade artifacts should be.
    Ruzstd,
}

fn compress_with_system_zstd(bytes: &[u8], level: i32) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("zstd")
        .arg(format!("-{level}"))
        .args(["-q", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(bytes).ok()?;
    let output = child.wait_with_output().ok()?;
    output.status.success().then_some(output.stdout)
}

/// Which body encoding the artifact uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FormatVersion {
    /// Fixed-width references. What is published.
    #[default]
    V1,
    /// Varint backward distances and ZigZag output deltas; roughly 57% smaller.
    /// Needs the consumer's `signet` feature.
    V2,
}

impl FormatVersion {
    pub fn tag(self) -> u16 {
        match self {
            Self::V1 => wire::FORMAT_VERSION_V1,
            Self::V2 => wire::FORMAT_VERSION_V2,
        }
    }

    pub fn parse(value: &str) -> Result<Self, SignetError> {
        match value {
            "1" => Ok(Self::V1),
            "2" => Ok(Self::V2),
            other => Err(SignetError::UnknownVersion(other.to_owned())),
        }
    }
}

#[derive(Debug, Error)]
pub enum SignetError {
    #[error("could not decode the upstream postcard graph: {0}")]
    Postcard(::postcard::Error),
    #[error("{what} exceeds the range the artifact format can express")]
    TooLarge { what: &'static str },
    #[error("node {index}: {what} does not point at a prior node")]
    NotAPriorNode { what: &'static str, index: usize },
    #[error(
        "unsupported black-box node {name:?} with {arity} arguments; only the \
         patched `bbf_inv` closure is understood"
    )]
    UnsupportedBlackBox { name: String, arity: usize },
    #[error("unknown envelope {0:?}, expected `cvywit` or `signet`")]
    UnknownEnvelope(String),
    #[error("unknown upstream operation schema {0:?}, expected `original` or `patched`")]
    UnknownSchema(String),
    #[error("unknown format version {0:?}, expected `1` or `2`")]
    UnknownVersion(String),
    #[error("unknown compression {0:?}, expected `none` or `zstd`")]
    UnknownCompression(String),
    #[error("R1CS SHA-256 must be 64 hexadecimal characters")]
    InvalidR1csDigest,
    #[error("invalid reference witness: {0}")]
    InvalidWtns(&'static str),
}

/// Decode a 64-character hex digest.
pub fn decode_sha256(value: &str) -> Result<[u8; 32], SignetError> {
    if value.len() != 64 {
        return Err(SignetError::InvalidR1csDigest);
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| SignetError::InvalidR1csDigest)?;
    }
    Ok(decoded)
}

/// Render a digest the way the artifact tables and pins spell it.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
