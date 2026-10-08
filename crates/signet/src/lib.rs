#![forbid(unsafe_code)]

//! Builds SIGNET witness-graph artifacts from `curvy-signet-builder` output.
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
//! The defaults - [`Envelope::Signet`], [`FormatVersion::V1`] and
//! [`Compression::Zstd`] - are what `curvy-witness` accepts without any feature
//! flag, and therefore what is publishable. [`FormatVersion::V2`] requires the
//! consumer's `signet-v2` feature; emitting it by default would produce artifacts
//! a stock client refuses.

pub mod encode;
pub mod postcard;
pub mod reseal;
pub mod wtns;

use curvy_witness::wire;
use thiserror::Error;

pub use encode::encode;
pub use postcard::{Graph, OperationSchema};
pub use reseal::{reseal, to_raw};

/// Which magic the artifact carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Envelope {
    /// `CVYWIT01`, retained as a supported compatibility envelope.
    Cvywit,
    /// `SIGNET01` - what the pipeline emits. Accepted by a default build.
    #[default]
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
    /// Raw SIGNET bytes.
    None,
    /// A zstd frame around those bytes. Accepted by a default build, and the
    /// digest to pin becomes the digest of the *compressed* file - that is what
    /// the evaluator is handed and therefore what it authenticates.
    #[default]
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
    let mut stdin = child.stdin.take()?;
    // Drain stdout while feeding stdin. Writing the entire artifact first can
    // deadlock once incompressible output fills the child's stdout pipe: zstd
    // blocks on output while the parent blocks on input. Production v1 graphs
    // are large enough to cross that boundary even though smaller fixtures are
    // not.
    let (output, wrote_input) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(bytes));
        let output = child.wait_with_output().ok();
        let wrote_input = writer.join().ok().and_then(Result::ok).is_some();
        (output, wrote_input)
    });
    if !wrote_input {
        return None;
    }
    let output = output?;
    output.status.success().then_some(output.stdout)
}

#[cfg(test)]
mod compression_tests {
    use std::io::Read;
    use std::process::Command;

    use super::compress_with_system_zstd;

    #[test]
    fn system_zstd_drains_large_output_while_writing() {
        if !Command::new("zstd")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }

        // Deterministic, effectively incompressible output well above ordinary
        // pipe capacity. The old write-then-drain implementation deadlocked on
        // this shape and on the 50-note production SIGNET v1 artifact.
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        let mut source = vec![0_u8; 2 * 1024 * 1024];
        for chunk in source.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        let compressed = compress_with_system_zstd(&source, 1).expect("system zstd");
        let mut decoder =
            ruzstd::decoding::StreamingDecoder::new(compressed.as_slice()).expect("zstd frame");
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).expect("decode frame");
        assert_eq!(decoded, source);
    }
}

/// Which body encoding the artifact uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FormatVersion {
    /// Fixed-width references. What is published.
    #[default]
    V1,
    /// Varint backward distances and ZigZag output deltas; roughly 57% smaller.
    /// Needs the consumer's `signet-v2` feature.
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
    #[error("not a SIGNET or CVYWIT artifact, or not a body version this tool understands")]
    NotAnArtifact,
    #[error("could not decompress the artifact: {0}")]
    Decompress(String),
}

/// Decode a 64-character hex digest.
pub fn decode_sha256(value: &str) -> Result<[u8; 32], SignetError> {
    // Check every byte before decoding: a length check alone admits multibyte
    // UTF-8 (slicing would then split a character and panic), and
    // `u8::from_str_radix` would accept a leading `+`.
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SignetError::InvalidR1csDigest);
    }
    let mut decoded = [0_u8; 32];
    for (byte, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *byte = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(decoded)
}

/// One ASCII hex digit. The caller has already rejected anything else.
fn hex_nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => digit - b'A' + 10,
    }
}

/// Render a digest the way the artifact tables and pins spell it.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_sha256_round_trips_either_case() {
        let digest: [u8; 32] = std::array::from_fn(|index| (index * 37 + 5) as u8);
        assert_eq!(decode_sha256(&hex(&digest)).unwrap(), digest);
        assert_eq!(
            decode_sha256(&hex(&digest).to_ascii_uppercase()).unwrap(),
            digest
        );
    }

    #[test]
    fn decode_sha256_rejects_non_hex_without_panicking() {
        // 64 bytes but 33 characters: slicing at byte 2 would split the first `é`.
        let multibyte = format!("a{}a", "é".repeat(31));
        assert_eq!(multibyte.len(), 64);
        // `u8::from_str_radix` accepts a sign, so "+1" alone would decode as 0x01.
        let signed = "+1".repeat(32);
        let short = "0".repeat(63);
        let long = "0".repeat(65);
        let spaced = format!(" {}", "0".repeat(63));
        let letter = format!("g{}", "0".repeat(63));
        for value in [&multibyte, &signed, &short, &long, &spaced, &letter] {
            assert!(
                matches!(decode_sha256(value), Err(SignetError::InvalidR1csDigest)),
                "{value:?} must be rejected"
            );
        }
    }
}
