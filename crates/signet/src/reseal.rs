//! Re-envelope an existing artifact without rebuilding it from source.
//!
//! Not every shipped graph has its postcard `graph.bin` kept beside it, and
//! rebuilding one means circom, a C++ toolchain and the circuit tree. The body of
//! an artifact does not depend on its envelope: [`encode`](crate::encode()) writes the
//! magic first and nothing after it varies with the envelope, so moving `CVYWIT01`
//! to `SIGNET01` is a splice of the first eight bytes over bytes that are otherwise
//! copied verbatim. `the_envelope_only_changes_the_magic` in `tests/roundtrip.rs`
//! holds the encoder to that, which is what makes this safe rather than plausible.
//!
//! What resealing does not do is change what an artifact *means*. It cannot repair a
//! graph exported under the wrong [`OperationSchema`](crate::OperationSchema), and it
//! cannot re-encode version 1 as version 2. Both of those need the postcard source.

use std::io::{Cursor, Read};

use curvy_witness::wire;

use crate::{Envelope, SignetError};

const LEGACY_MAGIC: &[u8; 8] = b"CVYWIT01";
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Upper bound on a decompressed artifact here, matching
/// `curvy_witness::Limits::batch_prover().graph_bytes`. The pipeline is not a hostile
/// setting, but an unbounded decompress in a tool that runs on files fetched from a
/// release page is a gap worth not having.
const MAXIMUM_ARTIFACT_BYTES: usize = 96 * 1024 * 1024;
const MAXIMUM_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// What an artifact header says about itself, before any body is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactHeader {
    pub envelope: Envelope,
    pub version: u16,
}

/// Read the envelope and body version of a raw artifact.
pub fn describe(artifact: &[u8]) -> Result<ArtifactHeader, SignetError> {
    if artifact.len() < wire::HEADER_SIZE as usize {
        return Err(SignetError::NotAnArtifact);
    }
    let envelope = match &artifact[..8] {
        magic if magic == LEGACY_MAGIC => Envelope::Cvywit,
        magic if magic == wire::MAGIC => Envelope::Signet,
        _ => return Err(SignetError::NotAnArtifact),
    };
    let version = u16::from_le_bytes([artifact[8], artifact[9]]);
    let field = u16::from_le_bytes([artifact[10], artifact[11]]);
    if field != wire::FIELD_BN254_FR {
        return Err(SignetError::NotAnArtifact);
    }
    if version != wire::FORMAT_VERSION_V1 && version != wire::FORMAT_VERSION_V2 {
        return Err(SignetError::NotAnArtifact);
    }
    Ok(ArtifactHeader { envelope, version })
}

/// Rewrite a raw artifact's envelope, leaving every other byte alone.
///
/// The input must already be uncompressed; call [`decompress`] first if it is not.
/// Compressing the result is the caller's decision, because the digest to pin is the
/// digest of whatever is actually written.
pub fn reseal(artifact: &[u8], envelope: Envelope) -> Result<Vec<u8>, SignetError> {
    describe(artifact)?;
    let mut resealed = artifact.to_vec();
    resealed[..8].copy_from_slice(envelope.magic());
    Ok(resealed)
}

/// True when these bytes open a real zstd frame.
///
/// Skippable frames are legitimate zstd but the pipeline never emits one, and the
/// evaluator refuses them, so they are not artifacts as far as this tool is concerned.
pub fn is_zstd(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC
}

/// Unwrap a zstd frame, bounded the way the evaluator bounds one.
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, SignetError> {
    use ruzstd::decoding::StreamingDecoder;

    let mut decoder =
        StreamingDecoder::new_with_max_window_size(Cursor::new(bytes), MAXIMUM_WINDOW_BYTES)
            .map_err(|error| SignetError::Decompress(error.to_string()))?;

    let mut decoded = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = decoder
            .read(&mut chunk)
            .map_err(|error| SignetError::Decompress(error.to_string()))?;
        if count == 0 {
            break;
        }
        if decoded.len() + count > MAXIMUM_ARTIFACT_BYTES {
            return Err(SignetError::Decompress(format!(
                "expands beyond {MAXIMUM_ARTIFACT_BYTES} bytes"
            )));
        }
        decoded.extend_from_slice(&chunk[..count]);
    }
    Ok(decoded)
}

/// Read an artifact from disk in whichever shape it ships, returning raw bytes.
pub fn to_raw(bytes: &[u8]) -> Result<Vec<u8>, SignetError> {
    if is_zstd(bytes) {
        decompress(bytes)
    } else {
        Ok(bytes.to_vec())
    }
}
