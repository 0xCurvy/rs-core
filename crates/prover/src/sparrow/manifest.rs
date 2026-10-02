//! Authenticated chunk manifests for one-pass proving-key streams.

use std::io::Read;

use ark_bn254::Fr;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::{
    ProofBundle, SECTION_HEADER_BYTES, StreamingConfig, StreamingError, StreamingProofBuilder,
    ZKEY_SECTIONS, hex_digest, invalid, le_u64,
};

// Preserve the original type path for existing streaming callers. Manifest
// construction errors now belong to the shared artifact layer.
pub use crate::artifacts::manifest::ZkeyChunkManifest;
const HASH_BYTES: usize = 32;
#[cfg(feature = "parallel")]
const NATIVE_AUTH_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// A raw zkey stream that authenticates each complete manifest chunk before
/// forwarding it into the parser/prover. This removes the whole-file first pass.
pub struct ManifestProofStream {
    manifest: ZkeyChunkManifest,
    next_chunk: usize,
    received: u64,
    pending: Vec<u8>,
    /// Under `parallel`, a complete chunk that is authenticated but not yet
    /// framed: [`Self::push_complete_chunk`] frames it while it hashes the
    /// next chunk.
    #[cfg(feature = "parallel")]
    authenticated: Option<Vec<u8>>,
    framer: ZkeyFramer,
}

impl ManifestProofStream {
    pub fn new(
        assignment: Vec<Fr>,
        manifest: ZkeyChunkManifest,
        config: StreamingConfig,
    ) -> Result<Self, StreamingError> {
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(manifest.chunk_bytes)
            .map_err(|_| StreamingError::InvalidZkey("cannot allocate manifest chunk".into()))?;
        let builder = StreamingProofBuilder::new_manifest_authenticated(
            assignment,
            manifest.zkey_sha256(),
            config,
        )?
        .with_authenticated_length(manifest.zkey_bytes);
        Ok(Self {
            manifest,
            next_chunk: 0,
            received: 0,
            pending,
            #[cfg(feature = "parallel")]
            authenticated: None,
            framer: ZkeyFramer::new(builder),
        })
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), StreamingError> {
        self.received = self
            .received
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StreamingError::InvalidZkey("zkey byte count overflow".into()))?;
        if self.received > self.manifest.zkey_bytes {
            return invalid("zkey stream exceeds manifest size");
        }
        while !bytes.is_empty() {
            let wanted = self.manifest.chunk_bytes - self.pending.len();
            let take = wanted.min(bytes.len());
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() == self.manifest.chunk_bytes {
                let refill = !bytes.is_empty() || self.received < self.manifest.zkey_bytes;
                self.authenticate_pending(refill)?;
            }
        }
        Ok(())
    }

    /// Consume one complete manifest chunk without copying it into the internal
    /// partial-chunk buffer. Browser adapters use this after coalescing arbitrary
    /// `ReadableStream` pieces to the manifest's authenticated boundaries.
    ///
    /// Under `parallel` the chunk is hashed on the Rayon pool while the
    /// previous chunk, already authenticated by the previous call, is framed
    /// and parsed on the rest of the pool, so SHA-256 leaves the serial path.
    /// No byte is parsed before its chunk is authenticated, and chunks are
    /// parsed in order; the last one is parsed by [`Self::finish`].
    pub fn push_complete_chunk(&mut self, bytes: Vec<u8>) -> Result<(), StreamingError> {
        #[cfg(feature = "parallel")]
        {
            self.check_complete_chunk(&bytes)?;
            let expected = *self
                .manifest
                .chunk_hashes
                .get(self.next_chunk)
                .ok_or_else(|| StreamingError::InvalidZkey("too many zkey chunks".into()))?;
            let previous = self.authenticated.take();
            let framer = &mut self.framer;
            let (actual, framed) = rayon::join(
                || -> [u8; HASH_BYTES] { Sha256::digest(&bytes).into() },
                || {
                    previous
                        .as_deref()
                        .map_or(Ok(()), |chunk| framer.push(chunk))
                },
            );
            framed?;
            if actual != expected {
                return Err(StreamingError::ZkeyChunkHashMismatch {
                    index: self.next_chunk,
                    expected: hex_digest(expected),
                    actual: hex_digest(actual),
                });
            }
            self.next_chunk += 1;
            self.received += bytes.len() as u64;
            self.authenticated = Some(bytes);
            Ok(())
        }
        #[cfg(not(feature = "parallel"))]
        self.push_complete_chunk_ref(&bytes)
    }

    fn check_complete_chunk(&self, bytes: &[u8]) -> Result<(), StreamingError> {
        if !self.pending.is_empty() {
            return invalid("cannot mix partial and complete manifest chunks");
        }
        let remaining = self
            .manifest
            .zkey_bytes
            .checked_sub(self.received)
            .ok_or_else(|| StreamingError::InvalidZkey("zkey byte count overflow".into()))?;
        let expected = remaining.min(self.manifest.chunk_bytes as u64) as usize;
        if expected == 0 || bytes.len() != expected {
            return invalid("complete zkey chunk has the wrong size");
        }
        Ok(())
    }

    #[cfg(not(feature = "parallel"))]
    fn push_complete_chunk_ref(&mut self, bytes: &[u8]) -> Result<(), StreamingError> {
        self.check_complete_chunk(bytes)?;
        self.authenticate_chunk(bytes)?;
        self.received += bytes.len() as u64;
        Ok(())
    }

    /// Parse the chunk [`Self::push_complete_chunk`] authenticated last, so
    /// that later bytes follow it.
    fn frame_authenticated(&mut self) -> Result<(), StreamingError> {
        #[cfg(feature = "parallel")]
        if let Some(chunk) = self.authenticated.take() {
            self.framer.push(&chunk)?;
        }
        Ok(())
    }

    fn push_complete_chunks_ref(&mut self, bytes: &[u8]) -> Result<(), StreamingError> {
        if !self.pending.is_empty() || bytes.is_empty() {
            return invalid("invalid complete zkey chunk batch");
        }
        self.frame_authenticated()?;
        let remaining = self
            .manifest
            .zkey_bytes
            .checked_sub(self.received)
            .ok_or_else(|| StreamingError::InvalidZkey("zkey byte count overflow".into()))?;
        if bytes.len() as u64 > remaining
            || (bytes.len() as u64 != remaining
                && !bytes.len().is_multiple_of(self.manifest.chunk_bytes))
        {
            return invalid("complete zkey chunk batch has the wrong size");
        }
        let chunk_count = bytes.len().div_ceil(self.manifest.chunk_bytes);
        let hash_end = self
            .next_chunk
            .checked_add(chunk_count)
            .ok_or_else(|| StreamingError::InvalidZkey("zkey chunk count overflow".into()))?;
        let expected = self
            .manifest
            .chunk_hashes
            .get(self.next_chunk..hash_end)
            .ok_or_else(|| StreamingError::InvalidZkey("too many zkey chunks".into()))?;
        let verify = |(offset, (chunk, expected)): (usize, (&[u8], &[u8; HASH_BYTES]))| {
            let actual: [u8; HASH_BYTES] = Sha256::digest(chunk).into();
            if &actual == expected {
                Ok(())
            } else {
                Err(StreamingError::ZkeyChunkHashMismatch {
                    index: self.next_chunk + offset,
                    expected: hex_digest(expected),
                    actual: hex_digest(actual),
                })
            }
        };
        #[cfg(feature = "parallel")]
        bytes
            .par_chunks(self.manifest.chunk_bytes)
            .zip(expected.par_iter())
            .enumerate()
            .map(verify)
            .collect::<Result<(), _>>()?;
        #[cfg(not(feature = "parallel"))]
        bytes
            .chunks(self.manifest.chunk_bytes)
            .zip(expected)
            .enumerate()
            .try_for_each(verify)?;

        for chunk in bytes.chunks(self.manifest.chunk_bytes) {
            self.framer.push(chunk)?;
            self.next_chunk += 1;
            self.received += chunk.len() as u64;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<ProofBundle, StreamingError> {
        if self.received != self.manifest.zkey_bytes {
            return Err(StreamingError::UnexpectedEof);
        }
        if !self.pending.is_empty() {
            self.authenticate_pending(false)?;
        }
        if self.next_chunk != self.manifest.chunk_hashes.len() {
            return invalid("zkey chunk count disagrees with manifest size");
        }
        self.frame_authenticated()?;
        let builder = self.framer.finish()?;
        builder.finish()
    }

    fn authenticate_pending(&mut self, refill: bool) -> Result<(), StreamingError> {
        let pending = std::mem::take(&mut self.pending);
        self.authenticate_chunk(&pending)?;
        if refill {
            self.pending
                .try_reserve_exact(self.manifest.chunk_bytes)
                .map_err(|_| {
                    StreamingError::InvalidZkey("cannot allocate manifest chunk".into())
                })?;
        }
        Ok(())
    }

    fn authenticate_chunk(&mut self, bytes: &[u8]) -> Result<(), StreamingError> {
        self.frame_authenticated()?;
        let expected = self
            .manifest
            .chunk_hashes
            .get(self.next_chunk)
            .ok_or_else(|| StreamingError::InvalidZkey("too many zkey chunks".into()))?;
        let actual: [u8; HASH_BYTES] = Sha256::digest(bytes).into();
        if &actual != expected {
            return Err(StreamingError::ZkeyChunkHashMismatch {
                index: self.next_chunk,
                expected: hex_digest(expected),
                actual: hex_digest(actual),
            });
        }
        self.framer.push(bytes)?;
        self.next_chunk += 1;
        Ok(())
    }
}

struct ZkeyFramer {
    builder: Option<StreamingProofBuilder>,
    state: FrameState,
    header: Vec<u8>,
    sections: u32,
}

enum FrameState {
    FileHeader,
    SectionHeader,
    SectionBody(u64),
    Done,
}

impl ZkeyFramer {
    fn new(builder: StreamingProofBuilder) -> Self {
        Self {
            builder: Some(builder),
            state: FrameState::FileHeader,
            header: Vec::with_capacity(SECTION_HEADER_BYTES),
            sections: 0,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), StreamingError> {
        while !bytes.is_empty() {
            match self.state {
                FrameState::FileHeader | FrameState::SectionHeader => {
                    let wanted = SECTION_HEADER_BYTES - self.header.len();
                    let take = wanted.min(bytes.len());
                    self.header.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if self.header.len() != SECTION_HEADER_BYTES {
                        continue;
                    }
                    let header = std::mem::take(&mut self.header);
                    self.header = Vec::with_capacity(SECTION_HEADER_BYTES);
                    match self.state {
                        FrameState::FileHeader => {
                            self.builder_mut()?.begin_zkey(&header)?;
                            self.state = FrameState::SectionHeader;
                        }
                        FrameState::SectionHeader => {
                            let length = le_u64(&header[4..])?;
                            self.builder_mut()?.begin_section(&header)?;
                            if length == 0 {
                                self.end_section()?;
                            } else {
                                self.state = FrameState::SectionBody(length);
                            }
                        }
                        FrameState::SectionBody(_) | FrameState::Done => {
                            return invalid("header completed in an invalid stream state");
                        }
                    }
                }
                FrameState::SectionBody(remaining) => {
                    let take = usize::try_from(remaining.min(bytes.len() as u64))
                        .map_err(|_| StreamingError::InvalidZkey("section size overflow".into()))?;
                    self.builder_mut()?.push_section_chunk(&bytes[..take])?;
                    bytes = &bytes[take..];
                    let remaining = remaining - take as u64;
                    if remaining == 0 {
                        self.end_section()?;
                    } else {
                        self.state = FrameState::SectionBody(remaining);
                    }
                }
                FrameState::Done => return invalid("trailing bytes after zkey sections"),
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<StreamingProofBuilder, StreamingError> {
        if !matches!(self.state, FrameState::Done) || !self.header.is_empty() {
            return invalid("incomplete framed zkey stream");
        }
        self.builder
            .take()
            .ok_or_else(|| StreamingError::InvalidZkey("missing proof builder".into()))
    }

    fn end_section(&mut self) -> Result<(), StreamingError> {
        self.builder_mut()?.end_section()?;
        self.sections += 1;
        self.state = if self.sections == ZKEY_SECTIONS {
            FrameState::Done
        } else {
            FrameState::SectionHeader
        };
        Ok(())
    }

    fn builder_mut(&mut self) -> Result<&mut StreamingProofBuilder, StreamingError> {
        self.builder
            .as_mut()
            .ok_or_else(|| StreamingError::InvalidZkey("missing proof builder".into()))
    }
}

pub fn prove_reader_with_manifest_owned<R: Read>(
    reader: &mut R,
    assignment: Vec<Fr>,
    manifest: ZkeyChunkManifest,
    config: StreamingConfig,
) -> Result<ProofBundle, StreamingError> {
    let chunk_bytes = manifest.chunk_bytes();
    let zkey_bytes = manifest.zkey_bytes();
    let mut stream = ManifestProofStream::new(assignment, manifest, config)?;
    #[cfg(feature = "parallel")]
    let batch_chunks = (NATIVE_AUTH_BATCH_BYTES / chunk_bytes).max(1);
    #[cfg(not(feature = "parallel"))]
    let batch_chunks = 1;
    let batch_bytes = batch_chunks * chunk_bytes;
    let mut bytes = vec![0_u8; batch_bytes];
    let mut received = 0_u64;
    while received != zkey_bytes {
        let count = usize::try_from((zkey_bytes - received).min(batch_bytes as u64))
            .map_err(|_| StreamingError::InvalidZkey("zkey chunk size overflow".into()))?;
        reader
            .read_exact(&mut bytes[..count])
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => StreamingError::UnexpectedEof,
                _ => StreamingError::Io(error),
            })?;
        stream.push_complete_chunks_ref(&bytes[..count])?;
        received += count as u64;
    }
    if reader.read(&mut bytes[..1])? != 0 {
        return invalid("zkey stream exceeds manifest size");
    }
    stream.finish()
}
