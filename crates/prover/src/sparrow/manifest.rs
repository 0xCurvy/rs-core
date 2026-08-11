//! Authenticated chunk manifests for one-pass proving-key streams.

use std::io::Read;

use ark_bn254::Fr;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::{
    ProofBundle, SECTION_HEADER_BYTES, SparrowConfig, SparrowError, SparrowProofBuilder,
    ZKEY_SECTIONS, hex_digest, invalid, le_u32, le_u64, normalize_hash,
};

const MAGIC: &[u8; 8] = b"CVYZKM01";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 60;
const HASH_BYTES: usize = 32;
const MIN_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
#[cfg(feature = "parallel")]
const NATIVE_AUTH_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// A compact, independently pinned list of SHA-256 hashes over consecutive zkey
/// chunks. Its encoded size is 60 bytes plus 32 bytes per chunk, so hosts can
/// authenticate it in full before any zkey bytes are interpreted.
#[derive(Clone)]
pub struct ZkeyChunkManifest {
    chunk_bytes: usize,
    zkey_bytes: u64,
    zkey_sha256: String,
    chunk_hashes: Vec<[u8; HASH_BYTES]>,
}

impl ZkeyChunkManifest {
    pub fn from_bytes(
        bytes: &[u8],
        expected_manifest_sha256: &str,
        expected_zkey_sha256: &str,
    ) -> Result<Self, SparrowError> {
        let expected_manifest = normalize_hash(expected_manifest_sha256)?;
        let actual_manifest = hex_digest(Sha256::digest(bytes));
        if actual_manifest != expected_manifest {
            return Err(SparrowError::ManifestHashMismatch {
                expected: expected_manifest,
                actual: actual_manifest,
            });
        }
        if bytes.len() < HEADER_BYTES || &bytes[..8] != MAGIC {
            return invalid("invalid zkey chunk manifest header");
        }
        if le_u32(&bytes[8..12])? != VERSION {
            return invalid("unsupported zkey chunk manifest version");
        }
        let chunk_bytes = le_u32(&bytes[12..16])? as usize;
        if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
            || !chunk_bytes.is_power_of_two()
        {
            return invalid("invalid zkey manifest chunk size");
        }
        let zkey_bytes = le_u64(&bytes[16..24])?;
        let encoded_zkey_hash: [u8; HASH_BYTES] = bytes[24..56]
            .try_into()
            .map_err(|_| SparrowError::InvalidZkey("truncated manifest zkey hash".into()))?;
        let zkey_sha256 = hex_digest(encoded_zkey_hash);
        let expected_zkey = normalize_hash(expected_zkey_sha256)?;
        if zkey_sha256 != expected_zkey {
            return Err(SparrowError::ManifestZkeyHashMismatch {
                expected: expected_zkey,
                actual: zkey_sha256,
            });
        }
        let count = le_u32(&bytes[56..60])? as usize;
        let expected_count = if zkey_bytes == 0 {
            0
        } else {
            usize::try_from(zkey_bytes.div_ceil(chunk_bytes as u64))
                .map_err(|_| SparrowError::InvalidZkey("manifest chunk count overflow".into()))?
        };
        let expected_bytes =
            HEADER_BYTES
                .checked_add(count.checked_mul(HASH_BYTES).ok_or_else(|| {
                    SparrowError::InvalidZkey("manifest hash table overflow".into())
                })?)
                .ok_or_else(|| SparrowError::InvalidZkey("manifest size overflow".into()))?;
        if zkey_bytes == 0 || count != expected_count || bytes.len() != expected_bytes {
            return invalid("zkey manifest size or chunk count mismatch");
        }
        let chunk_hashes = bytes[HEADER_BYTES..]
            .chunks_exact(HASH_BYTES)
            .map(|hash| {
                hash.try_into()
                    .map_err(|_| SparrowError::InvalidZkey("truncated manifest chunk hash".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            chunk_bytes,
            zkey_bytes,
            zkey_sha256,
            chunk_hashes,
        })
    }

    pub fn generate<R: Read>(
        reader: &mut R,
        chunk_bytes: usize,
    ) -> Result<(Vec<u8>, String), SparrowError> {
        if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
            || !chunk_bytes.is_power_of_two()
        {
            return invalid("manifest chunk size must be a power of two from 64 KiB to 8 MiB");
        }
        let mut chunk = vec![0_u8; chunk_bytes];
        let mut zkey_hasher = Sha256::new();
        let mut chunk_hashes = Vec::<[u8; HASH_BYTES]>::new();
        let mut zkey_bytes = 0_u64;
        loop {
            let mut filled = 0;
            while filled != chunk.len() {
                let count = reader.read(&mut chunk[filled..])?;
                if count == 0 {
                    break;
                }
                filled += count;
            }
            if filled == 0 {
                break;
            }
            let bytes = &chunk[..filled];
            zkey_hasher.update(bytes);
            chunk_hashes.push(Sha256::digest(bytes).into());
            zkey_bytes = zkey_bytes
                .checked_add(filled as u64)
                .ok_or_else(|| SparrowError::InvalidZkey("zkey size overflow".into()))?;
            if filled != chunk.len() {
                break;
            }
        }
        if zkey_bytes == 0 {
            return invalid("cannot manifest an empty zkey");
        }
        let zkey_digest: [u8; HASH_BYTES] = zkey_hasher.finalize().into();
        let count = u32::try_from(chunk_hashes.len())
            .map_err(|_| SparrowError::InvalidZkey("too many manifest chunks".into()))?;
        let mut encoded = Vec::with_capacity(HEADER_BYTES + chunk_hashes.len() * HASH_BYTES);
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&VERSION.to_le_bytes());
        encoded.extend_from_slice(&(chunk_bytes as u32).to_le_bytes());
        encoded.extend_from_slice(&zkey_bytes.to_le_bytes());
        encoded.extend_from_slice(&zkey_digest);
        encoded.extend_from_slice(&count.to_le_bytes());
        for hash in chunk_hashes {
            encoded.extend_from_slice(&hash);
        }
        let manifest_sha256 = hex_digest(Sha256::digest(&encoded));
        Ok((encoded, manifest_sha256))
    }

    pub fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    pub fn zkey_bytes(&self) -> u64 {
        self.zkey_bytes
    }

    pub fn zkey_sha256(&self) -> &str {
        &self.zkey_sha256
    }

    /// Recheck a complete zkey against both the chunk table and the manifest's
    /// claimed whole-file digest.
    ///
    /// One-pass proving intentionally trusts an independently pinned manifest and
    /// therefore does not add a second whole-file hash. Release tooling can call
    /// this method once to prove that the published manifest is internally
    /// consistent without charging every proof for duplicate SHA-256 work.
    pub fn verify_reader<R: Read>(&self, reader: &mut R) -> Result<(), SparrowError> {
        let mut chunk = vec![0_u8; self.chunk_bytes];
        let mut whole = Sha256::new();
        let mut received = 0_u64;
        for (index, expected) in self.chunk_hashes.iter().enumerate() {
            let remaining = self.zkey_bytes.checked_sub(received).ok_or_else(|| {
                SparrowError::InvalidZkey("manifest chunk table exceeds zkey size".into())
            })?;
            let count = usize::try_from(remaining.min(self.chunk_bytes as u64))
                .map_err(|_| SparrowError::InvalidZkey("zkey chunk size overflow".into()))?;
            reader
                .read_exact(&mut chunk[..count])
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::UnexpectedEof => SparrowError::UnexpectedEof,
                    _ => SparrowError::Io(error),
                })?;
            let bytes = &chunk[..count];
            let actual: [u8; HASH_BYTES] = Sha256::digest(bytes).into();
            if &actual != expected {
                return Err(SparrowError::ZkeyChunkHashMismatch {
                    index,
                    expected: hex_digest(expected),
                    actual: hex_digest(actual),
                });
            }
            whole.update(bytes);
            received += count as u64;
        }
        if reader.read(&mut chunk[..1])? != 0 {
            return invalid("zkey stream exceeds manifest size");
        }
        let actual = hex_digest(whole.finalize());
        if actual != self.zkey_sha256 {
            return Err(SparrowError::ZkeyHashMismatch {
                expected: self.zkey_sha256.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// A raw zkey stream that authenticates each complete manifest chunk before
/// forwarding it into the parser/prover. This removes the whole-file first pass.
pub struct ManifestProofStream {
    manifest: ZkeyChunkManifest,
    next_chunk: usize,
    received: u64,
    pending: Vec<u8>,
    framer: ZkeyFramer,
}

impl ManifestProofStream {
    pub fn new(
        assignment: Vec<Fr>,
        manifest: ZkeyChunkManifest,
        config: SparrowConfig,
    ) -> Result<Self, SparrowError> {
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(manifest.chunk_bytes)
            .map_err(|_| SparrowError::InvalidZkey("cannot allocate manifest chunk".into()))?;
        let builder = SparrowProofBuilder::new_manifest_authenticated(
            assignment,
            manifest.zkey_sha256(),
            config,
        )?;
        Ok(Self {
            manifest,
            next_chunk: 0,
            received: 0,
            pending,
            framer: ZkeyFramer::new(builder),
        })
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), SparrowError> {
        self.received = self
            .received
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| SparrowError::InvalidZkey("zkey byte count overflow".into()))?;
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
    pub fn push_complete_chunk(&mut self, bytes: Vec<u8>) -> Result<(), SparrowError> {
        self.push_complete_chunk_ref(&bytes)
    }

    fn push_complete_chunk_ref(&mut self, bytes: &[u8]) -> Result<(), SparrowError> {
        if !self.pending.is_empty() {
            return invalid("cannot mix partial and complete manifest chunks");
        }
        let remaining = self
            .manifest
            .zkey_bytes
            .checked_sub(self.received)
            .ok_or_else(|| SparrowError::InvalidZkey("zkey byte count overflow".into()))?;
        let expected = remaining.min(self.manifest.chunk_bytes as u64) as usize;
        if expected == 0 || bytes.len() != expected {
            return invalid("complete zkey chunk has the wrong size");
        }
        self.authenticate_chunk(bytes)?;
        self.received += bytes.len() as u64;
        Ok(())
    }

    fn push_complete_chunks_ref(&mut self, bytes: &[u8]) -> Result<(), SparrowError> {
        if !self.pending.is_empty() || bytes.is_empty() {
            return invalid("invalid complete zkey chunk batch");
        }
        let remaining = self
            .manifest
            .zkey_bytes
            .checked_sub(self.received)
            .ok_or_else(|| SparrowError::InvalidZkey("zkey byte count overflow".into()))?;
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
            .ok_or_else(|| SparrowError::InvalidZkey("zkey chunk count overflow".into()))?;
        let expected = self
            .manifest
            .chunk_hashes
            .get(self.next_chunk..hash_end)
            .ok_or_else(|| SparrowError::InvalidZkey("too many zkey chunks".into()))?;
        let verify = |(offset, (chunk, expected)): (usize, (&[u8], &[u8; HASH_BYTES]))| {
            let actual: [u8; HASH_BYTES] = Sha256::digest(chunk).into();
            if &actual == expected {
                Ok(())
            } else {
                Err(SparrowError::ZkeyChunkHashMismatch {
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
            .map(verify)
            .collect::<Result<(), _>>()?;

        for chunk in bytes.chunks(self.manifest.chunk_bytes) {
            self.framer.push(chunk)?;
            self.next_chunk += 1;
            self.received += chunk.len() as u64;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<ProofBundle, SparrowError> {
        if self.received != self.manifest.zkey_bytes {
            return Err(SparrowError::UnexpectedEof);
        }
        if !self.pending.is_empty() {
            self.authenticate_pending(false)?;
        }
        if self.next_chunk != self.manifest.chunk_hashes.len() {
            return invalid("zkey chunk count disagrees with manifest size");
        }
        let builder = self.framer.finish()?;
        builder.finish()
    }

    fn authenticate_pending(&mut self, refill: bool) -> Result<(), SparrowError> {
        let pending = std::mem::take(&mut self.pending);
        self.authenticate_chunk(&pending)?;
        if refill {
            self.pending
                .try_reserve_exact(self.manifest.chunk_bytes)
                .map_err(|_| SparrowError::InvalidZkey("cannot allocate manifest chunk".into()))?;
        }
        Ok(())
    }

    fn authenticate_chunk(&mut self, bytes: &[u8]) -> Result<(), SparrowError> {
        let expected = self
            .manifest
            .chunk_hashes
            .get(self.next_chunk)
            .ok_or_else(|| SparrowError::InvalidZkey("too many zkey chunks".into()))?;
        let actual: [u8; HASH_BYTES] = Sha256::digest(bytes).into();
        if &actual != expected {
            return Err(SparrowError::ZkeyChunkHashMismatch {
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
    builder: Option<SparrowProofBuilder>,
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
    fn new(builder: SparrowProofBuilder) -> Self {
        Self {
            builder: Some(builder),
            state: FrameState::FileHeader,
            header: Vec::with_capacity(SECTION_HEADER_BYTES),
            sections: 0,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), SparrowError> {
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
                        .map_err(|_| SparrowError::InvalidZkey("section size overflow".into()))?;
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

    fn finish(mut self) -> Result<SparrowProofBuilder, SparrowError> {
        if !matches!(self.state, FrameState::Done) || !self.header.is_empty() {
            return invalid("incomplete framed zkey stream");
        }
        self.builder
            .take()
            .ok_or_else(|| SparrowError::InvalidZkey("missing proof builder".into()))
    }

    fn end_section(&mut self) -> Result<(), SparrowError> {
        self.builder_mut()?.end_section()?;
        self.sections += 1;
        self.state = if self.sections == ZKEY_SECTIONS {
            FrameState::Done
        } else {
            FrameState::SectionHeader
        };
        Ok(())
    }

    fn builder_mut(&mut self) -> Result<&mut SparrowProofBuilder, SparrowError> {
        self.builder
            .as_mut()
            .ok_or_else(|| SparrowError::InvalidZkey("missing proof builder".into()))
    }
}

pub fn prove_reader_with_manifest_owned<R: Read>(
    reader: &mut R,
    assignment: Vec<Fr>,
    manifest: ZkeyChunkManifest,
    config: SparrowConfig,
) -> Result<ProofBundle, SparrowError> {
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
            .map_err(|_| SparrowError::InvalidZkey("zkey chunk size overflow".into()))?;
        reader
            .read_exact(&mut bytes[..count])
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => SparrowError::UnexpectedEof,
                _ => SparrowError::Io(error),
            })?;
        stream.push_complete_chunks_ref(&bytes[..count])?;
        received += count as u64;
    }
    if reader.read(&mut bytes[..1])? != 0 {
        return invalid("zkey stream exceeds manifest size");
    }
    stream.finish()
}
