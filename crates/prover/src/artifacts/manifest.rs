//! Pinned chunk manifests shared by resident and streaming proving.
use sha2::{Digest, Sha256};
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("expected SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("zkey SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyHashMismatch { expected: String, actual: String },
    #[error("zkey manifest SHA-256 mismatch: expected {expected}, got {actual}")]
    ManifestHashMismatch { expected: String, actual: String },
    #[error("zkey manifest identifies {actual}, but protocol metadata pins {expected}")]
    ManifestZkeyHashMismatch { expected: String, actual: String },
    #[error("zkey chunk {index} SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyChunkHashMismatch {
        index: usize,
        expected: String,
        actual: String,
    },
    #[error("invalid zkey artifact: {0}")]
    InvalidZkey(String),
    #[error("zkey stream ended early")]
    UnexpectedEof,
    #[error("zkey I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

const MAGIC: &[u8; 8] = b"CVYZKM01";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 60;
const HASH_BYTES: usize = 32;
const MIN_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// A compact, independently pinned list of SHA-256 hashes over consecutive zkey
/// chunks. Its encoded size is 60 bytes plus 32 bytes per chunk, so hosts can
/// authenticate it in full before any zkey bytes are interpreted.
#[derive(Clone)]
pub struct ZkeyChunkManifest {
    pub(crate) chunk_bytes: usize,
    pub(crate) zkey_bytes: u64,
    pub(crate) zkey_sha256: String,
    pub(crate) chunk_hashes: Vec<[u8; HASH_BYTES]>,
}

impl ZkeyChunkManifest {
    pub fn from_bytes(
        bytes: &[u8],
        expected_manifest_sha256: &str,
        expected_zkey_sha256: &str,
    ) -> Result<Self, ArtifactError> {
        let expected_manifest = normalize_hash(expected_manifest_sha256)?;
        let actual_manifest = hex_digest(Sha256::digest(bytes));
        if actual_manifest != expected_manifest {
            return Err(ArtifactError::ManifestHashMismatch {
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
            .map_err(|_| ArtifactError::InvalidZkey("truncated manifest zkey hash".into()))?;
        let zkey_sha256 = hex_digest(encoded_zkey_hash);
        let expected_zkey = normalize_hash(expected_zkey_sha256)?;
        if zkey_sha256 != expected_zkey {
            return Err(ArtifactError::ManifestZkeyHashMismatch {
                expected: expected_zkey,
                actual: zkey_sha256,
            });
        }
        let count = le_u32(&bytes[56..60])? as usize;
        let expected_count = if zkey_bytes == 0 {
            0
        } else {
            usize::try_from(zkey_bytes.div_ceil(chunk_bytes as u64))
                .map_err(|_| ArtifactError::InvalidZkey("manifest chunk count overflow".into()))?
        };
        let expected_bytes =
            HEADER_BYTES
                .checked_add(count.checked_mul(HASH_BYTES).ok_or_else(|| {
                    ArtifactError::InvalidZkey("manifest hash table overflow".into())
                })?)
                .ok_or_else(|| ArtifactError::InvalidZkey("manifest size overflow".into()))?;
        if zkey_bytes == 0 || count != expected_count || bytes.len() != expected_bytes {
            return invalid("zkey manifest size or chunk count mismatch");
        }
        let chunk_hashes = bytes[HEADER_BYTES..]
            .chunks_exact(HASH_BYTES)
            .map(|hash| {
                hash.try_into()
                    .map_err(|_| ArtifactError::InvalidZkey("truncated manifest chunk hash".into()))
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
    ) -> Result<(Vec<u8>, String), ArtifactError> {
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
                .ok_or_else(|| ArtifactError::InvalidZkey("zkey size overflow".into()))?;
            if filled != chunk.len() {
                break;
            }
        }
        if zkey_bytes == 0 {
            return invalid("cannot manifest an empty zkey");
        }
        let zkey_digest: [u8; HASH_BYTES] = zkey_hasher.finalize().into();
        let count = u32::try_from(chunk_hashes.len())
            .map_err(|_| ArtifactError::InvalidZkey("too many manifest chunks".into()))?;
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
    pub fn verify_reader<R: Read>(&self, reader: &mut R) -> Result<(), ArtifactError> {
        let mut chunk = vec![0_u8; self.chunk_bytes];
        let mut whole = Sha256::new();
        let mut received = 0_u64;
        for (index, expected) in self.chunk_hashes.iter().enumerate() {
            let remaining = self.zkey_bytes.checked_sub(received).ok_or_else(|| {
                ArtifactError::InvalidZkey("manifest chunk table exceeds zkey size".into())
            })?;
            let count = usize::try_from(remaining.min(self.chunk_bytes as u64))
                .map_err(|_| ArtifactError::InvalidZkey("zkey chunk size overflow".into()))?;
            reader
                .read_exact(&mut chunk[..count])
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::UnexpectedEof => ArtifactError::UnexpectedEof,
                    _ => ArtifactError::Io(error),
                })?;
            let bytes = &chunk[..count];
            let actual: [u8; HASH_BYTES] = Sha256::digest(bytes).into();
            if &actual != expected {
                return Err(ArtifactError::ZkeyChunkHashMismatch {
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
            return Err(ArtifactError::ZkeyHashMismatch {
                expected: self.zkey_sha256.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// A forward-only reader that authenticates complete chunks before exposing
/// any bytes. Resident loading and SPARROW share the same pinned manifest type.
pub(crate) struct ManifestReader<'a, R> {
    source: &'a mut R,
    manifest: &'a ZkeyChunkManifest,
    chunk: Vec<u8>,
    position: usize,
    next_chunk: usize,
    delivered: u64,
}

impl<'a, R: Read> ManifestReader<'a, R> {
    pub(crate) fn new(source: &'a mut R, manifest: &'a ZkeyChunkManifest) -> Self {
        Self {
            source,
            manifest,
            chunk: Vec::new(),
            position: 0,
            next_chunk: 0,
            delivered: 0,
        }
    }

    pub(crate) fn finish(mut self) -> Result<(), ArtifactError> {
        if self.delivered != self.manifest.zkey_bytes {
            return Err(ArtifactError::UnexpectedEof);
        }
        self.chunk.resize(1, 0);
        loop {
            match self.source.read(&mut self.chunk[..1]) {
                Ok(0) => return Ok(()),
                Ok(_) => return invalid("zkey stream exceeds manifest size"),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl<R: Read> Read for ManifestReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.delivered == self.manifest.zkey_bytes {
            return Ok(0);
        }
        if self.position == self.chunk.len() {
            let count = (self.manifest.zkey_bytes - self.delivered)
                .min(self.manifest.chunk_bytes as u64) as usize;
            self.chunk.resize(count, 0);
            // Keep this chunk unavailable after a failed read or authentication.
            self.position = count;
            self.source.read_exact(&mut self.chunk)?;
            let actual: [u8; HASH_BYTES] = Sha256::digest(&self.chunk).into();
            let expected = &self.manifest.chunk_hashes[self.next_chunk];
            if &actual != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    ArtifactError::ZkeyChunkHashMismatch {
                        index: self.next_chunk,
                        expected: hex_digest(expected),
                        actual: hex_digest(actual),
                    },
                ));
            }
            self.next_chunk += 1;
            self.position = 0;
        }
        let count = output.len().min(self.chunk.len() - self.position);
        output[..count].copy_from_slice(&self.chunk[self.position..self.position + count]);
        self.position += count;
        self.delivered += count as u64;
        Ok(count)
    }
}

fn normalize_hash(value: &str) -> Result<String, ArtifactError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ArtifactError::InvalidExpectedHash);
    }
    Ok(value.to_ascii_lowercase())
}
fn hex_digest(value: impl AsRef<[u8]>) -> String {
    value
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn invalid<T>(message: impl Into<String>) -> Result<T, ArtifactError> {
    Err(ArtifactError::InvalidZkey(message.into()))
}
fn le_u32(bytes: &[u8]) -> Result<u32, ArtifactError> {
    bytes
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| ArtifactError::InvalidZkey("invalid u32 width".into()))
}
fn le_u64(bytes: &[u8]) -> Result<u64, ArtifactError> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| ArtifactError::InvalidZkey("invalid u64 width".into()))
}
