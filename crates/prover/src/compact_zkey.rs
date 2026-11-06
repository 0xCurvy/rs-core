//! Compact zkey: a smaller, lossless on-disk encoding of a snarkjs Groth16 zkey.
//!
//! A snarkjs zkey stores every curve point as affine `x` and `y` in 32-byte
//! Montgomery limbs, and its constraint coefficients as interleaved
//! `matrix | constraint | signal | value` records. Uniformly random coordinates
//! do not compress: on `verifyPixAggregationBound_2_9_30` sections 8 and 9 come
//! out of `xz -9e` exactly as large as they went in. The only way to shrink them
//! is to stop storing `y`, which a reader can recover from `x` and one sign bit.
//!
//! # Layout
//!
//! A compact zkey file (`.czkey`) is a 48-byte header followed by one zstd frame,
//! and nothing after it. Integers are little-endian.
//!
//! ```text
//! file
//! offset  bytes  field
//!      0      8  magic "CVYZKC01"; the 01 is the format version
//!      8     32  SHA-256 of the zkey this file decodes to
//!     40      8  length of that zkey in bytes
//!     48      …  one zstd frame holding the body
//!
//! body, inside the frame
//! offset  bytes  field
//!      0      4  the zkey's own format version (snarkjs writes 1)
//!      4      4  section count
//!      8  13 * n section table, in file order: id u32, zkey length u64, encoding u8
//!      …         one payload per section, in the same order
//! ```
//!
//! The header sits outside the frame and is readable without decompressing
//! anything. The frame is part of the format, not a file of its own: the file
//! has no `.zst` suffix and `zstd -d` does not open it.
//!
//! | encoding | payload |
//! |---|---|
//! | 0, raw | the section bytes unchanged |
//! | 1, G1 | 32 bytes per 64-byte point |
//! | 2, G2 | 64 bytes per 128-byte point |
//! | 3, coefficients | the count, then the `matrix`, `constraint` and `signal` columns as `u32`s, then the 32-byte values |
//!
//! A G1 or G2 payload is arkworks' compressed affine encoding, so any arkworks
//! reader can parse it with `G1Affine::deserialize_compressed` /
//! `G2Affine::deserialize_compressed`: `x` in canonical little-endian form (`c0`
//! then `c1` for G2), with bit 7 of the last byte set when `y` is the larger of
//! the two roots and bit 6 set for the point at infinity. snarkjs writes the point
//! at infinity as two zero coordinates; it decodes back to that.
//!
//! The encoder uses G1 for sections 3, 5, 6, 8 and 9, G2 for section 7, and the
//! coefficient columns for section 4. Sections 1, 2 and 10 stay raw. The indices
//! in section 4 are kept as plain `u32`s: they are already sorted, and zstd
//! compresses them better that way than as deltas.
//!
//! # Cost
//!
//! Decoding computes one square root per point, in `Fq` for G1 and `Fq2` for G2.
//! That is the whole price of the format, and it is paid on every load; the
//! crate README has measurements on production keys. The roots come from
//! `roots`, which computes them with fewer arkworks field operations than
//! arkworks' generic `sqrt` does. The square root also places every decoded
//! point on the curve, so no point decoded from a compact zkey can be
//! off-curve. G2 subgroup membership is not checked, as in the raw parser,
//! because the bytes are authenticated before decoding.
//!
//! # Trust
//!
//! [`crate::Prover::from_compact_zkey_bytes`] authenticates the whole file against
//! its pin before zstd sees it, as `curvy-witness` does for a compressed graph.
//! After decoding it hashes the reconstructed zkey and compares it with the digest
//! in the header, so a load fails rather than parsing a key that differs from the
//! one the encoder was given. That digest is the original zkey's, which for a
//! ceremony key is the one in the ceremony's `SHA256SUMS`.
//!
//! [`encode`] refuses any zkey it cannot reproduce byte for byte, and checks that
//! by decoding its own output.

use std::io::{self, Read};

use ark_bn254::{Fq, Fq2, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::short_weierstrass::{SWCurveConfig, SWFlags};
use ark_ff::{BigInt, Field};
use ark_serialize::{CanonicalDeserializeWithFlags, CanonicalSerialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::phase_timing::phase;
use crate::zkey::{deserialize_g1, deserialize_g2};

mod roots;

/// The first eight bytes of a compact zkey file.
pub const MAGIC: &[u8; 8] = b"CVYZKC01";

/// Whether `file` starts with [`MAGIC`], so a loader that takes either format
/// knows which decoder to authenticate it for. A raw zkey starts with `zkey`.
/// This reads nothing else and proves nothing: the pin is still checked first.
pub fn is_compact(file: &[u8]) -> bool {
    file.starts_with(MAGIC)
}

/// Bytes ahead of the zstd frame: the magic, the original zkey's SHA-256 and its
/// length.
pub const HEADER_BYTES: usize = 48;

/// Largest zstd window a compact zkey may declare. `zstd -19` uses 8 MiB, half
/// of this.
pub const MAX_WINDOW_BYTES: u64 = 16 * 1024 * 1024;

/// Default ceiling on the decoded zkey: the release validator's zkey limit.
pub const DEFAULT_MAX_ZKEY_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Most sections a compact zkey's table may list; a snarkjs Groth16 zkey has 10.
/// The table is refused beyond it before anything is allocated for it, so its
/// count cannot size an allocation whatever length limit the caller passes, and
/// [`describe`] passes none. [`encode`] refuses a zkey with more.
pub const MAX_SECTIONS: u32 = 64;

/// The zkey's format version and the section count, ahead of the section table.
const BODY_HEADER_BYTES: usize = 8;
const SECTION_ENTRY_BYTES: usize = 13;
const ZKEY_MAGIC: &[u8; 4] = b"zkey";
const ZKEY_HEADER_BYTES: u64 = 12;
const ZKEY_SECTION_HEADER_BYTES: u64 = 12;
const G1_RAW: usize = 64;
const G1_COMPACT: usize = 32;
const G2_RAW: usize = 128;
const G2_COMPACT: usize = 64;
const COEFFICIENT_RAW: usize = 3 * 4 + 32;

/// arkworks' compressed point at infinity: zero `x` with bit 6 of the last byte
/// set. arkworks ignores `x` once that flag is set; requiring zeros keeps one
/// body per zkey.
const G1_INFINITY: [u8; G1_COMPACT] = infinity();
const G2_INFINITY: [u8; G2_COMPACT] = infinity();

const fn infinity<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    bytes[N - 1] = 0x40;
    bytes
}

/// Points decoded per batch. Each batch is one read from the frame and, with
/// `parallel`, one parallel map.
const POINTS_PER_BATCH: usize = 1 << 16;

/// Coefficient entries copied per read.
const COEFFICIENTS_PER_BATCH: usize = 1 << 16;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CompactZkeyError {
    #[error("not a snarkjs zkey: {0}")]
    NotAZkey(String),
    #[error("not a compact zkey: {0}")]
    Malformed(String),
    #[error("the decoded zkey would exceed the {maximum}-byte limit")]
    TooLarge { maximum: u64 },
    #[error("could not reserve {bytes} bytes for the decoded zkey")]
    AllocationFailed { bytes: u64 },
    #[error("section {section}, point {index}: not a compressed curve point")]
    InvalidPoint { section: u32, index: usize },
    #[error("the compact zkey decodes to SHA-256 {actual}, not the {expected} its header names")]
    SourceDigestMismatch { expected: String, actual: String },
    #[error("encoding would not reproduce the zkey byte for byte: {0}")]
    Lossy(String),
    #[error("invalid zstd frame: {0}")]
    Zstd(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// How one section's bytes are stored in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionEncoding {
    Raw = 0,
    G1 = 1,
    G2 = 2,
    Coefficients = 3,
}

impl SectionEncoding {
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Raw),
            1 => Some(Self::G1),
            2 => Some(Self::G2),
            3 => Some(Self::Coefficients),
            _ => None,
        }
    }

    /// The encoding the encoder picks for a snarkjs Groth16 section id.
    fn for_section(id: u32) -> Self {
        match id {
            3 | 5 | 6 | 8 | 9 => Self::G1,
            7 => Self::G2,
            4 => Self::Coefficients,
            _ => Self::Raw,
        }
    }
}

/// One entry of the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactSection {
    pub id: u32,
    /// The section's length in the zkey, not in the body.
    pub zkey_bytes: u64,
    pub encoding: SectionEncoding,
}

/// What a compact zkey file says about the zkey it decodes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactZkeyHeader {
    pub zkey_sha256: [u8; 32],
    pub zkey_bytes: u64,
    pub zkey_version: u32,
    pub sections: Vec<CompactSection>,
}

/// Encode a snarkjs zkey as a compact zkey file.
///
/// `compress` wraps the body in one zstd frame; its window must not exceed
/// [`MAX_WINDOW_BYTES`]. ruzstd encodes only at level 1; release tooling passes
/// the system `zstd`. The zkey must be exactly a header and its
/// sections, with every point section holding canonical curve points; anything
/// else is refused rather than encoded lossily. The file is decoded with
/// [`inflate`] before it is returned and must reproduce `zkey` byte for byte.
pub fn encode(
    zkey: &[u8],
    compress: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, CompactZkeyError> {
    let (version, layout) = zkey_layout(zkey)?;

    let mut body = Vec::new();
    body.try_reserve_exact(zkey.len() / 2 + BODY_HEADER_BYTES + SECTION_ENTRY_BYTES * layout.len())
        .map_err(|_| CompactZkeyError::AllocationFailed {
            bytes: zkey.len() as u64,
        })?;
    body.extend_from_slice(&version.to_le_bytes());
    body.extend_from_slice(&(layout.len() as u32).to_le_bytes());
    for (section, _) in &layout {
        body.extend_from_slice(&section.id.to_le_bytes());
        body.extend_from_slice(&section.zkey_bytes.to_le_bytes());
        body.push(section.encoding as u8);
    }
    for (section, bytes) in &layout {
        encode_section(&mut body, section, bytes)?;
    }
    let frame = compress(&body);
    drop(body);

    let mut file = Vec::with_capacity(HEADER_BYTES + frame.len());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&sha256(zkey));
    file.extend_from_slice(&(zkey.len() as u64).to_le_bytes());
    file.extend_from_slice(&frame);
    drop(frame);

    let decoded = inflate(file.as_slice(), zkey.len() as u64).map_err(|error| {
        CompactZkeyError::Lossy(format!("the encoded file does not decode: {error}"))
    })?;
    if decoded != zkey {
        return Err(CompactZkeyError::Lossy("decoded bytes differ".to_owned()));
    }
    Ok(file)
}

/// Decode a compact zkey file from a reader back to the zkey it was made from.
///
/// The file must be exactly a header and one zstd frame: a window of at most
/// [`MAX_WINDOW_BYTES`], a body that ends where the frame ends, a matching
/// checksum when the frame has one, and nothing after it. The decoded zkey's
/// length is reserved up front once the section table is consistent, so
/// `max_zkey_bytes` is also an allocation bound. Authenticate the file first when
/// it comes from an untrusted source.
pub fn inflate<R: Read>(mut file: R, max_zkey_bytes: u64) -> Result<Vec<u8>, CompactZkeyError> {
    let (zkey_sha256, zkey_bytes) = read_file_header(&mut file, max_zkey_bytes)?;
    let mut decoder = zstd_decoder(file)?;
    let zkey = decode_body(&mut decoder, zkey_sha256, zkey_bytes)?;
    if read_some(&mut decoder)? {
        return Err(malformed("bytes follow the last section"));
    }
    if let Some(expected) = decoder.decoder.get_checksum_from_data()
        && decoder.decoder.get_calculated_checksum() != Some(expected)
    {
        return Err(CompactZkeyError::Zstd("checksum mismatch".to_owned()));
    }
    let (mut source, _) = decoder.into_parts();
    if read_some(&mut source)? {
        return Err(CompactZkeyError::Zstd(
            "bytes follow the zstd frame".to_owned(),
        ));
    }
    Ok(zkey)
}

/// Read a compact zkey file's header and section table without decoding any
/// section.
pub fn describe<R: Read>(mut file: R) -> Result<CompactZkeyHeader, CompactZkeyError> {
    let (zkey_sha256, zkey_bytes) = read_file_header(&mut file, u64::MAX)?;
    let (zkey_version, sections) = read_body_header(&mut zstd_decoder(file)?, zkey_bytes)?;
    Ok(CompactZkeyHeader {
        zkey_sha256,
        zkey_bytes,
        zkey_version,
        sections,
    })
}

fn zstd_decoder<R: Read>(
    frame: R,
) -> Result<ruzstd::decoding::StreamingDecoder<R, ruzstd::decoding::FrameDecoder>, CompactZkeyError>
{
    ruzstd::decoding::StreamingDecoder::new_with_max_window_size(frame, MAX_WINDOW_BYTES)
        .map_err(|error| CompactZkeyError::Zstd(error.to_string()))
}

fn malformed(what: impl Into<String>) -> CompactZkeyError {
    CompactZkeyError::Malformed(what.into())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    // 1 MiB updates for the same V8 tiering reason as `verify_sha256`.
    let mut hasher = Sha256::new();
    for chunk in bytes.chunks(1 << 20) {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Split a zkey into its sections, refusing anything a compact body could not
/// reproduce: a bad magic, a section running past the end, or trailing bytes.
/// A zkey's sections in file order, each with its bytes.
type Layout<'a> = Vec<(CompactSection, &'a [u8])>;

fn zkey_layout(zkey: &[u8]) -> Result<(u32, Layout<'_>), CompactZkeyError> {
    let not_a_zkey = |what: &str| CompactZkeyError::NotAZkey(what.to_owned());
    if zkey.len() < ZKEY_HEADER_BYTES as usize || &zkey[..4] != ZKEY_MAGIC {
        return Err(not_a_zkey("no zkey magic"));
    }
    let version = u32_at(zkey, 4);
    let count = u32_at(zkey, 8);
    if count > MAX_SECTIONS {
        return Err(CompactZkeyError::Lossy(format!(
            "the zkey has {count} sections; a compact zkey lists at most {MAX_SECTIONS}"
        )));
    }
    let mut position = ZKEY_HEADER_BYTES as usize;
    let mut layout = Vec::new();
    for _ in 0..count {
        if zkey.len() - position < ZKEY_SECTION_HEADER_BYTES as usize {
            return Err(not_a_zkey("truncated section header"));
        }
        let id = u32_at(zkey, position);
        let length = u64_at(zkey, position + 4);
        position += ZKEY_SECTION_HEADER_BYTES as usize;
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| position.checked_add(length))
            .filter(|end| *end <= zkey.len())
            .ok_or_else(|| not_a_zkey("a section runs past the end of the file"))?;
        layout.push((
            CompactSection {
                id,
                zkey_bytes: length,
                encoding: SectionEncoding::for_section(id),
            },
            &zkey[position..end],
        ));
        position = end;
    }
    if position != zkey.len() {
        return Err(not_a_zkey("bytes follow the last section"));
    }
    Ok((version, layout))
}

fn encode_section(
    body: &mut Vec<u8>,
    section: &CompactSection,
    bytes: &[u8],
) -> Result<(), CompactZkeyError> {
    let lossy = |what: &str| CompactZkeyError::Lossy(format!("section {}: {what}", section.id));
    match section.encoding {
        SectionEncoding::Raw => body.extend_from_slice(bytes),
        SectionEncoding::G1 => {
            if !bytes.len().is_multiple_of(G1_RAW) {
                return Err(lossy("not a whole number of G1 points"));
            }
            for (index, raw) in bytes.as_chunks::<G1_RAW>().0.iter().enumerate() {
                let point = deserialize_g1(&mut &raw[..])
                    .map_err(|_| lossy(&format!("point {index} is not canonical")))?;
                point
                    .serialize_compressed(&mut *body)
                    .map_err(|_| lossy("serialization failed"))?;
            }
        }
        SectionEncoding::G2 => {
            if !bytes.len().is_multiple_of(G2_RAW) {
                return Err(lossy("not a whole number of G2 points"));
            }
            for (index, raw) in bytes.as_chunks::<G2_RAW>().0.iter().enumerate() {
                let point = deserialize_g2(&mut &raw[..])
                    .map_err(|_| lossy(&format!("point {index} is not canonical")))?;
                point
                    .serialize_compressed(&mut *body)
                    .map_err(|_| lossy("serialization failed"))?;
            }
        }
        SectionEncoding::Coefficients => {
            let count = coefficient_count(section, bytes.get(..4))
                .map_err(|_| lossy("not a coefficient section"))?;
            let (records, rest) = bytes[4..].as_chunks::<COEFFICIENT_RAW>();
            debug_assert!(rest.is_empty() && records.len() == count);
            body.extend_from_slice(&bytes[..4]);
            for column in 0..3 {
                for record in records {
                    body.extend_from_slice(&record[column * 4..column * 4 + 4]);
                }
            }
            for record in records {
                body.extend_from_slice(&record[12..]);
            }
        }
    }
    Ok(())
}

/// The coefficient count, checked against the section's length.
fn coefficient_count(
    section: &CompactSection,
    count: Option<&[u8]>,
) -> Result<usize, CompactZkeyError> {
    let count = count
        .map(|bytes| u32_at(bytes, 0) as usize)
        .ok_or_else(|| malformed(format!("section {}: no coefficient count", section.id)))?;
    let expected = count
        .checked_mul(COEFFICIENT_RAW)
        .and_then(|records| records.checked_add(4))
        .map(|length| length as u64);
    if expected != Some(section.zkey_bytes) {
        return Err(malformed(format!(
            "section {}: {count} coefficients do not fill {} bytes",
            section.id, section.zkey_bytes
        )));
    }
    Ok(count)
}

/// The magic, the original zkey's digest and its length.
fn read_file_header<R: Read>(
    file: &mut R,
    max_zkey_bytes: u64,
) -> Result<([u8; 32], u64), CompactZkeyError> {
    let mut header = [0_u8; HEADER_BYTES];
    read_exact(file, &mut header)?;
    if &header[..8] != MAGIC {
        return Err(malformed("no CVYZKC01 magic"));
    }
    let mut zkey_sha256 = [0_u8; 32];
    zkey_sha256.copy_from_slice(&header[8..40]);
    let zkey_bytes = u64_at(&header, 40);
    if zkey_bytes > max_zkey_bytes {
        return Err(CompactZkeyError::TooLarge {
            maximum: max_zkey_bytes,
        });
    }
    Ok((zkey_sha256, zkey_bytes))
}

/// The zkey's format version and the section table, checked against the zkey
/// length the file header declares.
fn read_body_header<R: Read>(
    body: &mut R,
    zkey_bytes: u64,
) -> Result<(u32, Vec<CompactSection>), CompactZkeyError> {
    let mut header = [0_u8; BODY_HEADER_BYTES];
    read_exact(body, &mut header)?;
    let zkey_version = u32_at(&header, 0);
    let count = u32_at(&header, 4);
    if count > MAX_SECTIONS {
        return Err(malformed(format!(
            "{count} sections, more than the {MAX_SECTIONS} a compact zkey may list"
        )));
    }
    // Every section also costs the zkey at least its 12-byte header.
    if u64::from(count) > zkey_bytes.saturating_sub(ZKEY_HEADER_BYTES) / ZKEY_SECTION_HEADER_BYTES {
        return Err(malformed("more sections than the zkey length allows"));
    }

    let mut sections = Vec::with_capacity(count as usize);
    let mut total = ZKEY_HEADER_BYTES;
    for _ in 0..count {
        let mut entry = [0_u8; SECTION_ENTRY_BYTES];
        read_exact(body, &mut entry)?;
        let section = CompactSection {
            id: u32_at(&entry, 0),
            zkey_bytes: u64_at(&entry, 4),
            encoding: SectionEncoding::from_tag(entry[12])
                .ok_or_else(|| malformed(format!("unknown section encoding {}", entry[12])))?,
        };
        let unit = match section.encoding {
            SectionEncoding::G1 => G1_RAW as u64,
            SectionEncoding::G2 => G2_RAW as u64,
            SectionEncoding::Raw | SectionEncoding::Coefficients => 1,
        };
        if !section.zkey_bytes.is_multiple_of(unit) {
            return Err(malformed(format!(
                "section {}: {} bytes is not a whole number of points",
                section.id, section.zkey_bytes
            )));
        }
        total = total
            .checked_add(ZKEY_SECTION_HEADER_BYTES)
            .and_then(|total| total.checked_add(section.zkey_bytes))
            .ok_or_else(|| malformed("section lengths overflow"))?;
        sections.push(section);
    }
    if total != zkey_bytes {
        return Err(malformed(format!(
            "sections add up to {total} bytes, the header says {zkey_bytes}"
        )));
    }
    Ok((zkey_version, sections))
}

/// Decode the body inside the frame and check the result against the digest
/// the file header names.
fn decode_body<R: Read>(
    body: &mut R,
    zkey_sha256: [u8; 32],
    zkey_bytes: u64,
) -> Result<Vec<u8>, CompactZkeyError> {
    let (zkey_version, sections) = read_body_header(body, zkey_bytes)?;
    let capacity = usize::try_from(zkey_bytes).map_err(|_| CompactZkeyError::TooLarge {
        maximum: usize::MAX as u64,
    })?;
    let mut zkey = Vec::new();
    zkey.try_reserve_exact(capacity)
        .map_err(|_| CompactZkeyError::AllocationFailed { bytes: zkey_bytes })?;
    zkey.extend_from_slice(ZKEY_MAGIC);
    zkey.extend_from_slice(&zkey_version.to_le_bytes());
    zkey.extend_from_slice(&(sections.len() as u32).to_le_bytes());

    for section in &sections {
        zkey.extend_from_slice(&section.id.to_le_bytes());
        zkey.extend_from_slice(&section.zkey_bytes.to_le_bytes());
        let start = zkey.len();
        // The table already summed to the reserved length, so this never grows
        // the allocation.
        zkey.resize(start + section.zkey_bytes as usize, 0);
        let region = &mut zkey[start..];
        match section.encoding {
            SectionEncoding::Raw => read_exact(body, region)?,
            SectionEncoding::G1 => phase!(
                "load.zkey.inflate.g1",
                decode_points(body, region, section.id, G1_COMPACT, G1_RAW, decode_g1)
            )?,
            SectionEncoding::G2 => phase!(
                "load.zkey.inflate.g2",
                decode_points(body, region, section.id, G2_COMPACT, G2_RAW, decode_g2)
            )?,
            SectionEncoding::Coefficients => phase!(
                "load.zkey.inflate.coefficients",
                decode_coefficients(body, region, section)
            )?,
        }
    }

    let actual = phase!("load.zkey.inflate.sha256", sha256(&zkey));
    if actual != zkey_sha256 {
        return Err(CompactZkeyError::SourceDigestMismatch {
            expected: hex(&zkey_sha256),
            actual: hex(&actual),
        });
    }
    Ok(zkey)
}

/// Decode a point section into its zkey region, one batch at a time.
fn decode_points<R: Read>(
    body: &mut R,
    region: &mut [u8],
    section: u32,
    compact_bytes: usize,
    raw_bytes: usize,
    decode: fn(&[u8], &mut [u8]) -> bool,
) -> Result<(), CompactZkeyError> {
    let mut compact =
        vec![0_u8; region.len().min(POINTS_PER_BATCH * raw_bytes) / raw_bytes * compact_bytes];
    for (batch, raw) in region.chunks_mut(POINTS_PER_BATCH * raw_bytes).enumerate() {
        let points = raw.len() / raw_bytes;
        let compact = &mut compact[..points * compact_bytes];
        read_exact(body, compact)?;

        #[cfg(feature = "parallel")]
        let failed = compact
            .par_chunks_exact(compact_bytes)
            .zip(raw.par_chunks_exact_mut(raw_bytes))
            .position_first(|(compact, raw)| !decode(compact, raw));
        #[cfg(not(feature = "parallel"))]
        let failed = compact
            .chunks_exact(compact_bytes)
            .zip(raw.chunks_exact_mut(raw_bytes))
            .position(|(compact, raw)| !decode(compact, raw));

        if let Some(offset) = failed {
            return Err(CompactZkeyError::InvalidPoint {
                section,
                index: batch * POINTS_PER_BATCH + offset,
            });
        }
    }
    Ok(())
}

/// One compressed G1 point to snarkjs's two Montgomery coordinates.
///
/// The same point `G1Affine::deserialize_compressed_unchecked` returns, with
/// the faster root from [`roots`]; `decoded_points_are_arkworks_points` holds
/// the two together.
fn decode_g1(compact: &[u8], raw: &mut [u8]) -> bool {
    let Ok((x, flags)) = Fq::deserialize_with_flags::<_, SWFlags>(compact) else {
        return false;
    };
    if flags.is_infinity() {
        // snarkjs spells the point at infinity as two zero coordinates.
        if compact != G1_INFINITY {
            return false;
        }
        raw.fill(0);
        return true;
    }
    let Some(y) = roots::sqrt_fq(x.square() * x + G1Config::COEFF_B) else {
        return false;
    };
    let y = choose_root(y, flags);
    write_limbs(&mut raw[..32], x.0);
    write_limbs(&mut raw[32..], y.0);
    true
}

/// One compressed G2 point to snarkjs's four Montgomery limbs: `x.c0`, `x.c1`,
/// `y.c0`, `y.c1`.
fn decode_g2(compact: &[u8], raw: &mut [u8]) -> bool {
    let Ok((x, flags)) = Fq2::deserialize_with_flags::<_, SWFlags>(compact) else {
        return false;
    };
    if flags.is_infinity() {
        if compact != G2_INFINITY {
            return false;
        }
        raw.fill(0);
        return true;
    }
    let Some(y) = roots::sqrt_fq2(x.square() * x + G2Config::COEFF_B) else {
        return false;
    };
    let y = choose_root(y, flags);
    write_limbs(&mut raw[..32], x.c0.0);
    write_limbs(&mut raw[32..64], x.c1.0);
    write_limbs(&mut raw[64..96], y.c0.0);
    write_limbs(&mut raw[96..], y.c1.0);
    true
}

/// The root arkworks' compressed encoding names: the smaller of `y` and `-y`
/// under arkworks' own ordering when the sign flag is clear, the larger when
/// it is set. Both curves have `a = 0`, so `y^2 = x^3 + b`.
fn choose_root<F: Field + Ord>(root: F, flags: SWFlags) -> F {
    let negated = -root;
    let (smaller, larger) = if root < negated {
        (root, negated)
    } else {
        (negated, root)
    };
    if flags.is_positive() == Some(true) {
        smaller
    } else {
        larger
    }
}

/// A field element's internal Montgomery limbs, which is what snarkjs stores
/// (see `deserialize_field` in `zkey.rs`, the inverse).
fn write_limbs(output: &mut [u8], value: BigInt<4>) {
    for (bytes, limb) in output.as_chunks_mut::<8>().0.iter_mut().zip(value.0) {
        *bytes = limb.to_le_bytes();
    }
}

/// Undo the columnar split of section 4.
fn decode_coefficients<R: Read>(
    body: &mut R,
    region: &mut [u8],
    section: &CompactSection,
) -> Result<(), CompactZkeyError> {
    read_exact(body, &mut region[..4])?;
    let count = coefficient_count(section, Some(&region[..4]))?;
    let records = &mut region[4..];
    let mut column = vec![0_u8; count.min(COEFFICIENTS_PER_BATCH) * 32];
    for (offset, width) in [(0, 4), (4, 4), (8, 4), (12, 32)] {
        for batch in records.chunks_mut(COEFFICIENTS_PER_BATCH * COEFFICIENT_RAW) {
            let entries = batch.len() / COEFFICIENT_RAW;
            let values = &mut column[..entries * width];
            read_exact(body, values)?;
            for (record, value) in batch
                .as_chunks_mut::<COEFFICIENT_RAW>()
                .0
                .iter_mut()
                .zip(values.chunks_exact(width))
            {
                record[offset..offset + width].copy_from_slice(value);
            }
        }
    }
    Ok(())
}

fn read_exact<R: Read>(reader: &mut R, output: &mut [u8]) -> Result<(), CompactZkeyError> {
    reader.read_exact(output).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            malformed("truncated")
        } else {
            CompactZkeyError::Io(error)
        }
    })
}

/// True when the reader has at least one more byte.
fn read_some<R: Read>(reader: &mut R) -> Result<bool, CompactZkeyError> {
    let mut probe = [0_u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(count) => return Ok(count != 0),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(CompactZkeyError::Io(error)),
        }
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("eight bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::rand::RngCore;

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    fn fast(body: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(body, ruzstd::encoding::CompressionLevel::Fastest)
    }

    /// A zstd frame of raw blocks: every body byte stays where a mutation reaches
    /// the body parser instead of failing in zstd.
    fn stored(body: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(body, ruzstd::encoding::CompressionLevel::Uncompressed)
    }

    fn compact() -> Vec<u8> {
        encode(ZKEY, fast).expect("encode")
    }

    fn body_of(file: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        zstd_decoder(&file[HEADER_BYTES..])
            .expect("frame")
            .read_to_end(&mut body)
            .expect("body");
        body
    }

    /// `file`'s header around a different body.
    fn around(file: &[u8], body: &[u8]) -> Vec<u8> {
        [&file[..HEADER_BYTES], stored(body).as_slice()].concat()
    }

    fn pin(bytes: &[u8]) -> String {
        hex(&sha256(bytes))
    }

    #[test]
    fn the_fixture_round_trips_byte_for_byte() {
        let file = compact();
        assert!(file.len() < ZKEY.len(), "{} !< {}", file.len(), ZKEY.len());
        assert_eq!(
            inflate(file.as_slice(), DEFAULT_MAX_ZKEY_BYTES).expect("inflate"),
            ZKEY
        );
        // The header is readable without zstd.
        assert_eq!(&file[..8], MAGIC);
        assert_eq!(file[8..40], sha256(ZKEY));
        assert_eq!(u64_at(&file, 40), ZKEY.len() as u64);
        // The same body in a stored frame decodes the same.
        assert_eq!(
            inflate(
                around(&file, &body_of(&file)).as_slice(),
                DEFAULT_MAX_ZKEY_BYTES
            )
            .expect("stored"),
            ZKEY
        );

        let header = describe(file.as_slice()).expect("describe");
        assert_eq!(header.zkey_sha256, sha256(ZKEY));
        assert_eq!(header.zkey_bytes, ZKEY.len() as u64);
        let encodings = header
            .sections
            .iter()
            .map(|section| (section.id, section.encoding))
            .collect::<Vec<_>>();
        for (id, encoding) in [
            (1, SectionEncoding::Raw),
            (2, SectionEncoding::Raw),
            (3, SectionEncoding::G1),
            (4, SectionEncoding::Coefficients),
            (5, SectionEncoding::G1),
            (6, SectionEncoding::G1),
            (7, SectionEncoding::G2),
            (8, SectionEncoding::G1),
            (9, SectionEncoding::G1),
        ] {
            assert!(
                encodings.contains(&(id, encoding)),
                "section {id}: {encodings:?}"
            );
        }
    }

    /// A bare zstd frame, the pre-header layout, is not a compact zkey.
    #[test]
    fn a_file_without_the_header_is_refused() {
        let error = inflate(
            fast(&body_of(&compact())).as_slice(),
            DEFAULT_MAX_ZKEY_BYTES,
        )
        .expect_err("no header");
        assert!(error.to_string().contains("CVYZKC01"), "{error}");
        assert!(describe(&b"zkey"[..]).is_err());
    }

    /// The point of using arkworks' encoding: a reader that knows nothing about
    /// this module can take a point payload apart with `deserialize_compressed`,
    /// subgroup check included, and get the same points the raw parser does.
    #[test]
    fn point_payloads_are_arkworks_compressed_points() {
        let file = compact();
        let body = body_of(&file);
        let header = describe(file.as_slice()).expect("header");
        let (_, layout) = zkey_layout(ZKEY).expect("layout");
        let mut offset = BODY_HEADER_BYTES + SECTION_ENTRY_BYTES * header.sections.len();
        for ((section, raw), entry) in layout.iter().zip(&header.sections) {
            assert_eq!(section.id, entry.id);
            match entry.encoding {
                SectionEncoding::G1 => {
                    for raw in raw.as_chunks::<G1_RAW>().0 {
                        let compact = &body[offset..offset + G1_COMPACT];
                        let point = G1Affine::deserialize_compressed(compact).expect("G1");
                        assert_eq!(point, deserialize_g1(&mut &raw[..]).expect("raw G1"));
                        offset += G1_COMPACT;
                    }
                }
                SectionEncoding::G2 => {
                    for raw in raw.as_chunks::<G2_RAW>().0 {
                        let compact = &body[offset..offset + G2_COMPACT];
                        let point = G2Affine::deserialize_compressed(compact).expect("G2");
                        assert_eq!(point, deserialize_g2(&mut &raw[..]).expect("raw G2"));
                        offset += G2_COMPACT;
                    }
                }
                SectionEncoding::Raw | SectionEncoding::Coefficients => offset += raw.len(),
            }
        }
        assert_eq!(offset, body.len());
    }

    #[test]
    fn the_point_at_infinity_survives_in_its_one_spelling() {
        let mut compact = Vec::new();
        G1Affine::identity()
            .serialize_compressed(&mut compact)
            .expect("serialize");
        assert_eq!(compact, G1_INFINITY);
        let mut raw = [0xAA_u8; G1_RAW];
        assert!(decode_g1(&compact, &mut raw));
        assert_eq!(raw, [0; G1_RAW]);
        assert!(deserialize_g1(&mut &raw[..]).expect("raw").is_zero());

        let mut compact = Vec::new();
        G2Affine::identity()
            .serialize_compressed(&mut compact)
            .expect("serialize");
        assert_eq!(compact, G2_INFINITY);
        let mut raw = [0xAA_u8; G2_RAW];
        assert!(decode_g2(&compact, &mut raw));
        assert_eq!(raw, [0; G2_RAW]);

        // arkworks would read these as infinity too; the decoder must not.
        let mut stray = G1_INFINITY;
        stray[0] = 1;
        assert!(G1Affine::deserialize_compressed_unchecked(&stray[..]).is_ok());
        assert!(!decode_g1(&stray, &mut [0; G1_RAW]));
        let mut stray = G2_INFINITY;
        stray[40] = 1;
        assert!(!decode_g2(&stray, &mut [0; G2_RAW]));
    }

    #[test]
    fn every_truncation_is_refused() {
        let file = compact();
        for length in 0..file.len() {
            assert!(
                inflate(&file[..length], DEFAULT_MAX_ZKEY_BYTES).is_err(),
                "accepted a {length}-byte prefix of the file"
            );
        }
        let body = body_of(&file);
        for length in 0..body.len() {
            assert!(
                inflate(
                    around(&file, &body[..length]).as_slice(),
                    DEFAULT_MAX_ZKEY_BYTES
                )
                .is_err(),
                "accepted a {length}-byte prefix of the body"
            );
        }
        let mut longer = body.clone();
        longer.push(0);
        assert!(inflate(around(&file, &longer).as_slice(), DEFAULT_MAX_ZKEY_BYTES).is_err());
        let mut trailing = file.clone();
        trailing.push(0);
        assert!(inflate(trailing.as_slice(), DEFAULT_MAX_ZKEY_BYTES).is_err());
    }

    #[test]
    fn a_changed_payload_byte_fails_the_source_digest_or_the_point_decoder() {
        let file = compact();
        let body = body_of(&file);
        let sections = describe(file.as_slice()).expect("header").sections.len();
        let payload = BODY_HEADER_BYTES + SECTION_ENTRY_BYTES * sections;
        for position in (payload..body.len()).step_by(97) {
            let mut corrupted = body.clone();
            corrupted[position] ^= 0x01;
            let error = inflate(around(&file, &corrupted).as_slice(), DEFAULT_MAX_ZKEY_BYTES)
                .expect_err("a changed payload must not decode");
            assert!(
                matches!(
                    error,
                    CompactZkeyError::SourceDigestMismatch { .. }
                        | CompactZkeyError::InvalidPoint { .. }
                        | CompactZkeyError::Malformed(_)
                ),
                "byte {position}: {error}"
            );
        }
    }

    #[test]
    fn the_size_limit_applies_before_allocation() {
        let file = compact();
        let error = inflate(file.as_slice(), ZKEY.len() as u64 - 1).expect_err("over the limit");
        assert!(
            matches!(error, CompactZkeyError::TooLarge { .. }),
            "{error}"
        );

        // A table that does not add up to the declared length is refused before
        // the declared length is reserved.
        let mut inflated = file.clone();
        inflated[40..48].copy_from_slice(&(1_u64 << 40).to_le_bytes());
        let error = inflate(inflated.as_slice(), u64::MAX).expect_err("inconsistent length");
        assert!(matches!(error, CompactZkeyError::Malformed(_)), "{error}");
    }

    /// A section count is refused before it sizes anything, also by `describe`,
    /// which reads the table with no length limit.
    #[test]
    fn the_section_count_cannot_size_an_allocation() {
        let file = compact();
        let body = body_of(&file);
        for (count, refused) in [
            (MAX_SECTIONS, false),
            (MAX_SECTIONS + 1, true),
            (u32::MAX, true),
        ] {
            let mut forged = body.clone();
            forged[4..8].copy_from_slice(&count.to_le_bytes());
            let mut forged = around(&file, &forged);
            forged[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
            let error = describe(forged.as_slice()).expect_err("a forged table");
            assert_eq!(
                error.to_string().contains("more than the 64"),
                refused,
                "{count}: {error}"
            );
            assert!(inflate(forged.as_slice(), u64::MAX).is_err(), "{count}");
        }

        // The encoder refuses what the decoder would.
        let sections = MAX_SECTIONS + 1;
        let mut zkey = [&b"zkey"[..], &1_u32.to_le_bytes(), &sections.to_le_bytes()].concat();
        for id in 0..sections {
            zkey.extend_from_slice(&(100 + id).to_le_bytes());
            zkey.extend_from_slice(&0_u64.to_le_bytes());
        }
        let error = encode(&zkey, fast).expect_err("too many sections");
        assert!(matches!(error, CompactZkeyError::Lossy(_)), "{error}");
    }

    #[test]
    fn zkeys_the_body_cannot_reproduce_are_refused() {
        let mut trailing = ZKEY.to_vec();
        trailing.push(0);
        assert!(matches!(
            encode(&trailing, fast),
            Err(CompactZkeyError::NotAZkey(_))
        ));
        assert!(matches!(
            encode(&ZKEY[..ZKEY.len() - 1], fast),
            Err(CompactZkeyError::NotAZkey(_))
        ));
        assert!(encode(b"not a zkey", fast).is_err());

        // A point that is not on the curve has no square root to recover `y`
        // from, so the encoder must refuse it rather than write a body that
        // decodes to something else.
        let (_, layout) = zkey_layout(ZKEY).expect("layout");
        let (_, a_query) = layout
            .iter()
            .find(|(section, _)| section.id == 5)
            .expect("section 5");
        let offset = a_query.as_ptr() as usize - ZKEY.as_ptr() as usize;
        let point = (0..a_query.len() / G1_RAW)
            .find(|index| a_query[index * G1_RAW..(index + 1) * G1_RAW] != [0; G1_RAW])
            .expect("a finite A point");
        let mut off_curve = ZKEY.to_vec();
        off_curve[offset + point * G1_RAW + 32] ^= 0x01;
        assert!(matches!(
            encode(&off_curve, fast),
            Err(CompactZkeyError::Lossy(_))
        ));

        // A compressor whose frame the decoder refuses is caught too.
        assert!(matches!(
            encode(ZKEY, |_| b"not zstd".to_vec()),
            Err(CompactZkeyError::Lossy(_))
        ));
    }

    /// The loaders must hand back exactly the key the raw file loads to, and must
    /// check the compact file's pin before decoding anything.
    #[test]
    fn the_prover_loads_the_same_key_from_either_file() {
        use crate::{Prover, ProverError};
        use std::io::Cursor;

        let file = compact();
        let raw = Prover::from_zkey_bytes(ZKEY, &pin(ZKEY)).expect("raw");
        let loaded = Prover::from_compact_zkey_bytes(&file, &pin(&file)).expect("compact");
        let streamed = Prover::from_compact_zkey_reader(&mut Cursor::new(&file), &pin(&file))
            .expect("compact reader");
        for prover in [&loaded, &streamed] {
            assert_eq!(prover.verifying_key_digest(), raw.verifying_key_digest());
            assert_eq!(prover.num_constraints(), raw.num_constraints());
            assert_eq!(prover.num_public(), raw.num_public());
        }

        // The original zkey's digest is not the compact file's pin.
        assert!(matches!(
            Prover::from_compact_zkey_bytes(&file, &pin(ZKEY)),
            Err(ProverError::ZkeyHashMismatch { .. })
        ));
        // A pinned file whose header names a different zkey digest is refused
        // after decoding, before parsing.
        let mut mislabelled = file.clone();
        mislabelled[8] ^= 1;
        let error = Prover::from_compact_zkey_bytes(&mislabelled, &pin(&mislabelled))
            .err()
            .expect("a mislabelled file must not load");
        let ProverError::ZkeyIo(error) = error else {
            panic!("expected a zkey I/O error, got {error}");
        };
        assert!(matches!(
            error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<CompactZkeyError>()),
            Some(CompactZkeyError::SourceDigestMismatch { .. })
        ));
    }

    /// Random multi-byte mutations of the body and of the whole file: errors,
    /// never panics, and nothing decodes unless it reproduces the digest it names.
    #[test]
    fn mutated_bodies_and_files_fail_cleanly() {
        let file = compact();
        let body = body_of(&file);
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..4_000 {
            let source = if round % 2 == 0 { &body } else { &file };
            let mut mutated = source.clone();
            for _ in 0..1 + next() % 4 {
                let at = (next() % mutated.len() as u64) as usize;
                mutated[at] = next() as u8;
            }
            if next() % 8 == 0 {
                mutated.truncate((next() % mutated.len() as u64) as usize);
            }
            let decoded = if round % 2 == 0 {
                inflate(around(&file, &mutated).as_slice(), 1 << 20)
            } else {
                inflate(mutated.as_slice(), 1 << 20)
            };
            if let Ok(zkey) = decoded {
                assert_eq!(zkey, ZKEY, "round {round}: decoded to a different zkey");
            }
        }
    }

    /// The decoder computes `y` itself; it has to agree with arkworks'
    /// `deserialize_compressed_unchecked` on every point, both signs, and on
    /// which inputs are not points at all.
    #[test]
    fn decoded_points_are_arkworks_points() {
        use ark_ec::CurveGroup;
        use ark_std::UniformRand;

        let mut rng = ark_std::test_rng();
        for _ in 0..500 {
            let point = ark_bn254::G1Projective::rand(&mut rng).into_affine();
            for point in [point, -point] {
                let mut compact = Vec::new();
                point.serialize_compressed(&mut compact).expect("serialize");
                let mut raw = [0_u8; G1_RAW];
                assert!(decode_g1(&compact, &mut raw));
                assert_eq!(deserialize_g1(&mut &raw[..]).expect("raw"), point);
            }
            let point = ark_bn254::G2Projective::rand(&mut rng).into_affine();
            for point in [point, -point] {
                let mut compact = Vec::new();
                point.serialize_compressed(&mut compact).expect("serialize");
                let mut raw = [0_u8; G2_RAW];
                assert!(decode_g2(&compact, &mut raw));
                assert_eq!(deserialize_g2(&mut &raw[..]).expect("raw"), point);
            }
        }
        // Random x: about half are not on the curve. Accept exactly what
        // arkworks accepts, and decode it to the same point.
        let mut accepted = 0;
        for _ in 0..1_000 {
            let mut compact = [0_u8; G1_COMPACT];
            Fq::rand(&mut rng)
                .serialize_compressed(&mut compact[..])
                .expect("serialize");
            compact[G1_COMPACT - 1] |= u8::from(rng.next_u32() & 1 == 1) << 7;
            let expected = G1Affine::deserialize_compressed_unchecked(&compact[..]).ok();
            let mut raw = [0_u8; G1_RAW];
            assert_eq!(decode_g1(&compact, &mut raw), expected.is_some());
            if let Some(point) = expected {
                assert_eq!(deserialize_g1(&mut &raw[..]).expect("raw"), point);
                accepted += 1;
            }

            let mut compact = [0_u8; G2_COMPACT];
            Fq2::rand(&mut rng)
                .serialize_compressed(&mut compact[..])
                .expect("serialize");
            compact[G2_COMPACT - 1] |= u8::from(rng.next_u32() & 1 == 1) << 7;
            let expected = G2Affine::deserialize_compressed_unchecked(&compact[..]).ok();
            let mut raw = [0_u8; G2_RAW];
            assert_eq!(decode_g2(&compact, &mut raw), expected.is_some());
            if let Some(point) = expected {
                assert_eq!(deserialize_g2(&mut &raw[..]).expect("raw"), point);
            }
        }
        assert!((300..700).contains(&accepted), "{accepted}");
    }
}
