//! Encoding helpers for EdDSA and cipher boundaries.
//!
//! EdDSA uses little-endian integers; cipher inputs use big-endian bytes.

use core::str::FromStr;
use std::fmt;

use num_bigint::BigUint;

/// Parses a non-negative decimal integer without field reduction.
pub fn dec_to_biguint(s: &str) -> BigUint {
    BigUint::from_str(s).unwrap_or_else(|_| panic!("invalid decimal integer: {s:?}"))
}

/// Decodes hex with Node `Buffer.from(hex, "hex")` semantics.
///
/// Stops at the first invalid pair and drops a trailing nibble. Does not strip `0x`.
pub fn from_hex_lossy(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        match (hex_nibble(bytes[i]), hex_nibble(bytes[i + 1])) {
            (Some(hi), Some(lo)) => {
                out.push((hi << 4) | lo);
                i += 2;
            }
            _ => break, // Node stops at the first invalid pair.
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HexDecodeError {
    OddLength { actual: usize },
    InvalidCharacter { character: char, index: usize },
    WrongLength { expected: usize, actual: usize },
}

impl fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength { actual } => {
                write!(
                    f,
                    "hex must contain complete byte pairs; received {actual} characters"
                )
            }
            Self::InvalidCharacter {
                character: 'x' | 'X',
                index: 1,
            } => f.write_str(
                "hex must be unprefixed; remove the leading 0x before passing private key material",
            ),
            Self::InvalidCharacter { character, index } => {
                write!(f, "invalid hex character {character:?} at index {index}")
            }
            Self::WrongLength { expected, actual } => {
                write!(
                    f,
                    "hex must decode to exactly {expected} bytes; received {actual}"
                )
            }
        }
    }
}

impl std::error::Error for HexDecodeError {}

/// Decodes exactly `N` bytes of unprefixed hex.
pub fn from_hex_exact<const N: usize>(s: &str) -> Result<[u8; N], HexDecodeError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexDecodeError::OddLength {
            actual: bytes.len(),
        });
    }

    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for (pair_index, pair) in bytes.chunks_exact(2).enumerate() {
        let index = pair_index * 2;
        let hi = hex_nibble(pair[0]).ok_or(HexDecodeError::InvalidCharacter {
            character: pair[0] as char,
            index,
        })?;
        let lo = hex_nibble(pair[1]).ok_or(HexDecodeError::InvalidCharacter {
            character: pair[1] as char,
            index: index + 1,
        })?;
        decoded.push((hi << 4) | lo);
    }

    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| HexDecodeError::WrongLength {
            expected: N,
            actual: decoded.len(),
        })
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes a little-endian integer (`leBufferToBigInt`).
pub fn le_bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

/// Encodes a raw integer as 32 big-endian bytes without field reduction.
///
/// Panics when the value is at least `2^256`.
pub fn biguint_to_be_32(value: &BigUint) -> [u8; 32] {
    let be = value.to_bytes_be();
    assert!(
        be.len() <= 32,
        "biguint_to_be_32: value exceeds 32 bytes (>= 2^256)"
    );
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Encodes an integer as fixed-length little-endian bytes.
///
/// Panics when the value does not fit in `len` bytes.
pub fn biguint_to_le_bytes(value: &BigUint, len: usize) -> Vec<u8> {
    let mut out = value.to_bytes_le();
    assert!(
        out.len() <= len,
        "biguint_to_le_bytes: value exceeds {len} bytes"
    );
    out.resize(len, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_matches_node_buffer_from() {
        assert_eq!(from_hex_lossy("00ff10"), vec![0x00, 0xff, 0x10]);
        assert_eq!(from_hex_lossy("abc"), vec![0xab]); // odd: trailing nibble dropped
        assert_eq!(from_hex_lossy("zz"), Vec::<u8>::new()); // invalid: stop immediately
        assert_eq!(from_hex_lossy("0xab"), Vec::<u8>::new()); // no 0x strip (stops at 'x')
        assert_eq!(from_hex_lossy(""), Vec::<u8>::new());
    }

    #[test]
    fn exact_hex_rejects_lossy_inputs() {
        assert_eq!(from_hex_exact::<2>("00ff").unwrap(), [0x00, 0xff]);
        assert_eq!(
            from_hex_exact::<1>("0xab").unwrap_err().to_string(),
            "hex must be unprefixed; remove the leading 0x before passing private key material"
        );
        assert_eq!(
            from_hex_exact::<2>("abc").unwrap_err(),
            HexDecodeError::OddLength { actual: 3 }
        );
        assert_eq!(
            from_hex_exact::<2>("ab").unwrap_err(),
            HexDecodeError::WrongLength {
                expected: 2,
                actual: 1
            }
        );
    }

    #[test]
    fn le_conversions() {
        // 0x0102 little-endian = bytes [0x02, 0x01, 0, 0]
        let v = BigUint::from(0x0102u32);
        assert_eq!(biguint_to_le_bytes(&v, 4), vec![0x02, 0x01, 0x00, 0x00]);
        assert_eq!(le_bytes_to_biguint(&[0x02, 0x01, 0x00, 0x00]), v);
    }
}
