//! Byte/integer encodings used at the EdDSA boundary.
//!
//! EdDSA-Poseidon (`@zk-kit/eddsa-poseidon`) is **little-endian** for all
//! buffer<->integer conversions (`leBufferToBigInt` / `leBigIntToBuffer`) — the
//! opposite of the note cipher, which is big-endian. Keeping the two explicit
//! here prevents accidental endianness flips.

use core::str::FromStr;

use num_bigint::BigUint;

/// Parse a non-negative decimal string into a raw integer (no field reduction) —
/// the boundary for the cipher key material, `sha256BigInt`, and the EdDSA message.
pub fn dec_to_biguint(s: &str) -> BigUint {
    BigUint::from_str(s).unwrap_or_else(|_| panic!("invalid decimal integer: {s:?}"))
}

/// Decode a hex string into bytes with the **lenient semantics of Node's
/// `Buffer.from(hex, "hex")`** (the EdDSA private-key encoding the SDK relies on):
/// parse byte pairs left-to-right, stop at the first invalid hex character, and
/// drop a trailing odd nibble. No `0x` stripping — `Buffer.from` does not strip it
/// either (it would stop at the `x`).
pub fn from_hex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        match (hex_nibble(bytes[i]), hex_nibble(bytes[i + 1])) {
            (Some(hi), Some(lo)) => {
                out.push((hi << 4) | lo);
                i += 2;
            }
            _ => break, // stop at the first invalid character (Node behaviour)
        }
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Little-endian bytes -> integer (`leBufferToBigInt`).
pub fn le_bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

/// Integer -> fixed 32-byte **big-endian** bytes (`bigIntToBytes(value, 32)`), used
/// for the cipher key material and `sha256BigInt`. Packs the **raw** value with NO
/// field reduction (left-padded with zeros). Panics if the value does not fit in 32
/// bytes (matches the TS overflow guard at `value >= 2^256`).
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

/// Integer -> fixed-length little-endian bytes (`leBigIntToBuffer(value, len)`).
/// Panics if the value does not fit in `len` bytes (matches the JS overflow guard).
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
        assert_eq!(from_hex("00ff10"), vec![0x00, 0xff, 0x10]);
        assert_eq!(from_hex("abc"), vec![0xab]); // odd: trailing nibble dropped
        assert_eq!(from_hex("zz"), Vec::<u8>::new()); // invalid: stop immediately
        assert_eq!(from_hex("0xab"), Vec::<u8>::new()); // no 0x strip (stops at 'x')
        assert_eq!(from_hex(""), Vec::<u8>::new());
    }

    #[test]
    fn le_conversions() {
        // 0x0102 little-endian = bytes [0x02, 0x01, 0, 0]
        let v = BigUint::from(0x0102u32);
        assert_eq!(biguint_to_le_bytes(&v, 4), vec![0x02, 0x01, 0x00, 0x00]);
        assert_eq!(le_bytes_to_biguint(&[0x02, 0x01, 0x00, 0x00]), v);
    }
}
