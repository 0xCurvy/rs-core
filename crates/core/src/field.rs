//! BN254 scalar field (`Fr`) - the SNARK scalar field shared by circom, snarkjs,
//! poseidon-lite, and @zk-kit:
//!
//! ```text
//! 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! ```
//!
//! The public API speaks **decimal strings** at the boundary; internally we use
//! `ark_bn254::Fr`. These helpers are the single conversion point.

use core::str::FromStr;

use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

/// The BN254 scalar field element.
pub use ark_bn254::Fr;

/// Decimal string of the field modulus (`SNARK_SCALAR_FIELD`).
pub const FIELD_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Parse a decimal string into a field element, **reducing modulo the field
/// modulus** (`modulus + 5` → `5`, `-1` → `modulus − 1`).
///
/// This is deliberate: it mirrors how poseidon-lite / circom coerce inputs, so it
/// is the correct boundary for *field-element* values (Poseidon inputs, amounts,
/// commitments). For *raw 256-bit* integers that must NOT be reduced - the cipher
/// key material, `sha256BigInt` inputs, and the EdDSA signing message - use a
/// [`num_bigint::BigUint`] with the raw byte encodings in [`crate::encoding`].
///
/// Panics only if `s` is not a valid (optionally signed) decimal integer.
pub fn fr_from_dec(s: &str) -> Fr {
    Fr::from_str(s).unwrap_or_else(|_| panic!("invalid field decimal: {s:?}"))
}

/// Reduce a non-negative integer modulo the field modulus into an `Fr`.
pub fn fr_from_biguint(v: &BigUint) -> Fr {
    Fr::from_be_bytes_mod_order(&v.to_bytes_be())
}

/// Render a field element as a canonical non-negative decimal string.
pub fn fr_to_dec(x: &Fr) -> String {
    fr_to_biguint(x).to_str_radix(10)
}

/// Field element as a `BigUint` of its canonical representative in `[0, modulus)`.
pub fn fr_to_biguint(x: &Fr) -> BigUint {
    BigUint::from_bytes_be(&x.into_bigint().to_bytes_be())
}

/// 32-byte **big-endian** packing of a field element's canonical representative.
/// This is the wire encoding used by the note cipher and `sha256BigInt`.
pub fn fr_to_be_32(x: &Fr) -> [u8; 32] {
    let be = x.into_bigint().to_bytes_be(); // BN254 Fr -> BigInt<4> -> exactly 32 bytes
    debug_assert_eq!(be.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&be);
    out
}

/// Interpret big-endian bytes as an integer reduced into the field (`mod modulus`).
pub fn fr_from_be_bytes_mod(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_roundtrip() {
        for s in [
            "0",
            "1",
            "42",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        ] {
            assert_eq!(fr_to_dec(&fr_from_dec(s)), s);
        }
    }

    #[test]
    fn from_dec_reduces_out_of_range() {
        // Documents the boundary contract: fr_from_dec reduces mod modulus rather
        // than rejecting (matching poseidon-lite/circom coercion).
        let p_plus_5 = "21888242871839275222246405745257275088548364400416034343698204186575808495622";
        assert_eq!(fr_from_dec(p_plus_5), Fr::from(5u64));
        assert_eq!(fr_from_dec("-1"), -Fr::from(1u64));
    }

    #[test]
    fn field_modulus_constant_matches_arkworks() {
        // Catch any off-by-one in FIELD_MODULUS_DEC against arkworks' own modulus.
        let be = <Fr as PrimeField>::MODULUS.to_bytes_be();
        let dec = BigUint::from_bytes_be(&be).to_str_radix(10);
        assert_eq!(dec, FIELD_MODULUS_DEC);
    }
}
