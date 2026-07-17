//! BN254 scalar field (`Fr`) - the SNARK scalar field shared by circom, snarkjs,
//! poseidon-lite, and @zk-kit:
//!
//! ```text
//! 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! ```
//!
//! The public API speaks **decimal strings** at the boundary; internally we use
//! `ark_bn254::Fr`. These helpers are the single conversion point.

use core::{fmt, str::FromStr};

use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

/// The BN254 scalar field element.
pub use ark_bn254::Fr;

/// Decimal string of the field modulus (`SNARK_SCALAR_FIELD`).
pub const FIELD_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// A canonically parsed BN254 field element for untrusted protocol boundaries.
///
/// Unlike [`fr_from_dec`], this type rejects non-canonical encodings instead of
/// reducing them modulo the field. Internally trusted arithmetic can continue to
/// use [`Fr`] directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254Fr(Fr);

/// Failure to parse a canonical BN254 field element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bn254FrError {
    InvalidDecimal,
    NonCanonicalDecimal,
    OutOfRange,
}

impl fmt::Display for Bn254FrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDecimal => f.write_str("invalid unsigned decimal field element"),
            Self::NonCanonicalDecimal => f.write_str("non-canonical decimal field element"),
            Self::OutOfRange => f.write_str("field element is greater than or equal to the BN254 modulus"),
        }
    }
}

impl std::error::Error for Bn254FrError {}

impl Bn254Fr {
    /// Parse a canonical unsigned decimal integer in `[0, p)`.
    pub fn try_from_dec(s: &str) -> Result<Self, Bn254FrError> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Bn254FrError::InvalidDecimal);
        }
        if s.len() > 1 && s.starts_with('0') {
            return Err(Bn254FrError::NonCanonicalDecimal);
        }
        let value = BigUint::parse_bytes(s.as_bytes(), 10).ok_or(Bn254FrError::InvalidDecimal)?;
        let modulus = BigUint::parse_bytes(FIELD_MODULUS_DEC.as_bytes(), 10).expect("valid BN254 modulus");
        if value >= modulus {
            return Err(Bn254FrError::OutOfRange);
        }
        Ok(Self(fr_from_biguint(&value)))
    }

    /// Wrap an already canonical internal field element.
    #[inline]
    pub fn from_fr(value: Fr) -> Self {
        Self(value)
    }

    #[inline]
    pub fn as_fr(&self) -> &Fr {
        &self.0
    }

    #[inline]
    pub fn into_inner(self) -> Fr {
        self.0
    }

    pub fn to_dec(self) -> String {
        fr_to_dec(&self.0)
    }

    pub fn to_le_32(self) -> [u8; 32] {
        let bytes = fr_to_biguint(&self.0).to_bytes_le();
        let mut out = [0u8; 32];
        out[..bytes.len()].copy_from_slice(&bytes);
        out
    }
}

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

    #[test]
    fn checked_field_parser_rejects_reduction_and_noncanonical_decimal() {
        assert_eq!(Bn254Fr::try_from_dec("42").unwrap().to_dec(), "42");
        assert_eq!(Bn254Fr::try_from_dec("00"), Err(Bn254FrError::NonCanonicalDecimal));
        assert_eq!(Bn254Fr::try_from_dec("-1"), Err(Bn254FrError::InvalidDecimal));
        assert_eq!(Bn254Fr::try_from_dec(FIELD_MODULUS_DEC), Err(Bn254FrError::OutOfRange));
    }
}
