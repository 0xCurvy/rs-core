//! BN254 scalar field (`Fr`) - the SNARK scalar field shared by circom, snarkjs,
//! poseidon-lite, and @zk-kit:
//!
//! ```text
//! 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! ```
//!
//! The public API speaks **decimal strings** at the boundary; internally we use
//! `ark_bn254::Fr`. These helpers are the single conversion point.

use core::fmt;

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
            Self::OutOfRange => {
                f.write_str("field element is greater than or equal to the BN254 modulus")
            }
        }
    }
}

impl std::error::Error for Bn254FrError {}

impl Bn254Fr {
    /// Parse a canonical unsigned decimal integer in `[0, p)`.
    pub fn try_from_dec(s: &str) -> Result<Self, Bn254FrError> {
        use crate::encoding::{DecimalU256Error, try_dec_to_le_32};
        if s.len() > FIELD_MODULUS_DEC.len() {
            return Err(Bn254FrError::OutOfRange);
        }
        let bytes = try_dec_to_le_32(s).map_err(|error| match error {
            DecimalU256Error::InvalidDecimal => Bn254FrError::InvalidDecimal,
            DecimalU256Error::OutOfRange => Bn254FrError::OutOfRange,
        })?;
        if s.len() > 1 && s.starts_with('0') {
            return Err(Bn254FrError::NonCanonicalDecimal);
        }
        crate::secret_field::from_le_bytes(&bytes)
            .map(Self)
            .ok_or(Bn254FrError::OutOfRange)
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
        crate::secret_field::to_le_bytes(self.0)
    }
}

/// Parse a decimal string into a field element, **reducing modulo the field
/// modulus** (`modulus + 5` → `5`, `-1` → `modulus − 1`).
///
/// This is deliberate: it mirrors how poseidon-lite / circom coerce inputs, so it
/// is the correct boundary for *field-element* values (Poseidon inputs, amounts,
/// commitments). For *raw 256-bit* integers that must NOT be reduced - the cipher
/// key material, `sha256BigInt` inputs, and the EdDSA signing message - use the
/// checked raw encodings in [`crate::encoding`], such as
/// [`crate::encoding::try_dec_to_le_32`].
///
/// Panics only if `s` is not a valid (optionally signed) decimal integer.
pub fn fr_from_dec(s: &str) -> Fr {
    try_fr_from_dec(s).expect("invalid field decimal")
}

/// Fallible reducing decimal parser. Uses bounded-size arithmetic, including for
/// long inputs, and never includes input contents in an error.
/// Work depends on digit count; sign and validation status remain observable.
pub fn try_fr_from_dec(s: &str) -> Result<Fr, Bn254FrError> {
    try_fr_from_decimal_bytes(s.as_bytes())
}

pub(crate) fn try_fr_from_decimal_bytes(s: &[u8]) -> Result<Fr, Bn254FrError> {
    use crate::secret_field::{self, Element};
    use crypto_bigint::{U256, ctutils::CtSelect};
    use zeroize::Zeroizing;

    let negative = s.first() == Some(&b'-');
    #[cfg(feature = "leakage")]
    let negative = crate::leakage::public_flag(negative);
    let digits = &s[usize::from(negative)..];
    if digits.is_empty() {
        return Err(Bn254FrError::InvalidDecimal);
    }
    let mut invalid = 0_u8;
    let mut value = Zeroizing::new(Element::ZERO);
    for chunk in digits.chunks(19) {
        let mut word = Zeroizing::new(0_u64);
        for character in chunk {
            let digit = character.wrapping_sub(b'0');
            invalid |= u8::from(digit > 9);
            *word = word.wrapping_mul(10).wrapping_add(u64::from(digit));
        }
        let scale = Element::new(&U256::from(10_u64.pow(chunk.len() as u32)));
        *value = secret_field::add(*value * scale, Element::new(&U256::from(*word)));
    }
    let invalid = invalid != 0;
    #[cfg(feature = "leakage")]
    let invalid = crate::leakage::public_flag(invalid);
    if invalid {
        return Err(Bn254FrError::InvalidDecimal);
    }
    let negated = Zeroizing::new(secret_field::negate(*value));
    Ok(secret_field::into_ark(Element::from_montgomery(
        value
            .as_montgomery()
            .ct_select(negated.as_montgomery(), u8::from(negative).into()),
    )))
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
    let mut bytes = crate::secret_field::to_le_bytes(*x);
    bytes.reverse();
    bytes
}

/// Interpret big-endian bytes as an integer reduced into the field (`mod modulus`).
pub fn fr_from_be_bytes_mod(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Decode one canonical 32-byte big-endian field element.
///
/// Unlike [`fr_from_be_bytes_mod`], this rejects encodings greater than or equal
/// to the modulus instead of silently reducing them. Use it for persisted or
/// network-supplied tree data where non-canonical encodings indicate corruption.
pub fn fr_from_be_32_checked(bytes: &[u8]) -> Option<Fr> {
    let mut encoded = zeroize::Zeroizing::new(<[u8; 32]>::try_from(bytes).ok()?);
    encoded.reverse();
    crate::secret_field::from_le_bytes(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_field_decimal_reduction_matches_integer_oracle() {
        let modulus = BigUint::parse_bytes(FIELD_MODULUS_DEC.as_bytes(), 10).unwrap();
        for length in [1, 18, 19, 20, 38, 76, 77, 78, 256, 4096] {
            for digit in ['0', '1', '5', '9'] {
                let decimal = digit.to_string().repeat(length);
                let integer = BigUint::parse_bytes(decimal.as_bytes(), 10).unwrap();
                let expected = fr_from_biguint(&(&integer % &modulus));
                assert_eq!(try_fr_from_dec(&decimal).unwrap(), expected);
                assert_eq!(try_fr_from_dec(&format!("-{decimal}")).unwrap(), -expected);
            }
        }
        for invalid in ["", "-", "+5", "5_", "1e2", "１２", " 5", "5 "] {
            assert!(try_fr_from_dec(invalid).is_err());
        }
        for index in 0..78 {
            let mut malformed = [b'9'; 78];
            malformed[index] = 0xff;
            assert!(try_fr_from_decimal_bytes(&malformed).is_err());
        }
    }

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
        let p_plus_5 =
            "21888242871839275222246405745257275088548364400416034343698204186575808495622";
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
    fn canonical_binary_decoder_rejects_reduction_and_wrong_lengths() {
        let five = fr_to_be_32(&Fr::from(5u64));
        assert_eq!(fr_from_be_32_checked(&five), Some(Fr::from(5u64)));
        assert_eq!(fr_from_be_32_checked(&five[..31]), None);

        let modulus = <Fr as PrimeField>::MODULUS.to_bytes_be();
        assert_eq!(fr_from_be_32_checked(&modulus), None);
    }

    #[test]
    fn checked_field_parser_rejects_reduction_and_noncanonical_decimal() {
        assert_eq!(Bn254Fr::try_from_dec("42").unwrap().to_dec(), "42");
        assert_eq!(
            Bn254Fr::try_from_dec("00"),
            Err(Bn254FrError::NonCanonicalDecimal)
        );
        assert_eq!(
            Bn254Fr::try_from_dec("-1"),
            Err(Bn254FrError::InvalidDecimal)
        );
        assert_eq!(
            Bn254Fr::try_from_dec(FIELD_MODULUS_DEC),
            Err(Bn254FrError::OutOfRange)
        );
    }
}
