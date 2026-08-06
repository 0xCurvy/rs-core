//! BabyJubjub twisted Edwards curve over BN254 `Fr` - a faithful port of
//! `@zk-kit/baby-jubjub@1.0.3` (EIP-2494). Only the two operations EdDSA needs are
//! ported: point addition and scalar multiplication. The curve lives over the same
//! field as everything else (`Fr`), so no separate curve crate is required.
//!
//! Curve: `a·x² + y² = 1 + d·x²y²` with `a = 168700`, `d = 168696`.

use std::{fmt, sync::LazyLock};

use ark_ff::{AdditiveGroup, Field};
use num_bigint::BigUint;
use zeroize::Zeroize;

use crate::field::{Bn254Fr, Bn254FrError, Fr, fr_from_dec};

/// An affine BabyJubjub point `(x, y)`.
pub type Point = (Fr, Fr);

/// A canonical scalar in `[0, l)`. Zero is valid for arithmetic values such as a
/// signature response, but not for a private key or nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BabyJubScalar(BigUint);

/// A canonical non-zero scalar in `[1, l)`, stored as fixed-width little-endian
/// bytes so the owned key material can be cleared on drop.
///
/// The current prototype point multiplication still converts this value to a
/// `BigUint` and is not constant-time. See the module-level security note in the
/// scalar-signature proposal before using it in a hostile co-resident setting.
pub struct BabyJubSecretScalar([u8; 32]);

/// A checked affine point in the prime-order BabyJubJub subgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BabyJubPoint {
    x: Fr,
    y: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BabyJubError {
    InvalidScalarDecimal,
    NonCanonicalScalarDecimal,
    ScalarOutOfRange,
    ZeroSecretScalar,
    InvalidCoordinate(Bn254FrError),
    PointNotOnCurve,
    PointNotInSubgroup,
    IdentityPoint,
}

impl fmt::Display for BabyJubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScalarDecimal => f.write_str("invalid unsigned decimal BabyJubJub scalar"),
            Self::NonCanonicalScalarDecimal => {
                f.write_str("non-canonical decimal BabyJubJub scalar")
            }
            Self::ScalarOutOfRange => {
                f.write_str("BabyJubJub scalar is greater than or equal to the subgroup order")
            }
            Self::ZeroSecretScalar => f.write_str("BabyJubJub secret scalar must be non-zero"),
            Self::InvalidCoordinate(e) => write!(f, "invalid BabyJubJub coordinate: {e}"),
            Self::PointNotOnCurve => f.write_str("point is not on BabyJubJub"),
            Self::PointNotInSubgroup => {
                f.write_str("point is not in the BabyJubJub prime-order subgroup")
            }
            Self::IdentityPoint => {
                f.write_str("BabyJubJub identity is not a valid public or nonce point")
            }
        }
    }
}

impl std::error::Error for BabyJubError {}

impl From<Bn254FrError> for BabyJubError {
    fn from(value: Bn254FrError) -> Self {
        Self::InvalidCoordinate(value)
    }
}

const COEFF_A_U64: u64 = 168700;
const COEFF_D_U64: u64 = 168696;

static COEFF_A: LazyLock<Fr> = LazyLock::new(|| Fr::from(COEFF_A_U64));
static COEFF_D: LazyLock<Fr> = LazyLock::new(|| Fr::from(COEFF_D_U64));

/// The BabyJubjub base point `Base8` (the order-`subOrder` subgroup generator).
pub static BASE8: LazyLock<Point> = LazyLock::new(|| {
    (
        fr_from_dec("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        fr_from_dec(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        ),
    )
});

/// The large prime subgroup order `l` (`subOrder = order >> 3`). EdDSA scalars and
/// the signature `S` are reduced modulo this.
pub static SUB_ORDER: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
        10,
    )
    .unwrap()
});

fn parse_scalar_decimal(s: &str) -> Result<BigUint, BabyJubError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BabyJubError::InvalidScalarDecimal);
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(BabyJubError::NonCanonicalScalarDecimal);
    }
    BigUint::parse_bytes(s.as_bytes(), 10).ok_or(BabyJubError::InvalidScalarDecimal)
}

impl BabyJubScalar {
    /// Construct a canonical scalar without reducing it.
    pub fn try_from_biguint(value: BigUint) -> Result<Self, BabyJubError> {
        if value >= *SUB_ORDER {
            return Err(BabyJubError::ScalarOutOfRange);
        }
        Ok(Self(value))
    }

    pub fn try_from_dec(s: &str) -> Result<Self, BabyJubError> {
        Self::try_from_biguint(parse_scalar_decimal(s)?)
    }

    pub fn try_from_le_bytes(bytes: [u8; 32]) -> Result<Self, BabyJubError> {
        Self::try_from_biguint(BigUint::from_bytes_le(&bytes))
    }

    #[inline]
    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }

    pub fn to_le_32(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes_le();
        let mut out = [0u8; 32];
        out[..bytes.len()].copy_from_slice(&bytes);
        out
    }

    pub fn to_dec(&self) -> String {
        self.0.to_str_radix(10)
    }
}

impl BabyJubSecretScalar {
    pub fn try_from_biguint(value: BigUint) -> Result<Self, BabyJubError> {
        let scalar = BabyJubScalar::try_from_biguint(value)?;
        if scalar.0 == BigUint::from(0u8) {
            return Err(BabyJubError::ZeroSecretScalar);
        }
        Ok(Self(scalar.to_le_32()))
    }

    pub fn try_from_dec(s: &str) -> Result<Self, BabyJubError> {
        Self::try_from_biguint(parse_scalar_decimal(s)?)
    }

    pub fn try_from_le_bytes(bytes: [u8; 32]) -> Result<Self, BabyJubError> {
        Self::try_from_biguint(BigUint::from_bytes_le(&bytes))
    }

    #[inline]
    pub fn to_le_32(&self) -> [u8; 32] {
        self.0
    }

    #[inline]
    pub(crate) fn to_biguint(&self) -> BigUint {
        BigUint::from_bytes_le(&self.0)
    }

    pub fn to_dec(&self) -> String {
        self.to_biguint().to_str_radix(10)
    }
}

impl Drop for BabyJubSecretScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl BabyJubPoint {
    /// Check curve and subgroup membership. The identity is allowed here for
    /// arithmetic uses; public/nonce boundaries should call [`Self::try_from_xy_non_identity`].
    pub fn try_from_xy(x: Fr, y: Fr) -> Result<Self, BabyJubError> {
        let point = (x, y);
        if !is_on_curve(point) {
            return Err(BabyJubError::PointNotOnCurve);
        }
        if !is_in_subgroup(point) {
            return Err(BabyJubError::PointNotInSubgroup);
        }
        Ok(Self { x, y })
    }

    pub fn try_from_xy_non_identity(x: Fr, y: Fr) -> Result<Self, BabyJubError> {
        let point = Self::try_from_xy(x, y)?;
        if point.is_identity() {
            return Err(BabyJubError::IdentityPoint);
        }
        Ok(point)
    }

    /// Parse canonical decimal coordinates, then check curve, subgroup, and
    /// non-identity requirements.
    pub fn try_from_dec(x: &str, y: &str) -> Result<Self, BabyJubError> {
        let x = Bn254Fr::try_from_dec(x)?.into_inner();
        let y = Bn254Fr::try_from_dec(y)?.into_inner();
        Self::try_from_xy_non_identity(x, y)
    }

    #[inline]
    pub(crate) fn from_subgroup_non_identity_unchecked(point: Point) -> Self {
        debug_assert!(is_on_curve(point));
        debug_assert!(is_in_subgroup(point));
        debug_assert_ne!(point, identity());
        Self {
            x: point.0,
            y: point.1,
        }
    }

    #[inline]
    pub fn x(&self) -> Fr {
        self.x
    }

    #[inline]
    pub fn y(&self) -> Fr {
        self.y
    }

    #[inline]
    pub fn as_tuple(&self) -> Point {
        (self.x, self.y)
    }

    #[inline]
    pub fn is_identity(&self) -> bool {
        self.as_tuple() == identity()
    }
}

/// The neutral element `(0, 1)`.
#[inline]
pub fn identity() -> Point {
    (Fr::ZERO, Fr::ONE)
}

/// Whether `point` satisfies the BabyJubJub twisted-Edwards equation.
pub fn is_on_curve(point: Point) -> bool {
    let (x, y) = point;
    let x2 = x * x;
    let y2 = y * y;
    *COEFF_A * x2 + y2 == Fr::ONE + *COEFF_D * x2 * y2
}

/// Whether an on-curve point is in the subgroup generated by [`BASE8`].
pub fn is_in_subgroup(point: Point) -> bool {
    is_on_curve(point) && mul_point_escalar(point, &SUB_ORDER) == identity()
}

/// Twisted Edwards point addition, mirroring `@zk-kit`'s exact formula:
///
/// ```text
/// x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)
/// y3 = (y1·y2 − a·x1·x2) / (1 − d·x1·x2·y1·y2)
/// ```
///
/// The addition law is complete on BabyJubjub, so the denominators never vanish.
pub fn add_point(p1: Point, p2: Point) -> Point {
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    let a = *COEFF_A;
    let d = *COEFF_D;

    let beta = x1 * y2;
    let gamma = y1 * x2;
    let delta = (y1 - a * x1) * (x2 + y2);
    let dtau = d * (beta * gamma);

    let x3 = (beta + gamma)
        * (Fr::ONE + dtau)
            .inverse()
            .expect("babyjubjub: x denominator nonzero");
    let y3 = (delta + a * beta - gamma)
        * (Fr::ONE - dtau)
            .inverse()
            .expect("babyjubjub: y denominator nonzero");
    (x3, y3)
}

/// Scalar multiplication `e · base` via LSB-first double-and-add (`mulPointEscalar`).
/// `e` is consumed as a non-negative integer of any size (it need not be reduced
/// modulo the subgroup order - the result is identical either way).
pub fn mul_point_escalar(base: Point, e: &BigUint) -> Point {
    let mut res = identity();
    let mut exp = base;
    for i in 0..e.bits() {
        if e.bit(i) {
            res = add_point(res, exp);
        }
        exp = add_point(exp, exp);
    }
    res
}

/// Direct public-key derivation from a canonical non-zero subgroup scalar.
pub fn public_key_from_scalar(scalar: &BabyJubSecretScalar) -> BabyJubPoint {
    BabyJubPoint::from_subgroup_non_identity_unchecked(mul_point_escalar(
        *BASE8,
        &scalar.to_biguint(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FIELD_MODULUS_DEC;

    #[test]
    fn scalar_boundaries_are_strict() {
        assert_eq!(
            BabyJubSecretScalar::try_from_dec("0").err(),
            Some(BabyJubError::ZeroSecretScalar)
        );
        assert_eq!(
            BabyJubScalar::try_from_dec("00").unwrap_err(),
            BabyJubError::NonCanonicalScalarDecimal
        );
        assert_eq!(
            BabyJubScalar::try_from_dec(&SUB_ORDER.to_string()).unwrap_err(),
            BabyJubError::ScalarOutOfRange
        );
        assert_eq!(
            BabyJubSecretScalar::try_from_dec("1").unwrap().to_dec(),
            "1"
        );
    }

    #[test]
    fn direct_public_key_is_checked() {
        let one = BabyJubSecretScalar::try_from_dec("1").unwrap();
        assert_eq!(public_key_from_scalar(&one).as_tuple(), *BASE8);
        assert!(BabyJubPoint::try_from_xy(BASE8.0, BASE8.1).is_ok());
        assert_eq!(
            BabyJubPoint::try_from_xy_non_identity(Fr::ZERO, Fr::ONE),
            Err(BabyJubError::IdentityPoint)
        );
        assert_eq!(
            BabyJubPoint::try_from_xy(Fr::ZERO, Fr::ZERO),
            Err(BabyJubError::PointNotOnCurve)
        );
        assert!(matches!(
            BabyJubPoint::try_from_dec(FIELD_MODULUS_DEC, "1"),
            Err(BabyJubError::InvalidCoordinate(_))
        ));
    }
}
