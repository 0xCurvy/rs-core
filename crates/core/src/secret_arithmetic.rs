//! Fixed-width arithmetic for secret keys and nonces. Scalar multiplication and
//! response arithmetic use fixed schedules. Input validity and nonce rejection
//! produce observable status; public verification uses arkworks/BigUint.
use crate::{
    babyjubjub::{BASE8, Point},
    field::Fr,
    secret_field::{self, Element as F},
};
use ark_ff::{BigInteger, PrimeField};
use crypto_bigint::{
    U256, U512, const_monty_params,
    ctutils::{CtEq, CtLt, CtSelect},
    modular::ConstMontyForm,
};
use zeroize::{Zeroize, Zeroizing};

const_monty_params!(
    ScalarModulus,
    U256,
    "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1"
);
const_monty_params!(
    WideScalarModulus,
    U512,
    "0000000000000000000000000000000000000000000000000000000000000000060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1"
);
type S = ConstMontyForm<ScalarModulus, { U256::LIMBS }>;
type W = ConstMontyForm<WideScalarModulus, { U512::LIMBS }>;
const NONCE_LIMIT: U512 = U512::from_be_hex(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbba4adb0e45af571b8d20dfc055ea708b9b93530a07b13bca1bb54118134de2",
);
const ORDER: U256 =
    U256::from_be_hex("060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1");

pub(crate) fn valid_secret(bytes: &[u8; 32]) -> bool {
    let n = Zeroizing::new(U256::from_le_slice(bytes));
    let valid = bool::from(n.ct_lt(&ORDER) & !n.ct_eq(&U256::ZERO));
    #[cfg(feature = "leakage")]
    let valid = crate::leakage::public_flag(valid);
    valid
}
pub(crate) fn reduce_wide(bytes: &[u8; 64]) -> [u8; 32] {
    let n = Zeroizing::new(U512::from_le_slice(bytes));
    let value = Zeroizing::new(W::new(&n));
    let reduced: Zeroizing<[u8; 64]> = Zeroizing::new(value.retrieve().to_le_bytes().into());
    let mut result = [0u8; 32];
    result.copy_from_slice(&reduced[..32]);
    result
}
pub(crate) fn nonce_candidate(bytes: &[u8; 64]) -> Option<[u8; 32]> {
    let n = Zeroizing::new(U512::from_le_slice(bytes));
    let in_range = bool::from(n.ct_lt(&NONCE_LIMIT));
    #[cfg(feature = "leakage")]
    let in_range = crate::leakage::public_flag(in_range);
    if !in_range {
        return None;
    }
    let mut reduced = reduce_wide(bytes);
    if !valid_secret(&reduced) {
        reduced.zeroize();
        return None;
    }
    Some(reduced)
}
pub(crate) fn response(
    nonce: &[u8; 32],
    challenge: Fr,
    secret: &[u8; 32],
    cofactor: u64,
) -> [u8; 32] {
    let r = Zeroizing::new(S::new(&U256::from_le_slice(nonce)));
    let key = Zeroizing::new(S::new(&U256::from_le_slice(secret)));
    let h = S::new(&U256::from_le_slice(&challenge.into_bigint().to_bytes_le()));
    let result = Zeroizing::new(*r + h * S::new(&U256::from(cofactor)) * *key);
    let bytes: [u8; 32] = result.retrieve().to_le_bytes().into();
    #[cfg(feature = "leakage")]
    let bytes = {
        let mut bytes = bytes;
        crate::leakage::public_bytes(&mut bytes);
        bytes
    };
    bytes
}

struct Projective {
    x: F,
    y: F,
    z: F,
}
impl Drop for Projective {
    fn drop(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}
impl Projective {
    fn identity() -> Self {
        Self {
            x: F::ZERO,
            y: F::ONE,
            z: F::ONE,
        }
    }
    // EFD add-2008-bbjlp, valid also for doubling and identity. BabyJubjub
    // has square a and nonsquare d: the denominators never vanish on curve.
    // https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
    fn add(&self, rhs: &Self) -> Self {
        let a = Zeroizing::new(self.z * rhs.z);
        let b = Zeroizing::new(a.square());
        let c = Zeroizing::new(self.x * rhs.x);
        let d = Zeroizing::new(self.y * rhs.y);
        let e = Zeroizing::new(F::new(&U256::from(168696u64)) * *c * *d);
        let f = Zeroizing::new(*b - *e);
        let g = Zeroizing::new(*b + *e);
        Self {
            x: *a * *f * ((self.x + self.y) * (rhs.x + rhs.y) - *c - *d),
            y: *a * *g * (*d - F::new(&U256::from(168700u64)) * *c),
            z: *f * *g,
        }
    }
    fn select(&self, rhs: &Self, bit: crypto_bigint::Choice) -> Self {
        let select =
            |x: F, y: F| F::from_montgomery(x.as_montgomery().ct_select(y.as_montgomery(), bit));
        Self {
            x: select(self.x, rhs.x),
            y: select(self.y, rhs.y),
            z: select(self.z, rhs.z),
        }
    }
}
/// Base8 multiplication over all 256 scalar bits, including zero and high bits.
pub(crate) fn base_mul(bytes: &[u8; 32]) -> Point {
    #[cfg(feature = "leakage")]
    let arithmetic = crate::leakage::phase(crate::leakage::Phase::PointArithmetic);
    let scalar = Zeroizing::new(U256::from_le_slice(bytes));
    let field = |x: Fr| F::new(&U256::from_le_slice(&x.into_bigint().to_bytes_le()));
    let base = Projective {
        x: field(BASE8.0),
        y: field(BASE8.1),
        z: F::ONE,
    };
    let mut point = Projective::identity();
    for bit in (0..256).rev() {
        let doubled = point.add(&point);
        let added = doubled.add(&base);
        point = doubled.select(&added, scalar.bit(bit));
    }
    // Constant-time safegcd inverse. Completeness guarantees nonzero Z.
    let inverse = point.z.invert();
    let invertible = bool::from(inverse.is_some());
    #[cfg(feature = "leakage")]
    let invertible = crate::leakage::public_flag(invertible);
    assert!(invertible, "complete BabyJubjub projective formula");
    let inverse = Zeroizing::new(F::from_montgomery(
        inverse
            .map(|value| *value.as_montgomery())
            .unwrap_or(U256::ZERO),
    ));
    let x = point.x * *inverse;
    let y = point.y * *inverse;
    #[cfg(feature = "leakage")]
    drop(arithmetic);
    #[cfg(feature = "leakage")]
    let _encoding = crate::leakage::phase(crate::leakage::Phase::PointEncoding);
    // These are public output coordinates; subsequent variable-time encoding
    // and signature verification depend only on data returned to the caller.
    let mut coordinates: [u8; 64] = [0; 64];
    coordinates[..32].copy_from_slice(&x.retrieve().to_le_bytes());
    coordinates[32..].copy_from_slice(&y.retrieve().to_le_bytes());
    #[cfg(feature = "leakage")]
    crate::leakage::public_bytes(&mut coordinates);
    (
        secret_field::into_ark(F::new(&U256::from_le_slice(&coordinates[..32]))),
        secret_field::into_ark(F::new(&U256::from_le_slice(&coordinates[32..]))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use num_bigint::BigUint;
    #[test]
    fn complete_formula_matches_affine_oracle_for_scalar_boundaries() {
        assert!(Fr::from(168700u64).legendre().is_qr());
        assert!(Fr::from(168696u64).legendre().is_qnr());
        let mut cases = vec![[0u8; 32], [0xffu8; 32], ORDER.to_le_bytes().into()];
        for bit in [0, 1, 63, 64, 127, 128, 191, 192, 250, 251, 254, 255] {
            let mut bytes = [0u8; 32];
            bytes[bit / 8] = 1 << (bit % 8);
            cases.push(bytes);
        }
        for i in 0..16u8 {
            cases.push(std::array::from_fn(|j| {
                i.wrapping_mul(31).wrapping_add(j as u8 * 7)
            }));
        }
        for bytes in cases {
            assert_eq!(
                base_mul(&bytes),
                crate::babyjubjub::mul_point_escalar(*BASE8, &BigUint::from_bytes_le(&bytes))
            );
        }
    }
    #[test]
    fn fixed_width_reduction_and_response_match_bigints() {
        let order = &*crate::babyjubjub::SUB_ORDER;
        let space = BigUint::from(1_u8) << 512;
        let limit: BigUint = &space - (&space % order);
        assert_eq!(BigUint::from_bytes_le(&NONCE_LIMIT.to_le_bytes()), limit);
        assert!(nonce_candidate(&NONCE_LIMIT.to_le_bytes().into()).is_none());
        assert!(nonce_candidate(&[0; 64]).is_none());
        assert!(nonce_candidate(&[0xff; 64]).is_none());
        let below: [u8; 64] = (NONCE_LIMIT - U512::ONE).to_le_bytes().into();
        assert_eq!(
            BigUint::from_bytes_le(&nonce_candidate(&below).unwrap()),
            order - BigUint::from(1_u8)
        );
        for i in 0..24u8 {
            let wide: [u8; 64] = std::array::from_fn(|j| i.wrapping_mul(43).wrapping_add(j as u8));
            assert_eq!(
                BigUint::from_bytes_le(&reduce_wide(&wide)),
                BigUint::from_bytes_le(&wide) % order
            );
            let key = std::array::from_fn(|j| wide[j]);
            let r = std::array::from_fn(|j| wide[j + 32]);
            for cofactor in [1, 8] {
                let h = Fr::from(1000u64 + i as u64);
                let expected = (BigUint::from_bytes_le(&r)
                    + BigUint::from(cofactor)
                        * crate::field::fr_to_biguint(&h)
                        * BigUint::from_bytes_le(&key))
                    % order;
                assert_eq!(
                    BigUint::from_bytes_le(&response(&r, h, &key, cofactor)),
                    expected
                );
            }
        }
    }
}
