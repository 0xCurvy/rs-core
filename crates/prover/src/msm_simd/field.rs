//! The arithmetic interface shared by the kernel's field representations, so
//! the MSM kernel is written once for G1 (`U29x9`) and G2 (`Fq2Simd`).

use ark_bn254::Fq;
use ark_ff::{BigInt, Field, PrimeField};

/// A BN254 base-field element in some Montgomery representation.
///
/// Representations may keep values only *weakly* reduced (for example in
/// `[0, 2p)`); `equals`, `is_zero` and `to_ark` compare and convert modulo p.
/// Every operation accepts any value the representation's own operations
/// produce.
pub trait PocField: Copy + Send + Sync + 'static + core::fmt::Debug {
    /// The arkworks field this represents (`Fq` for G1, `Fq2` for G2).
    type Ark: Field;
    fn zero() -> Self;
    fn one() -> Self;
    fn from_ark(x: &Self::Ark) -> Self;
    fn to_ark(&self) -> Self::Ark;
    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn double(&self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn square(&self) -> Self;
    fn is_zero(&self) -> bool;
    fn equals(&self, rhs: &Self) -> bool;
    /// Field inversion through arkworks (two conversions plus arkworks'
    /// binary-GCD inversion). The kernel calls it once per batch.
    #[inline]
    fn inverse(&self) -> Self {
        Self::from_ark(&Field::inverse(&self.to_ark()).expect("non-zero"))
    }
}

/// The Montgomery form of an arkworks element (`a * 2^256 mod p`).
#[inline(always)]
pub fn ark_mont_limbs(x: &Fq) -> [u64; 4] {
    (x.0).0
}

/// Build an arkworks element from its Montgomery form, which must be `< p`.
#[inline(always)]
pub fn ark_from_mont_limbs(limbs: [u64; 4]) -> Fq {
    debug_assert!(BigInt(limbs) < Fq::MODULUS);
    Fq::new_unchecked(BigInt(limbs))
}
