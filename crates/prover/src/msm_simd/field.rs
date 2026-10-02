//! The arithmetic interface shared by every representation, so the MSM kernel
//! and the benchmarks are written once and instantiated per representation.

use ark_bn254::Fq;
use ark_ff::{AdditiveGroup, BigInt, Field, PrimeField};

/// A BN254 base-field element in some Montgomery representation.
///
/// Representations may keep values only *weakly* reduced (for example in
/// `[0, 2p)`); `equals`, `is_zero` and `to_ark` compare and convert modulo p.
/// Every operation accepts any value the representation's own operations
/// produce.
pub trait PocField: Copy + Send + Sync + 'static + core::fmt::Debug {
    /// The arkworks field this represents (`Fq` for G1, `Fq2` for G2).
    type Ark: Field;
    const NAME: &'static str;
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

/// Baseline: arkworks' 4x64-bit Montgomery `Fq`, unchanged (a newtype only so
/// the trait's method names do not shadow arkworks' own on `Fq`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ark(pub Fq);

impl PocField for Ark {
    type Ark = Fq;
    const NAME: &'static str = "ark";
    #[inline(always)]
    fn zero() -> Self {
        Ark(Fq::ZERO)
    }
    #[inline(always)]
    fn one() -> Self {
        Ark(Fq::ONE)
    }
    #[inline(always)]
    fn from_ark(x: &Fq) -> Self {
        Ark(*x)
    }
    #[inline(always)]
    fn to_ark(&self) -> Fq {
        self.0
    }
    #[inline(always)]
    fn add(&self, rhs: &Self) -> Self {
        Ark(self.0 + rhs.0)
    }
    #[inline(always)]
    fn sub(&self, rhs: &Self) -> Self {
        Ark(self.0 - rhs.0)
    }
    #[inline(always)]
    fn double(&self) -> Self {
        Ark(AdditiveGroup::double(&self.0))
    }
    #[inline(always)]
    fn neg(&self) -> Self {
        Ark(-self.0)
    }
    #[inline(always)]
    fn mul(&self, rhs: &Self) -> Self {
        Ark(self.0 * rhs.0)
    }
    #[inline(always)]
    fn square(&self) -> Self {
        Ark(Field::square(&self.0))
    }
    #[inline(always)]
    fn is_zero(&self) -> bool {
        self.0 == Fq::ZERO
    }
    #[inline(always)]
    fn equals(&self, rhs: &Self) -> bool {
        self.0 == rhs.0
    }
    #[inline]
    fn inverse(&self) -> Self {
        Ark(Field::inverse(&self.0).expect("non-zero"))
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
