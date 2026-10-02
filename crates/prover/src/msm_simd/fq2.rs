//! Experiment D: BN254 Fq2 = Fq[u] / (u^2 + 1) on top of the custom Fq
//! representations, for the G2 kernel.
//!
//! - `Fq2Ark`: arkworks' `Fq2`, unchanged (baseline).
//! - `Fq2Of<B>`: Karatsuba multiplication (3 base multiplications) and
//!   complex squaring (2) over any base representation `B`.
//! - `Fq2Simd` (WASM only): the 9x29 base, with the three Karatsuba products
//!   computed by one 4-lane `mul4` (lanes a0*b0, a1*b1, (a0+a1)(b0+b1)) and
//!   the two squaring products by one `mul4`.

use ark_bn254::Fq2;
use ark_ff::{AdditiveGroup, Field};

use crate::msm_simd::field::PocField;
use crate::msm_simd::u29x9::U29x9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Fq2Ark(pub Fq2);

impl PocField for Fq2Ark {
    type Ark = Fq2;
    const NAME: &'static str = "fq2-ark";
    #[inline(always)]
    fn zero() -> Self {
        Fq2Ark(Fq2::ZERO)
    }
    #[inline(always)]
    fn one() -> Self {
        Fq2Ark(Fq2::ONE)
    }
    #[inline(always)]
    fn from_ark(x: &Fq2) -> Self {
        Fq2Ark(*x)
    }
    #[inline(always)]
    fn to_ark(&self) -> Fq2 {
        self.0
    }
    #[inline(always)]
    fn add(&self, rhs: &Self) -> Self {
        Fq2Ark(self.0 + rhs.0)
    }
    #[inline(always)]
    fn sub(&self, rhs: &Self) -> Self {
        Fq2Ark(self.0 - rhs.0)
    }
    #[inline(always)]
    fn double(&self) -> Self {
        Fq2Ark(AdditiveGroup::double(&self.0))
    }
    #[inline(always)]
    fn neg(&self) -> Self {
        Fq2Ark(-self.0)
    }
    #[inline(always)]
    fn mul(&self, rhs: &Self) -> Self {
        Fq2Ark(self.0 * rhs.0)
    }
    #[inline(always)]
    fn square(&self) -> Self {
        Fq2Ark(Field::square(&self.0))
    }
    #[inline(always)]
    fn is_zero(&self) -> bool {
        self.0 == Fq2::ZERO
    }
    #[inline(always)]
    fn equals(&self, rhs: &Self) -> bool {
        self.0 == rhs.0
    }
    #[inline]
    fn inverse(&self) -> Self {
        Fq2Ark(Field::inverse(&self.0).expect("non-zero"))
    }
}

/// Fq2 over a base representation `B` (`c0 + c1 * u`, `u^2 = -1`).
#[derive(Clone, Copy, Debug)]
pub struct Fq2Of<B>(pub B, pub B);

macro_rules! fq2_common {
    () => {
        type Ark = Fq2;
        #[inline(always)]
        fn zero() -> Self {
            Self(U29x9::zero(), U29x9::zero())
        }
        #[inline(always)]
        fn one() -> Self {
            Self(U29x9::one(), U29x9::zero())
        }
        #[inline(always)]
        fn from_ark(x: &Fq2) -> Self {
            Self(U29x9::from_ark(&x.c0), U29x9::from_ark(&x.c1))
        }
        #[inline(always)]
        fn to_ark(&self) -> Fq2 {
            Fq2::new(self.0.to_ark(), self.1.to_ark())
        }
        #[inline(always)]
        fn add(&self, rhs: &Self) -> Self {
            Self(self.0.add(&rhs.0), self.1.add(&rhs.1))
        }
        #[inline(always)]
        fn sub(&self, rhs: &Self) -> Self {
            Self(self.0.sub(&rhs.0), self.1.sub(&rhs.1))
        }
        #[inline(always)]
        fn double(&self) -> Self {
            Self(self.0.double(), self.1.double())
        }
        #[inline(always)]
        fn neg(&self) -> Self {
            Self(self.0.neg(), self.1.neg())
        }
        #[inline(always)]
        fn is_zero(&self) -> bool {
            self.0.is_zero() && self.1.is_zero()
        }
        #[inline(always)]
        fn equals(&self, rhs: &Self) -> bool {
            self.0.equals(&rhs.0) && self.1.equals(&rhs.1)
        }
    };
}

impl PocField for Fq2Of<U29x9> {
    const NAME: &'static str = "fq2-u29x9";
    fq2_common!();
    #[inline(always)]
    fn mul(&self, rhs: &Self) -> Self {
        let v0 = self.0.mul(&rhs.0);
        let v1 = self.1.mul(&rhs.1);
        let v2 = self.0.add(&self.1).mul(&rhs.0.add(&rhs.1));
        Self(v0.sub(&v1), v2.sub(&v0).sub(&v1))
    }
    #[inline(always)]
    fn square(&self) -> Self {
        let c0 = self.0.add(&self.1).mul(&self.0.sub(&self.1));
        let c1 = self.0.double().mul(&self.1);
        Self(c0, c1)
    }
}

#[cfg(target_arch = "wasm32")]
pub use simd::Fq2Simd;

#[cfg(target_arch = "wasm32")]
mod simd {
    use super::*;
    use crate::msm_simd::simd::U29x9x4;

    #[inline(never)]
    fn mul4(a: &U29x9x4, b: &U29x9x4) -> U29x9x4 {
        U29x9x4(crate::msm_simd::simd::mul4(&a.0, &b.0))
    }

    /// Fq2 over the 9x29 base whose base products run in `mul4` lanes.
    #[derive(Clone, Copy, Debug)]
    pub struct Fq2Simd(pub U29x9, pub U29x9);

    impl PocField for Fq2Simd {
        const NAME: &'static str = "fq2-simd";
        fq2_common!();
        #[inline(always)]
        fn mul(&self, rhs: &Self) -> Self {
            let zero = U29x9::zero();
            let a = U29x9x4::pack([&self.0, &self.1, &self.0.add(&self.1), &zero]);
            let b = U29x9x4::pack([&rhs.0, &rhs.1, &rhs.0.add(&rhs.1), &zero]);
            let [v0, v1, v2, _] = mul4(&a, &b).unpack();
            Self(v0.sub(&v1), v2.sub(&v0).sub(&v1))
        }
        #[inline(always)]
        fn square(&self) -> Self {
            let zero = U29x9::zero();
            let a = U29x9x4::pack([&self.0.add(&self.1), &self.0.double(), &zero, &zero]);
            let b = U29x9x4::pack([&self.0.sub(&self.1), &self.1, &zero, &zero]);
            let [c0, c1, _, _] = mul4(&a, &b).unpack();
            Self(c0, c1)
        }
    }
}
