//! BN254 Fq2 = Fq[u] / (u^2 + 1) over the 9x29 base, for the G2 kernel:
//! `Fq2Simd` computes the three Karatsuba products with one 4-lane `mul4`
//! (lanes a0*b0, a1*b1, (a0+a1)(b0+b1)) and the two complex-squaring products
//! with one `mul4`.

use ark_bn254::Fq2;

use crate::msm_simd::field::PocField;
use crate::msm_simd::u29x9::U29x9;

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
