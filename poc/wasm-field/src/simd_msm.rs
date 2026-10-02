//! Batch application with four simd128 lanes (WASM only), for any
//! [`Lanes4`] field: G1 over `U29x9`, G2 over `Fq2Simd`.
//!
//! Same contract as `msm::ScalarApply`, so the scheduling (distinct buckets,
//! deferral, XYZZ overflow) is untouched. Pending addition `k` runs in lane
//! `k % 4`: each lane keeps its own Montgomery-trick prefix chain, the four
//! lane products share one field inversion (plus 9 multiplications to split
//! it), and every multiplication of the forward and backward passes is a
//! 4-lane `mul4`/`sqr4`. Classification (Add / Double / Cancel) and the
//! denominators stay scalar; Double and Cancel lanes are patched in scalar
//! code, and a Cancel lane uses denominator 1 so its chain is unaffected.
//! Bucket coordinates are gathered into limb-sliced form and scattered back
//! per group of four. The running-sum reduction is `simd_reduce`.

#![cfg(target_arch = "wasm32")]

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};

use crate::lanes::Lanes4;
use crate::msm::{Aff, BatchApply, FREE, Pending, SCHEDULED, Stats, Step, Xyzz};

pub struct SimdApply<F: Lanes4> {
    prefix: Vec<F::V>,
    dens: Vec<F::V>,
}

impl<F: Lanes4> Default for SimdApply<F> {
    fn default() -> Self {
        SimdApply {
            prefix: Vec::new(),
            dens: Vec::new(),
        }
    }
}

impl<C: SWCurveConfig<BaseField = F::Ark>, F: Lanes4> BatchApply<C, F> for SimdApply<F> {
    const NAME: &'static str = "simd4";

    fn window_sum(buckets: &[Aff<F>], overflow: &[Xyzz<F>]) -> Projective<C> {
        crate::simd_reduce::window_sum::<C, F>(buckets, overflow)
    }

    fn apply(
        &mut self,
        buckets: &mut [Aff<F>],
        batch: &mut [Pending<F>],
        state: &mut [u8],
        stats: &mut Stats,
    ) {
        let n = batch.len();
        let groups = n.div_ceil(4);
        let one = F::one();
        let zero = F::zero();
        self.prefix.clear();
        self.dens.clear();

        // Forward: classify, and chain the denominators per lane.
        let mut product = F::pack(&[one; 4]);
        for g in 0..groups {
            let mut den = [one; 4];
            for (l, slot) in den.iter_mut().enumerate() {
                let k = 4 * g + l;
                if k >= n {
                    break;
                }
                let pending = &mut batch[k];
                let bucket = &buckets[pending.bucket as usize];
                if !bucket.x.equals(&pending.point.x) {
                    pending.step = Step::Add;
                    *slot = pending.point.x.sub(&bucket.x);
                } else if bucket.y.equals(&pending.point.y) && !bucket.y.is_zero() {
                    pending.step = Step::Double;
                    *slot = bucket.y.double();
                } else {
                    pending.step = Step::Cancel;
                }
            }
            let den4 = F::pack(&den);
            self.prefix.push(product);
            self.dens.push(den4);
            product = F::mul4(&product, &den4);
        }

        // One inversion for the four lane products.
        let p = F::unpack(&product);
        let (p01, p23) = (p[0].mul(&p[1]), p[2].mul(&p[3]));
        let inv = p01.mul(&p23).inverse();
        stats.inversions += 1;
        let (i01, i23) = (inv.mul(&p23), inv.mul(&p01));
        let mut inverse = F::pack(&[
            i01.mul(&p[1]),
            i01.mul(&p[0]),
            i23.mul(&p[3]),
            i23.mul(&p[2]),
        ]);

        // Backward: peel each lane's inverse off its running product.
        for g in (0..groups).rev() {
            let (mut bx, mut by, mut px, mut py) = ([zero; 4], [zero; 4], [zero; 4], [zero; 4]);
            let mut special = false;
            for l in 0..4 {
                let k = 4 * g + l;
                if k >= n {
                    break;
                }
                let pending = &batch[k];
                let bucket = &buckets[pending.bucket as usize];
                bx[l] = bucket.x;
                by[l] = bucket.y;
                px[l] = pending.point.x;
                py[l] = pending.point.y;
                special |= pending.step != Step::Add;
            }
            let (bx4, by4, px4, py4) = (F::pack(&bx), F::pack(&by), F::pack(&px), F::pack(&py));
            let mut num4 = F::sub4(&py4, &by4);
            if special {
                let mut num = F::unpack(&num4);
                for l in 0..4 {
                    let k = 4 * g + l;
                    if k < n && batch[k].step == Step::Double {
                        let square = bx[l].square();
                        num[l] = square.double().add(&square);
                    }
                }
                num4 = F::pack(&num);
            }
            let t = F::mul4(&inverse, &self.prefix[g]);
            let lambda = F::mul4(&num4, &t);
            inverse = F::mul4(&inverse, &self.dens[g]);
            let x3 = F::sub4(&F::sub4(&F::sqr4(&lambda), &bx4), &px4);
            let y3 = F::sub4(&F::mul4(&lambda, &F::sub4(&bx4, &x3)), &by4);
            let (xs, ys) = (F::unpack(&x3), F::unpack(&y3));
            for l in 0..4 {
                let k = 4 * g + l;
                if k >= n {
                    break;
                }
                let pending = &batch[k];
                let index = pending.bucket as usize;
                if state[index] == SCHEDULED {
                    state[index] = FREE;
                }
                buckets[index] = match pending.step {
                    Step::Add | Step::Double => {
                        if pending.step == Step::Add {
                            stats.adds += 1;
                        } else {
                            stats.doubles += 1;
                        }
                        Aff {
                            x: xs[l],
                            y: ys[l],
                            inf: false,
                        }
                    }
                    Step::Cancel => {
                        stats.cancels += 1;
                        Aff::identity()
                    }
                };
            }
        }
    }
}
