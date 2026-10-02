//! Running-sum bucket reduction with four simd128 lanes (WASM only), for any
//! [`Lanes4`] field.
//!
//! A window's `2^(w-1)` buckets are split into four contiguous segments, one
//! per lane. Lane `l` runs production's running-sum algorithm over its
//! segment `[s_l, e_l)`, ending with `running_l = sum B_k` and
//! `sum_l = sum (k - s_l + 1) B_k`; then
//! `sum_k (k + 1) B_k = sum_l (sum_l + s_l * running_l)`, combined in arkworks
//! (8 conversions and 3 small scalar multiplications per window).
//!
//! Every lane executes the general XYZZ formulas (madd-2008-s, add-2008-s)
//! with 4-lane arithmetic; lanes that need another case (an empty bucket, a
//! zero accumulator, equal x so doubling or cancellation, or an XYZZ
//! overflow bucket) are blended out and redone with the scalar `Xyzz` code.
//! Each lane's case is decided before any lane is updated, so a lane that
//! cancels to zero is not re-seeded from the same bucket.

#![cfg(target_arch = "wasm32")]

use core::arch::wasm32::*;

use ark_ec::PrimeGroup;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_std::Zero;

use crate::lanes::Lanes4;
use crate::msm::{Aff, Xyzz};

struct Xyzz4<F: Lanes4> {
    x: F::V,
    y: F::V,
    zz: F::V,
    zzz: F::V,
}

impl<F: Lanes4> Clone for Xyzz4<F> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<F: Lanes4> Copy for Xyzz4<F> {}

impl<F: Lanes4> Xyzz4<F> {
    fn zero() -> Self {
        let z = F::pack(&[F::zero(); 4]);
        Xyzz4 {
            x: z,
            y: z,
            zz: z,
            zzz: z,
        }
    }

    fn get(&self, lane: usize) -> Xyzz<F> {
        Xyzz {
            x: F::get(&self.x, lane),
            y: F::get(&self.y, lane),
            zz: F::get(&self.zz, lane),
            zzz: F::get(&self.zzz, lane),
        }
    }

    fn set(&mut self, lane: usize, p: &Xyzz<F>) {
        F::set(&mut self.x, lane, &p.x);
        F::set(&mut self.y, lane, &p.y);
        F::set(&mut self.zz, lane, &p.zz);
        F::set(&mut self.zzz, lane, &p.zzz);
    }

    /// `self` in lanes where `keep` is all-ones, else `other`.
    fn select(&self, other: &Self, keep: v128) -> Self {
        Xyzz4 {
            x: F::select(&self.x, &other.x, keep),
            y: F::select(&self.y, &other.y, keep),
            zz: F::select(&self.zz, &other.zz, keep),
            zzz: F::select(&self.zzz, &other.zzz, keep),
        }
    }
}

fn lane_mask(lanes: [bool; 4]) -> v128 {
    let m = |b: bool| if b { u32::MAX } else { 0 };
    u32x4(m(lanes[0]), m(lanes[1]), m(lanes[2]), m(lanes[3]))
}

fn lane_set(mask: v128) -> [bool; 4] {
    [
        u32x4_extract_lane::<0>(mask) != 0,
        u32x4_extract_lane::<1>(mask) != 0,
        u32x4_extract_lane::<2>(mask) != 0,
        u32x4_extract_lane::<3>(mask) != 0,
    ]
}

/// madd-2008-s in every lane; also the lanes where `P = U2 - X1` is 0.
fn madd4<F: Lanes4>(r: &Xyzz4<F>, bx: &F::V, by: &F::V) -> (Xyzz4<F>, v128) {
    let u2 = F::mul4(bx, &r.zz);
    let s2 = F::mul4(by, &r.zzz);
    let p = F::sub4(&u2, &r.x);
    let rr = F::sub4(&s2, &r.y);
    let pp = F::sqr4(&p);
    let ppp = F::mul4(&pp, &p);
    let q = F::mul4(&r.x, &pp);
    let x3 = F::sub4(&F::sub4(&F::sqr4(&rr), &ppp), &F::add4(&q, &q));
    let y3 = F::sub4(&F::mul4(&rr, &F::sub4(&q, &x3)), &F::mul4(&r.y, &ppp));
    let out = Xyzz4 {
        x: x3,
        y: y3,
        zz: F::mul4(&r.zz, &pp),
        zzz: F::mul4(&r.zzz, &ppp),
    };
    (out, F::zero_lanes(&p))
}

/// add-2008-s (`s += r`) in every lane; also the lanes where `U2 - U1` is 0.
fn add4_xyzz<F: Lanes4>(s: &Xyzz4<F>, r: &Xyzz4<F>) -> (Xyzz4<F>, v128) {
    let u1 = F::mul4(&s.x, &r.zz);
    let u2 = F::mul4(&r.x, &s.zz);
    let s1 = F::mul4(&s.y, &r.zzz);
    let s2 = F::mul4(&r.y, &s.zzz);
    let p = F::sub4(&u2, &u1);
    let rr = F::sub4(&s2, &s1);
    let pp = F::sqr4(&p);
    let ppp = F::mul4(&pp, &p);
    let q = F::mul4(&u1, &pp);
    let x3 = F::sub4(&F::sub4(&F::sqr4(&rr), &ppp), &F::add4(&q, &q));
    let y3 = F::sub4(&F::mul4(&rr, &F::sub4(&q, &x3)), &F::mul4(&s1, &ppp));
    let out = Xyzz4 {
        x: x3,
        y: y3,
        zz: F::mul4(&F::mul4(&s.zz, &r.zz), &pp),
        zzz: F::mul4(&F::mul4(&s.zzz, &r.zzz), &ppp),
    };
    (out, F::zero_lanes(&p))
}

pub fn window_sum<C, F>(buckets: &[Aff<F>], overflow: &[Xyzz<F>]) -> Projective<C>
where
    C: SWCurveConfig<BaseField = F::Ark>,
    F: Lanes4,
{
    let count = buckets.len();
    if count < 4 || !count.is_multiple_of(4) {
        return crate::msm::scalar_window_sum(buckets, overflow).to_ark();
    }
    let seg = count / 4;
    let mut running = Xyzz4::<F>::zero();
    let mut sum = Xyzz4::<F>::zero();
    let mut run_zero = [true; 4];
    let mut sum_zero = [true; 4];
    let one = F::one();

    for step in (0..seg).rev() {
        let ks: [usize; 4] = core::array::from_fn(|l| l * seg + step);
        let b: [&Aff<F>; 4] = core::array::from_fn(|l| &buckets[ks[l]]);

        // running += bucket
        let was_zero = run_zero;
        let general: [bool; 4] = core::array::from_fn(|l| !b[l].inf && !was_zero[l]);
        if general.iter().any(|&g| g) {
            let bx = F::pack(&[b[0].x, b[1].x, b[2].x, b[3].x]);
            let by = F::pack(&[b[0].y, b[1].y, b[2].y, b[3].y]);
            let (next, p_zero) = madd4(&running, &bx, &by);
            let p_zero = lane_set(p_zero);
            let take: [bool; 4] = core::array::from_fn(|l| general[l] && !p_zero[l]);
            let old = running;
            running = next.select(&old, lane_mask(take));
            for l in 0..4 {
                if general[l] && p_zero[l] {
                    let mut r = old.get(l);
                    r.add_affine(b[l]);
                    running.set(l, &r);
                    run_zero[l] = r.is_zero();
                }
            }
        }
        for l in 0..4 {
            if was_zero[l] && !b[l].inf {
                let seed = Xyzz {
                    x: b[l].x,
                    y: b[l].y,
                    zz: one,
                    zzz: one,
                };
                running.set(l, &seed);
                run_zero[l] = false;
            }
        }
        if !overflow.is_empty() {
            for l in 0..4 {
                let o = &overflow[ks[l]];
                if !o.is_zero() {
                    let mut r = if run_zero[l] {
                        Xyzz::zero()
                    } else {
                        running.get(l)
                    };
                    r.add_xyzz(o);
                    running.set(l, &r);
                    run_zero[l] = r.is_zero();
                }
            }
        }

        // sum += running
        let sum_was_zero = sum_zero;
        let general: [bool; 4] = core::array::from_fn(|l| !run_zero[l] && !sum_was_zero[l]);
        if general.iter().any(|&g| g) {
            let (next, p_zero) = add4_xyzz(&sum, &running);
            let p_zero = lane_set(p_zero);
            let take: [bool; 4] = core::array::from_fn(|l| general[l] && !p_zero[l]);
            let old = sum;
            sum = next.select(&old, lane_mask(take));
            for l in 0..4 {
                if general[l] && p_zero[l] {
                    let mut s = old.get(l);
                    s.add_xyzz(&running.get(l));
                    sum.set(l, &s);
                    sum_zero[l] = s.is_zero();
                }
            }
        }
        for l in 0..4 {
            if sum_was_zero[l] && !run_zero[l] {
                sum.set(l, &running.get(l));
                sum_zero[l] = false;
            }
        }
    }

    let mut total = Projective::<C>::zero();
    for l in 0..4 {
        if !sum_zero[l] {
            total += sum.get(l).to_ark::<C>();
        }
        if !run_zero[l] && l > 0 {
            total += running.get(l).to_ark::<C>().mul_bigint([(l * seg) as u64]);
        }
    }
    total
}
