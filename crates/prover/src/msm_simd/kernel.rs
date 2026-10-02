//! A BN254 batch-affine Pippenger MSM, generic over the curve (G1 or G2) and
//! the base-field representation.
//!
//! This is a line-by-line port of `AffineBuckets` from
//! `crates/prover/src/msm.rs` (signed windows, batches of pairwise distinct
//! buckets, one shared inversion per batch via Montgomery's trick, Add /
//! Double / Cancel classification before the inversion, deferral of points
//! whose bucket is already scheduled, and XYZZ overflow buckets for hot
//! buckets). The XYZZ formulas are ports of arkworks' `Bucket` (ark-ec 0.6),
//! used here for the overflow buckets and the running-sum reduction so the
//! whole window runs in the chosen field. Only the final combination of the
//! ~20 window sums uses arkworks' projective arithmetic.
//!
//! BN254 G1 and G2 both have `a = 0`, so the `a`-terms of the formulas are
//! dropped (asserted in `msm`).

use core::cmp::Ordering;

use ark_bn254::Fr;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AdditiveGroup, AffineRepr};
use ark_ff::{BigInt, PrimeField, Zero};

use crate::msm_simd::field::PocField;

#[derive(Clone, Copy, Debug)]
pub struct Aff<F> {
    pub x: F,
    pub y: F,
    pub inf: bool,
}

impl<F: PocField> Aff<F> {
    #[inline(always)]
    pub fn identity() -> Self {
        Aff {
            x: F::zero(),
            y: F::zero(),
            inf: true,
        }
    }

    pub fn from_ark<C: SWCurveConfig<BaseField = F::Ark>>(p: &Affine<C>) -> Self {
        match p.xy() {
            None => Self::identity(),
            Some((x, y)) => Aff {
                x: F::from_ark(&x),
                y: F::from_ark(&y),
                inf: false,
            },
        }
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        Aff {
            x: self.x,
            y: self.y.neg(),
            inf: self.inf,
        }
    }
}

/// Extended Jacobian (XYZZ) point: x = X/ZZ, y = Y/ZZZ; ZZ = ZZZ = 0 is the identity.
#[derive(Clone, Copy, Debug)]
pub struct Xyzz<F> {
    pub x: F,
    pub y: F,
    pub zz: F,
    pub zzz: F,
}

impl<F: PocField> Xyzz<F> {
    #[inline(always)]
    pub fn zero() -> Self {
        Xyzz {
            x: F::one(),
            y: F::one(),
            zz: F::zero(),
            zzz: F::zero(),
        }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.zz.is_zero() && self.zzz.is_zero()
    }

    /// mdbl-2008-s-1 (a = 0).
    fn double_affine(p: &Aff<F>) -> Self {
        if p.inf {
            return Self::zero();
        }
        let u = p.y.double();
        let v = u.square();
        let w = u.mul(&v);
        let s = p.x.mul(&v);
        let x2 = p.x.square();
        let m = x2.double().add(&x2);
        let x = m.square().sub(&s.double());
        let y = m.mul(&s.sub(&x)).sub(&w.mul(&p.y));
        Xyzz {
            x,
            y,
            zz: v,
            zzz: w,
        }
    }

    /// dbl-2008-s-1 (a = 0).
    fn double_in_place(&mut self) {
        let u = self.y.double();
        let v = u.square();
        let w = u.mul(&v);
        let s = self.x.mul(&v);
        let x2 = self.x.square();
        let m = x2.double().add(&x2);
        let x = m.square().sub(&s.double());
        let y = m.mul(&s.sub(&x)).sub(&w.mul(&self.y));
        self.x = x;
        self.y = y;
        self.zz = self.zz.mul(&v);
        self.zzz = self.zzz.mul(&w);
    }

    /// madd-2008-s, with arkworks' doubling and cancellation branches.
    #[inline]
    pub fn add_affine(&mut self, other: &Aff<F>) {
        if other.inf {
            return;
        }
        if self.is_zero() {
            *self = Xyzz {
                x: other.x,
                y: other.y,
                zz: F::one(),
                zzz: F::one(),
            };
            return;
        }
        let u2 = other.x.mul(&self.zz);
        let s2 = other.y.mul(&self.zzz);
        if self.x.equals(&u2) {
            if self.y.equals(&s2) {
                *self = Self::double_affine(other);
            } else {
                *self = Self::zero();
            }
            return;
        }
        let p = u2.sub(&self.x);
        let r = s2.sub(&self.y);
        let pp = p.square();
        let ppp = pp.mul(&p);
        let q = self.x.mul(&pp);
        let x = r.square().sub(&ppp).sub(&q.double());
        let y = r.mul(&q.sub(&x)).sub(&self.y.mul(&ppp));
        self.x = x;
        self.y = y;
        self.zz = self.zz.mul(&pp);
        self.zzz = self.zzz.mul(&ppp);
    }

    /// add-2008-s, with arkworks' doubling and cancellation branches.
    #[inline]
    pub fn add_xyzz(&mut self, other: &Self) {
        if self.is_zero() {
            *self = *other;
            return;
        }
        if other.is_zero() {
            return;
        }
        let u1 = self.x.mul(&other.zz);
        let u2 = other.x.mul(&self.zz);
        let s1 = self.y.mul(&other.zzz);
        let s2 = other.y.mul(&self.zzz);
        if u1.equals(&u2) {
            if s1.equals(&s2) {
                self.double_in_place();
            } else {
                *self = Self::zero();
            }
            return;
        }
        let p = u2.sub(&u1);
        let r = s2.sub(&s1);
        let pp = p.square();
        let ppp = pp.mul(&p);
        let q = u1.mul(&pp);
        let x = r.square().sub(&ppp).sub(&q.double());
        let y = r.mul(&q.sub(&x)).sub(&s1.mul(&ppp));
        self.x = x;
        self.y = y;
        self.zz = self.zz.mul(&pp).mul(&other.zz);
        self.zzz = self.zzz.mul(&ppp).mul(&other.zzz);
    }

    /// Jacobian (X, Y, Z) = (x * zz, y * zzz, zz), as arkworks converts buckets.
    pub fn to_ark<C: SWCurveConfig<BaseField = F::Ark>>(&self) -> Projective<C> {
        if self.is_zero() {
            return Projective::ZERO;
        }
        let (x, y, zz, zzz) = (
            self.x.to_ark(),
            self.y.to_ark(),
            self.zz.to_ark(),
            self.zzz.to_ark(),
        );
        Projective::new_unchecked(x * zz, y * zzz, zz)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Add,
    Double,
    Cancel,
}

pub struct Pending<F> {
    pub bucket: u32,
    pub step: Step,
    pub point: Aff<F>,
}

/// Applies one batch of pending additions (all to distinct buckets) with a
/// shared inversion: the 4-lane simd128 `SimdApply` (`simd_msm.rs`), the
/// same contract as production's `msm::AffineBuckets`.
pub trait BatchApply<C: SWCurveConfig<BaseField = F::Ark>, F: PocField>: Default {
    fn apply(
        &mut self,
        buckets: &mut [Aff<F>],
        batch: &mut [Pending<F>],
        state: &mut [u8],
        stats: &mut Stats,
    );

    /// Running-sum reduction `sum_k (k + 1) * (bucket[k] + overflow[k])`.
    fn window_sum(buckets: &[Aff<F>], overflow: &[Xyzz<F>]) -> Projective<C> {
        scalar_window_sum(buckets, overflow).to_ark()
    }
}

/// Production's running-sum reduction, in the field `F`.
pub fn scalar_window_sum<F: PocField>(buckets: &[Aff<F>], overflow: &[Xyzz<F>]) -> Xyzz<F> {
    let mut sum = Xyzz::<F>::zero();
    let mut running = Xyzz::<F>::zero();
    if overflow.is_empty() {
        for bucket in buckets.iter().rev() {
            running.add_affine(bucket);
            sum.add_xyzz(&running);
        }
    } else {
        for (bucket, overflow) in buckets.iter().zip(overflow).rev() {
            running.add_affine(bucket);
            running.add_xyzz(overflow);
            sum.add_xyzz(&running);
        }
    }
    sum
}

pub const FREE: u8 = 0;
pub const SCHEDULED: u8 = 1;
const HOT: u8 = 2;
const MIN_RETRY_BATCH: usize = 8;

/// Same policy as production: `2^(width-1) / 4`, clamped to 32..=1024.
#[cfg(any(feature = "sparrow", feature = "wasm-simd-selftest"))]
pub fn batch_size(width: usize) -> usize {
    ((1_usize << (width - 1)) / 4).clamp(32, 1_024)
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub inversions: u64,
    pub adds: u64,
    pub doubles: u64,
    pub cancels: u64,
    pub overflow_adds: u64,
}

pub struct AffineBuckets<C: SWCurveConfig<BaseField = F::Ark>, F: PocField, A: BatchApply<C, F>> {
    buckets: Vec<Aff<F>>,
    overflow: Vec<Xyzz<F>>,
    batch: Vec<Pending<F>>,
    deferred: Vec<(u32, Aff<F>)>,
    state: Vec<u8>,
    batch_size: usize,
    applier: A,
    pub stats: Stats,
    curve: core::marker::PhantomData<C>,
}

impl<C: SWCurveConfig<BaseField = F::Ark>, F: PocField, A: BatchApply<C, F>>
    AffineBuckets<C, F, A>
{
    pub fn with_batch_size(width: usize, batch_size: usize) -> Self {
        let count = 1_usize << (width - 1);
        let batch_size = batch_size.max(1);
        Self {
            buckets: vec![Aff::identity(); count],
            overflow: Vec::new(),
            batch: Vec::with_capacity(batch_size),
            deferred: Vec::with_capacity(batch_size),
            state: vec![FREE; count],
            batch_size,
            applier: A::default(),
            stats: Stats::default(),
            curve: core::marker::PhantomData,
        }
    }

    /// Fallibly allocate a window's persistent buckets with the production
    /// batch size (SPARROW). Batch scratch grows on demand.
    #[cfg(feature = "sparrow")]
    pub fn try_new(width: usize) -> Option<Self> {
        debug_assert!(C::COEFF_A.is_zero(), "the formulas assume a = 0");
        let count = 1_usize << (width - 1);
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(count).ok()?;
        buckets.resize(count, Aff::identity());
        let mut state = Vec::new();
        state.try_reserve_exact(count).ok()?;
        state.resize(count, FREE);
        Some(Self {
            buckets,
            overflow: Vec::new(),
            batch: Vec::new(),
            deferred: Vec::new(),
            state,
            batch_size: batch_size(width),
            applier: A::default(),
            stats: Stats::default(),
            curve: core::marker::PhantomData,
        })
    }

    /// Drop the batch scratch, the applier's included, between SPARROW
    /// chunks, so only the buckets stay resident. Call after [`Self::finish`].
    #[cfg(feature = "sparrow")]
    pub fn release_scratch(&mut self) {
        debug_assert!(self.batch.is_empty() && self.deferred.is_empty());
        self.batch = Vec::new();
        self.deferred = Vec::new();
        self.applier = A::default();
    }

    #[inline]
    pub fn add_digit(&mut self, digit: i16, base: &Aff<F>) {
        match digit.cmp(&0) {
            Ordering::Greater => self.add(digit as usize - 1, *base),
            Ordering::Less => self.add(digit.unsigned_abs() as usize - 1, base.neg()),
            Ordering::Equal => {}
        }
    }

    #[inline]
    fn add(&mut self, bucket: usize, point: Aff<F>) {
        if point.inf {
            return;
        }
        match self.state[bucket] {
            FREE => {}
            SCHEDULED => {
                self.defer(bucket, point);
                return;
            }
            _ => {
                self.stats.overflow_adds += 1;
                self.overflow[bucket].add_affine(&point);
                return;
            }
        }
        let current = &mut self.buckets[bucket];
        if current.inf {
            *current = point;
            return;
        }
        self.schedule(bucket, point);
        while self.batch.len() == self.batch_size {
            self.apply_batch();
            self.retry_deferred();
        }
    }

    #[inline]
    fn schedule(&mut self, bucket: usize, point: Aff<F>) {
        self.state[bucket] = SCHEDULED;
        self.batch.push(Pending {
            bucket: bucket as u32,
            step: Step::Add,
            point,
        });
    }

    #[inline]
    fn defer(&mut self, bucket: usize, point: Aff<F>) {
        if self.deferred.len() == self.batch_size {
            self.spill_deferred();
        }
        self.deferred.push((bucket as u32, point));
    }

    #[cold]
    fn spill_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        if self.overflow.is_empty() {
            self.overflow = vec![Xyzz::zero(); self.buckets.len()];
        }
        for (bucket, point) in self.deferred.drain(..) {
            self.stats.overflow_adds += 1;
            self.overflow[bucket as usize].add_affine(&point);
            self.state[bucket as usize] = HOT;
        }
    }

    fn retry_deferred(&mut self) {
        let mut kept = 0;
        for index in 0..self.deferred.len() {
            let (bucket, point) = self.deferred[index];
            let slot = bucket as usize;
            match self.state[slot] {
                FREE if self.batch.len() < self.batch_size => {
                    if self.buckets[slot].inf {
                        self.buckets[slot] = point;
                    } else {
                        self.schedule(slot, point);
                    }
                }
                FREE | SCHEDULED => {
                    self.deferred[kept] = (bucket, point);
                    kept += 1;
                }
                _ => {
                    self.stats.overflow_adds += 1;
                    self.overflow[slot].add_affine(&point);
                }
            }
        }
        self.deferred.truncate(kept);
    }

    fn apply_batch(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        self.applier.apply(
            &mut self.buckets,
            &mut self.batch,
            &mut self.state,
            &mut self.stats,
        );
        self.batch.clear();
    }

    pub fn finish(&mut self) {
        loop {
            self.apply_batch();
            if self.deferred.is_empty() {
                return;
            }
            self.retry_deferred();
            if self.batch.len() < MIN_RETRY_BATCH {
                self.apply_batch();
                self.spill_deferred();
                return;
            }
        }
    }

    /// Running-sum reduction of this window (see [`BatchApply::window_sum`]).
    pub fn window_sum(&self) -> Projective<C> {
        debug_assert!(self.batch.is_empty() && self.deferred.is_empty());
        A::window_sum(&self.buckets, &self.overflow)
    }
}

/// Signed-window Pippenger, one window at a time (as production's serial
/// `batch_affine_msm`). Bases must already be in the kernel's representation.
pub fn msm<C, F, A>(
    bases: &[Aff<F>],
    scalars: &[BigInt<4>],
    width: usize,
    batch: usize,
    stats: &mut Stats,
) -> Projective<C>
where
    C: SWCurveConfig<BaseField = F::Ark>,
    F: PocField,
    A: BatchApply<C, F>,
{
    assert!(C::COEFF_A.is_zero(), "the formulas assume a = 0");
    let size = bases.len().min(scalars.len());
    let (bases, scalars) = (&bases[..size], &scalars[..size]);
    let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        let _ = &stats;
        let sums: Vec<Projective<C>> = (0..windows)
            .into_par_iter()
            .map(|window| {
                let mut buckets = AffineBuckets::<C, F, A>::with_batch_size(width, batch);
                for (base, scalar) in bases.iter().zip(scalars) {
                    buckets.add_digit(signed_window_digit(scalar, width, window), base);
                }
                buckets.finish();
                buckets.window_sum()
            })
            .collect();
        let mut total = Projective::<C>::ZERO;
        for sum in sums.iter().rev() {
            for _ in 0..width {
                total.double_in_place();
            }
            total += sum;
        }
        return total;
    }
    #[allow(unreachable_code)]
    let mut sums = Vec::with_capacity(windows);
    for window in 0..windows {
        let mut buckets = AffineBuckets::<C, F, A>::with_batch_size(width, batch);
        for (base, scalar) in bases.iter().zip(scalars) {
            buckets.add_digit(signed_window_digit(scalar, width, window), base);
        }
        buckets.finish();
        sums.push(buckets.window_sum());
        let s = buckets.stats;
        stats.inversions += s.inversions;
        stats.adds += s.adds;
        stats.doubles += s.doubles;
        stats.cancels += s.cancels;
        stats.overflow_adds += s.overflow_adds;
    }
    let mut total = Projective::<C>::ZERO;
    for sum in sums.iter().rev() {
        for _ in 0..width {
            total.double_in_place();
        }
        total += sum;
    }
    total
}

/// Production's random-access balanced digit (`crates/prover/src/msm.rs`).
pub fn signed_window_digit(scalar: &BigInt<4>, width: usize, window: usize) -> i16 {
    let radix = 1_i32 << width;
    let midpoint = radix >> 1;
    let mut carry = 0;
    if window != 0 {
        let mut prior = window - 1;
        loop {
            let digit = scalar_window(scalar, prior * width, width) as i32;
            if digit != midpoint - 1 {
                carry = i32::from(digit >= midpoint);
                break;
            }
            if prior == 0 {
                break;
            }
            prior -= 1;
        }
    }
    let unsigned = scalar_window(scalar, window * width, width) as i32 + carry;
    if unsigned >= midpoint {
        (unsigned - radix) as i16
    } else {
        unsigned as i16
    }
}

fn scalar_window(scalar: &BigInt<4>, start_bit: usize, width: usize) -> usize {
    let words = scalar.as_ref();
    let limb = start_bit / 64;
    let shift = start_bit % 64;
    let mut value = words.get(limb).copied().unwrap_or(0) >> shift;
    if shift != 0 && shift + width > 64 {
        value |= words.get(limb + 1).copied().unwrap_or(0) << (64 - shift);
    }
    (value & ((1_u64 << width) - 1)) as usize
}

/// Convert arkworks bases to the kernel's representation.
#[cfg(feature = "wasm-simd-selftest")]
pub fn convert_bases<C: SWCurveConfig<BaseField = F::Ark>, F: PocField>(
    bases: &[Affine<C>],
) -> Vec<Aff<F>> {
    bases.iter().map(Aff::from_ark).collect()
}
