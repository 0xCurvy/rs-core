//! BN254 multi-scalar multiplication scheduled on the caller's Rayon pool.
//!
//! This uses the public `VariableBaseMSM`/bucket types and BN254 group
//! arithmetic from `ark-ec` 0.6. Arkworks 0.6's signed MSM creates a private
//! thread pool for each large
//! chunk. Native callers pay for those transient pools, and `wasm-bindgen-rayon`
//! cannot create them because browser workers must come from the pool that the
//! host initialized with `initThreadPool`. This module keeps the same group
//! arithmetic in arkworks but owns the scheduling boundary.
//!
//! Resident G1/G2 MSMs of at least 4,096 points, and every SPARROW query, keep
//! each window's buckets in affine coordinates and add points in batches whose
//! buckets are pairwise distinct, so a whole batch shares one field inversion
//! (Montgomery's trick). Each addition then costs about 5M + 1S instead of the
//! 8M + 2S of an XYZZ mixed addition. Doubling, `P + (-P)`, identity bases, and
//! empty buckets are resolved before the shared inversion. A point whose bucket
//! already has a pending addition waits for the next batch; if such collisions
//! persist (repeated digits, which random inputs do not produce), the bucket
//! switches to arkworks' XYZZ form instead. Smaller resident MSMs keep the XYZZ
//! accumulator throughout. Both accumulators branch on public bases and
//! witness-derived digits: like the rest of this module they are variable-time.
//! Neither validates bases; for points off the curve both return meaningless
//! (and different) sums, but batch-affine never divides by zero.

#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
use std::any::{Any, TypeId};
use std::cmp::Ordering;

use ark_bn254::Fr;
use ark_ec::VariableBaseMSM;
use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine, Bucket, Projective, SWCurveConfig},
};
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
use ark_ff::PrimeField;
use ark_ff::{AdditiveGroup, BigInt, Field, Zero};
#[cfg(all(feature = "sparrow", feature = "bench"))]
use std::ops::AddAssign;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// How one window folds its points into buckets. Either choice produces the
/// same group element; only the cost differs.
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Accumulation {
    /// Arkworks' XYZZ buckets: one mixed addition per point.
    Xyzz,
    /// Affine buckets whose independent additions share one inversion.
    /// Falls back to [`Self::Xyzz`] for curves other than BN254 G1/G2.
    BatchAffine,
}

/// Smallest MSM that uses batch-affine buckets. Below it, an inversion per
/// batch and the scheduling bookkeeping cost more than they save.
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
const BATCH_AFFINE_MIN_POINTS: usize = 1 << 12;

/// Compute a signed-Pippenger MSM without constructing a Rayon pool.
///
/// Under `parallel`, independent scalar windows run on the current global (or
/// installed) pool. Without it, the exact same recoding executes serially.
/// As with arkworks' `msm_bigint`, mismatched inputs are truncated to the
/// shorter slice.
/// Scalars must be canonical BN254 Fr integers (`Fr::into_bigint()`); the
/// 254-bit window count is not an API for arbitrary 256-bit integers. Bucket
/// indices depend on the witness: this routine is variable-time.
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
pub(crate) fn msm_bigint<V>(bases: &[V::MulBase], scalars: &[BigInt<4>]) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return V::zero();
    }

    msm_bigint_with_window::<V>(bases, scalars, resident_window_bits(size))
}

#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
fn resident_window_bits(points: usize) -> usize {
    #[cfg(feature = "parallel")]
    {
        adaptive_window_bits(points)
    }
    #[cfg(not(feature = "parallel"))]
    {
        serial_window_bits(points)
    }
}

/// Window policy for builds without `parallel`.
#[cfg(any(
    all(feature = "bench", feature = "parallel"),
    all(not(feature = "parallel"), any(feature = "compact-matrix", test))
))]
pub(crate) fn serial_window_bits(points: usize) -> usize {
    // Serial execution benefits from fewer scans of the query. Approximate
    // ln(points) + 2, as in arkworks, while retaining the proven width cap.
    if points < 32 {
        3
    } else {
        ((ark_std::log2(points) as usize * 69 / 100) + 2).min(16)
    }
}

#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
pub(crate) fn msm_bigint_with_window<V>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    width: usize,
) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let size = bases.len().min(scalars.len());
    let accumulation = if size >= BATCH_AFFINE_MIN_POINTS {
        Accumulation::BatchAffine
    } else {
        Accumulation::Xyzz
    };
    msm_bigint_with_accumulation::<V>(bases, scalars, width, accumulation, None)
}

/// [`msm_bigint_with_window`] with an explicit accumulator. `batch` overrides
/// the batch-affine batch size (benchmarks only; `None` is the production size).
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
pub(crate) fn msm_bigint_with_accumulation<V>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    width: usize,
    accumulation: Accumulation,
    batch: Option<usize>,
) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    debug_assert!((3..=16).contains(&width));
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return V::zero();
    }

    let bases = &bases[..size];
    let scalars = &scalars[..size];
    if accumulation == Accumulation::BatchAffine {
        let batch = batch.unwrap_or_else(|| batch_size(width));
        if let Some(sum) =
            batch_affine_msm::<V, ark_bn254::g1::Config>(bases, scalars, width, batch)
        {
            return sum;
        }
        if let Some(sum) =
            batch_affine_msm::<V, ark_bn254::g2::Config>(bases, scalars, width, batch)
        {
            return sum;
        }
    }
    let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);

    #[cfg(feature = "parallel")]
    let window_sums = (0..windows)
        .into_par_iter()
        .map(|window| signed_window_sum::<V>(bases, scalars, width, window))
        .collect::<Vec<_>>();

    #[cfg(not(feature = "parallel"))]
    let window_sums = (0..windows)
        .map(|window| signed_window_sum::<V>(bases, scalars, width, window))
        .collect::<Vec<_>>();

    reduce_msm_window_sums(&window_sums, width)
}

/// Run the batch-affine MSM when `V` is the short-Weierstrass group of `P`.
///
/// The prover's generic callers name arkworks' `VariableBaseMSM`, which does
/// not expose affine coordinates. `V` is `'static` (every arkworks group is),
/// so its concrete type can be identified safely; `None` selects the generic
/// XYZZ path for any other group.
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
fn batch_affine_msm<V, P>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    width: usize,
    batch: usize,
) -> Option<V>
where
    V: VariableBaseMSM<ScalarField = Fr>,
    P: SWCurveConfig<ScalarField = Fr>,
{
    if TypeId::of::<V>() != TypeId::of::<Projective<P>>() {
        return None;
    }
    let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
    let window_sum = |window: usize| {
        let mut buckets = AffineBuckets::<P>::with_batch_size(width, batch);
        for (base, scalar) in bases.iter().zip(scalars) {
            buckets.add_digit(
                signed_window_digit(scalar, width, window),
                same_type::<_, Affine<P>>(base),
            );
        }
        buckets.finish();
        buckets.window_sum()
    };

    #[cfg(feature = "parallel")]
    let window_sums = (0..windows)
        .into_par_iter()
        .map(window_sum)
        .collect::<Vec<_>>();
    #[cfg(not(feature = "parallel"))]
    let window_sums = (0..windows).map(window_sum).collect::<Vec<_>>();

    let total = reduce_msm_window_sums::<Projective<P>>(&window_sums, width);
    Some(*same_type::<_, V>(&total))
}

/// Reinterpret a value whose concrete type the caller has already matched.
/// `Any` repeats the check, a comparison of two type ids known at compile time.
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
#[inline(always)]
fn same_type<T: 'static, U: 'static>(value: &T) -> &U {
    (value as &dyn Any)
        .downcast_ref::<U>()
        .expect("MSM dispatch matched the concrete curve type")
}

/// Batch size for `2^(width - 1)` buckets. A batch of `b` additions collides
/// about `b^2 / 2^width` times, while each batch pays one field inversion.
pub(crate) fn batch_size(width: usize) -> usize {
    ((1_usize << (width - 1)) / 4).clamp(32, 1_024)
}

/// Empirical policy shared by the resident `parallel` MSM and SPARROW's
/// adaptive windows, with smaller widths for tiny general-purpose keys. Window
/// width changes only the amount of work and temporary bucket memory, never
/// the MSM result.
///
/// From 4,096 points both accumulate batch-affine, which favors wider windows
/// than XYZZ/projective buckets did: more buckets mean fewer batch collisions
/// and larger batches per inversion, and fewer windows mean fewer passes.
/// Measured on BN254 G1/G2 with 4-13 Rayon workers (`msm_accumulation sweep`,
/// `sparrow_query_msm`) for uniform scalars and for witness-like ones (many
/// 0/1/64-bit values, so most windows see fewer points). Witness-like inputs
/// prefer a bit or two less below 2^17 points; these widths favor uniform
/// scalars (the costlier MSMs) except where that regressed small witness-like
/// MSMs.
#[cfg(any(feature = "parallel", feature = "sparrow", test))]
pub(crate) fn adaptive_window_bits(points: usize) -> usize {
    match points {
        0..=31 => 3,
        32..=255 => 5,
        256..=1_023 => 7,
        1_024..=4_095 => 8,
        4_096..=16_383 => 10,
        16_384..=65_536 => 12,
        65_537..=524_288 => 13,
        _ => 14,
    }
}

#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
fn signed_window_sum<V>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    width: usize,
    window: usize,
) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let buckets = xyzz_buckets::<V>(
        bases,
        scalars
            .iter()
            .map(|s| signed_window_digit(s, width, window)),
        width,
    );
    xyzz_window_sum::<V>(&buckets)
}

#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
fn xyzz_buckets<V>(
    bases: &[V::MulBase],
    digits: impl Iterator<Item = i16>,
    width: usize,
) -> Vec<V::Bucket>
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    // Keep arkworks' curve-specific bucket representation (XYZZ for BN254)
    // while retaining control of scheduling. It is faster than accumulating
    // projective points and does not create a thread pool.
    let mut buckets = vec![V::ZERO_BUCKET; 1_usize << (width - 1)];
    for (base, digit) in bases.iter().zip(digits) {
        match digit.cmp(&0) {
            Ordering::Greater => buckets[digit as usize - 1] += base,
            Ordering::Less => buckets[digit.unsigned_abs() as usize - 1] -= base,
            Ordering::Equal => {}
        }
    }
    buckets
}

#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
fn xyzz_window_sum<V>(buckets: &[V::Bucket]) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let mut sum = V::ZERO_BUCKET;
    let mut running = V::ZERO_BUCKET;
    for bucket in buckets.iter().rev() {
        running += bucket;
        sum += &running;
    }
    sum.into()
}

/// How a scheduled addition resolves once both operands are known.
#[derive(Clone, Copy)]
enum Step {
    /// Distinct x: the chord through both points.
    Add,
    /// The bucket equals the point: the tangent.
    Double,
    /// `P + (-P)` (or doubling a 2-torsion point): the identity.
    Cancel,
}

struct PendingAdd<P: SWCurveConfig> {
    bucket: u32,
    step: Step,
    /// Product of the denominators scheduled before this one.
    prefix: P::BaseField,
    point: Affine<P>,
}

/// Affine buckets for one signed window.
///
/// Every scheduled addition targets a distinct bucket, so none depends on
/// another and the whole batch shares one inversion. A point whose bucket is
/// already scheduled is deferred until the batch is applied. When deferred
/// points pile up (repeated digits, which random inputs essentially never
/// produce), they are added to XYZZ overflow buckets, allocated only then, and
/// their buckets become "hot": later points for a hot bucket go straight to
/// its XYZZ overflow. Adversarial digit patterns therefore cost about the
/// same as the plain XYZZ accumulator instead of one inversion per point.
pub(crate) struct AffineBuckets<P: SWCurveConfig> {
    buckets: Vec<Affine<P>>,
    overflow: Vec<Bucket<P>>,
    batch: Vec<PendingAdd<P>>,
    deferred: Vec<(u32, Affine<P>)>,
    /// [`FREE`], [`SCHEDULED`], or [`HOT`] per bucket.
    state: Vec<u8>,
    batch_size: usize,
}

/// The bucket has no pending addition.
const FREE: u8 = 0;
/// The bucket has a pending addition in the current batch.
const SCHEDULED: u8 = 1;
/// The bucket's points go directly to its XYZZ overflow bucket. A hot bucket
/// is never scheduled again, but may still have one pending addition from
/// before it became hot.
const HOT: u8 = 2;

/// A final retry smaller than this means the remaining deferred points are
/// concentrated in very few buckets.
const MIN_RETRY_BATCH: usize = 8;

impl<P: SWCurveConfig> AffineBuckets<P> {
    #[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
    pub(crate) fn with_batch_size(width: usize, batch_size: usize) -> Self {
        let count = 1_usize << (width - 1);
        let batch_size = batch_size.max(1);
        Self {
            buckets: vec![Affine::identity(); count],
            overflow: Vec::new(),
            batch: Vec::with_capacity(batch_size),
            deferred: Vec::with_capacity(batch_size),
            state: vec![FREE; count],
            batch_size,
        }
    }

    /// Fallibly allocate the persistent buckets for a `width`-bit window,
    /// with the production batch size. Batch scratch grows on demand.
    #[cfg(feature = "sparrow")]
    pub(crate) fn try_new(width: usize) -> Option<Self> {
        let count = 1_usize << (width - 1);
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(count).ok()?;
        buckets.resize(count, Affine::identity());
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
        })
    }

    /// Fold `digit * base` into the window for a balanced signed digit.
    #[inline]
    pub(crate) fn add_digit(&mut self, digit: i16, base: &Affine<P>) {
        match digit.cmp(&0) {
            Ordering::Greater => self.add(digit as usize - 1, *base),
            Ordering::Less => self.add(digit.unsigned_abs() as usize - 1, -*base),
            Ordering::Equal => {}
        }
    }

    #[inline]
    fn add(&mut self, bucket: usize, point: Affine<P>) {
        if point.is_zero() {
            return;
        }
        match self.state[bucket] {
            FREE => {}
            SCHEDULED => {
                self.defer(bucket, point);
                return;
            }
            _ => {
                self.overflow[bucket] += &point;
                return;
            }
        }
        let current = &mut self.buckets[bucket];
        if current.is_zero() {
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
    fn schedule(&mut self, bucket: usize, point: Affine<P>) {
        self.state[bucket] = SCHEDULED;
        self.batch.push(PendingAdd {
            bucket: bucket as u32,
            step: Step::Add,
            prefix: P::BaseField::ONE,
            point,
        });
    }

    #[inline]
    fn defer(&mut self, bucket: usize, point: Affine<P>) {
        if self.deferred.len() == self.batch_size {
            self.spill_deferred();
        }
        self.deferred.push((bucket as u32, point));
    }

    /// Add every deferred point to the XYZZ overflow buckets and mark their
    /// buckets hot.
    #[cold]
    fn spill_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        if self.overflow.is_empty() {
            self.overflow = vec![Bucket::ZERO; self.buckets.len()];
        }
        for (bucket, point) in self.deferred.drain(..) {
            self.overflow[bucket as usize] += &point;
            self.state[bucket as usize] = HOT;
        }
    }

    /// Reschedule deferred points, oldest first, whose bucket is now free.
    fn retry_deferred(&mut self) {
        let mut kept = 0;
        for index in 0..self.deferred.len() {
            let (bucket, point) = self.deferred[index];
            let slot = bucket as usize;
            match self.state[slot] {
                FREE if self.batch.len() < self.batch_size => {
                    if self.buckets[slot].is_zero() {
                        self.buckets[slot] = point;
                    } else {
                        self.schedule(slot, point);
                    }
                }
                FREE | SCHEDULED => {
                    self.deferred[kept] = (bucket, point);
                    kept += 1;
                }
                _ => self.overflow[slot] += &point,
            }
        }
        self.deferred.truncate(kept);
    }

    /// Apply every scheduled addition with one shared inversion.
    fn apply_batch(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let Self {
            buckets,
            batch,
            state,
            ..
        } = self;

        // Forward pass: classify each addition and accumulate the product of
        // its denominator. Every denominator is non-zero by construction, even
        // for invalid input: `x2 - x1` only when the x differ, `2y` only when
        // y is non-zero (the field's characteristic is odd).
        let mut product = P::BaseField::ONE;
        for pending in batch.iter_mut() {
            let bucket = &buckets[pending.bucket as usize];
            pending.prefix = product;
            if bucket.x != pending.point.x {
                pending.step = Step::Add;
                product *= pending.point.x - bucket.x;
            } else if bucket.y == pending.point.y && !bucket.y.is_zero() {
                pending.step = Step::Double;
                product *= bucket.y.double();
            } else {
                // Same x and a different y is `P + (-P)`. Doubling a point with
                // y = 0 is also the identity. (Arkworks' XYZZ addition draws the
                // same distinction.)
                pending.step = Step::Cancel;
            }
        }

        // Backward pass: peel each inverse off the running product.
        let mut inverse = product
            .inverse()
            .expect("batch-affine denominators are non-zero");
        for pending in batch.iter().rev() {
            let index = pending.bucket as usize;
            if state[index] == SCHEDULED {
                state[index] = FREE;
            }
            let bucket = &mut buckets[index];
            let point = &pending.point;
            let (numerator, denominator) = match pending.step {
                Step::Add => (point.y - bucket.y, point.x - bucket.x),
                Step::Double => {
                    let square = bucket.x.square();
                    let mut numerator = square.double();
                    numerator += square;
                    if !P::COEFF_A.is_zero() {
                        numerator += P::COEFF_A;
                    }
                    (numerator, bucket.y.double())
                }
                Step::Cancel => {
                    *bucket = Affine::identity();
                    continue;
                }
            };
            let lambda = numerator * (inverse * pending.prefix);
            inverse *= denominator;
            // For a doubling, point.x == bucket.x, so this is also the tangent
            // formula x3 = lambda^2 - 2x.
            let x = lambda.square() - bucket.x - point.x;
            let y = lambda * (bucket.x - x) - bucket.y;
            *bucket = Affine::new_unchecked(x, y);
        }
        batch.clear();
    }

    /// Apply every pending and deferred addition.
    pub(crate) fn finish(&mut self) {
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

    /// Drop the batch scratch between SPARROW chunks, so only the buckets
    /// stay resident. Call after [`Self::finish`].
    #[cfg(feature = "sparrow")]
    pub(crate) fn release_scratch(&mut self) {
        debug_assert!(self.batch.is_empty() && self.deferred.is_empty());
        self.batch = Vec::new();
        self.deferred = Vec::new();
    }

    /// Running-sum reduction: `sum_k (k + 1) * bucket[k]`. Call
    /// [`Self::finish`] first.
    pub(crate) fn window_sum(&self) -> Projective<P> {
        debug_assert!(self.batch.is_empty() && self.deferred.is_empty());
        let mut sum = Bucket::<P>::ZERO;
        let mut running = Bucket::<P>::ZERO;
        if self.overflow.is_empty() {
            for bucket in self.buckets.iter().rev() {
                running += bucket;
                sum += &running;
            }
        } else {
            for (bucket, overflow) in self.buckets.iter().zip(&self.overflow).rev() {
                running += bucket;
                running += overflow;
                sum += &running;
            }
        }
        sum.into()
    }
}

/// Serial, per-phase timing of one MSM for profiling: signed-digit recoding,
/// bucket accumulation, bucket (running-sum) reduction, and the final
/// window combination. Production interleaves the first two phases.
#[cfg(all(feature = "bench", feature = "parallel"))]
pub(crate) fn profile_msm_phases<P>(
    bases: &[Affine<P>],
    scalars: &[BigInt<4>],
    width: usize,
    accumulation: Accumulation,
) -> (Projective<P>, [std::time::Duration; 4])
where
    P: SWCurveConfig<ScalarField = Fr>,
{
    use std::time::{Duration, Instant};
    let size = bases.len().min(scalars.len());
    let (bases, scalars) = (&bases[..size], &scalars[..size]);
    let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
    let mut phases = [Duration::ZERO; 4];
    let mut window_sums = Vec::with_capacity(windows);
    let mut digits = Vec::with_capacity(size);
    for window in 0..windows {
        let started = Instant::now();
        digits.clear();
        digits.extend(
            scalars
                .iter()
                .map(|s| signed_window_digit(s, width, window)),
        );
        phases[0] += started.elapsed();
        match accumulation {
            Accumulation::Xyzz => {
                let started = Instant::now();
                let buckets = xyzz_buckets::<Projective<P>>(bases, digits.iter().copied(), width);
                phases[1] += started.elapsed();
                let started = Instant::now();
                window_sums.push(xyzz_window_sum::<Projective<P>>(&buckets));
                phases[2] += started.elapsed();
            }
            Accumulation::BatchAffine => {
                let started = Instant::now();
                let mut buckets = AffineBuckets::<P>::with_batch_size(width, batch_size(width));
                for (base, &digit) in bases.iter().zip(&digits) {
                    buckets.add_digit(digit, base);
                }
                buckets.finish();
                phases[1] += started.elapsed();
                let started = Instant::now();
                window_sums.push(buckets.window_sum());
                phases[2] += started.elapsed();
            }
        }
    }
    let started = Instant::now();
    let total = reduce_msm_window_sums::<Projective<P>>(&window_sums, width);
    phases[3] = started.elapsed();
    (total, phases)
}

/// Return one balanced radix-2^width digit without materializing every digit.
///
/// Carry normally depends on every lower window. Walking backward across the
/// only ambiguous raw digit (`midpoint - 1`) makes it random-access, allowing
/// separate windows to be evaluated by separate workers on the existing pool.
#[cfg(any(feature = "parallel", feature = "compact-matrix", test))]
pub(crate) fn signed_window_digit(scalar: &BigInt<4>, width: usize, window: usize) -> i16 {
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

#[cfg(all(feature = "sparrow", any(not(feature = "parallel"), test)))]
pub(crate) fn for_each_signed_window(
    scalar: &BigInt<4>,
    width: usize,
    windows: usize,
    mut emit: impl FnMut(usize, i16),
) {
    let radix = 1_i32 << width;
    let midpoint = radix >> 1;
    let mut carry = 0_i32;
    for window in 0..windows {
        let unsigned = scalar_window(scalar, window * width, width) as i32 + carry;
        let digit = if unsigned >= midpoint {
            carry = 1;
            unsigned - radix
        } else {
            carry = 0;
            unsigned
        };
        emit(window, digit as i16);
    }
    // This is BN254-specific: its Fr modulus and Curvy's allowed 3..=16 widths
    // make the padded top window consume the final carry.
    debug_assert_eq!(carry, 0, "scalar does not fit the signed window count");
}

/// Reduce SPARROW's persistent affine windows (after [`AffineBuckets::finish`])
/// to the MSM value.
#[cfg(feature = "sparrow")]
pub(crate) fn reduce_affine_windows<P>(windows: &[AffineBuckets<P>], width: usize) -> Projective<P>
where
    P: SWCurveConfig<ScalarField = Fr>,
{
    // Each window's running-sum reduction is independent, so spread them
    // over the pool.
    #[cfg(feature = "parallel")]
    let window_sums = windows
        .par_iter()
        .map(AffineBuckets::window_sum)
        .collect::<Vec<_>>();
    #[cfg(not(feature = "parallel"))]
    let window_sums = windows
        .iter()
        .map(AffineBuckets::window_sum)
        .collect::<Vec<_>>();
    reduce_msm_window_sums::<Projective<P>>(&window_sums, width)
}

/// Projective-bucket reduction kept for `sparrow::phase_bench`'s kernels.
#[cfg(all(feature = "sparrow", feature = "bench"))]
pub(crate) fn reduce_bucket_windows<G>(buckets: &[Vec<G::Group>], width: usize) -> G::Group
where
    G: AffineRepr<ScalarField = Fr>,
    for<'a> G::Group: AddAssign<&'a G::Group>,
{
    let reduce = |window: &Vec<G::Group>| {
        let mut sum = G::Group::zero();
        let mut running = G::Group::zero();
        for bucket in window.iter().rev() {
            running += bucket;
            sum += &running;
        }
        sum
    };
    // Each window's running-sum reduction is independent. Spreading them over
    // the pool measured 3-7x faster than the serial loop; the phase is only
    // ~1-5% of bucket accumulation, about 0.2-0.3 s per proof.
    #[cfg(feature = "parallel")]
    let window_sums = buckets.par_iter().map(reduce).collect::<Vec<_>>();
    #[cfg(not(feature = "parallel"))]
    let window_sums = buckets.iter().map(reduce).collect::<Vec<_>>();
    reduce_group_window_sums::<G>(&window_sums, width)
}

fn reduce_msm_window_sums<V>(window_sums: &[V], width: usize) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let mut total = V::zero();
    for sum in window_sums.iter().rev() {
        for _ in 0..width {
            total.double_in_place();
        }
        total += sum;
    }
    total
}

#[cfg(all(feature = "sparrow", feature = "bench"))]
fn reduce_group_window_sums<G>(window_sums: &[G::Group], width: usize) -> G::Group
where
    G: AffineRepr<ScalarField = Fr>,
    for<'a> G::Group: AddAssign<&'a G::Group>,
{
    let mut total = G::Group::zero();
    for sum in window_sums.iter().rev() {
        for _ in 0..width {
            total.double_in_place();
        }
        total += sum;
    }
    total
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

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
    use ark_ff::{BigInt, BigInteger, PrimeField, UniformRand};

    use super::{
        Accumulation, AffineBuckets, adaptive_window_bits, msm_bigint,
        msm_bigint_with_accumulation, msm_bigint_with_window,
    };

    fn carry_cases(width: usize) -> Vec<BigInt<4>> {
        use num_bigint::BigUint;
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
        let mut values = vec![BigUint::from(0_u8), BigUint::from(1_u8), &modulus - 1_u8];
        for bit in [width - 1, width, 63, 64, 65, 127, 128, 191, 192, 253] {
            let boundary = BigUint::from(1_u8) << bit;
            values.extend([&boundary - 1_u8, boundary.clone(), boundary + 1_u8]);
        }
        // Long runs of the ambiguous digit, with and without a carry entering
        // the run. Include limb crossings and a negative full-size bucket.
        for first in [(1_u64 << (width - 1)) - 1, 1_u64 << (width - 1)] {
            let mut value = BigUint::from(first);
            for window in 1..(250 / width) {
                value += BigUint::from((1_u64 << (width - 1)) - 1) << (window * width);
            }
            values.push(value);
        }
        values
            .into_iter()
            .filter(|v| v < &modulus)
            .map(|v| Fr::from_le_bytes_mod_order(&v.to_bytes_le()).into_bigint())
            .collect()
    }

    #[test]
    fn balanced_digits_reconstruct_canonical_integers_without_modular_reduction() {
        use num_bigint::{BigInt as Integer, Sign};
        for width in 3..=16 {
            let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
            for scalar in carry_cases(width) {
                let expected = Integer::from_bytes_le(Sign::Plus, &scalar.to_bytes_le());
                let mut actual = Integer::from(0);
                for window in 0..windows {
                    let digit = super::signed_window_digit(&scalar, width, window);
                    assert!(
                        (-(1_i32 << (width - 1))..(1_i32 << (width - 1)))
                            .contains(&i32::from(digit))
                    );
                    actual += Integer::from(digit) << (window * width);
                }
                assert_eq!(actual, expected, "width={width}, scalar={scalar}");
                #[cfg(feature = "sparrow")]
                super::for_each_signed_window(&scalar, width, windows, |window, digit| {
                    assert_eq!(digit, super::signed_window_digit(&scalar, width, window));
                });
            }
        }
    }

    #[test]
    fn every_width_matches_naive_g1_and_g2_including_infinity_and_cancellation() {
        let mut rng = ark_std::test_rng();
        for width in 3..=16 {
            let mut scalars = carry_cases(width);
            scalars.extend((0..8).map(|_| Fr::rand(&mut rng).into_bigint()));
            let mut g1 = (0..scalars.len())
                .map(|_| G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let mut g2 = (0..scalars.len())
                .map(|_| G2Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            g1[2] = G1Affine::identity();
            g2[2] = G2Affine::identity();
            // Equal scalars on opposite bases cancel in both groups.
            scalars[4] = scalars[3];
            g1[4] = -g1[3];
            g2[4] = -g2[3];
            let lengths = [
                (g1.len(), scalars.len()),
                (g1.len() - 1, scalars.len()),
                (g1.len(), scalars.len() - 1),
            ];
            for &(base_len, scalar_len) in &lengths[..if width == 3 { 3 } else { 1 }] {
                let values = &scalars[..scalar_len];
                let expected_g1: G1Projective = g1[..base_len]
                    .iter()
                    .zip(values)
                    .map(|(b, s)| b.mul_bigint(s))
                    .sum();
                let expected_g2: G2Projective = g2[..base_len]
                    .iter()
                    .zip(values)
                    .map(|(b, s)| b.mul_bigint(s))
                    .sum();
                assert_eq!(
                    msm_bigint_with_window::<G1Projective>(&g1[..base_len], values, width),
                    expected_g1,
                    "G1 width={width}"
                );
                assert_eq!(
                    msm_bigint_with_window::<G2Projective>(&g2[..base_len], values, width),
                    expected_g2,
                    "G2 width={width}"
                );
            }
        }
    }

    #[test]
    fn global_pool_msm_matches_arkworks_for_g1_and_g2() {
        let mut rng = ark_std::test_rng();
        for size in [0, 1, 2, 31, 32, 257] {
            let scalars = (0..size)
                .map(|_| Fr::rand(&mut rng).into_bigint())
                .collect::<Vec<BigInt<4>>>();
            let g1 = powers::<G1Affine>(size);
            let g2 = powers::<G2Affine>(size);

            assert_eq!(
                msm_bigint::<G1Projective>(&g1, &scalars),
                G1Projective::msm_bigint(&g1, &scalars)
            );
            assert_eq!(
                msm_bigint::<G2Projective>(&g2, &scalars),
                G2Projective::msm_bigint(&g2, &scalars)
            );
        }
    }

    #[test]
    fn global_pool_msm_handles_carry_and_truncation_edges() {
        let modulus_minus_one = {
            let mut value = Fr::MODULUS;
            value.sub_with_borrow(&BigInt::from(1_u64));
            value
        };
        let scalars = [
            BigInt::from(0_u64),
            BigInt::from(1_u64),
            BigInt::from(127_u64),
            BigInt::from(128_u64),
            modulus_minus_one,
        ];
        let bases = powers::<G1Affine>(scalars.len() + 1);
        assert_eq!(
            msm_bigint::<G1Projective>(&bases, &scalars),
            G1Projective::msm_bigint(&bases, &scalars)
        );
    }

    #[test]
    fn every_supported_window_reconstructs_the_same_msm() {
        let mut rng = ark_std::test_rng();
        let scalars = (0..128)
            .map(|_| Fr::rand(&mut rng).into_bigint())
            .collect::<Vec<BigInt<4>>>();
        let bases = powers::<G1Affine>(scalars.len());
        let expected = G1Projective::msm_bigint(&bases, &scalars);

        for width in 3..=16 {
            assert_eq!(
                msm_bigint_with_window::<G1Projective>(&bases, &scalars, width),
                expected,
                "window {width}"
            );
        }
    }

    #[test]
    fn window_policy_stays_inside_the_proven_bn254_widths() {
        for size in [0, 1, 31, 32, 255, 256, 32_768, 2_097_153, usize::MAX] {
            assert!((3..=14).contains(&adaptive_window_bits(size)));
        }
    }

    /// Batch-affine, XYZZ, and arkworks' independent MSM agree for every
    /// listed width. `batches` adds batch-size overrides small enough to
    /// exercise deferral, retry, and XYZZ spill on these inputs.
    fn assert_accumulators_match<V>(
        bases: &[V::MulBase],
        scalars: &[BigInt<4>],
        widths: &[usize],
        batches: &[usize],
    ) where
        V: VariableBaseMSM<ScalarField = Fr>,
    {
        let expected = V::msm_bigint(bases, scalars);
        for &width in widths {
            assert_eq!(
                msm_bigint_with_accumulation::<V>(bases, scalars, width, Accumulation::Xyzz, None),
                expected,
                "XYZZ width={width} size={}",
                scalars.len()
            );
            let overrides = batches.iter().copied().map(Some);
            for batch in std::iter::once(None).chain(overrides) {
                assert_eq!(
                    msm_bigint_with_accumulation::<V>(
                        bases,
                        scalars,
                        width,
                        Accumulation::BatchAffine,
                        batch
                    ),
                    expected,
                    "batch-affine width={width} batch={batch:?} size={}",
                    scalars.len()
                );
            }
        }
    }

    fn random_scalars(size: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<BigInt<4>> {
        (0..size).map(|_| Fr::rand(rng).into_bigint()).collect()
    }

    /// Distinct, unstructured bases: `start, start + step, ...` for a random
    /// point and step (one scalar multiplication each, then additions).
    fn random_bases<G>(size: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<G>
    where
        G: AffineRepr<ScalarField = Fr>,
    {
        let step = G::generator() * Fr::rand(rng);
        let mut point = G::generator() * Fr::rand(rng);
        let mut points = Vec::with_capacity(size);
        for _ in 0..size {
            points.push(point);
            point += step;
        }
        G::Group::normalize_batch(&points)
    }

    #[test]
    fn batch_affine_matches_arkworks_for_random_g1_and_g2_inputs() {
        // Every width is covered by the carry-case test below and the ignored
        // exhaustive sweep; the widest windows dominate debug-build time.
        let mut rng = ark_std::test_rng();
        for (size, g1_widths, g2_widths) in [
            (1, &[3, 16][..], &[3, 16][..]),
            (31, &[3, 4, 6, 9, 12, 15], &[5, 11]),
            (1_000, &[5, 9], &[9]),
        ] {
            let scalars = random_scalars(size, &mut rng);
            let g1 = random_bases::<G1Affine>(size, &mut rng);
            assert_accumulators_match::<G1Projective>(&g1, &scalars, g1_widths, &[3, 32]);
            let g2 = random_bases::<G2Affine>(size, &mut rng);
            assert_accumulators_match::<G2Projective>(&g2, &scalars, g2_widths, &[3]);
        }
    }

    /// Exhaustive release-mode sweep: random and adversarial inputs for every
    /// size class up to 2^14 at every supported width, for G1 and G2.
    /// `cargo test --release -p curvy-prover --features parallel --lib -- --ignored`
    #[test]
    #[ignore = "minutes in debug builds; run in release"]
    fn batch_affine_matches_arkworks_for_every_size_class_and_width() {
        let mut rng = ark_std::test_rng();
        let all_widths = (3..=16).collect::<Vec<_>>();
        let mut sizes = vec![1, 2, 3, 4, 5, 7, 8, 9];
        for log in 4..=14 {
            sizes.extend([(1 << log) - 1, 1 << log, (1 << log) + 1]);
        }
        sizes.extend([1_000, 3_000, 10_000]);
        for size in sizes {
            let scalars = random_scalars(size, &mut rng);
            let batches: &[usize] = if size <= 1 << 10 { &[1, 3, 32] } else { &[64] };
            assert_accumulators_match::<G1Projective>(
                &random_bases::<G1Affine>(size, &mut rng),
                &scalars,
                &all_widths,
                batches,
            );
            assert_accumulators_match::<G2Projective>(
                &random_bases::<G2Affine>(size, &mut rng),
                &scalars,
                &all_widths,
                batches,
            );
        }
        assert_adversarial_cases_match(1_000, &all_widths, &[1, 3, 64]);
        for width in 3..=16 {
            let scalars = carry_cases(width);
            let g1 = random_bases::<G1Affine>(scalars.len(), &mut rng);
            let g2 = random_bases::<G2Affine>(scalars.len(), &mut rng);
            assert_accumulators_match::<G1Projective>(&g1, &scalars, &[width], &[1, 2]);
            assert_accumulators_match::<G2Projective>(&g2, &scalars, &[width], &[1, 2]);
        }
    }

    #[test]
    fn production_dispatch_matches_arkworks_at_the_batch_affine_threshold() {
        let mut rng = ark_std::test_rng();
        for size in [
            super::BATCH_AFFINE_MIN_POINTS - 1,
            super::BATCH_AFFINE_MIN_POINTS,
        ] {
            let scalars = random_scalars(size, &mut rng);
            let g1 = random_bases::<G1Affine>(size, &mut rng);
            let g2 = random_bases::<G2Affine>(size, &mut rng);
            assert_eq!(
                msm_bigint::<G1Projective>(&g1, &scalars),
                G1Projective::msm_bigint(&g1, &scalars)
            );
            assert_eq!(
                msm_bigint::<G2Projective>(&g2, &scalars),
                G2Projective::msm_bigint(&g2, &scalars)
            );
        }
    }

    #[test]
    fn batch_affine_handles_adversarial_bases_and_scalars() {
        assert_adversarial_cases_match(40, &[4, 9], &[1, 3]);
    }

    /// Repeated identical bases, P and -P, identity bases, zero scalars, one
    /// scalar everywhere (every point in one bucket per window), digits that
    /// are negatives of each other on one base, and carry/top-window scalars.
    fn assert_adversarial_cases_match(size: usize, widths: &[usize], batches: &[usize]) {
        let mut rng = ark_std::test_rng();
        let p1 = G1Projective::rand(&mut rng).into_affine();
        let p2 = G2Projective::rand(&mut rng).into_affine();
        let q1 = G1Projective::rand(&mut rng).into_affine();
        let q2 = G2Projective::rand(&mut rng).into_affine();
        let random = random_scalars(size, &mut rng);
        let same = vec![random[0]; size];
        let ones = vec![BigInt::from(1_u64); size];
        let zeros = vec![BigInt::from(0_u64); size];
        let modulus_minus_one = {
            let mut value = Fr::MODULUS;
            value.sub_with_borrow(&BigInt::from(1_u64));
            value
        };
        // Equal scalars on P and -P cancel; s and r - s on one base produce
        // digits that are negatives of each other.
        let mut pairs = random.clone();
        let mut complements = random.clone();
        for index in (1..size).step_by(2) {
            pairs[index] = pairs[index - 1];
            complements[index] = (-Fr::from_bigint(random[index - 1]).unwrap()).into_bigint();
        }
        let edges = (0..size)
            .map(|index| match index % 4 {
                0 => modulus_minus_one,
                1 => BigInt::from(0_u64),
                2 => BigInt::from(1_u64),
                _ => random[index],
            })
            .collect::<Vec<_>>();
        let scalar_sets = [&random, &same, &ones, &zeros, &pairs, &complements, &edges];

        // Runs of P, P, -P, -P, Q, identity: doubling, cancellation back to an
        // empty bucket, then reuse of that bucket.
        let g1_sets = [
            vec![p1; size],
            (0..size)
                .map(|i| if i % 2 == 0 { p1 } else { -p1 })
                .collect(),
            (0..size)
                .map(|i| [p1, p1, -p1, -p1, q1, G1Affine::identity()][i % 6])
                .collect(),
            vec![G1Affine::identity(); size],
            random_bases::<G1Affine>(size, &mut rng),
        ];
        let g2_sets = [
            vec![p2; size],
            (0..size)
                .map(|i| if i % 2 == 0 { p2 } else { -p2 })
                .collect(),
            (0..size)
                .map(|i| [p2, p2, -p2, -p2, q2, G2Affine::identity()][i % 6])
                .collect(),
            vec![G2Affine::identity(); size],
            random_bases::<G2Affine>(size, &mut rng),
        ];
        for scalars in scalar_sets {
            for bases in &g1_sets {
                assert_accumulators_match::<G1Projective>(bases, scalars, widths, batches);
            }
            for bases in &g2_sets {
                assert_accumulators_match::<G2Projective>(bases, scalars, widths, &batches[1..]);
            }
        }
    }

    #[test]
    fn batch_affine_carry_cases_match_for_every_width() {
        let mut rng = ark_std::test_rng();
        for width in 3..=16 {
            let scalars = carry_cases(width);
            let g1 = random_bases::<G1Affine>(scalars.len(), &mut rng);
            assert_accumulators_match::<G1Projective>(&g1, &scalars, &[width], &[2]);
            if width % 4 == 1 {
                let g2 = random_bases::<G2Affine>(scalars.len(), &mut rng);
                assert_accumulators_match::<G2Projective>(&g2, &scalars, &[width], &[]);
            }
        }
    }

    /// Drive one window's buckets directly with every branch: empty buckets,
    /// doubling, cancellation, identity points, deferral, retry, and spill.
    #[test]
    fn affine_buckets_match_naive_bucket_sums() {
        use ark_ec::short_weierstrass::Projective;
        let mut rng = ark_std::test_rng();
        let p = G1Projective::rand(&mut rng).into_affine();
        let q = G1Projective::rand(&mut rng).into_affine();
        let points = [p, -p, p, q, -q, (p + q).into_affine(), G1Affine::identity()];
        for width in [3, 4, 6] {
            let digit_limit = 1_i16 << (width - 1);
            for batch in [1, 2, 3, 5, 8, 64] {
                for round in 0..6 {
                    let mut buckets =
                        AffineBuckets::<ark_bn254::g1::Config>::with_batch_size(width, batch);
                    let mut expected = G1Projective::default();
                    for step in 0..(40 + 50 * round) {
                        let digit = if round % 2 == 0 {
                            // Concentrated: few buckets, many collisions.
                            [1, -1, 2, 1, 1][step % 5]
                        } else {
                            rand_digit(&mut rng, digit_limit)
                        };
                        let point = points[(step * 3 + round) % points.len()];
                        buckets.add_digit(digit, &point);
                        let multiple = point.mul_bigint([u64::from(digit.unsigned_abs())]);
                        if digit < 0 {
                            expected -= multiple;
                        } else {
                            expected += multiple;
                        }
                    }
                    buckets.finish();
                    let actual: Projective<_> = buckets.window_sum();
                    assert_eq!(
                        actual, expected,
                        "width={width} batch={batch} round={round}"
                    );
                }
            }
        }
    }

    fn rand_digit(rng: &mut impl ark_std::rand::Rng, limit: i16) -> i16 {
        rng.gen_range(-limit..limit)
    }

    fn powers<G>(size: usize) -> Vec<G>
    where
        G: AffineRepr<ScalarField = Fr>,
    {
        let generator = G::Group::generator();
        (1..=size)
            .map(|scalar| generator.mul_bigint([scalar as u64]).into_affine())
            .collect()
    }
}
