//! BN254 multi-scalar multiplication scheduled on the caller's Rayon pool.
//!
//! This uses the public `VariableBaseMSM`/bucket types and BN254 group
//! arithmetic from `ark-ec` 0.6. Arkworks 0.6's signed MSM creates a private
//! thread pool for each large
//! chunk. Native callers pay for those transient pools, and `wasm-bindgen-rayon`
//! cannot create them because browser workers must come from the pool that the
//! host initialized with `initThreadPool`. This module keeps the same group
//! arithmetic in arkworks but owns the scheduling boundary.

use ark_bn254::Fr;
#[cfg(feature = "sparrow")]
use ark_ec::AffineRepr;
#[cfg(any(feature = "parallel", test))]
use ark_ec::VariableBaseMSM;
use ark_ff::BigInt;
#[cfg(any(feature = "parallel", test))]
use ark_ff::PrimeField;
#[cfg(feature = "sparrow")]
use ark_ff::{AdditiveGroup, Zero};
#[cfg(feature = "sparrow")]
use std::ops::AddAssign;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Compute a signed-Pippenger MSM without constructing a Rayon pool.
///
/// Under `parallel`, independent scalar windows run on the current global (or
/// installed) pool. Without it, the exact same recoding executes serially.
/// As with arkworks' `msm_bigint`, mismatched inputs are truncated to the
/// shorter slice.
#[cfg(any(feature = "parallel", test))]
pub(crate) fn msm_bigint<V>(bases: &[V::MulBase], scalars: &[BigInt<4>]) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return V::zero();
    }

    msm_bigint_with_window::<V>(bases, scalars, adaptive_window_bits(size))
}

#[cfg(any(feature = "parallel", test))]
fn msm_bigint_with_window<V>(bases: &[V::MulBase], scalars: &[BigInt<4>], width: usize) -> V
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

/// Empirical policy shared with SPARROW's native circuit sweep, with smaller
/// widths for tiny general-purpose keys. Window width changes only the amount
/// of work and temporary bucket memory, never the MSM result.
pub(crate) fn adaptive_window_bits(points: usize) -> usize {
    match points {
        0..=31 => 3,
        32..=255 => 5,
        256..=1_023 => 7,
        1_024..=32_768 => 8,
        32_769..=65_536 => 9,
        65_537..=262_144 => 10,
        262_145..=524_288 => 11,
        524_289..=2_097_152 => 12,
        _ => 13,
    }
}

#[cfg(any(feature = "parallel", test))]
fn signed_window_sum<V>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    width: usize,
    window: usize,
) -> V
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    // Keep arkworks' curve-specific bucket representation (XYZZ for BN254)
    // while retaining control of scheduling. It is faster than accumulating
    // projective points and does not create a thread pool.
    let mut buckets = vec![V::ZERO_BUCKET; 1_usize << (width - 1)];
    for (base, scalar) in bases.iter().zip(scalars) {
        let digit = signed_window_digit(scalar, width, window);
        match digit.cmp(&0) {
            std::cmp::Ordering::Greater => buckets[digit as usize - 1] += base,
            std::cmp::Ordering::Less => buckets[digit.unsigned_abs() as usize - 1] -= base,
            std::cmp::Ordering::Equal => {}
        }
    }

    let mut sum = V::ZERO_BUCKET;
    let mut running = V::ZERO_BUCKET;
    for bucket in buckets.iter().rev() {
        running += bucket;
        sum += &running;
    }
    sum.into()
}

/// Return one balanced radix-2^width digit without materializing every digit.
///
/// Carry normally depends on every lower window. Walking backward across the
/// only ambiguous raw digit (`midpoint - 1`) makes it random-access, allowing
/// separate windows to be evaluated by separate workers on the existing pool.
#[cfg(any(feature = "parallel", test))]
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

#[cfg(feature = "sparrow")]
pub(crate) fn reduce_bucket_windows<G>(buckets: &[Vec<G::Group>], width: usize) -> G::Group
where
    G: AffineRepr<ScalarField = Fr>,
    for<'a> G::Group: AddAssign<&'a G::Group>,
{
    let window_sums = buckets
        .iter()
        .map(|window| {
            let mut sum = G::Group::zero();
            let mut running = G::Group::zero();
            for bucket in window.iter().rev() {
                running += bucket;
                sum += &running;
            }
            sum
        })
        .collect::<Vec<_>>();
    reduce_group_window_sums::<G>(&window_sums, width)
}

#[cfg(any(feature = "parallel", test))]
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

#[cfg(feature = "sparrow")]
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

    use super::{adaptive_window_bits, msm_bigint, msm_bigint_with_window};

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
            assert!((3..=13).contains(&adaptive_window_bits(size)));
        }
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
