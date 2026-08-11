//! Identical native/WASM kernels used to locate the platform performance gap.

use std::ops::{AddAssign, SubAssign};

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

#[cfg(feature = "parallel")]
use super::accumulate_signed_window;
use super::reduce_windows;
#[cfg(not(feature = "parallel"))]
use super::{accumulate_signed_digits, for_each_signed_window};

pub fn sha256(bytes: usize, rounds: usize) -> Result<u32, &'static str> {
    if bytes == 0 || bytes > 512 * 1024 * 1024 || rounds == 0 || rounds > 64 {
        return Err("invalid SHA benchmark dimensions");
    }
    let mut input = vec![0x5a_u8; bytes];
    let mut fingerprint = 0_u32;
    for round in 0..rounds {
        let digest = Sha256::digest(&input);
        fingerprint ^= u32::from_le_bytes(digest[..4].try_into().expect("SHA-256 word"));
        input[round % bytes] ^= digest[round % digest.len()];
    }
    Ok(fingerprint)
}

pub fn field_multiplication(iterations: usize) -> Result<u32, &'static str> {
    if iterations == 0 || iterations > 100_000_000 {
        return Err("invalid field benchmark iteration count");
    }
    let mut left = Fr::from(0x9e37_79b9_u64);
    let mut right = Fr::from(0x85eb_ca6b_u64);
    for index in 0..iterations {
        left *= right;
        left += Fr::from((index as u64).wrapping_mul(0x1000_0001));
        right.square_in_place();
        right += Fr::from(0xc2b2_ae35_u64);
    }
    Ok(left.into_bigint().0[0] as u32)
}

pub fn fft(log_size: u32, rounds: usize) -> Result<u32, &'static str> {
    if !(10..=24).contains(&log_size) || rounds == 0 || rounds > 16 {
        return Err("invalid FFT benchmark dimensions");
    }
    let size = 1_usize << log_size;
    let domain = GeneralEvaluationDomain::<Fr>::new(size).ok_or("unsupported FFT size")?;
    let mut values = (0..size)
        .map(|index| Fr::from((index as u64).wrapping_mul(0x9e37_79b9)))
        .collect::<Vec<_>>();
    for _ in 0..rounds {
        domain.fft_in_place(&mut values);
        domain.ifft_in_place(&mut values);
    }
    Ok(values[size / 3].into_bigint().0[0] as u32)
}

pub fn g1_msm(log_size: u32, width: usize) -> Result<u32, &'static str> {
    let result = synthetic_msm(G1Affine::generator(), log_size, width)?;
    Ok(result.into_affine().x.into_bigint().0[0] as u32)
}

pub fn g2_msm(log_size: u32, width: usize) -> Result<u32, &'static str> {
    let result = synthetic_msm(G2Affine::generator(), log_size, width)?;
    Ok(result.into_affine().x.c0.into_bigint().0[0] as u32)
}

fn synthetic_msm<G>(base: G, log_size: u32, width: usize) -> Result<G::Group, &'static str>
where
    G: AffineRepr<ScalarField = Fr> + Send + Sync,
    G::Group: Send + Sync,
    for<'a> G::Group: AddAssign<&'a G> + SubAssign<&'a G> + AddAssign<&'a G::Group>,
{
    if !(10..=22).contains(&log_size) || !(4..=16).contains(&width) {
        return Err("invalid MSM benchmark dimensions");
    }
    let count = 1_usize << log_size;
    let pairs = (0..count)
        .map(|index| {
            let scalar = Fr::from(
                (index as u64)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(1),
            );
            (base, scalar.into_bigint())
        })
        .collect::<Vec<_>>();
    let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
    let bucket_count = 1_usize << (width - 1);
    let mut buckets = (0..windows)
        .map(|_| vec![G::Group::zero(); bucket_count])
        .collect::<Vec<_>>();
    #[cfg(feature = "parallel")]
    buckets
        .par_iter_mut()
        .enumerate()
        .for_each(|(window, buckets)| accumulate_signed_window(buckets, &pairs, width, window));
    #[cfg(not(feature = "parallel"))]
    {
        let mut signed_digits = (0..windows)
            .map(|_| Vec::with_capacity(pairs.len()))
            .collect::<Vec<_>>();
        for (_, scalar) in &pairs {
            for_each_signed_window(scalar, width, windows, |window, digit| {
                signed_digits[window].push(digit);
            });
        }
        buckets
            .iter_mut()
            .zip(&signed_digits)
            .for_each(|(buckets, digits)| accumulate_signed_digits(buckets, &pairs, digits));
    }
    Ok(reduce_windows::<G>(&buckets, width))
}
