//! `simdSparrowSelfTest`: SPARROW's streamed query accumulation, whose
//! persistent buckets are the SIMD kernel's under `wasm-simd-msm`, against
//! arkworks' `VariableBaseMSM` for G1 and G2. Points travel as zkey records
//! through `QueryAccumulator` exactly as in a proof: record-splitting pushes,
//! a scalar offset, decoding, chunked accumulation and the final reduction.
//!
//! Cases, for G1 and G2:
//! - every width 4..=16 on random bases with witness-like scalars (zero, one,
//!   64-bit, uniform), with 37-point chunks (a chunk boundary inside a batch
//!   at every width) and with one chunk (full batches mid-chunk);
//! - adversarial bases (all equal, P and -P, a P/-P/Q/identity mix, all
//!   identity, a P/-P/2P/identity/random mix) times adversarial scalars
//!   (uniform, all equal, all one, all zero, repeated pairs, complementary
//!   pairs, edge values), at widths 4, 9 and 13 with chunks of 1, 5 and 100
//!   points, plus the adaptive width (3 bits for these small queries);
//! - hot buckets: every scalar equal, so each window sends every point to
//!   one bucket; at 1,500-point chunks the deferral queue spills mid-chunk at
//!   every width, and the bucket stays hot (XYZZ overflow) across chunks.
//!
//! Cases rotate through three push patterns: record-splitting pushes, runs
//! of 13 whole records plus a split one, and the whole section at once. With
//! `parallel` the latter two decode every run of at least 1 (or 3) records
//! on the Rayon pool, so the parallel decode meets every chunk boundary.
//!
//! [`stress_case`] (part of `simdMsmStress`) streams one randomized query per
//! seed for the runner's time-bounded stress mode.

use std::sync::Arc;

use ark_bn254::{Fr, g1, g2};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, UniformRand};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

use super::{
    G1_BYTES, G1Windows, G2_BYTES, G2Windows, QueryAccumulator, StreamingConfig, StreamingError,
    decode_g1, decode_g2, valid_g1, valid_g2,
};
use crate::msm::WindowBuckets;

/// Leading assignment entries the query skips, as for the L query.
const OFFSET: usize = 3;

trait Query: SWCurveConfig<ScalarField = Fr> {
    type Windows: WindowBuckets<Curve = Self>;
    const NAME: &'static str;
    const RECORD_BYTES: usize;
    /// Push size that splits records.
    const PUSH_BYTES: usize;
    fn decode(bytes: &[u8]) -> Result<Affine<Self>, StreamingError>;
    fn validate(point: &Affine<Self>) -> bool;
    /// zkey encoding: Montgomery limbs, the identity as zeros.
    fn encode(point: &Affine<Self>, out: &mut Vec<u8>);
}

impl Query for g1::Config {
    type Windows = G1Windows;
    const NAME: &'static str = "G1";
    const RECORD_BYTES: usize = G1_BYTES;
    const PUSH_BYTES: usize = 97;
    fn decode(bytes: &[u8]) -> Result<Affine<Self>, StreamingError> {
        decode_g1(bytes)
    }
    fn validate(point: &Affine<Self>) -> bool {
        valid_g1(point)
    }
    fn encode(point: &Affine<Self>, out: &mut Vec<u8>) {
        for limb in point.x.0.0.into_iter().chain(point.y.0.0) {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
}

impl Query for g2::Config {
    type Windows = G2Windows;
    const NAME: &'static str = "G2";
    const RECORD_BYTES: usize = G2_BYTES;
    const PUSH_BYTES: usize = 201;
    fn decode(bytes: &[u8]) -> Result<Affine<Self>, StreamingError> {
        decode_g2(bytes)
    }
    fn validate(point: &Affine<Self>) -> bool {
        valid_g2(point)
    }
    fn encode(point: &Affine<Self>, out: &mut Vec<u8>) {
        for coordinate in [point.x.c0, point.x.c1, point.y.c0, point.y.c1] {
            for limb in coordinate.0.0 {
                out.extend_from_slice(&limb.to_le_bytes());
            }
        }
    }
}

/// Stream `bases` as a zkey query section through SPARROW's accumulator and
/// compare with arkworks. `pattern` (any number) picks the push pattern.
fn run<P: Query>(
    bases: &[Affine<P>],
    scalars: &[Fr],
    window_bits: usize,
    chunk_points: usize,
    case: &str,
    pattern: u32,
) -> Result<(), String> {
    let (push_bytes, parallel_min_records) = match pattern % 3 {
        0 => (P::PUSH_BYTES, usize::MAX),
        1 => (13 * P::RECORD_BYTES + 5, 1),
        _ => (bases.len().max(1) * P::RECORD_BYTES, 3),
    };
    let label = || {
        format!(
            "{} {case}: width={window_bits} chunk={chunk_points} size={} push={push_bytes}",
            P::NAME,
            bases.len()
        )
    };
    let bigints: Vec<BigInt<4>> = scalars.iter().map(|s| s.into_bigint()).collect();
    let expected = Projective::<P>::msm_bigint(bases, &bigints);

    let mut assignment = vec![Fr::from(7_u64); OFFSET];
    assignment.extend_from_slice(scalars);
    let mut section = Vec::with_capacity(bases.len() * P::RECORD_BYTES);
    for base in bases {
        P::encode(base, &mut section);
    }
    let config = StreamingConfig {
        window_bits,
        msm_chunk_points: chunk_points,
        ..StreamingConfig::default()
    }
    .validate()
    .map_err(|error| format!("{}: {error}", label()))?;
    let mut query = QueryAccumulator::<P::Windows>::new(
        Arc::from(assignment),
        OFFSET,
        bases.len(),
        P::RECORD_BYTES,
        P::decode,
        P::validate,
        config,
    )
    .map_err(|error| format!("{}: {error}", label()))?;
    #[cfg(feature = "parallel")]
    {
        query.parallel_min_records = parallel_min_records;
    }
    #[cfg(not(feature = "parallel"))]
    let _ = parallel_min_records;
    for piece in section.chunks(push_bytes) {
        query
            .push(piece)
            .map_err(|error| format!("{}: {error}", label()))?;
    }
    let got = query
        .finish()
        .map_err(|error| format!("{}: {error}", label()))?;
    if got != expected {
        return Err(format!("SPARROW SIMD MSM mismatch, {}", label()));
    }
    Ok(())
}

/// Distinct, unstructured bases: `start, start + step, ...`.
fn random_bases<P: Query>(size: usize, rng: &mut StdRng) -> Vec<Affine<P>> {
    let step = Projective::<P>::generator() * Fr::rand(rng);
    let mut point = Projective::<P>::generator() * Fr::rand(rng);
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        points.push(point);
        point += step;
    }
    Projective::<P>::normalize_batch(&points)
}

/// Production's witness mix: zeros, ones, 64-bit values and uniform values.
fn witness_scalars(size: usize, rng: &mut StdRng) -> Vec<Fr> {
    (0..size)
        .map(|_| match rng.gen_range(0..4) {
            0 => Fr::from(0_u64),
            1 => Fr::from(1_u64),
            2 => Fr::from(rng.r#gen::<u64>()),
            _ => Fr::rand(rng),
        })
        .collect()
}

fn width_sweep<P: Query>(size: usize, rng: &mut StdRng) -> Result<u32, String> {
    let bases = random_bases::<P>(size, rng);
    let scalars = witness_scalars(size, rng);
    let mut n = 0;
    for width in 4..=16 {
        for chunk in [37, size] {
            run::<P>(&bases, &scalars, width, chunk, "random/witness", n)?;
            n += 1;
        }
    }
    Ok(n)
}

fn adversarial<P: Query>(size: usize, rng: &mut StdRng) -> Result<u32, String> {
    let p = Projective::<P>::rand(rng).into_affine();
    let q = Projective::<P>::rand(rng).into_affine();
    let double = (p + p).into_affine();
    let identity = Affine::<P>::identity();
    let random = random_bases::<P>(size, rng);
    let base_sets: [(&str, Vec<Affine<P>>); 5] = [
        ("all P", vec![p; size]),
        (
            "P/-P",
            (0..size).map(|i| if i % 2 == 0 { p } else { -p }).collect(),
        ),
        (
            "P,P,-P,-P,Q,0",
            (0..size)
                .map(|i| [p, p, -p, -p, q, identity][i % 6])
                .collect(),
        ),
        ("all identity", vec![identity; size]),
        (
            "P,-P,2P,0,random",
            (0..size)
                .map(|i| match i % 7 {
                    0 | 4 => p,
                    1 => -p,
                    3 => identity,
                    6 => double,
                    _ => random[i],
                })
                .collect(),
        ),
    ];

    let uniform: Vec<Fr> = (0..size).map(|_| Fr::rand(rng)).collect();
    let mut pairs = uniform.clone();
    let mut complements = uniform.clone();
    for i in (1..size).step_by(2) {
        pairs[i] = pairs[i - 1];
        complements[i] = -uniform[i - 1];
    }
    let edges: Vec<Fr> = (0..size)
        .map(|i| match i % 4 {
            0 => -Fr::from(1_u64),
            1 => Fr::from(0_u64),
            2 => Fr::from(1_u64),
            _ => uniform[i],
        })
        .collect();
    let scalar_sets: [(&str, Vec<Fr>); 7] = [
        ("uniform", uniform.clone()),
        ("all equal", vec![uniform[0]; size]),
        ("all one", vec![Fr::from(1_u64); size]),
        ("all zero", vec![Fr::from(0_u64); size]),
        ("repeated pairs", pairs),
        ("complementary pairs", complements),
        ("edges", edges),
    ];

    let mut n = 0;
    for (base_name, bases) in &base_sets {
        for (scalar_name, scalars) in &scalar_sets {
            let case = format!("{base_name} x {scalar_name}");
            for width in [4, 9, 13] {
                for chunk in [1, 5, 100] {
                    run::<P>(bases, scalars, width, chunk, &case, n)?;
                    n += 1;
                }
            }
            run::<P>(
                &bases[..size.min(20)],
                &scalars[..size.min(20)],
                StreamingConfig::ADAPTIVE_WINDOW_BITS,
                7,
                &case,
                n,
            )?;
            n += 1;
        }
    }
    Ok(n)
}

fn hot_buckets<P: Query>(size: usize, rng: &mut StdRng) -> Result<u32, String> {
    let p = Projective::<P>::rand(rng).into_affine();
    let base_sets: [(&str, Vec<Affine<P>>); 3] = [
        ("random", random_bases::<P>(size, rng)),
        ("all P", vec![p; size]),
        (
            "P/-P/P",
            (0..size).map(|i| if i % 3 == 1 { -p } else { p }).collect(),
        ),
    ];
    let scalars = vec![Fr::rand(rng); size];
    let mut n = 0;
    for (name, bases) in &base_sets {
        let case = format!("hot bucket, {name}");
        for width in [4, 13, 16] {
            for chunk in [64, 1_500] {
                run::<P>(bases, &scalars, width, chunk, &case, n)?;
                n += 1;
            }
        }
    }
    Ok(n)
}

fn curve<P: Query>(size: usize, rng: &mut StdRng) -> Result<u32, String> {
    Ok(width_sweep::<P>(16 * size, rng)?
        + adversarial::<P>(size, rng)?
        + hot_buckets::<P>(2_600, rng)?)
}

/// Returns the number of streamed MSMs compared; an error names the first
/// mismatch. `size` is the adversarial query size (G2 uses half); the width
/// sweep uses 16 times as many points.
pub(crate) fn self_test(size: usize, seed: u64) -> Result<u32, String> {
    if size == 0 {
        return Err("size must be positive".into());
    }
    let mut rng = StdRng::seed_from_u64(seed);
    Ok(curve::<g1::Config>(size, &mut rng)? + curve::<g2::Config>(size.div_ceil(2), &mut rng)?)
}

/// One randomized streamed query against arkworks: a random curve, size (up
/// to `max_size`, G2 half), width (4..=16 or adaptive), chunk size, and base
/// and scalar mix. Returns the number of streamed MSMs compared (1).
pub(crate) fn stress_case(seed: u64, max_size: usize) -> Result<u32, String> {
    // Not the kernel case's stream: the same seed drives a different input.
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5350_4152_524f_5753);
    if rng.gen_bool(0.5) {
        stress::<g1::Config>(&mut rng, max_size.max(1), seed)
    } else {
        stress::<g2::Config>(&mut rng, max_size.div_ceil(2).max(1), seed)
    }
}

fn stress<P: Query>(rng: &mut StdRng, max_size: usize, seed: u64) -> Result<u32, String> {
    let size = rng.gen_range(1..=max_size);
    let p = Projective::<P>::rand(rng).into_affine();
    let identity = Affine::<P>::identity();
    let base_kind = rng.gen_range(0..3);
    let bases: Vec<Affine<P>> = match base_kind {
        0 => random_bases::<P>(size, rng),
        1 => {
            let pool = [p, -p, (p + p).into_affine(), identity];
            (0..size)
                .map(|_| pool[rng.gen_range(0..pool.len())])
                .collect()
        }
        _ => {
            let mut bases = random_bases::<P>(size, rng);
            for base in bases.iter_mut() {
                if rng.gen_range(0..8) == 0 {
                    *base = identity;
                }
            }
            bases
        }
    };
    let scalar_kind = rng.gen_range(0..4);
    let scalars: Vec<Fr> = match scalar_kind {
        0 => witness_scalars(size, rng),
        1 => (0..size).map(|_| Fr::rand(rng)).collect(),
        2 => vec![Fr::rand(rng); size],
        _ => {
            let mut s: Vec<Fr> = (0..size).map(|_| Fr::rand(rng)).collect();
            for i in (1..size).step_by(2) {
                s[i] = -s[i - 1];
            }
            s
        }
    };
    let width = if rng.gen_range(0..5) == 0 {
        StreamingConfig::ADAPTIVE_WINDOW_BITS
    } else {
        rng.gen_range(4..=16)
    };
    let chunk = rng.gen_range(1..=size + 8);
    let pattern = rng.gen_range(0..3);
    let case =
        format!("stress seed {seed}, bases {base_kind}, scalars {scalar_kind}, pattern {pattern}");
    run::<P>(&bases, &scalars, width, chunk, &case, pattern)?;
    Ok(1)
}
