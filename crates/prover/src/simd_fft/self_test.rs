//! Development check for `wasm-simd-fft`, run inside the WASM build
//! (`simdFftSelfTest`): `qap::finish_evaluations` (SIMD transforms, concurrent
//! with `parallel`) against the ark-poly witness-map step, on random and edge
//! inputs (zero, one, r-1, a delta; full, partial and empty constraint rows)
//! for every domain size 2^min_log..2^max_log. Run it on a pool of at most
//! `MAX_WORKERS` threads: on a larger one the SIMD path is not taken.
//! `simdFftStress` is one randomized round per seed for the runner's
//! time-bounded stress mode. Both are `wasm-simd-selftest` only.

use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
use core::arch::wasm32::{u32x4, u32x4_extract_lane};
use wasm_bindgen::prelude::{JsError, wasm_bindgen};

use super::fr29::{const_from_ark, mont_mul, raw_from_ark, raw_to_ark};
use super::gen_u29::mul4;
use super::ntt;

type Domain = GeneralEvaluationDomain<Fr>;

/// Returns the number of witness maps compared; throws on the first mismatch.
/// Above 2^16 only the random full-row case runs (each case is three
/// transforms per path).
#[wasm_bindgen(js_name = simdFftSelfTest)]
pub fn simd_fft_self_test(min_log: u32, max_log: u32, seed: u32) -> u32 {
    assert!((3..=24).contains(&min_log) && min_log <= max_log && max_log <= 24);
    let mut rng = StdRng::seed_from_u64(u64::from(seed));
    let mut checks = 0;
    for log in min_log..=max_log {
        let n = 1usize << log;
        let domain = Domain::new(n).expect("domain");
        let g = Domain::new(2 * n).expect("double domain").element(1);
        // On a larger pool this compares ark-poly with itself.
        assert_eq!(
            super::WitnessStep::new(&domain, g).is_some(),
            super::pool_allows_simd(),
            "SIMD step availability at 2^{log}"
        );
        let random = |rng: &mut StdRng| (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let (a, b) = (random(&mut rng), random(&mut rng));
        let mut cases = vec![(a.clone(), b.clone(), n - 1)];
        if log <= 16 {
            let mut delta = vec![Fr::zero(); n];
            delta[1] = Fr::one();
            let mut edge = vec![-Fr::one(); n];
            edge[n - 1] = Fr::one();
            cases.extend([
                (a.clone(), b.clone(), n),
                (a.clone(), b.clone(), n / 2),
                (a, b, 0),
                (vec![Fr::zero(); n], vec![Fr::zero(); n], n),
                (vec![Fr::one(); n], vec![Fr::one(); n], n),
                (vec![-Fr::one(); n], edge.clone(), n),
                (delta, edge, n - 3),
            ]);
        }
        for (a, b, rows) in cases {
            let want = reference(domain, g, &a, &b, rows);
            let (mut a, mut b, mut c) = (a, b, Vec::new());
            crate::qap::finish_evaluations(domain, &mut a, &mut b, &mut c, rows)
                .expect("finish_evaluations");
            assert!(a == want, "witness map differs at 2^{log}, {rows} rows");
            checks += 1;
        }
    }
    checks
}

/// `finish_evaluations` on ark-poly alone.
fn reference(domain: Domain, g: Fr, a: &[Fr], b: &[Fr], rows: usize) -> Vec<Fr> {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    let mut c = vec![Fr::zero(); a.len()];
    for i in 0..rows {
        c[i] = a[i] * b[i];
    }
    for v in [&mut a, &mut b, &mut c] {
        domain.ifft_in_place(v);
        Domain::distribute_powers_and_mul_by_const(v, g, Fr::one());
        domain.fft_in_place(v);
    }
    a.iter()
        .zip(&b)
        .zip(&c)
        .map(|((a, b), c)| *a * b - c)
        .collect()
}

/// An arkworks Fr: uniform, or an edge value (0, +-1, small, 2^k).
fn fr_sample(rng: &mut StdRng) -> Fr {
    match rng.gen_range(0..8) {
        0 => Fr::zero(),
        1 => Fr::one(),
        2 => -Fr::one(),
        3 => Fr::from(rng.r#gen::<u32>()),
        4 => Fr::from(2_u64).pow([rng.gen_range(0..254_u64)]),
        _ => Fr::rand(rng),
    }
}

fn fr_vector(n: usize, rng: &mut StdRng) -> Vec<Fr> {
    match rng.gen_range(0..4) {
        0 => vec![fr_sample(rng); n],
        1 => (0..n)
            .map(|_| {
                if rng.gen_range(0..4) == 0 {
                    fr_sample(rng)
                } else {
                    Fr::zero()
                }
            })
            .collect(),
        _ => (0..n).map(|_| fr_sample(rng)).collect(),
    }
}

fn check(ok: bool, what: impl FnOnce() -> String) -> Result<(), JsError> {
    if ok {
        Ok(())
    } else {
        Err(JsError::new(&what()))
    }
}

/// Stress round: randomized differential checks of the FFT's Fr arithmetic
/// (fr29's Montgomery data trick, scalar and 4-lane, chained), of single
/// NTTs against ark-poly (forward, inverse with the n^-1 scale, coset
/// pre-scaling), and of one witness map, each at a random size up to
/// 2^max_log. Returns the number of comparisons; throws on a mismatch.
#[wasm_bindgen(js_name = simdFftStress)]
pub fn simd_fft_stress(seed: u32, max_log: u32) -> Result<u32, JsError> {
    if !(3..=20).contains(&max_log) {
        return Err(JsError::new("max_log must be in 3..=20"));
    }
    let mut rng = StdRng::seed_from_u64(u64::from(seed));
    let mut checks = 0;

    // Field: x * c on raw (arkworks Montgomery) data, scalar and 4 lanes.
    for _ in 0..16 {
        let (x, c) = (fr_sample(&mut rng), fr_sample(&mut rng));
        let got = raw_to_ark(&mont_mul(&raw_from_ark(&x), &const_from_ark(&c)));
        check(got == x * c, || {
            format!("Fr mont_mul (seed {seed}): {x} * {c}")
        })?;
        let xs: [Fr; 4] = core::array::from_fn(|_| fr_sample(&mut rng));
        let cs: [Fr; 4] = core::array::from_fn(|_| fr_sample(&mut rng));
        let pack =
            |e: [[u32; 9]; 4]| core::array::from_fn(|i| u32x4(e[0][i], e[1][i], e[2][i], e[3][i]));
        let raw = pack(xs.map(|x| raw_from_ark(&x)));
        let consts = pack(cs.map(|c| const_from_ark(&c)));
        // Twice: the first product (< 2r) is a valid input to the second.
        let product = mul4(&mul4(&raw, &consts), &consts);
        for lane in 0..4 {
            let limbs: [u32; 9] = core::array::from_fn(|i| match lane {
                0 => u32x4_extract_lane::<0>(product[i]),
                1 => u32x4_extract_lane::<1>(product[i]),
                2 => u32x4_extract_lane::<2>(product[i]),
                _ => u32x4_extract_lane::<3>(product[i]),
            });
            let want = xs[lane] * cs[lane] * cs[lane];
            check(raw_to_ark(&limbs) == want, || {
                format!("Fr mul4 lane {lane} (seed {seed})")
            })?;
        }
        checks += 5;
    }

    // Single NTTs against ark-poly.
    let log = rng.gen_range(3..=max_log);
    let n = 1_usize << log;
    let domain = Domain::new(n).expect("domain");
    let mut buf = Vec::new();
    let input = fr_vector(n, &mut rng);
    let (mut got, mut want) = (input.clone(), input.clone());
    ntt::ntt(
        &ntt::Plan::new(n, domain.group_gen()),
        &mut got,
        &mut buf,
        None,
        None,
    );
    domain.fft_in_place(&mut want);
    check(got == want, || format!("NTT 2^{log} (seed {seed})"))?;
    let (mut got, mut want) = (input.clone(), input.clone());
    let inverse = ntt::Plan::new(n, domain.group_gen_inv());
    ntt::ntt(&inverse, &mut got, &mut buf, None, Some(domain.size_inv()));
    domain.ifft_in_place(&mut want);
    check(got == want, || format!("inverse NTT 2^{log} (seed {seed})"))?;
    let (g, c) = (fr_sample(&mut rng), fr_sample(&mut rng));
    let (mut got, mut want) = (input.clone(), input);
    ntt::ntt(
        &ntt::Plan::new(n, domain.group_gen()),
        &mut got,
        &mut buf,
        Some((g, c)),
        None,
    );
    Domain::distribute_powers_and_mul_by_const(&mut want, g, c);
    domain.fft_in_place(&mut want);
    check(got == want, || format!("coset NTT 2^{log} (seed {seed})"))?;
    checks += 3;

    // One witness map through `qap::finish_evaluations`.
    let log = rng.gen_range(3..=max_log);
    let n = 1_usize << log;
    let domain = Domain::new(n).expect("domain");
    let g = Domain::new(2 * n).expect("double domain").element(1);
    let rows = match rng.gen_range(0..4) {
        0 => n,
        1 => 0,
        _ => rng.gen_range(0..=n),
    };
    let (a, b) = (fr_vector(n, &mut rng), fr_vector(n, &mut rng));
    let want = reference(domain, g, &a, &b, rows);
    let (mut a, mut b, mut c) = (a, b, Vec::new());
    crate::qap::finish_evaluations(domain, &mut a, &mut b, &mut c, rows)
        .map_err(|error| JsError::new(&format!("finish_evaluations: {error}")))?;
    check(a == want, || {
        format!("witness map 2^{log}, {rows} rows (seed {seed})")
    })?;
    Ok(checks + 1)
}
