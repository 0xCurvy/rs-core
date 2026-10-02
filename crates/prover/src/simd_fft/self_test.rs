//! Development check for `wasm-simd-fft`, run inside the WASM build
//! (`simdFftSelfTest`): `qap::finish_evaluations` (SIMD transforms, concurrent
//! with `parallel`) against the ark-poly witness-map step, on random and edge
//! inputs (zero, one, r-1, a delta; full, partial and empty constraint rows)
//! for every domain size 2^min_log..2^max_log. Run it on a pool of at most
//! `MAX_WORKERS` threads: on a larger one the SIMD path is not taken.

use ark_bn254::Fr;
use ark_ff::{One, UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use wasm_bindgen::prelude::wasm_bindgen;

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
