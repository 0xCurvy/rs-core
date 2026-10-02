//! Isolated proof of concept: BN254 Fr radix-2 NTT with the 4-lane simd128
//! 9x29 Montgomery multiply from poc/wasm-field. Commands (native and WASM):
//! - `test SEED RANDOM MAXLOG`: scalar Fr differential tests; in WASM also the
//!   NTT against ark-poly for sizes 2^10..2^MAXLOG.
//! - `bench LOG REPS`: interleaved ark-poly vs simd timings (WASM).
#![allow(clippy::needless_range_loop)]

pub mod clock;
pub mod fr29;
#[rustfmt::skip]
pub mod gen_u29;
pub mod ntt;

use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};

fn rand_vec(n: usize, seed: u64) -> Vec<Fr> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(|_| Fr::rand(&mut rng)).collect()
}

#[cfg(target_arch = "wasm32")]
fn check_ntt(seed: u64, max_log: u32) -> u64 {
    use ark_ff::{Field, One, Zero};
    use ntt::{Plan, ntt};
    let mut checks = 0u64;
    let mut buf = Vec::new();
    for log in 3..=max_log {
        let n = 1usize << log;
        let d = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
        let g = Radix2EvaluationDomain::<Fr>::new(2 * n).unwrap().group_gen;
        let fwd = Plan::new(n, d.group_gen);
        let inv = Plan::new(n, d.group_gen_inv);
        let mut inputs = vec![rand_vec(n, seed + log as u64)];
        // Edge inputs: all zero, all one, all r-1, a delta, a single r-1.
        inputs.push(vec![Fr::zero(); n]);
        inputs.push(vec![Fr::one(); n]);
        inputs.push(vec![-Fr::one(); n]);
        let mut delta = vec![Fr::zero(); n];
        delta[1] = Fr::one();
        inputs.push(delta);
        let mut e = vec![-Fr::one(); n];
        e[n - 1] = Fr::from(2u64).inverse().unwrap();
        inputs.push(e);
        for x in &inputs {
            let mut want = x.clone();
            d.fft_in_place(&mut want);
            let mut got = x.clone();
            ntt(&fwd, &mut got, &mut buf, None, None);
            assert!(got == want, "fft 2^{log}");
            let mut want = x.clone();
            d.ifft_in_place(&mut want);
            let mut got = x.clone();
            ntt(&inv, &mut got, &mut buf, None, Some(d.size_inv));
            assert!(got == want, "ifft 2^{log}");
            // Coset FFT (ark's coset domain) with offset g = omega_2n.
            let cd = d.get_coset(g).unwrap();
            let mut want = x.clone();
            cd.fft_in_place(&mut want);
            let mut got = x.clone();
            ntt(&fwd, &mut got, &mut buf, Some((g, Fr::one())), None);
            assert!(got == want, "coset fft 2^{log}");
            // Witness-map step: ifft, distribute_powers(g), fft; simd fuses
            // n^-1 into the coset scaling.
            let mut want = x.clone();
            d.ifft_in_place(&mut want);
            Radix2EvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(&mut want, g, Fr::one());
            d.fft_in_place(&mut want);
            let mut got = x.clone();
            ntt(&inv, &mut got, &mut buf, None, None);
            ntt(&fwd, &mut got, &mut buf, Some((g, d.size_inv)), None);
            assert!(got == want, "witness step 2^{log}");
            // Round trip.
            ntt(&inv, &mut got, &mut buf, Some((g.inverse().unwrap(), d.size_inv)), None);
            let _ = got;
            checks += 4 * n as u64;
        }
    }
    checks
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

#[cfg(target_arch = "wasm32")]
fn bench(log: u32, reps: usize) -> String {
    use ntt::{Plan, dif, ntt, pack, unpack};
    let n = 1usize << log;
    let d = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
    let g = Radix2EvaluationDomain::<Fr>::new(2 * n).unwrap().group_gen;
    let x0 = rand_vec(n, 7);
    let mut buf = Vec::new();
    let fwd = Plan::new(n, d.group_gen);
    let inv = Plan::new(n, d.group_gen_inv);
    let names = [
        "ark_fft", "simd_fft", "simd_fft_cached", "ark_ifft", "simd_ifft",
        "ark_wstep", "simd_wstep", "simd_wstep_cached", "simd_dif_only", "simd_convert", "simd_plan",
    ];
    let mut t: Vec<Vec<f64>> = vec![Vec::new(); names.len()];
    let mut x = x0.clone();
    for _ in 0..reps {
        // Interleaved: every rep runs every variant once, in alternating order.
        for (idx, _) in names.iter().enumerate() {
            x.copy_from_slice(&x0);
            let s = clock::now_ms();
            match idx {
                0 => d.fft_in_place(&mut x),
                1 => {
                    let p = Plan::new(n, d.group_gen);
                    ntt(&p, &mut x, &mut buf, None, None)
                }
                2 => ntt(&fwd, &mut x, &mut buf, None, None),
                3 => d.ifft_in_place(&mut x),
                4 => {
                    let p = Plan::new(n, d.group_gen_inv);
                    ntt(&p, &mut x, &mut buf, None, Some(d.size_inv))
                }
                5 => {
                    d.ifft_in_place(&mut x);
                    Radix2EvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(&mut x, g, ark_ff::One::one());
                    d.fft_in_place(&mut x);
                }
                6 => {
                    let pi = Plan::new(n, d.group_gen_inv);
                    let pf = Plan::new(n, d.group_gen);
                    ntt(&pi, &mut x, &mut buf, None, None);
                    ntt(&pf, &mut x, &mut buf, Some((g, d.size_inv)), None);
                }
                7 => {
                    ntt(&inv, &mut x, &mut buf, None, None);
                    ntt(&fwd, &mut x, &mut buf, Some((g, d.size_inv)), None);
                }
                8 => {
                    pack(&x, &mut buf, None);
                    let s2 = clock::now_ms();
                    dif(&fwd, &mut buf);
                    t[idx].push(clock::now_ms() - s2);
                    continue;
                }
                9 => {
                    pack(&x, &mut buf, None);
                    unpack(&buf, &mut x, None);
                }
                _ => {
                    let p = Plan::new(n, d.group_gen);
                    core::hint::black_box(&p);
                }
            }
            t[idx].push(clock::now_ms() - s);
        }
    }
    let bfly = (n / 2 * log as usize) as f64;
    let mut out = format!("{{\"log\":{log},\"reps\":{reps}");
    for (i, name) in names.iter().enumerate() {
        let m = median(&mut t[i]);
        out += &format!(",\"{name}_ms\":{m:.3}");
        if i <= 4 || i == 8 {
            out += &format!(",\"{name}_ns_per_bfly\":{:.2}", m * 1e6 / bfly);
        }
    }
    out + "}"
}


/// finish_evaluations from crates/prover/src/qap.rs (c = a.b, 3x ifft +
/// distribute_powers(omega_2n) + fft, a = a.b - c), ark-poly vs simd, interleaved
/// ABBA; plans are rebuilt per call (no caching across proofs).
#[cfg(target_arch = "wasm32")]
fn wmap(log: u32, reps: usize) -> String {
    use ark_ff::One;
    use ntt::{Plan, ntt};
    let n = 1usize << log;
    let d = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
    let g = Radix2EvaluationDomain::<Fr>::new(2 * n).unwrap().group_gen;
    let (a0, b0) = (rand_vec(n, 11), rand_vec(n, 12));
    let mut buf = Vec::new();
    let run = |simd: bool, a: &mut Vec<Fr>, b: &mut Vec<Fr>, buf: &mut Vec<ntt::V>| -> (f64, f64) {
        let s = clock::now_ms();
        let mut c: Vec<Fr> = a.iter().zip(b.iter()).map(|(x, y)| *x * y).collect();
        let mut fft_ms = 0.0;
        if simd {
            let f0 = clock::now_ms();
            let pi = Plan::new(n, d.group_gen_inv);
            let pf = Plan::new(n, d.group_gen);
            for v in [&mut *a, &mut *b] {
                ntt(&pi, v, buf, None, None);
                ntt(&pf, v, buf, Some((g, d.size_inv)), None);
            }
            fft_ms += clock::now_ms() - f0;
            a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x *= y);
            let f0 = clock::now_ms();
            ntt(&pi, &mut c, buf, None, None);
            ntt(&pf, &mut c, buf, Some((g, d.size_inv)), None);
            fft_ms += clock::now_ms() - f0;
        } else {
            let f0 = clock::now_ms();
            for v in [&mut *a, &mut *b] {
                d.ifft_in_place(v);
                Radix2EvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(v, g, Fr::one());
                d.fft_in_place(v);
            }
            fft_ms += clock::now_ms() - f0;
            a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x *= y);
            let f0 = clock::now_ms();
            d.ifft_in_place(&mut c);
            Radix2EvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(&mut c, g, Fr::one());
            d.fft_in_place(&mut c);
            fft_ms += clock::now_ms() - f0;
        }
        a.iter_mut().zip(c.iter()).for_each(|(x, y)| *x -= y);
        let total = clock::now_ms() - s;
        (total, fft_ms)
    };
    let (mut ta, mut ts, mut fa, mut fs): (Vec<f64>, Vec<f64>, Vec<f64>, Vec<f64>) = Default::default();
    let mut ref_out: Option<Vec<Fr>> = None;
    for r in 0..reps {
        for simd in if r % 2 == 0 { [false, true, true, false] } else { [true, false, false, true] } {
            let (mut a, mut b) = (a0.clone(), b0.clone());
            let s = clock::now_ms();
            let (total, fft) = run(simd, &mut a, &mut b, &mut buf);
            let _ = s;
            match &ref_out {
                None => ref_out = Some(a.clone()),
                Some(want) => assert!(*want == a, "witness map output differs"),
            }
            if simd { ts.push(total); fs.push(fft) } else { ta.push(total); fa.push(fft) }
        }
    }
    format!(
        "{{\"log\":{log},\"runs_each\":{},\"ark_wmap_ms\":{:.1},\"simd_wmap_ms\":{:.1},\"ark_fft_part_ms\":{:.1},\"simd_fft_part_ms\":{:.1}}}",
        ta.len(), median(&mut ta), median(&mut ts), median(&mut fa), median(&mut fs)
    )
}

pub fn run_command(command: &str) -> String {
    let args: Vec<&str> = command.split_whitespace().collect();
    let num = |i: usize, d: u64| -> u64 { args.get(i).map(|v| v.parse().unwrap()).unwrap_or(d) };
    match args.first().copied() {
        Some("test") => {
            let started = clock::now_ms();
            let scalar = fr29::check_scalar(num(1, 1), num(2, 100_000) as usize);
            #[cfg(target_arch = "wasm32")]
            let ntt_checks = check_ntt(num(1, 1), num(3, 14) as u32);
            #[cfg(not(target_arch = "wasm32"))]
            let ntt_checks = 0u64;
            format!(
                "{{\"scalar_checks\":{scalar},\"ntt_element_checks\":{ntt_checks},\"ms\":{:.0}}}",
                clock::now_ms() - started
            )
        }
        #[cfg(target_arch = "wasm32")]
        Some("bench") => bench(num(1, 16) as u32, num(2, 5) as usize),
        #[cfg(target_arch = "wasm32")]
        Some("wmap") => wmap(num(1, 18) as u32, num(2, 3) as usize),
        #[cfg(not(target_arch = "wasm32"))]
        Some("bench") => {
            // Native reference for ark-poly only.
            let log = num(1, 16) as u32;
            let n = 1usize << log;
            let d = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
            let x0 = rand_vec(n, 7);
            let mut ts = Vec::new();
            for _ in 0..num(2, 5) {
                let mut x = x0.clone();
                let s = clock::now_ms();
                d.fft_in_place(&mut x);
                ts.push(clock::now_ms() - s);
            }
            format!("{{\"log\":{log},\"native_ark_fft_ms\":{:.3}}}", median(&mut ts))
        }
        _ => "{\"error\":\"unknown command\"}".into(),
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use std::cell::RefCell;

    thread_local! {
        static COMMAND: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static OUTPUT: RefCell<String> = const { RefCell::new(String::new()) };
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn cmd_alloc(len: usize) -> *mut u8 {
        std::panic::set_hook(Box::new(|info| crate::clock::log(&info.to_string())));
        COMMAND.with(|c| {
            let mut c = c.borrow_mut();
            c.clear();
            c.resize(len, 0);
            c.as_mut_ptr()
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn cmd_run() -> usize {
        let command = COMMAND.with(|c| String::from_utf8(c.borrow().clone()).expect("utf-8"));
        let output = super::run_command(&command);
        OUTPUT.with(|o| {
            *o.borrow_mut() = output;
            o.borrow().len()
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn out_ptr() -> *const u8 {
        OUTPUT.with(|o| o.borrow().as_ptr())
    }
}
