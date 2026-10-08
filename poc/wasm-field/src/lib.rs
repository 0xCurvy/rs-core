//! Isolated proof of concept: how fast can BN254 Fq arithmetic and a
//! batch-affine G1 MSM kernel run in WebAssembly? See README.md.
//!
//! The crate builds as a native library/binary and as a bare `cdylib` WASM
//! module (no wasm-bindgen): JS writes a command string into linear memory,
//! calls `cmd_run`, and reads back a JSON result. The same command runs
//! natively through `src/main.rs`.

// Limb arithmetic indexes several arrays in lockstep on purpose.
#![allow(clippy::needless_range_loop)]

pub mod bench;
pub mod check;
pub mod clock;
pub mod field;
pub mod fq2;
#[rustfmt::skip]
pub mod gen_u29;
pub mod lanes;
pub mod msm;
pub mod simd;
pub mod simd_bench;
pub mod simd_msm;
pub mod simd_reduce;
pub mod u29x9;
pub mod u32x8;

/// Run one command and return its JSON result.
///
/// - `test SEED RANDOM CHAIN MSM_SIZE`: differential tests (B), plus the kernel's
///   adversarial cases at MSM_SIZE points (0 skips them).
/// - `fields SCALE SAMPLES`: field microbenchmarks (A).
/// - `msm SIZE WIDTHS FIELDS INPUT REPS [g1|g2]`: kernel timings (C, D), e.g.
///   `msm 16 12,13,14 ark,u29x9,simd random 3`. SIZE is log2(points) when below
///   64, else a point count. INPUT is `random`, `generator` or
///   `witness:ZERO:ONE`. FIELDS: ark, u32x8 (G1), u29x9, simd (WASM).
pub fn run_command(command: &str) -> String {
    let args: Vec<&str> = command.split_whitespace().collect();
    let num = |i: usize, default: f64| -> f64 {
        args.get(i)
            .map(|v| v.parse().expect("number"))
            .unwrap_or(default)
    };
    match args.first().copied() {
        Some("test") => {
            let (seed, random, chain, msm_size) = (
                num(1, 1.0) as u64,
                num(2, 100_000.0) as usize,
                num(3, 1_000_000.0) as usize,
                num(4, 24.0) as usize,
            );
            let started = clock::now_ms();
            #[allow(unused_mut)]
            let mut tally = check::run_all(seed, random, chain, msm_size);
            #[cfg(target_arch = "wasm32")]
            {
                let mut sections = simd_bench::checks(seed, random, chain);
                {
                    use ark_std::rand::SeedableRng;
                    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed ^ 0xf2);
                    let r = &mut rng;
                    sections.push((
                        "fq2-simd edge pairs".into(),
                        check::fq2_edge_values::<fq2::Fq2Simd>(r),
                    ));
                    sections.push((
                        "fq2-simd random".into(),
                        check::random_values::<fq2::Fq2Simd>(r, random / 4),
                    ));
                    sections.push((
                        "fq2-simd chains".into(),
                        check::chains::<fq2::Fq2Simd>(r, chain / 4),
                    ));
                }
                if msm_size > 0 {
                    use ark_std::rand::SeedableRng;
                    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed ^ 0x3c3c);
                    sections.push((
                        "msm g1 u29x9/simd4 adversarial".to_string(),
                        check::msm_cases::<
                            ark_bn254::g1::Config,
                            u29x9::U29x9,
                            simd_msm::SimdApply<u29x9::U29x9>,
                        >(&mut rng, msm_size),
                    ));
                    sections.push((
                        "msm g1 u29x9/simd4 widths 3-16".to_string(),
                        check::msm_width_sweep::<
                            ark_bn254::g1::Config,
                            u29x9::U29x9,
                            simd_msm::SimdApply<u29x9::U29x9>,
                        >(&mut rng, 30 * msm_size),
                    ));
                    sections.push((
                        "msm g2 fq2-simd/simd4 widths 3-16".to_string(),
                        check::msm_width_sweep::<
                            ark_bn254::g2::Config,
                            fq2::Fq2Simd,
                            simd_msm::SimdApply<fq2::Fq2Simd>,
                        >(&mut rng, 30 * msm_size / 4),
                    ));
                    sections.push((
                        "msm g2 fq2-simd/simd4 adversarial".to_string(),
                        check::msm_cases::<
                            ark_bn254::g2::Config,
                            fq2::Fq2Simd,
                            simd_msm::SimdApply<fq2::Fq2Simd>,
                        >(&mut rng, msm_size / 2),
                    ));
                }
                for (name, n) in sections {
                    tally.checks += n;
                    tally.sections.push((name, n));
                }
            }
            let json = tally.json();
            format!(
                "{{\"target\":\"{}\",\"seed\":{seed},\"ms\":{:.0},{}",
                target(),
                clock::now_ms() - started,
                &json[1..]
            )
        }
        Some("fields") => {
            let json = bench::fields(num(1, 1.0), num(2, 7.0) as usize);
            format!("{{\"target\":\"{}\",\"fields\":{json}}}", target())
        }
        Some("msm") => {
            let size = num(1, 14.0) as usize;
            let size = if size < 64 { 1 << size } else { size };
            let widths: Vec<usize> = args
                .get(2)
                .unwrap_or(&"12,13,14")
                .split(',')
                .map(|w| w.parse().unwrap())
                .collect();
            let fields: Vec<&str> = args.get(3).unwrap_or(&"ark,u29x9").split(',').collect();
            let input = bench::Input::parse(args.get(4).copied().unwrap_or("random"));
            let reps = num(5, 3.0) as usize;
            let curve = args.get(6).copied().unwrap_or("g1");
            let json = bench::msm_all(curve, size, &widths, &fields, input, reps);
            format!("{{\"target\":\"{}\",\"msm\":{json}}}", target())
        }
        _ => panic!("unknown command: {command}"),
    }
}

pub fn target() -> &'static str {
    if cfg!(target_arch = "wasm32") {
        "wasm32"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "native"
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use std::cell::RefCell;

    thread_local! {
        static COMMAND: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static OUTPUT: RefCell<String> = const { RefCell::new(String::new()) };
    }

    /// Reserve `len` bytes for the next command and return where to write it.
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

    /// Run the command written after `cmd_alloc`; returns the output length.
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
