//! Measure the ordinary whole-key native prover with a precomputed WTNS.

use std::{env, fs, time::Instant};

use curvy_prover::Prover;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: whole_key_wtns <zkey> <zkey-sha256> <wtns> <threads>".into());
    }
    let threads = args[4].parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let total_started = Instant::now();
    let read_started = Instant::now();
    let zkey = fs::read(&args[1])?;
    let zkey_read_ms = read_started.elapsed().as_secs_f64() * 1_000.0;

    let parse_started = Instant::now();
    let prover = Prover::from_zkey_bytes(&zkey, &args[2])?;
    let zkey_parse_ms = parse_started.elapsed().as_secs_f64() * 1_000.0;
    drop(zkey);

    let witness_started = Instant::now();
    let witness = fs::read(&args[3])?;
    let witness_read_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;

    let proof_started = Instant::now();
    let bundle = prover.prove_wtns(&witness)?;
    let proof_ms = proof_started.elapsed().as_secs_f64() * 1_000.0;

    println!("threads={threads}");
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("zkey_read_ms={zkey_read_ms:.3}");
    println!("zkey_parse_and_auth_ms={zkey_parse_ms:.3}");
    println!("witness_read_ms={witness_read_ms:.3}");
    println!("proof_and_self_verify_ms={proof_ms:.3}");
    println!("proof_json_bytes={}", bundle.proof_json.len());
    println!(
        "total_ms={:.3}",
        total_started.elapsed().as_secs_f64() * 1_000.0
    );
    Ok(())
}
