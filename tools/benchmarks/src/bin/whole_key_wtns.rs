//! Measure the ordinary whole-key native prover with a precomputed WTNS.

use std::{env, fs, fs::File, io::BufReader, time::Instant};

use curvy_prover::{HAWK_PROFILE, Prover, ProverMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if !(args.len() == 5 || (matches!(args.len(), 6 | 9) && args[5] == "--load-only")) {
        return Err(
            "usage: whole_key_wtns <zkey> <zkey-sha256> <wtns> <threads> [--load-only [--manifest <path> <sha256>]]".into(),
        );
    }
    let load_only = args.len() >= 6;
    let threads = args[4].parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let total_started = Instant::now();
    let read_started = Instant::now();
    let mut zkey = BufReader::new(File::open(&args[1])?);
    let zkey_open_ms = read_started.elapsed().as_secs_f64() * 1_000.0;

    let parse_started = Instant::now();
    let prover = if args.len() == 9 {
        if args[6] != "--manifest" {
            return Err("expected --manifest".into());
        }
        let bytes = fs::read(&args[7])?;
        let manifest = curvy_prover::sparrow::manifest::ZkeyChunkManifest::from_bytes(
            &bytes, &args[8], &args[2],
        )?;
        Prover::from_zkey_manifest_reader(&mut zkey, &manifest)?
    } else {
        Prover::from_zkey_reader(&mut zkey, &args[2])?
    };
    let zkey_parse_ms = parse_started.elapsed().as_secs_f64() * 1_000.0;
    drop(zkey);

    println!("prover_mode={}", ProverMode::Resident);
    println!("profile={HAWK_PROFILE}");
    println!(
        "operation={}",
        if load_only { "load-only" } else { "prove" }
    );
    println!("threads={threads}");
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("zkey_open_ms={zkey_open_ms:.3}");
    println!("zkey_parse_and_auth_ms={zkey_parse_ms:.3}");
    println!("constraints={}", prover.num_constraints());
    println!("public_inputs={}", prover.num_public());
    println!("matrix_storage_bytes={}", prover.matrix_storage_bytes());
    if load_only {
        println!(
            "total_ms={:.3}",
            total_started.elapsed().as_secs_f64() * 1_000.0
        );
        return Ok(());
    }

    let witness_started = Instant::now();
    let witness = fs::read(&args[3])?;
    let witness_read_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;

    let decode_started = Instant::now();
    let assignment = curvy_prover::wtns::read_wtns(&witness)?;
    let witness_decode_ms = decode_started.elapsed().as_secs_f64() * 1_000.0;

    let proof_started = Instant::now();
    let proof = prover.prove(&assignment)?;
    let proof_ms = proof_started.elapsed().as_secs_f64() * 1_000.0;

    let verify_started = Instant::now();
    let verified = prover.verify(&proof, prover.public_inputs(&assignment)?)?;
    let self_verify_ms = verify_started.elapsed().as_secs_f64() * 1_000.0;
    if !verified {
        return Err("generated Groth16 proof did not verify".into());
    }

    println!("wtns_bytes={}", witness.len());
    println!("witness_read_ms={witness_read_ms:.3}");
    println!("witness_fields={}", assignment.len());
    println!("witness_decode_ms={witness_decode_ms:.3}");
    println!("proof_generation_ms={proof_ms:.3}");
    println!("self_verify_ms={self_verify_ms:.3}");
    println!("self_verified={verified}");
    println!(
        "total_ms={:.3}",
        total_started.elapsed().as_secs_f64() * 1_000.0
    );
    Ok(())
}
