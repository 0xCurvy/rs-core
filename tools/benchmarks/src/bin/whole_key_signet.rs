//! End-to-end whole-key proving from an authenticated SIGNET input graph.

use std::{env, fs, fs::File, io::BufReader, time::Instant};

use curvy_prover::ResidentProver;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 7 {
        return Err("usage: whole_key_signet <zkey> <zkey-sha256> <signet> <signet-sha256> <input-json> <threads>".into());
    }
    let threads = args[6].parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let total_started = Instant::now();

    let graph_read_started = Instant::now();
    let graph = fs::read(&args[3])?;
    let graph_read_ms = graph_read_started.elapsed().as_secs_f64() * 1_000.0;

    let bundle_load_started = Instant::now();
    let mut zkey = BufReader::new(File::open(&args[1])?);
    let prover = ResidentProver::from_artifacts_reader_with_limits(
        &mut zkey,
        &args[2],
        &graph,
        &args[4],
        curvy_witness::Limits::batch_prover(),
    )?;
    let bundle_load_ms = bundle_load_started.elapsed().as_secs_f64() * 1_000.0;
    drop(zkey);
    drop(graph);

    let input_read_started = Instant::now();
    let input = fs::read_to_string(&args[5])?;
    let input_read_ms = input_read_started.elapsed().as_secs_f64() * 1_000.0;

    let witness_started = Instant::now();
    let assignment = prover.calculate_witness_json(&input)?;
    let witness_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;

    let proof_started = Instant::now();
    let proof = prover.prove_assignment(&assignment)?;
    let proof_ms = proof_started.elapsed().as_secs_f64() * 1_000.0;

    println!("prover_mode={}", prover.mode());
    println!("profile={}", prover.profile());
    println!("threads={threads}");
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("signet_bytes={}", fs::metadata(&args[3])?.len());
    println!("constraints={}", prover.num_constraints());
    println!("public_inputs={}", prover.num_public());
    println!("assignment_size={}", assignment.len());
    println!("matrix_storage_bytes={}", prover.matrix_storage_bytes());
    println!("signet_read_ms={graph_read_ms:.3}");
    println!("authenticated_bundle_load_ms={bundle_load_ms:.3}");
    println!("input_read_ms={input_read_ms:.3}");
    println!("witness_ms={witness_ms:.3}");
    println!("proof_and_self_verify_ms={proof_ms:.3}");
    println!("proof_json_bytes={}", proof.proof_json.len());
    println!(
        "total_ms={:.3}",
        total_started.elapsed().as_secs_f64() * 1_000.0
    );
    Ok(())
}
