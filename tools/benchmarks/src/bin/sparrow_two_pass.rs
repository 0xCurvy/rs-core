//! Measure the two-pass SPARROW fallback from a SIGNET source graph.

use std::{env, fs, fs::File, io::Seek, io::SeekFrom, time::Instant};

use curvy_prover::sparrow::{
    SparrowConfig, SparrowProver, authenticate_reader, prove_reader_owned,
};
use curvy_witness::Limits;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 8 {
        return Err("usage: sparrow_two_pass <zkey> <zkey-sha256> <graph> <graph-sha256> <input-json> <threads> <client|batch>".into());
    }
    let threads = args[6].parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let limits = match args[7].as_str() {
        "client" => Limits::client(),
        "batch" => Limits::batch_prover(),
        _ => return Err("limits must be client or batch".into()),
    };
    let config = SparrowConfig::default();
    let total_started = Instant::now();

    let graph_read_started = Instant::now();
    let graph = fs::read(&args[3])?;
    let graph_read_ms = graph_read_started.elapsed().as_secs_f64() * 1_000.0;
    let graph_compile_started = Instant::now();
    let prover = SparrowProver::from_signet_bytes(&graph, &args[4], &args[2], limits, config)?;
    let graph_compile_ms = graph_compile_started.elapsed().as_secs_f64() * 1_000.0;
    drop(graph);

    let input = fs::read_to_string(&args[5])?;
    let witness_started = Instant::now();
    let assignment = prover.calculate_witness_json(&input)?;
    let witness_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;
    let sage_slots = prover.sage_slot_count();
    let assignment_size = prover.assignment_size();
    // This harness proves once. Releasing the compiled SAGE instruction stream
    // lets the allocator reuse that storage for FFT and MSM working sets.
    drop(prover);

    let mut zkey = File::open(&args[1])?;
    let auth_started = Instant::now();
    authenticate_reader(&mut zkey, &args[2], config.io_chunk_bytes)?;
    let auth_ms = auth_started.elapsed().as_secs_f64() * 1_000.0;
    zkey.seek(SeekFrom::Start(0))?;

    let proof_started = Instant::now();
    let bundle = prove_reader_owned(&mut zkey, assignment, &args[2], config)?;
    let proof_ms = proof_started.elapsed().as_secs_f64() * 1_000.0;

    println!("threads={threads}");
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("graph_bytes={}", fs::metadata(&args[3])?.len());
    println!("sage_slots={sage_slots}");
    println!("assignment_size={assignment_size}");
    println!("graph_read_ms={graph_read_ms:.3}");
    println!("graph_compile_ms={graph_compile_ms:.3}");
    println!("witness_ms={witness_ms:.3}");
    println!("zkey_auth_pass_ms={auth_ms:.3}");
    println!("sparrow_proof_and_self_verify_ms={proof_ms:.3}");
    println!("proof_json_bytes={}", bundle.proof_json.len());
    println!(
        "total_ms={:.3}",
        total_started.elapsed().as_secs_f64() * 1_000.0
    );
    Ok(())
}
