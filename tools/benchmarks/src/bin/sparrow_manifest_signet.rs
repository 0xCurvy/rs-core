//! End-to-end one-pass SPARROW proving from an authenticated SIGNET source graph.

use std::{env, fs, fs::File, time::Instant};

use curvy_prover::sparrow::manifest::{ZkeyChunkManifest, prove_reader_with_manifest_owned};
use curvy_prover::{StreamingConfig, StreamingProver};
use curvy_witness::Limits;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if !(9..=11).contains(&args.len()) {
        return Err("usage: sparrow_manifest_signet <zkey> <zkey-sha256> <manifest> <manifest-sha256> <signet> <signet-sha256> <input-json> <threads> [window-bits|adaptive] [msm-chunk-points]".into());
    }
    let threads = args[8].parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let mut config = StreamingConfig::native_adaptive();
    if let Some(value) = args.get(9) {
        config.window_bits = if value == "adaptive" {
            StreamingConfig::ADAPTIVE_WINDOW_BITS
        } else {
            value.parse()?
        };
    }
    if let Some(value) = args.get(10) {
        config.msm_chunk_points = value.parse()?;
    }
    let total_started = Instant::now();

    let graph_read_started = Instant::now();
    let graph = fs::read(&args[5])?;
    let graph_read_ms = graph_read_started.elapsed().as_secs_f64() * 1_000.0;
    let compile_started = Instant::now();
    let prover = StreamingProver::from_signet_bytes(
        &graph,
        &args[6],
        &args[2],
        Limits::batch_prover(),
        config,
    )?;
    let graph_compile_ms = compile_started.elapsed().as_secs_f64() * 1_000.0;
    drop(graph);

    let input_read_started = Instant::now();
    let input = fs::read_to_string(&args[7])?;
    let input_read_ms = input_read_started.elapsed().as_secs_f64() * 1_000.0;
    let witness_started = Instant::now();
    let assignment = prover.calculate_witness_json(&input)?;
    let witness_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;
    let prover_mode = prover.mode();
    let profile = prover.profile();
    let sage_slots = prover.sage_slot_count();
    let assignment_size = prover.assignment_size();
    drop(prover);

    let manifest_started = Instant::now();
    let manifest_bytes = fs::read(&args[3])?;
    let manifest = ZkeyChunkManifest::from_bytes(&manifest_bytes, &args[4], &args[2])?;
    let manifest_load_ms = manifest_started.elapsed().as_secs_f64() * 1_000.0;
    let manifest_bytes_len = manifest_bytes.len();
    drop(manifest_bytes);

    let proof_started = Instant::now();
    let proof =
        prove_reader_with_manifest_owned(&mut File::open(&args[1])?, assignment, manifest, config)?;
    let proof_ms = proof_started.elapsed().as_secs_f64() * 1_000.0;

    println!("prover_mode={prover_mode}");
    println!("profile={profile}");
    println!("threads={threads}");
    println!(
        "window_policy={}",
        if config.uses_adaptive_window() {
            "adaptive"
        } else {
            "fixed"
        }
    );
    if !config.uses_adaptive_window() {
        println!("window_bits={}", config.window_bits);
    }
    println!("msm_chunk_points={}", config.msm_chunk_points);
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("manifest_bytes={manifest_bytes_len}");
    println!("signet_bytes={}", fs::metadata(&args[5])?.len());
    println!("sage_slots={sage_slots}");
    println!("assignment_size={assignment_size}");
    println!("signet_read_ms={graph_read_ms:.3}");
    println!("signet_to_sage_compile_ms={graph_compile_ms:.3}");
    println!("input_read_ms={input_read_ms:.3}");
    println!("witness_ms={witness_ms:.3}");
    println!("manifest_load_ms={manifest_load_ms:.3}");
    println!("sparrow_proof_and_verify_ms={proof_ms:.3}");
    println!("proof_json_bytes={}", proof.proof_json.len());
    println!(
        "total_ms={:.3}",
        total_started.elapsed().as_secs_f64() * 1_000.0
    );
    Ok(())
}
