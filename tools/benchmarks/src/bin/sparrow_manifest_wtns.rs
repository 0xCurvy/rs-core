//! Measure one-pass SPARROW proving with a precomputed WTNS.

use std::{env, fs, fs::File, time::Instant};

use curvy_prover::{
    sparrow::{
        SparrowConfig,
        manifest::{ZkeyChunkManifest, prove_reader_with_manifest_owned},
    },
    wtns::read_wtns,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if !(7..=9).contains(&args.len()) {
        return Err("usage: sparrow_manifest_wtns <zkey> <zkey-sha256> <manifest> <manifest-sha256> <wtns> <threads> [window-bits|adaptive] [msm-chunk-points]".into());
    }
    let threads = args[6].parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let mut config = SparrowConfig::native_adaptive();
    if let Some(value) = args.get(7) {
        config.window_bits = if value == "adaptive" {
            SparrowConfig::ADAPTIVE_WINDOW_BITS
        } else {
            value.parse()?
        };
    }
    if let Some(value) = args.get(8) {
        config.msm_chunk_points = value.parse()?;
    }
    let total_started = Instant::now();

    let witness_read_started = Instant::now();
    let witness = fs::read(&args[5])?;
    let witness_read_ms = witness_read_started.elapsed().as_secs_f64() * 1_000.0;

    let witness_decode_started = Instant::now();
    let assignment = read_wtns(&witness)?;
    let witness_decode_ms = witness_decode_started.elapsed().as_secs_f64() * 1_000.0;
    let assignment_size = assignment.len();
    drop(witness);

    let manifest_started = Instant::now();
    let manifest_bytes = fs::read(&args[3])?;
    let manifest = ZkeyChunkManifest::from_bytes(&manifest_bytes, &args[4], &args[2])?;
    let manifest_load_ms = manifest_started.elapsed().as_secs_f64() * 1_000.0;
    let manifest_bytes_len = manifest_bytes.len();
    drop(manifest_bytes);

    let proof_started = Instant::now();
    let bundle =
        prove_reader_with_manifest_owned(&mut File::open(&args[1])?, assignment, manifest, config)?;
    let proof_ms = proof_started.elapsed().as_secs_f64() * 1_000.0;

    let adaptive_window = config.uses_adaptive_window();
    println!("threads={threads}");
    println!(
        "window_policy={}",
        if adaptive_window { "adaptive" } else { "fixed" }
    );
    if !adaptive_window {
        println!("window_bits={}", config.window_bits);
    }
    println!("msm_chunk_points={}", config.msm_chunk_points);
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("manifest_bytes={manifest_bytes_len}");
    println!("assignment_size={assignment_size}");
    println!("witness_read_ms={witness_read_ms:.3}");
    println!("witness_decode_ms={witness_decode_ms:.3}");
    println!("manifest_load_ms={manifest_load_ms:.3}");
    println!("sparrow_one_pass_proof_and_verify_ms={proof_ms:.3}");
    println!("proof_json_bytes={}", bundle.proof_json.len());
    println!(
        "total_ms={:.3}",
        total_started.elapsed().as_secs_f64() * 1_000.0
    );
    Ok(())
}
