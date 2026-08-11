//! Measure first-use SAGE compilation against a warm derived-cache load.
//!
//! This mirrors the browser cache's CPU work but intentionally excludes file
//! reads and Cache API writes, which depend on the host and browser.

use std::{env, fs, time::Instant};

use curvy_witness::{Limits, sage::SageGraph};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 4 || args.len() > 5 {
        return Err("usage: sage_cache <graph> <graph-sha256> <client|batch> [warm-rounds]".into());
    }
    let limits = match args[3].as_str() {
        "client" => Limits::client(),
        "batch" => Limits::batch_prover(),
        _ => return Err("limits must be client or batch".into()),
    };
    let rounds = args
        .get(4)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(7);
    if rounds == 0 || rounds > 100 {
        return Err("warm-rounds must be in 1..=100".into());
    }

    let source = fs::read(&args[1])?;
    let started = Instant::now();
    let graph = SageGraph::from_bytes_with_limits(&source, &args[2], limits)?;
    let compile = started.elapsed();

    let started = Instant::now();
    let program = graph.to_compiled_bytes()?;
    let serialize = started.elapsed();
    if !program.starts_with(b"SAGEPC01") {
        return Err("SAGE encoder returned an unexpected cache format".into());
    }
    let assignment_size = graph.assignment_size();
    let slots = graph.slot_count();
    drop(graph);

    let started = Instant::now();
    let program_sha256 = hex(Sha256::digest(&program));
    let digest = started.elapsed();

    let started = Instant::now();
    let roundtrip =
        SageGraph::from_compiled_bytes_with_limits(&program, &program_sha256, &args[2], limits)?;
    let roundtrip_load = started.elapsed();
    drop(roundtrip);

    let mut warm = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let started = Instant::now();
        // The browser first validates the Cache API entry against its stored
        // digest; the Rust decoder then repeats authentication at its boundary.
        let observed = hex(Sha256::digest(&program));
        if observed != program_sha256 {
            return Err("derived cache changed during benchmark".into());
        }
        let loaded = SageGraph::from_compiled_bytes_with_limits(
            &program,
            &program_sha256,
            &args[2],
            limits,
        )?;
        warm.push(started.elapsed());
        drop(loaded);
    }
    warm.sort_unstable();
    let warm_median = warm[warm.len() / 2];

    println!("format=SAGEPC01");
    println!(
        "cache_compiler_version={}",
        curvy_witness::sage::CACHE_VERSION
    );
    println!("source_bytes={}", source.len());
    println!("program_bytes={}", program.len());
    println!("assignment_size={assignment_size}");
    println!("sage_slots={slots}");
    println!("source_compile_ms={:.3}", compile.as_secs_f64() * 1_000.0);
    println!("serialize_ms={:.3}", serialize.as_secs_f64() * 1_000.0);
    println!("program_digest_ms={:.3}", digest.as_secs_f64() * 1_000.0);
    println!(
        "first_roundtrip_load_ms={:.3}",
        roundtrip_load.as_secs_f64() * 1_000.0
    );
    println!(
        "warm_cache_validation_median_ms={:.3}",
        warm_median.as_secs_f64() * 1_000.0
    );
    println!(
        "cold_cpu_total_ms={:.3}",
        (compile + serialize + digest + roundtrip_load).as_secs_f64() * 1_000.0
    );
    Ok(())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
