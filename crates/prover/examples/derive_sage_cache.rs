//! Derive and validate a local SAGE cache entry from a pinned SIGNET graph.

use std::{env, fs};

use curvy_witness::{Limits, sage::SageGraph};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err(
            "usage: derive_sage_cache <signet> <signet-sha256> <program-out> <client|batch>".into(),
        );
    }
    let limits = match args[4].as_str() {
        "client" => Limits::client(),
        "batch" => Limits::batch_prover(),
        _ => return Err("limits must be client or batch".into()),
    };
    let graph_bytes = fs::read(&args[1])?;
    let graph = SageGraph::from_bytes_with_limits(&graph_bytes, &args[2], limits)?;
    let program = graph.to_compiled_bytes()?;
    let program_sha256 = hex(Sha256::digest(&program));
    SageGraph::from_compiled_bytes_with_limits(&program, &program_sha256, &args[2], limits)?;
    fs::write(&args[3], &program)?;
    println!("source_graph_sha256={}", args[2].to_ascii_lowercase());
    println!("program_bytes={}", program.len());
    println!("program_sha256={program_sha256}");
    println!("assignment_size={}", graph.assignment_size());
    println!("sage_slots={}", graph.slot_count());
    Ok(())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
