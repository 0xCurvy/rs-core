//! Repeated, self-verified resident proofs from authenticated production graphs.
use curvy_prover::{Prover, ResidentProver};
use curvy_witness::{Limits, WitnessGraph, sage::SageGraph};
use serde::Deserialize;
use serde_json::json;
use std::{env, fs, fs::File, io::BufReader, time::Instant};

#[derive(Deserialize)]
struct Config {
    zkey: String,
    zkey_sha256: String,
    graph: String,
    graph_sha256: String,
    backend: String,
    program: Option<String>,
    program_sha256: Option<String>,
    notes: usize,
    threads: usize,
    samples: usize,
    scratch_bytes: Option<usize>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = serde_json::from_slice(&fs::read(
        env::args().nth(1).ok_or("expected config path")?,
    )?)?;
    if config.samples == 0 || config.threads == 0 {
        return Err("samples and threads must be positive".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build_global()?;
    let started = Instant::now();
    let prover = Prover::from_zkey_reader(
        &mut BufReader::new(File::open(&config.zkey)?),
        &config.zkey_sha256,
    )?;
    let key_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let resident = match config.backend.as_str() {
        "graph" => ResidentProver::with_graph(
            prover,
            WitnessGraph::from_bytes_with_limits(
                &fs::read(&config.graph)?,
                &config.graph_sha256,
                Limits::batch_prover(),
            )?,
        )?,
        "sage" => ResidentProver::with_sage(
            prover,
            SageGraph::from_bytes_with_limits(
                &fs::read(&config.graph)?,
                &config.graph_sha256,
                Limits::batch_prover(),
            )?,
        )?,
        "cached" => ResidentProver::from_compiled_sage(
            prover,
            &fs::read(config.program.as_ref().ok_or("missing program")?)?,
            config
                .program_sha256
                .as_deref()
                .ok_or("missing program pin")?,
            &config.graph_sha256,
            Limits::batch_prover(),
        )?,
        _ => return Err("backend must be graph, sage, or cached".into()),
    };
    let witness_load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let input = curvy_core::witness::build_pending_commitment(
        &curvy_core::imt::Imt::new(30),
        30,
        config.notes,
        &[ark_bn254::Fr::from(1)],
    );
    let mut circuit_input = serde_json::to_value(&input)?;
    circuit_input
        .as_object_mut()
        .ok_or("expected object")?
        .remove("newNotesRoot");
    let input_json = circuit_input.to_string();
    let public_hash = input
        .input_hash
        .parse::<ark_bn254::Fr>()
        .map_err(|_| "invalid input hash")?;
    let expected_publics = serde_json::to_string(&[public_hash.to_string()])?;
    let mut samples = Vec::new();
    #[cfg(feature = "scratch")]
    let mut witness = curvy_witness::WitnessWorkspace::new(config.scratch_bytes.unwrap_or(0));
    #[cfg(feature = "scratch")]
    let mut proof = curvy_prover::ProofWorkspace::new(config.scratch_bytes.unwrap_or(0));
    #[cfg(not(feature = "scratch"))]
    if config.scratch_bytes.is_some() {
        return Err("build with --features scratch".into());
    }
    for index in 0..=config.samples {
        let started = Instant::now();
        #[cfg(feature = "scratch")]
        let bundle = if config.scratch_bytes.is_some() {
            resident.prove_json_with_workspace(&input_json, &mut witness, &mut proof)?
        } else {
            resident.prove_json(&input_json)?
        };
        #[cfg(not(feature = "scratch"))]
        let bundle = resident.prove_json(&input_json)?;
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        if bundle.public_signals_json != expected_publics {
            return Err("public input mismatch".into());
        }
        if index != 0 {
            samples.push(elapsed);
        }
    }
    #[cfg(feature = "scratch")]
    let retained = witness.retained_bytes() + proof.retained_bytes();
    #[cfg(not(feature = "scratch"))]
    let retained = 0;
    let linux_peak_rss_bytes = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(|kib| kib * 1024)
            })
        });
    println!(
        "{}",
        json!({"backend":config.backend, "notes":config.notes, "threads":config.threads,
        "key_ms":key_ms, "witness_load_ms":witness_load_ms, "proof_and_witness_ms":samples,
        "self_verified":true, "scratch_retained_bytes":retained, "constraints":resident.num_constraints(),
        "linux_peak_rss_bytes":linux_peak_rss_bytes})
    );
    Ok(())
}
