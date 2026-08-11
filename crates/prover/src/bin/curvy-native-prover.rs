use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use curvy_prover::CircuitProver;

const DEFAULT_THREADS: usize = 1;
const MAX_THREADS: usize = 64;
// Published keys are currently below 1 GiB. Keep enough headroom for larger
// circuits without allowing an accidentally substituted device/file to grow the
// process until the allocator aborts before SHA-256 can reject it.
const MAX_ZKEY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

struct Arguments {
    zkey_path: PathBuf,
    zkey_sha256: String,
    graph_path: PathBuf,
    graph_sha256: String,
    input_path: PathBuf,
    proof_path: PathBuf,
    public_path: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments()?;
    let rayon_threads = configure_rayon()?;

    let load_started = Instant::now();
    let limits = curvy_witness::Limits::batch_prover();
    let zkey = read_limited(&arguments.zkey_path, MAX_ZKEY_BYTES, "zkey")?;
    let graph = read_limited(
        &arguments.graph_path,
        limits.graph_bytes as u64,
        "witness graph",
    )?;
    let input_json = String::from_utf8(read_limited(
        &arguments.input_path,
        limits.input_json_bytes as u64,
        "input JSON",
    )?)
    .map_err(|_| "input JSON must be valid UTF-8")?;
    let artifact_load = load_started.elapsed();

    let initialization_started = Instant::now();
    let prover = CircuitProver::from_artifacts(
        &zkey,
        &arguments.zkey_sha256,
        &graph,
        &arguments.graph_sha256,
    )?;
    let artifact_initialization = initialization_started.elapsed();
    drop(zkey);
    drop(graph);

    let witness_started = Instant::now();
    let assignment = prover.calculate_witness_json(&input_json)?;
    let witness_calculation = witness_started.elapsed();
    drop(input_json);

    let proof_started = Instant::now();
    let bundle = prover.prove_assignment(&assignment)?;
    let proof_generation = proof_started.elapsed();

    fs::write(&arguments.proof_path, bundle.proof_json)?;
    fs::write(&arguments.public_path, bundle.public_signals_json)?;
    println!(
        concat!(
            "{{",
            "\"artifactLoadMs\":{:.3},",
            "\"artifactInitializationMs\":{:.3},",
            "\"witnessCalculationMs\":{:.3},",
            "\"proofGenerationMs\":{:.3},",
            "\"rayonThreads\":{}",
            "}}"
        ),
        elapsed_ms(artifact_load),
        elapsed_ms(artifact_initialization),
        elapsed_ms(witness_calculation),
        elapsed_ms(proof_generation),
        rayon_threads,
    );
    Ok(())
}

fn parse_arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("curvy-native-prover"));
    let usage = || {
        format!(
            concat!(
                "usage: {} <zkey> <zkey-sha256> <graph.bin> <graph-sha256> ",
                "<input.json> <proof.json> <public.json>"
            ),
            PathBuf::from(&program).display()
        )
    };
    let zkey_path = arguments.next().ok_or_else(usage)?;
    let zkey_sha256 = utf8_argument(arguments.next().ok_or_else(usage)?, "zkey SHA-256")?;
    let graph_path = arguments.next().ok_or_else(usage)?;
    let graph_sha256 = utf8_argument(arguments.next().ok_or_else(usage)?, "graph SHA-256")?;
    let input_path = arguments.next().ok_or_else(usage)?;
    let proof_path = arguments.next().ok_or_else(usage)?;
    let public_path = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage().into());
    }
    Ok(Arguments {
        zkey_path: zkey_path.into(),
        zkey_sha256,
        graph_path: graph_path.into(),
        graph_sha256,
        input_path: input_path.into(),
        proof_path: proof_path.into(),
        public_path: public_path.into(),
    })
}

fn utf8_argument(value: OsString, label: &str) -> Result<String, Box<dyn Error>> {
    value
        .into_string()
        .map_err(|_| format!("{label} must be valid UTF-8").into())
}

fn configured_threads() -> Result<usize, Box<dyn Error>> {
    let Some(value) = env::var_os("CURVY_PROVER_NUM_THREADS") else {
        return Ok(DEFAULT_THREADS);
    };
    let value = value
        .into_string()
        .map_err(|_| "CURVY_PROVER_NUM_THREADS must be valid UTF-8")?;
    let threads = value
        .parse::<usize>()
        .map_err(|_| "CURVY_PROVER_NUM_THREADS must be an integer")?;
    if !(1..=MAX_THREADS).contains(&threads) {
        return Err(format!("CURVY_PROVER_NUM_THREADS must be in 1..={MAX_THREADS}").into());
    }
    Ok(threads)
}

#[cfg(feature = "parallel")]
fn configure_rayon() -> Result<usize, Box<dyn Error>> {
    let threads = configured_threads()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|index| format!("curvy-prover-{index}"))
        .build_global()?;
    Ok(threads)
}

#[cfg(not(feature = "parallel"))]
fn configure_rayon() -> Result<usize, Box<dyn Error>> {
    let threads = configured_threads()?;
    if threads != 1 {
        return Err("this curvy-native-prover build does not include Rayon".into());
    }
    Ok(threads)
}

fn elapsed_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn read_limited(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let expected = file.metadata()?.len();
    if expected > maximum {
        return Err(format!(
            "{label} is {expected} bytes; maximum accepted size is {maximum} bytes"
        )
        .into());
    }

    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let next = (bytes.len() as u64)
            .checked_add(count as u64)
            .filter(|length| *length <= maximum)
            .ok_or_else(|| format!("{label} grew beyond its {maximum}-byte limit while reading"))?;
        bytes.try_reserve_exact(count)?;
        bytes.extend_from_slice(&buffer[..count]);
        debug_assert_eq!(bytes.len() as u64, next);
    }
    if bytes.len() as u64 != expected {
        return Err(format!("{label} changed size while it was being read").into());
    }
    Ok(bytes)
}
