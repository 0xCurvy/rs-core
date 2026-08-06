//! `signet` - build and check witness-graph artifacts.

use std::process::ExitCode;

use curvy_signet::{
    Compression, Compressor, DEFAULT_COMPRESSION_LEVEL, Envelope, FormatVersion, Graph,
    OperationSchema, compress, decode_sha256, encode, hex, wtns,
};
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};

const USAGE: &str = "\
signet - build and check SIGNET witness-graph artifacts

  signet export <graph.bin> <out.bin> <r1cs-sha256>\n      [--ops patched|original] [--envelope cvywit|signet] [--version 1|2]\n      [--compress none|zstd] [--level N]
      Encode an upstream postcard graph. Prints the artifact size and its SHA-256,
      which is the value to pin in protocol metadata.

  signet validate <artifact> <sha256> <input.json> <reference.wtns>
      Evaluate the artifact and compare every signal against a reference witness.

  signet inspect <artifact> <sha256>
      Print what the evaluator sees: signal count and source R1CS digest.

Defaults are `--envelope cvywit --version 1`: the only combination a stock
curvy-witness accepts. Both alternatives need the consumer's `signet` feature.

`--compress zstd` shells out to the system `zstd` (default level 9, which keeps the
frame window at half the consumer's cap) and falls back to the weaker built-in
encoder if that binary is missing. Every artifact is loaded back through the
evaluator before it is written.

`--ops` says which upstream built the postcard. `patched` (the default) is the
current pipeline; `original` is needed for graphs predating the bitwise patch,
including PIX aggregation and withdrawal. Choosing wrong is SILENT - it remaps
every operation from index 14 up. Always follow an export with `validate`.";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("export") => export(&arguments[1..]),
        Some("validate") => validate(&arguments[1..]),
        Some("inspect") => inspect(&arguments[1..]),
        Some("-h" | "--help" | "help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
}

fn export(arguments: &[String]) -> Result<(), String> {
    let positional = arguments
        .iter()
        .take_while(|argument| !argument.starts_with("--"))
        .collect::<Vec<_>>();
    if positional.len() != 3 {
        return Err(format!(
            "export needs three positional arguments\n\n{USAGE}"
        ));
    }
    let mut envelope = Envelope::default();
    let mut version = FormatVersion::default();
    let mut schema = OperationSchema::default();
    let mut compression = Compression::default();
    let mut level = DEFAULT_COMPRESSION_LEVEL;
    let mut flags = arguments[positional.len()..].iter();
    while let Some(flag) = flags.next() {
        let value = flags
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--ops" => schema = OperationSchema::parse(value).map_err(|e| e.to_string())?,
            "--compress" => compression = Compression::parse(value).map_err(|e| e.to_string())?,
            "--level" => {
                level = value
                    .parse()
                    .map_err(|_| format!("--level needs an integer, got {value:?}"))?
            }
            "--envelope" => envelope = Envelope::parse(value).map_err(|e| e.to_string())?,
            "--version" => version = FormatVersion::parse(value).map_err(|e| e.to_string())?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    let source = std::fs::read(positional[0]).map_err(|e| format!("{}: {e}", positional[0]))?;
    let graph = Graph::from_postcard(&source, schema).map_err(|e| e.to_string())?;
    let r1cs = decode_sha256(positional[2]).map_err(|e| e.to_string())?;
    let bytes = encode(&graph, r1cs, envelope, version).map_err(|e| e.to_string())?;
    let (artifact, compressor) = match compression {
        Compression::None => (bytes.clone(), None),
        Compression::Zstd => {
            let (compressed, compressor) = compress(&bytes, level);
            (compressed, Some(compressor))
        }
    };

    // Load what we are about to write, through the evaluator a client uses. This is
    // what catches a frame whose window exceeds the consumer's cap, and any header
    // field written at the wrong offset - at generation time rather than at a client.
    let artifact_sha = hex(&Sha256::digest(&artifact));
    let loaded = WitnessGraph::from_bytes_with_limits(
        &artifact,
        &artifact_sha,
        curvy_witness::Limits::batch_prover(),
    )
    .map_err(|e| format!("refusing to write an artifact the evaluator rejects: {e}"))?;
    if loaded.assignment_size() != graph.signals.len() {
        return Err(format!(
            "round-trip disagreed on signal count: wrote {}, read back {}",
            graph.signals.len(),
            loaded.assignment_size()
        ));
    }

    std::fs::write(positional[1], &artifact).map_err(|e| format!("{}: {e}", positional[1]))?;

    println!("nodes={}", graph.nodes.len());
    println!("signals={}", graph.signals.len());
    println!("graph_bytes={}", bytes.len());
    println!("graph_sha256={}", hex(&Sha256::digest(&bytes)));
    if let Some(compressor) = compressor {
        // The evaluator authenticates whatever bytes it is handed, so a compressed
        // artifact pins its compressed digest. The uncompressed pair is printed too
        // because the publication record carries both.
        println!("artifact_bytes={}", artifact.len());
        println!("artifact_sha256={artifact_sha}");
        println!("pin=artifact_sha256");
        match compressor {
            Compressor::SystemZstd => println!("compressor=zstd -{level}"),
            Compressor::Ruzstd => {
                println!("compressor=ruzstd (level 1)");
                eprintln!(
                    "warning: `zstd` was not found, so this artifact is roughly twice \
                     the size it should be; install zstd before publishing"
                );
            }
        }
    } else {
        println!("pin=graph_sha256");
    }
    println!("round_trip=ok");
    eprintln!("note: confirm this artifact with `signet validate` before pinning it");
    Ok(())
}

fn validate(arguments: &[String]) -> Result<(), String> {
    let [artifact, expected_sha, input_path, reference_path] = arguments else {
        return Err(format!("validate needs four arguments\n\n{USAGE}"));
    };

    let graph = load(artifact, expected_sha)?;
    let input = std::fs::read_to_string(input_path).map_err(|e| format!("{input_path}: {e}"))?;
    let candidate = graph
        .calculate_json(&input)
        .map_err(|e| format!("evaluating {artifact}: {e}"))?;

    let reference_bytes =
        std::fs::read(reference_path).map_err(|e| format!("{reference_path}: {e}"))?;
    let reference = wtns::read(&reference_bytes).map_err(|e| e.to_string())?;

    match wtns::first_difference(&candidate, &reference) {
        None => {
            println!("signals={}", candidate.len());
            println!("parity=exact");
            Ok(())
        }
        Some(index) if candidate.len() != reference.len() => Err(format!(
            "assignment length differs: artifact {} vs reference {} (first index {index})",
            candidate.len(),
            reference.len()
        )),
        Some(index) => Err(format!(
            "signal {index} differs: artifact {} vs reference {}",
            wtns::decimal(candidate[index]),
            wtns::decimal(reference[index])
        )),
    }
}

fn inspect(arguments: &[String]) -> Result<(), String> {
    let [artifact, expected_sha] = arguments else {
        return Err(format!("inspect needs two arguments\n\n{USAGE}"));
    };
    let graph = load(artifact, expected_sha)?;
    println!("signals={}", graph.assignment_size());
    println!("r1cs_sha256={}", hex(&graph.r1cs_sha256()));
    Ok(())
}

/// Load through the shipped evaluator, under the batch-prover budget.
///
/// The tool has to handle pending(50), which a client deliberately cannot. Structural
/// validation is identical either way - only the ceilings differ - so this still
/// rejects everything a client would reject for any reason other than size.
fn load(artifact: &str, expected_sha: &str) -> Result<WitnessGraph, String> {
    let bytes = std::fs::read(artifact).map_err(|e| format!("{artifact}: {e}"))?;
    WitnessGraph::from_bytes_with_limits(
        &bytes,
        expected_sha,
        curvy_witness::Limits::batch_prover(),
    )
    .map_err(|e| format!("{artifact}: {e}"))
}
