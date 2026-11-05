//! `signet` - build and check witness-graph artifacts.

use std::process::ExitCode;

use curvy_signet::{
    Compression, Compressor, DEFAULT_COMPRESSION_LEVEL, Envelope, FormatVersion, Graph,
    OperationSchema, compress, decode_sha256, encode, hex, transcode, wtns,
};
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};

const USAGE: &str = "\
signet - build and check SIGNET witness-graph artifacts

  signet export <graph.bin> <out.bin> <r1cs-sha256>\n      [--ops patched|original] [--envelope cvywit|signet] [--version 1|2]\n      [--compress none|zstd] [--level N] [--compressor zstd|any]
      Encode an upstream postcard graph. Prints the artifact size and its SHA-256,
      which is the value to pin in protocol metadata.

  signet reseal <artifact> <sha256> <out.bin>\n      [--envelope cvywit|signet] [--compress none|zstd] [--level N]\n      [--compressor zstd|any]
      Rewrite an existing artifact's envelope and compression without rebuilding it
      from source. The body is copied untouched, so this cannot change what the
      graph computes - only how it is wrapped. Use it when a profile's postcard
      `graph.bin` was not kept.

  signet transcode <artifact> <sha256> <out.bin>\n      [--version 2|1] [--envelope cvywit|signet] [--compress none|zstd] [--level N]\n      [--compressor zstd|any] [--input input.json [--reference reference.wtns]]
      Re-encode an existing artifact's body in the other body version (version 2
      by default) without its postcard source. The header, source R1CS digest
      included, is kept byte for byte apart from the version field, and so is the
      envelope unless --envelope says otherwise. The result must decode back to
      the source body byte for byte and load through the evaluator before it is
      written. The source and the result are both evaluated, on --input or else on
      an all-zero input, and must agree on every signal; --reference also compares
      them with circom's witness.

  signet validate <artifact> <sha256> <input.json> <reference.wtns>
      Evaluate the artifact and compare every signal against a reference witness.

  signet inspect <artifact> <sha256>
      Print what the evaluator sees: signal count and source R1CS digest.

Defaults are `--envelope signet --version 1 --compress zstd`, which a stock
curvy-witness accepts. `--envelope cvywit` still works for older consumers. Only
`--version 2` needs the consumer's `signet-v2` feature.

Compression shells out to the system `zstd` (default level 9, which keeps the
frame window at half the consumer's cap) and falls back to the weaker built-in
encoder if that binary is missing or fails; `--compressor zstd` refuses the
fallback before anything is written, as publication should. A compressed
artifact pins its *compressed* digest; `export` prints both and labels which
one. Every artifact is loaded back through the evaluator before it is written,
under the batch-prover limits; `client_limits=` says whether a client built with
the default limits loads it too.

`--ops` says which upstream built the postcard. `patched` is the default;
`original` is for graphs built before the bitwise patch. Choosing wrong is SILENT
- it remaps every operation from index 14 up. Always follow an export with
`validate`.";

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
        Some("reseal") => reseal_command(&arguments[1..]),
        Some("transcode") => transcode_command(&arguments[1..]),
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
    let mut require_zstd = false;
    let mut flags = arguments[positional.len()..].iter();
    while let Some(flag) = flags.next() {
        let value = flags
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--ops" => schema = OperationSchema::parse(value).map_err(|e| e.to_string())?,
            "--compress" => compression = Compression::parse(value).map_err(|e| e.to_string())?,
            "--level" => level = compression_level(value)?,
            "--envelope" => envelope = Envelope::parse(value).map_err(|e| e.to_string())?,
            "--version" => version = FormatVersion::parse(value).map_err(|e| e.to_string())?,
            "--compressor" => require_zstd = compressor_requirement(value)?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    let source = std::fs::read(positional[0]).map_err(|e| format!("{}: {e}", positional[0]))?;
    let graph = Graph::from_postcard(&source, schema).map_err(|e| e.to_string())?;
    let r1cs = decode_sha256(positional[2]).map_err(|e| e.to_string())?;
    let bytes = encode(&graph, r1cs, envelope, version).map_err(|e| e.to_string())?;
    let (artifact, compressor) = wrap(&bytes, compression, level, require_zstd)?;

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

    let client = client_limits(&artifact, &artifact_sha);
    write_new(positional[1], &artifact)?;

    println!("nodes={}", graph.nodes.len());
    println!("signals={}", graph.signals.len());
    print_digests(&bytes, &artifact, &artifact_sha, compressor, level);
    println!("round_trip=ok");
    print_client_limits(&client);
    eprintln!("note: confirm this artifact with `signet validate` before pinning it");
    Ok(())
}

/// Re-envelope and re-compress an artifact that has no postcard source left.
///
/// The safety argument is narrow and mechanically checked: the version-1 and
/// version-2 bodies are envelope independent, so the rewrite may change exactly
/// the first eight bytes and must copy everything after them byte-for-byte.
fn reseal_command(arguments: &[String]) -> Result<(), String> {
    let positional = arguments
        .iter()
        .take_while(|argument| !argument.starts_with("--"))
        .collect::<Vec<_>>();
    if positional.len() != 3 {
        return Err(format!(
            "reseal needs three positional arguments\n\n{USAGE}"
        ));
    }
    let mut envelope = Envelope::default();
    let mut compression = Compression::default();
    let mut level = DEFAULT_COMPRESSION_LEVEL;
    let mut require_zstd = false;
    let mut flags = arguments[positional.len()..].iter();
    while let Some(flag) = flags.next() {
        let value = flags
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--envelope" => envelope = Envelope::parse(value).map_err(|e| e.to_string())?,
            "--compress" => compression = Compression::parse(value).map_err(|e| e.to_string())?,
            "--level" => level = compression_level(value)?,
            "--compressor" => require_zstd = compressor_requirement(value)?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    // Authenticating the source is the point of taking a digest here. Resealing an
    // artifact you have not identified would launder an unknown file into one
    // carrying a fresh pin.
    let source_bytes =
        std::fs::read(positional[0]).map_err(|e| format!("{}: {e}", positional[0]))?;
    let source = load_bytes(&source_bytes, positional[1], positional[0])?;

    let raw = curvy_signet::to_raw(&source_bytes).map_err(|e| e.to_string())?;
    let described = curvy_signet::reseal::describe(&raw).map_err(|e| e.to_string())?;
    let bytes = curvy_signet::reseal(&raw, envelope).map_err(|e| e.to_string())?;
    if raw.get(8..) != bytes.get(8..) {
        return Err("reseal changed bytes outside the eight-byte envelope".to_owned());
    }

    let (artifact, compressor) = wrap(&bytes, compression, level, require_zstd)?;

    let artifact_sha = hex(&Sha256::digest(&artifact));
    let resealed = WitnessGraph::from_bytes_with_limits(
        &artifact,
        &artifact_sha,
        curvy_witness::Limits::batch_prover(),
    )
    .map_err(|e| format!("refusing to write an artifact the evaluator rejects: {e}"))?;
    if resealed.assignment_size() != source.assignment_size() {
        return Err(format!(
            "reseal changed the signal count: {} in, {} out",
            source.assignment_size(),
            resealed.assignment_size()
        ));
    }
    if resealed.r1cs_sha256() != source.r1cs_sha256() {
        return Err("reseal changed the source R1CS digest".to_owned());
    }

    let client = client_limits(&artifact, &artifact_sha);
    write_new(positional[2], &artifact)?;

    println!("signals={}", resealed.assignment_size());
    println!(
        "from={:?} to={:?} version={}",
        described.envelope, envelope, described.version
    );
    print_digests(&bytes, &artifact, &artifact_sha, compressor, level);
    println!("body=unchanged");
    print_client_limits(&client);
    Ok(())
}

/// Re-encode an artifact's body in the other version, with no postcard source.
///
/// Three checks stand between the decoder and the output file. The header must
/// be unchanged apart from the version field (and the magic, when `--envelope`
/// asks for a different one). The result must transcode back to the source body
/// byte for byte, which version 1's fixed-width records make an exact test of
/// every node, reference and output. And it must load through the evaluator with
/// the source's signal count and R1CS digest. `--input` adds evaluation parity
/// between source and result; `--reference` adds circom's witness.
fn transcode_command(arguments: &[String]) -> Result<(), String> {
    let positional = arguments
        .iter()
        .take_while(|argument| !argument.starts_with("--"))
        .collect::<Vec<_>>();
    if positional.len() != 3 {
        return Err(format!(
            "transcode needs three positional arguments\n\n{USAGE}"
        ));
    }
    let mut target = FormatVersion::V2;
    let mut envelope = None;
    let mut compression = Compression::default();
    let mut level = DEFAULT_COMPRESSION_LEVEL;
    let mut input_path = None;
    let mut reference_path = None;
    let mut require_zstd = false;
    let mut flags = arguments[positional.len()..].iter();
    while let Some(flag) = flags.next() {
        let value = flags
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--version" => target = FormatVersion::parse(value).map_err(|e| e.to_string())?,
            "--envelope" => envelope = Some(Envelope::parse(value).map_err(|e| e.to_string())?),
            "--compress" => compression = Compression::parse(value).map_err(|e| e.to_string())?,
            "--level" => level = compression_level(value)?,
            "--input" => input_path = Some(value.as_str()),
            "--reference" => reference_path = Some(value.as_str()),
            "--compressor" => require_zstd = compressor_requirement(value)?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if reference_path.is_some() && input_path.is_none() {
        return Err("--reference needs --input: the witness is computed from it".to_owned());
    }

    // As with reseal, an unidentified file must not come out the other side
    // carrying a fresh pin.
    let source_bytes =
        std::fs::read(positional[0]).map_err(|e| format!("{}: {e}", positional[0]))?;
    let source = load_bytes(&source_bytes, positional[1], positional[0])?;

    let raw = curvy_signet::to_raw(&source_bytes).map_err(|e| e.to_string())?;
    let described = curvy_signet::reseal::describe(&raw).map_err(|e| e.to_string())?;
    let source_version =
        FormatVersion::parse(&described.version.to_string()).map_err(|e| e.to_string())?;
    let mut bytes = transcode(&raw, target).map_err(|e| e.to_string())?;
    if let Some(envelope) = envelope {
        bytes = curvy_signet::reseal(&bytes, envelope).map_err(|e| e.to_string())?;
    }

    if raw.get(10..64) != bytes.get(10..64) || bytes.get(8..10) != Some(&target.tag().to_le_bytes())
    {
        return Err("transcode changed header bytes other than the body version".to_owned());
    }
    let mut back = transcode(&bytes, source_version).map_err(|e| e.to_string())?;
    back[..8].copy_from_slice(&raw[..8]);
    if back != raw {
        return Err("the transcoded body does not decode back to the source body".to_owned());
    }

    let (artifact, compressor) = wrap(&bytes, compression, level, require_zstd)?;
    let artifact_sha = hex(&Sha256::digest(&artifact));
    let transcoded = WitnessGraph::from_bytes_with_limits(
        &artifact,
        &artifact_sha,
        curvy_witness::Limits::batch_prover(),
    )
    .map_err(|e| format!("refusing to write an artifact the evaluator rejects: {e}"))?;
    if transcoded.assignment_size() != source.assignment_size() {
        return Err(format!(
            "transcode changed the signal count: {} in, {} out",
            source.assignment_size(),
            transcoded.assignment_size()
        ));
    }
    if transcoded.r1cs_sha256() != source.r1cs_sha256() {
        return Err("transcode changed the source R1CS digest".to_owned());
    }

    // The body checks above run on this tool's own parser, so a misreading shared by
    // both directions would pass them. Evaluating through the evaluator's decoder
    // would not: with no input given, compare the two on an all-zero input.
    let parity = match input_path {
        None => {
            let zero = |graph: &WitnessGraph| graph.calculate_json("{}").map_err(|e| e.to_string());
            let (expected, candidate) = (zero(&source), zero(&transcoded));
            let differs = match (&expected, &candidate) {
                (Ok(expected), Ok(candidate)) => {
                    wtns::first_difference(candidate, expected).is_some()
                }
                _ => expected != candidate,
            };
            if differs {
                return Err(
                    "the source and the result evaluate differently on an all-zero input"
                        .to_owned(),
                );
            }
            "zero-input"
        }
        Some(input_path) => {
            let input =
                std::fs::read_to_string(input_path).map_err(|e| format!("{input_path}: {e}"))?;
            let expected = source
                .calculate_json(&input)
                .map_err(|e| format!("evaluating the source: {e}"))?;
            let candidate = transcoded
                .calculate_json(&input)
                .map_err(|e| format!("evaluating the result: {e}"))?;
            if let Some(index) = wtns::first_difference(&candidate, &expected) {
                return Err(format!(
                    "signal {index} differs between the source and the result"
                ));
            }
            if let Some(reference_path) = reference_path {
                let reference_bytes =
                    std::fs::read(reference_path).map_err(|e| format!("{reference_path}: {e}"))?;
                let reference = wtns::read(&reference_bytes).map_err(|e| e.to_string())?;
                if let Some(index) = wtns::first_difference(&candidate, &reference) {
                    return Err(format!("signal {index} differs from the reference witness"));
                }
                "exact"
            } else {
                "source"
            }
        }
    };

    let client = client_limits(&artifact, &artifact_sha);
    write_new(positional[2], &artifact)?;

    println!("signals={}", transcoded.assignment_size());
    println!(
        "from_version={} to_version={}",
        described.version,
        target.tag()
    );
    print_digests(&bytes, &artifact, &artifact_sha, compressor, level);
    println!("round_trip=ok");
    println!("parity={parity}");
    print_client_limits(&client);
    if parity == "zero-input" {
        eprintln!("note: confirm this artifact with `signet validate` before pinning it");
    }
    if target == FormatVersion::V2 {
        eprintln!(
            "note: version 2 loads only in consumers built with curvy-witness's \
             `signet-v2` feature (curvy-prover's `signet-v2`)"
        );
    }
    Ok(())
}

/// Raw bytes as they are, or inside a zstd frame. With `require_zstd`, a frame
/// from the ruzstd fallback is refused before anything is written.
fn wrap(
    bytes: &[u8],
    compression: Compression,
    level: i32,
    require_zstd: bool,
) -> Result<(Vec<u8>, Option<Compressor>), String> {
    match compression {
        Compression::None => Ok((bytes.to_vec(), None)),
        Compression::Zstd => match compress(bytes, level) {
            (_, Compressor::Ruzstd) if require_zstd => Err(
                "the system `zstd` is missing or failed, and --compressor zstd refuses \
                 the ruzstd fallback"
                    .to_owned(),
            ),
            (compressed, compressor) => Ok((compressed, Some(compressor))),
        },
    }
}

fn compressor_requirement(value: &str) -> Result<bool, String> {
    match value {
        "zstd" => Ok(true),
        "any" => Ok(false),
        other => Err(format!("--compressor needs `zstd` or `any`, got {other:?}")),
    }
}

/// Whether a client with the default limits loads the artifact too. Every write
/// is gated on the batch-prover limits, which accept graphs a browser refuses.
fn client_limits(artifact: &[u8], artifact_sha: &str) -> Result<(), String> {
    WitnessGraph::from_bytes_with_limits(artifact, artifact_sha, curvy_witness::Limits::client())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn print_client_limits(client: &Result<(), String>) {
    match client {
        Ok(()) => println!("client_limits=ok"),
        Err(error) => {
            println!("client_limits=exceeded");
            eprintln!(
                "note: a client with the default limits refuses this artifact ({error}); \
                 only hosts using Limits::batch_prover() load it"
            );
        }
    }
}

/// The digest block every writing subcommand prints.
///
/// The evaluator authenticates whatever bytes it is handed, so a compressed
/// artifact pins its compressed digest. The uncompressed pair is printed too
/// because the publication record carries both.
fn print_digests(
    bytes: &[u8],
    artifact: &[u8],
    artifact_sha: &str,
    compressor: Option<Compressor>,
    level: i32,
) {
    println!("graph_bytes={}", bytes.len());
    println!("graph_sha256={}", hex(&Sha256::digest(bytes)));
    if let Some(compressor) = compressor {
        println!("artifact_bytes={}", artifact.len());
        println!("artifact_sha256={artifact_sha}");
        println!("pin=artifact_sha256");
        match compressor {
            Compressor::SystemZstd => println!("compressor=zstd -{level}"),
            Compressor::Ruzstd => {
                println!("compressor=ruzstd (level 1)");
                eprintln!(
                    "warning: the system `zstd` is missing or failed, so this artifact \
                     was compressed with ruzstd's level 1 and is roughly twice the size \
                     it should be; publish with --compressor zstd"
                );
            }
        }
    } else {
        println!("pin=graph_sha256");
    }
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
    let bytes = std::fs::read(artifact).map_err(|e| format!("{artifact}: {e}"))?;
    print_client_limits(&client_limits(&bytes, expected_sha));
    Ok(())
}

/// Load through the shipped evaluator, under the batch-prover budget.
///
/// Only the ceilings differ from a client load; structural validation is
/// identical, so this still rejects everything a client would reject for any
/// reason other than size.
fn load(artifact: &str, expected_sha: &str) -> Result<WitnessGraph, String> {
    let bytes = std::fs::read(artifact).map_err(|e| format!("{artifact}: {e}"))?;
    load_bytes(&bytes, expected_sha, artifact)
}

fn compression_level(value: &str) -> Result<i32, String> {
    let level = value
        .parse::<i32>()
        .map_err(|_| format!("--level needs an integer, got {value:?}"))?;
    if !(1..=19).contains(&level) {
        return Err(format!("--level must be in 1..=19, got {level}"));
    }
    Ok(level)
}

fn load_bytes(bytes: &[u8], expected_sha: &str, label: &str) -> Result<WitnessGraph, String> {
    WitnessGraph::from_bytes_with_limits(bytes, expected_sha, curvy_witness::Limits::batch_prover())
        .map_err(|e| format!("{label}: {e}"))
}

fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{path}: refusing to overwrite output: {error}")
            } else {
                format!("{path}: {error}")
            }
        })?;
    // Do not leave a truncated artifact behind, under the name it was meant to have.
    output.write_all(bytes).map_err(|error| {
        drop(output);
        let _ = std::fs::remove_file(path);
        format!("{path}: {error}")
    })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};

    use super::{compression_level, hex, reseal_command};

    #[test]
    fn compression_level_is_validated_before_invoking_zstd() {
        assert_eq!(compression_level("1"), Ok(1));
        assert_eq!(compression_level("19"), Ok(19));
        assert!(compression_level("0").is_err());
        assert!(compression_level("20").is_err());
        assert!(compression_level("fast").is_err());
    }

    #[test]
    fn reseal_command_authenticates_the_bytes_it_copies_and_refuses_overwrite() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "curvy-signet-reseal-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create isolated test directory");
        let source_path = directory.join("source.bin");
        let output_path = directory.join("output.bin");
        let source = graph_bytes();
        std::fs::write(&source_path, &source).expect("write source fixture");
        let digest = hex(&Sha256::digest(&source));
        let arguments = vec![
            source_path.to_string_lossy().into_owned(),
            digest,
            output_path.to_string_lossy().into_owned(),
            "--envelope".to_owned(),
            "signet".to_owned(),
            "--compress".to_owned(),
            "none".to_owned(),
        ];

        let mut wrong_digest_arguments = arguments.clone();
        wrong_digest_arguments[1] = "00".repeat(32);
        let error = reseal_command(&wrong_digest_arguments)
            .expect_err("reseal must authenticate the exact source bytes");
        assert!(error.contains("SHA-256 mismatch"), "{error}");
        assert!(
            !output_path.exists(),
            "authentication failure must not create an output"
        );

        reseal_command(&arguments).expect("reseal authenticated source");
        let output = std::fs::read(&output_path).expect("read resealed output");
        assert_eq!(&output[..8], b"SIGNET01");
        assert_eq!(output[8..], source[8..]);

        let error = reseal_command(&arguments).expect_err("existing output must not be replaced");
        assert!(error.contains("refusing to overwrite output"), "{error}");

        std::fs::remove_file(output_path).expect("remove output fixture");
        std::fs::remove_file(source_path).expect("remove source fixture");
        std::fs::remove_dir(directory).expect("remove test directory");
    }

    fn graph_bytes() -> Vec<u8> {
        let mut graph = Vec::new();
        graph.extend_from_slice(b"CVYWIT01");
        graph.extend_from_slice(&1_u16.to_le_bytes());
        graph.extend_from_slice(&1_u16.to_le_bytes());
        graph.extend_from_slice(&64_u32.to_le_bytes());
        graph.extend_from_slice(&[0_u8; 32]);
        graph.extend_from_slice(&2_u32.to_le_bytes());
        graph.extend_from_slice(&2_u32.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
        graph.extend_from_slice(&2_u32.to_le_bytes());
        graph.push(1);
        let mut one = [0_u8; 32];
        one[0] = 1;
        graph.extend_from_slice(&one);
        graph.push(0);
        graph.extend_from_slice(&1_u32.to_le_bytes());
        graph.extend_from_slice(&0_u32.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
        graph.extend_from_slice(&fnv1a("a").to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
        graph
    }

    fn fnv1a(value: &str) -> u64 {
        value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
        })
    }
}
