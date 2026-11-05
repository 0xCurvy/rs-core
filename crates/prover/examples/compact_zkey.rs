//! Make and check compact zkeys (see `curvy_prover::compact_zkey`).
//!
//! ```text
//! compact_zkey encode  <zkey> <zkey-sha256> <out> [--level N]
//! compact_zkey decode  <compact> <compact-sha256> <out.zkey>
//! compact_zkey inspect <compact>
//! compact_zkey verify  <compact> <zkey-sha256>
//! compact_zkey bench   <zkey> <zkey-sha256> <compact> <compact-sha256>
//!                      [<graph> <graph-sha256> <input.json>] [--runs N] [--only zkey|compact]
//! ```
//!
//! `encode` authenticates the zkey and writes the compact file: the header, then
//! the body in a zstd frame (the system `zstd` at level 9 by default, ruzstd's
//! level 1 if it is missing). Level 19 is about 2% smaller and decodes as fast;
//! it only makes this step slower. Before writing, the file is decoded through
//! the decoder the prover uses and must give the original bytes back, and both
//! files must load as provers with the same verifying key. It prints the compact
//! file's digest, which is the pin `Prover::from_compact_zkey_bytes` takes.
//!
//! `verify` prints JSON for the release validator: the compact file's size and
//! digest, and the zkey it decodes to, which must match the given pin.
//!
//! `bench` times loads of both files, alternating, and with a witness graph and
//! input also times proofs from each loaded key. `--only` loads one kind, for a
//! per-process peak RSS from `/usr/bin/time`.

use std::{env, fs, process::ExitCode, time::Instant};

use curvy_prover::{Prover, compact_zkey};
use sha2::{Digest, Sha256};

const DEFAULT_LEVEL: i32 = 9;

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.first().map(String::as_str) {
        Some("encode") => encode(&arguments[1..]),
        Some("decode") => decode(&arguments[1..]),
        Some("inspect") => inspect(&arguments[1..]),
        Some("verify") => verify(&arguments[1..]),
        Some("bench") => bench(&arguments[1..]),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage:
  compact_zkey encode  <zkey> <zkey-sha256> <out> [--level N]
  compact_zkey decode  <compact> <compact-sha256> <out.zkey>
  compact_zkey inspect <compact>
  compact_zkey verify  <compact> <zkey-sha256>
  compact_zkey bench   <zkey> <zkey-sha256> <compact> <compact-sha256>
                       [<graph> <graph-sha256> <input.json>] [--runs N] [--only zkey|compact]";

fn encode(arguments: &[String]) -> Result<(), String> {
    let (positional, flags) = arguments.split_at(arguments.len().min(3));
    let [zkey_path, zkey_sha, output] = positional else {
        return Err(USAGE.to_owned());
    };
    let level = match flags {
        [] => DEFAULT_LEVEL,
        [flag, value] if flag == "--level" => value
            .parse::<i32>()
            .ok()
            .filter(|level| (1..=19).contains(level))
            .ok_or_else(|| format!("--level must be in 1..=19, got {value:?}"))?,
        _ => return Err(USAGE.to_owned()),
    };

    let zkey = fs::read(zkey_path).map_err(|e| format!("{zkey_path}: {e}"))?;
    if hex(&Sha256::digest(&zkey)) != zkey_sha.to_ascii_lowercase() {
        return Err(format!("{zkey_path}: SHA-256 does not match the given pin"));
    }

    let started = Instant::now();
    let mut compressor = String::new();
    // `encode` decodes the file it builds and refuses one that does not give the
    // zkey back, so a frame wider than the decoder's window cap fails here.
    let file = compact_zkey::encode(&zkey, |body| {
        let (frame, used) = compress(body, level);
        compressor = used;
        frame
    })
    .map_err(|e| e.to_string())?;
    let encode_ms = started.elapsed().as_secs_f64() * 1e3;
    let compact_sha = hex(&Sha256::digest(&file));

    let started = Instant::now();
    let compact_prover = Prover::from_compact_zkey_bytes(&file, &compact_sha)
        .map_err(|e| format!("the prover rejects the compact zkey: {e}"))?;
    let compact_load_ms = started.elapsed().as_secs_f64() * 1e3;
    let started = Instant::now();
    let zkey_prover = Prover::from_zkey_bytes(&zkey, zkey_sha)
        .map_err(|e| format!("the prover rejects the zkey: {e}"))?;
    let zkey_load_ms = started.elapsed().as_secs_f64() * 1e3;
    if compact_prover.verifying_key_digest() != zkey_prover.verifying_key_digest()
        || compact_prover.num_constraints() != zkey_prover.num_constraints()
    {
        return Err("the compact zkey loads as a different key".to_owned());
    }

    write_new(output, &file)?;
    println!("zkey_bytes={}", zkey.len());
    println!("zkey_sha256={}", zkey_sha.to_ascii_lowercase());
    println!("compact_bytes={}", file.len());
    println!("compact_sha256={compact_sha}");
    println!("pin=compact_sha256");
    println!("compressor={compressor}");
    println!("round_trip=ok");
    println!("vk_sha256={}", compact_prover.verifying_key_digest());
    println!("encode_ms={encode_ms:.0}");
    println!("zkey_load_ms={zkey_load_ms:.0}");
    println!("compact_load_ms={compact_load_ms:.0}");
    Ok(())
}

fn decode(arguments: &[String]) -> Result<(), String> {
    let [compact_path, compact_sha, output] = arguments else {
        return Err(USAGE.to_owned());
    };
    let compact = read_pinned(compact_path, compact_sha)?;
    let zkey = compact_zkey::inflate(compact.as_slice(), compact_zkey::DEFAULT_MAX_ZKEY_BYTES)
        .map_err(|e| e.to_string())?;
    write_new(output, &zkey)?;
    println!("zkey_bytes={}", zkey.len());
    println!("zkey_sha256={}", hex(&Sha256::digest(&zkey)));
    Ok(())
}

fn inspect(arguments: &[String]) -> Result<(), String> {
    let [compact_path] = arguments else {
        return Err(USAGE.to_owned());
    };
    let compact = fs::read(compact_path).map_err(|e| format!("{compact_path}: {e}"))?;
    let header = compact_zkey::describe(compact.as_slice()).map_err(|e| e.to_string())?;
    println!("compact_bytes={}", compact.len());
    println!("compact_sha256={}", hex(&Sha256::digest(&compact)));
    println!("zkey_bytes={}", header.zkey_bytes);
    println!("zkey_sha256={}", hex(&header.zkey_sha256));
    for section in &header.sections {
        println!(
            "section={} zkey_bytes={} encoding={:?}",
            section.id, section.zkey_bytes, section.encoding
        );
    }
    Ok(())
}

fn verify(arguments: &[String]) -> Result<(), String> {
    let [compact_path, zkey_sha] = arguments else {
        return Err(USAGE.to_owned());
    };
    let compact = fs::read(compact_path).map_err(|e| format!("{compact_path}: {e}"))?;
    let zkey = compact_zkey::inflate(compact.as_slice(), compact_zkey::DEFAULT_MAX_ZKEY_BYTES)
        .map_err(|e| e.to_string())?;
    let decoded_sha = hex(&Sha256::digest(&zkey));
    if decoded_sha != zkey_sha.to_ascii_lowercase() {
        return Err(format!(
            "the compact zkey decodes to {decoded_sha}, not {zkey_sha}"
        ));
    }
    println!(
        "{{\"compactZkey\":{{\"bytes\":{},\"sha256\":\"{}\"}},\"zkey\":{{\"bytes\":{},\"sha256\":\"{decoded_sha}\"}}}}",
        compact.len(),
        hex(&Sha256::digest(&compact)),
        zkey.len()
    );
    Ok(())
}

fn bench(arguments: &[String]) -> Result<(), String> {
    use curvy_prover::ResidentProver;

    let positional = arguments
        .iter()
        .take_while(|argument| !argument.starts_with("--"))
        .collect::<Vec<_>>();
    if positional.len() != 4 && positional.len() != 7 {
        return Err(USAGE.to_owned());
    }
    let mut runs = 5_usize;
    let mut only = None;
    let mut flags = arguments[positional.len()..].iter();
    while let Some(flag) = flags.next() {
        let value = flags
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--runs" => {
                runs = value
                    .parse()
                    .map_err(|_| "--runs needs a count".to_owned())?
            }
            "--only" if value == "zkey" || value == "compact" => only = Some(value.as_str()),
            _ => return Err(USAGE.to_owned()),
        }
    }
    let zkey = read_pinned(positional[0], positional[1])?;
    let compact = read_pinned(positional[2], positional[3])?;
    let witness = if positional.len() == 7 {
        let graph = read_pinned(positional[4], positional[5])?;
        let input =
            fs::read_to_string(positional[6]).map_err(|e| format!("{}: {e}", positional[6]))?;
        Some((graph, input))
    } else {
        None
    };

    let load = |kind: &str| -> Result<(Prover, f64), String> {
        let started = Instant::now();
        let prover = match kind {
            "zkey" => Prover::from_zkey_bytes(&zkey, positional[1]),
            _ => Prover::from_compact_zkey_bytes(&compact, positional[3]),
        }
        .map_err(|e| format!("{kind}: {e}"))?;
        Ok((prover, started.elapsed().as_secs_f64() * 1e3))
    };
    let kinds = match only {
        Some(kind) => vec![kind],
        None => vec!["zkey", "compact"],
    };
    let mut loads = vec![Vec::new(); kinds.len()];
    let mut proofs = vec![Vec::new(); kinds.len()];
    let mut digests = Vec::new();
    for run in 0..runs {
        // Alternate which kind goes first so neither always runs on a warm cache.
        for step in 0..kinds.len() {
            let slot = (step + run) % kinds.len();
            let (prover, ms) = load(kinds[slot])?;
            loads[slot].push(ms);
            digests.push(prover.verifying_key_digest());
            if let Some((graph, input)) = &witness {
                let resident = ResidentProver::with_graph(
                    prover,
                    curvy_witness::WitnessGraph::from_bytes(graph, positional[5])
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let started = Instant::now();
                resident.prove_json(input).map_err(|e| e.to_string())?;
                proofs[slot].push(started.elapsed().as_secs_f64() * 1e3);
            }
        }
    }
    #[cfg(feature = "bench")]
    {
        // Phase totals over every load and proof above, per run.
        let mut totals: Vec<(&str, f64)> = Vec::new();
        for (name, ms) in curvy_prover::phase_timing::take() {
            match totals.iter_mut().find(|(seen, _)| *seen == name) {
                Some((_, total)) => *total += ms,
                None => totals.push((name, ms)),
            }
        }
        for (name, total) in totals {
            println!("phase {name} ms_per_run={:.1}", total / runs as f64);
        }
    }
    digests.dedup();
    if digests.len() != 1 {
        return Err("the two files loaded different verifying keys".to_owned());
    }
    for (slot, kind) in kinds.iter().enumerate() {
        print!(
            "{kind}: load_ms median={:.1} min={:.1}",
            median(&mut loads[slot]),
            min(&loads[slot])
        );
        if witness.is_some() {
            print!(
                " prove_ms median={:.1} min={:.1}",
                median(&mut proofs[slot]),
                min(&proofs[slot])
            );
        }
        println!(" runs={runs}");
    }
    println!("vk_sha256={}", digests[0]);
    Ok(())
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn min(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

fn read_pinned(path: &str, expected: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if hex(&Sha256::digest(&bytes)) != expected.to_ascii_lowercase() {
        return Err(format!("{path}: SHA-256 does not match the given pin"));
    }
    Ok(bytes)
}

/// The system `zstd` when it is installed: ruzstd only encodes at level 1.
fn compress(body: &[u8], level: i32) -> (Vec<u8>, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let system = (|| {
        let mut child = Command::new("zstd")
            .args([format!("-{level}"), "-q".into(), "-c".into()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut stdin = child.stdin.take()?;
        // Feed stdin from another thread: zstd blocks on a full stdout pipe.
        let (output, wrote) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(body));
            let output = child.wait_with_output().ok();
            (output, writer.join().ok().and_then(Result::ok).is_some())
        });
        let output = output.filter(|output| wrote && output.status.success())?;
        Some(output.stdout)
    })();
    match system {
        Some(frame) => (frame, format!("zstd -{level}")),
        None => {
            eprintln!("warning: `zstd` was not found; ruzstd level 1 is much larger");
            (
                ruzstd::encoding::compress_to_vec(
                    body,
                    ruzstd::encoding::CompressionLevel::Fastest,
                ),
                "ruzstd (level 1)".to_owned(),
            )
        }
    }
}

fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{path}: refusing to overwrite or cannot create: {e}"))?;
    file.write_all(bytes).map_err(|e| format!("{path}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
