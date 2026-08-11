//! Sweep fixed signed-Pippenger windows for one authenticated native profile.
//!
//! WTNS decoding and manifest parsing happen once and are excluded from each
//! sample. Every timed run rereads the zkey once and returns a self-verified
//! proof. Rounds alternate ascending/descending window order to reduce thermal
//! and cache-order bias.

use std::{env, fs, fs::File, time::Instant};

use curvy_prover::{
    sparrow::{
        SparrowConfig,
        manifest::{ZkeyChunkManifest, prove_reader_with_manifest_owned},
    },
    wtns::read_wtns,
};

const DEFAULT_WINDOWS: &str = "8,9,10,11,12,13";
const DEFAULT_SAMPLES: usize = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if !(7..=10).contains(&args.len()) {
        return Err("usage: native_window_sweep <zkey> <zkey-sha256> <manifest> <manifest-sha256> <wtns> <threads> [msm-chunk-points] [comma-separated-windows] [samples]".into());
    }

    let threads = args[6].parse::<usize>()?;
    if threads == 0 {
        return Err("threads must be positive".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let mut base_config = SparrowConfig::native_adaptive();
    if let Some(value) = args.get(7) {
        base_config.msm_chunk_points = value.parse()?;
    }
    let windows = parse_windows(args.get(8).map_or(DEFAULT_WINDOWS, String::as_str))?;
    let samples = args
        .get(9)
        .map_or(Ok(DEFAULT_SAMPLES), |value| value.parse())?;
    if samples < 3 || samples.is_multiple_of(2) {
        return Err("samples must be an odd number of at least three".into());
    }

    let assignment = read_wtns(&fs::read(&args[5])?)?;
    let manifest = ZkeyChunkManifest::from_bytes(&fs::read(&args[3])?, &args[4], &args[2])?;
    let mut timings = windows
        .iter()
        .copied()
        .map(|window| (window, Vec::with_capacity(samples)))
        .collect::<Vec<_>>();

    for round in 0..samples {
        let indices: Box<dyn Iterator<Item = usize>> = if round.is_multiple_of(2) {
            Box::new(0..timings.len())
        } else {
            Box::new((0..timings.len()).rev())
        };
        for index in indices {
            let window_bits = timings[index].0;
            let config = SparrowConfig {
                window_bits,
                ..base_config
            };
            let run_assignment = assignment.clone();
            let run_manifest = manifest.clone();
            let mut zkey = File::open(&args[1])?;
            let started = Instant::now();
            let proof =
                prove_reader_with_manifest_owned(&mut zkey, run_assignment, run_manifest, config)?;
            timings[index]
                .1
                .push(started.elapsed().as_secs_f64() * 1_000.0);
            drop(proof);
        }
    }

    println!("threads={threads}");
    println!("msm_chunk_points={}", base_config.msm_chunk_points);
    println!("samples={samples}");
    println!("zkey_bytes={}", fs::metadata(&args[1])?.len());
    println!("zkey_sha256={}", manifest.zkey_sha256());
    println!("manifest_sha256={}", args[4].to_ascii_lowercase());
    println!("assignment_size={}", assignment.len());
    println!("window_bits\tmedian_ms\tmin_ms\tmax_ms");
    let mut recommendation = None::<(usize, f64)>;
    for (window_bits, mut samples) in timings {
        samples.sort_by(f64::total_cmp);
        let median = samples[samples.len() / 2];
        recommendation = match recommendation {
            Some((_, fastest)) if fastest <= median => recommendation,
            _ => Some((window_bits, median)),
        };
        println!(
            "{window_bits}\t{median:.3}\t{:.3}\t{:.3}",
            samples[0],
            samples[samples.len() - 1]
        );
    }
    println!(
        "recommended_window_bits={}",
        recommendation.expect("at least one window").0
    );
    Ok(())
}

fn parse_windows(value: &str) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    let mut windows = value
        .split(',')
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()?;
    windows.sort_unstable();
    windows.dedup();
    if windows.is_empty() || windows.iter().any(|window| !(4..=16).contains(window)) {
        return Err("window widths must be comma-separated values in 4..=16".into());
    }
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::parse_windows;

    #[test]
    fn parses_sorts_and_deduplicates_windows() {
        assert_eq!(parse_windows("12,8,10,8").unwrap(), [8, 10, 12]);
        assert!(parse_windows("0,8").is_err());
        assert!(parse_windows("").is_err());
    }
}
