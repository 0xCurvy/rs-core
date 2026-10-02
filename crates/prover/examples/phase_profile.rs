//! Phase breakdown of resident (HAWK) loads and proofs on real artifacts, on
//! the same in-memory path as the browser's `WasmResidentProver`.
//!
//! ```sh
//! cargo run --release -p curvy-prover --features bench,parallel --example phase_profile -- \
//!     ZKEY ZKEY_SHA256 GRAPH GRAPH_SHA256 INPUT.json [SAMPLES]
//! ```
//!
//! Drop `parallel` for the serial build; `RAYON_NUM_THREADS` sizes the pool.
//! Prints one JSON line for the load, one per proof (after one warm-up), and
//! a summary with each phase's median. Phase names are documented on
//! `curvy_prover::phase_timing`; nested phases are included in their parents.

use std::{collections::BTreeMap, error::Error, fs, time::Instant};

use curvy_prover::{ResidentProver, phase_timing};

fn spans_json(spans: &[(&str, f64)], total_ms: f64) -> String {
    let fields: Vec<String> = spans
        .iter()
        .map(|(name, ms)| format!("\"{name}\":{ms:.3}"))
        .collect();
    format!("{{\"total_ms\":{total_ms:.3},{}}}", fields.join(","))
}

/// Sums repeated names (e.g. the two `proof.scalars` conversions).
fn merged(spans: Vec<(&'static str, f64)>) -> Vec<(&'static str, f64)> {
    let mut out: Vec<(&'static str, f64)> = Vec::new();
    for (name, ms) in spans {
        match out.iter_mut().find(|(seen, _)| *seen == name) {
            Some(entry) => entry.1 += ms,
            None => out.push((name, ms)),
        }
    }
    out
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(6..=7).contains(&args.len()) {
        return Err(format!(
            "usage: {} ZKEY ZKEY_SHA256 GRAPH GRAPH_SHA256 INPUT.json [SAMPLES]",
            args[0]
        )
        .into());
    }
    let samples: usize = args.get(6).map_or(Ok(5), |value| value.parse())?;
    let zkey = fs::read(&args[1])?;
    let graph = fs::read(&args[3])?;
    let input = fs::read_to_string(&args[5])?;

    phase_timing::take();
    let started = Instant::now();
    let prover = ResidentProver::from_artifacts(&zkey, &args[2], &graph, &args[4])?;
    let load_ms = started.elapsed().as_secs_f64() * 1_000.0;
    println!(
        "{{\"load\":{}}}",
        spans_json(&merged(phase_timing::take()), load_ms)
    );

    let mut totals = Vec::new();
    let mut phases: BTreeMap<&'static str, Vec<f64>> = BTreeMap::new();
    let mut order: Vec<&'static str> = Vec::new();
    for sample in 0..=samples {
        phase_timing::take();
        let started = Instant::now();
        prover.prove_json(&input)?;
        let total_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let spans = merged(phase_timing::take());
        if sample == 0 {
            continue;
        }
        println!("{{\"proof\":{}}}", spans_json(&spans, total_ms));
        totals.push(total_ms);
        for (name, ms) in spans {
            if !order.contains(&name) {
                order.push(name);
            }
            phases.entry(name).or_default().push(ms);
        }
    }
    let summary: Vec<(&str, f64)> = order
        .iter()
        .map(|name| (*name, median(phases.get_mut(name).expect("recorded"))))
        .collect();
    println!(
        "{{\"median\":{}}}",
        spans_json(&summary, median(&mut totals))
    );
    Ok(())
}
