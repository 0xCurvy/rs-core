//! Native benchmark CLI: `curvy-prover <circuit.zkey> <witness.wtns> [iters] [out-prefix]`
//! Prints zkey-parse / prove timings and (with out-prefix) writes the proof +
//! public signals in snarkjs JSON form for cross-verification by snarkjs itself.

use std::time::Instant;

use curvy_prover::{proof_to_snarkjs_json, publics_to_json, wtns::read_wtns, Prover};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: curvy-prover <circuit.zkey> <witness.wtns> [iters] [out-prefix]");
        std::process::exit(1);
    }
    let iters: usize = args.get(3).map(|s| s.parse().expect("iters")).unwrap_or(5);

    let zkey_bytes = std::fs::read(&args[1]).expect("read zkey");
    let wtns_bytes = std::fs::read(&args[2]).expect("read wtns");

    let t = Instant::now();
    let prover = Prover::from_zkey_bytes(&zkey_bytes);
    let t_parse = t.elapsed();
    let assignment = read_wtns(&wtns_bytes);
    println!(
        "circuit: {} constraints, {} public signals | zkey parse: {:?} | witness: {} elements",
        prover.num_constraints(),
        prover.num_public(),
        t_parse,
        assignment.len()
    );

    let proof = prover.prove(&assignment); // warm-up
    let mut times = Vec::with_capacity(iters);
    for i in 0..iters {
        let t = Instant::now();
        let _p = prover.prove(&assignment);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        times.push(ms);
        println!("prove[{i}]: {ms:.1}ms");
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "prove: min {:.1}ms / median {:.1}ms (threads: {})",
        times[0],
        times[times.len() / 2],
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into())
    );

    let publics = prover.public_inputs(&assignment);
    assert!(prover.verify(&proof, publics), "ark self-verify failed");
    println!("ark self-verify: ok");

    if let Some(prefix) = args.get(4) {
        std::fs::write(format!("{prefix}-proof.json"), proof_to_snarkjs_json(&proof)).unwrap();
        std::fs::write(format!("{prefix}-public.json"), publics_to_json(publics)).unwrap();
        println!("wrote {prefix}-proof.json / {prefix}-public.json");
    }
}
