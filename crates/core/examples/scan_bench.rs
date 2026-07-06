//! Scan throughput benchmark: `cargo run --release --example scan_bench [--features parallel] [N]`
//! Compare with `RAYON_NUM_THREADS=1` (or without the feature) for the serial baseline.

use std::time::Instant;

use curvy_core::stealth::{new_meta, scan, send};

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(4096);

    let (k, v, big_k, big_v) = new_meta();
    let (ok, ov, obig_k, obig_v) = new_meta(); // a stranger, for the non-matching case
    let _ = (ok, ov);

    // 64 real announcements each, tiled to n — per-announcement work is identical,
    // so tiling measures throughput without paying 4096 pairing-heavy sends.
    let make = |bk: &str, bv: &str| {
        let base: Vec<(String, String)> = (0..64)
            .map(|_| {
                let (_r, out) = send(bk, bv).expect("send");
                (out.big_r, out.view_tag)
            })
            .collect();
        let rs: Vec<String> = (0..n).map(|i| base[i % 64].0.clone()).collect();
        let tags: Vec<String> = (0..n).map(|i| base[i % 64].1.clone()).collect();
        (rs, tags)
    };

    let (match_rs, match_tags) = make(&big_k, &big_v);
    let (miss_rs, miss_tags) = make(&obig_k, &obig_v);

    let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into());
    let parallel = cfg!(feature = "parallel");
    println!("scan_bench: n={n}, parallel={parallel}, RAYON_NUM_THREADS={threads}");

    for (label, rs, tags) in [("matching", &match_rs, &match_tags), ("non-matching", &miss_rs, &miss_tags)] {
        let _ = scan(&k, &v, rs, tags).unwrap(); // warm
        let t0 = Instant::now();
        let out = scan(&k, &v, rs, tags).unwrap();
        let ms = t0.elapsed().as_secs_f64() * 1e3;
        let hits = out.len();
        println!(
            "scan {n} {label:>12}: {ms:8.1}ms  ({:6.1}µs/announcement, {hits} hits)",
            ms * 1000.0 / n as f64
        );
    }
}
