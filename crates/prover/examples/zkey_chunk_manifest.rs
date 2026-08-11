//! Generate the compact authenticated chunk table used by the one-pass prover.

use std::{env, fs, fs::File};

use curvy_prover::sparrow::manifest::ZkeyChunkManifest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: zkey_chunk_manifest <zkey> <manifest-out> <chunk-bytes>".into());
    }
    let chunk_bytes = args[3].parse::<usize>()?;
    let (manifest, manifest_sha256) =
        ZkeyChunkManifest::generate(&mut File::open(&args[1])?, chunk_bytes)?;
    let zkey_sha256 = manifest[24..56]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let parsed = ZkeyChunkManifest::from_bytes(&manifest, &manifest_sha256, &zkey_sha256)?;
    parsed.verify_reader(&mut File::open(&args[1])?)?;
    fs::write(&args[2], &manifest)?;
    println!("manifest_bytes={}", manifest.len());
    println!("manifest_sha256={manifest_sha256}");
    println!("zkey_sha256={zkey_sha256}");
    println!("chunk_bytes={chunk_bytes}");
    println!("full_digest_check=passed");
    Ok(())
}
