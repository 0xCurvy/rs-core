#![no_main]
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 { return; }
    let Some((&format, data)) = data.split_first() else { return; };
    match format % 3 {
        0 => { let _ = curvy_prover::wtns::read_wtns(data); }
        1 => { let _ = curvy_prover::zkey::read_zkey(&mut std::io::Cursor::new(data)); }
        _ => {
            let pin = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect::<String>();
            let key_pin = data.get(24..56).map(|v| v.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_else(|| "00".repeat(32));
            if let Ok(manifest) = curvy_prover::artifacts::manifest::ZkeyChunkManifest::from_bytes(data, &pin, &key_pin) {
                let mut key = &include_bytes!("../../crates/prover/testdata/multiplier.zkey")[..];
                let _ = curvy_prover::Prover::from_zkey_manifest_reader(&mut key, &manifest);
            }
        }
    }
});
