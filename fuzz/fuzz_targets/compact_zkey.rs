#![no_main]
//! The compact zkey decoder and encoder.
//!
//! The first byte picks a mode: a file header and a body, which the target wraps
//! in a stored zstd frame so mutations reach the body parser rather than zstd; a
//! whole compact file; or a zkey for the encoder. Whatever the decoder accepts
//! must re-encode to a file that decodes to the same zkey, and whatever the
//! encoder accepts must decode back to its input.
use curvy_prover::compact_zkey;
use libfuzzer_sys::fuzz_target;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

// Every seed decodes to well under this; mutated headers must not allocate more.
const LIMIT: u64 = 1 << 20;

fn stored(body: &[u8]) -> Vec<u8> {
    compress_to_vec(body, CompressionLevel::Uncompressed)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            let split = data.len().min(compact_zkey::HEADER_BYTES);
            let file = [&data[..split], stored(&data[split..]).as_slice()].concat();
            if let Ok(zkey) = compact_zkey::inflate(file.as_slice(), LIMIT)
                && let Ok(again) = compact_zkey::encode(&zkey, stored)
            {
                let decoded = compact_zkey::inflate(again.as_slice(), LIMIT)
                    .expect("a re-encoded file decodes");
                assert_eq!(decoded, zkey);
            }
        }
        1 => {
            let _ = compact_zkey::describe(data);
            let _ = compact_zkey::inflate(data, LIMIT);
        }
        _ => {
            if let Ok(file) = compact_zkey::encode(data, stored) {
                let zkey = compact_zkey::inflate(file.as_slice(), data.len() as u64)
                    .expect("an encoded file decodes");
                assert_eq!(zkey, data);
            }
        }
    }
});
