//! System-zstd compression of an input far larger than a pipe buffer.
//!
//! `compress` pipes the artifact through `zstd`. Writing all of stdin before reading
//! any of stdout deadlocks once zstd's pending output fills the stdout pipe: zstd
//! blocks writing, the exporter blocks writing stdin, and neither ever runs again.
//! That hung `signet export` on the pending-notes-commitment (50, 30) graph. The
//! input here is incompressible so the output is as large as the input, well past
//! any pipe buffer, and the test runs `compress` on a thread with a deadline so a
//! regression fails instead of hanging the suite.

use std::{sync::mpsc, thread, time::Duration};

use curvy_signet::{Compressor, compress};

fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn compresses_input_larger_than_a_pipe_buffer_without_deadlocking() {
    let input = incompressible(64 * 1024 * 1024);
    let (tx, rx) = mpsc::channel();
    let worker_input = input.clone();
    thread::spawn(move || {
        let _ = tx.send(compress(&worker_input, 9));
    });

    let (compressed, compressor) = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("compress did not finish: system zstd pipe deadlock");

    if compressor == Compressor::SystemZstd {
        let mut decoder =
            ruzstd::decoding::StreamingDecoder::new(compressed.as_slice()).expect("zstd frame");
        let mut round_trip = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut round_trip).expect("decode zstd frame");
        assert_eq!(round_trip, input, "system zstd frame does not round-trip");
    }
}
