# Parser fuzzing

This separate workspace keeps libFuzzer out of production dependencies. Its lockfile starts from the repository's dependency versions. The targets recompute artifact digests so mutations reach parsing after authentication instead of stopping at SHA-256 mismatch.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-07-03 fetch --manifest-path fuzz/Cargo.toml --locked
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz build
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run graph -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run sage -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run prover_formats -- -max_total_time=180 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run input_json -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
# The nested zkey matrix parser that Rust, C and WASM ship by default:
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz build --no-default-features
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run --no-default-features prover_formats -- -max_total_time=180 -timeout=10 -rss_limit_mb=1024 -max_len=65536
```

Graph/SAGE targets cap nodes, signals, input mappings, buffers, compressed bytes, and decompression windows. `graph` builds both evaluators from every input and asserts they accept the same artifacts and produce the same assignment, directly and through a `WitnessWorkspace` reused across runs, and that the compiled SAGE program round-trips. `sage` reads raw and zstd-compressed programs (a compressed program's source pin is recovered from the decompressed header) and asserts that accepted programs re-encode canonically.

The proving-format target caps bytes and selects a parser with its first byte modulo 5: WTNS, zkey, a mutated manifest over the fixture key, the one-pass resident parsers (`read_zkey_sequential`, `Prover::from_zkey_reader` with `zkey-single-pass`, and a manifest generated from the mutated key), or SPARROW streaming proofs over the mutated key (seekable and manifest-fed). Seeds include valid formats for each branch and the saved noncanonical-G2 reproducer. The compact and nested matrix backends are a compile-time choice in curvy-prover, exposed here as the fuzz crate's `compact-matrix` feature. It is on by default, so a plain build fuzzes the compact CSR parser (what the Node binding ships); `--no-default-features` builds the nested `parse_matrices` path that Rust, C and WASM ship by default. Only `prover_formats` uses curvy-prover, so it is the one target worth running in both configurations; every target must still build in both, and CI builds both and runs `prover_formats` in each. Default cargo-fuzz enables AddressSanitizer, overflow checks, and debug assertions. These short runs are regression coverage, not exhaustive evidence of parser correctness.

`input_json` fuzzes the streaming JSON/decimal boundary against the authenticated
multiplier graph and a built-in graph with scalar, one- and two-dimensional array
inputs. It asserts that errors never repeat an object input or a planted
`PRIVATE` sentinel outside an echoed signal name, and that echoed names stay within
128 bytes. Run it with the same sanitizer and byte/time limits above.

The opt-in WASM SIMD kernels (curvy-prover `wasm-simd-msm`, `wasm-simd-fft`) are
not fuzzed here: they compile only for wasm32 with simd128, which cargo-fuzz's
native libFuzzer builds never target. `scripts/simd-selftest.mjs --stress SECONDS`
runs a time-bounded randomized differential check of them against arkworks inside
the WASM module instead (see tools/browser/README.md).
