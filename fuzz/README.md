# Parser fuzzing

A separate Cargo workspace of libFuzzer targets for the artifact and input parsers. The targets recompute artifact digests, so mutated inputs reach the parsers instead of failing the SHA-256 check.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-08-15 fetch --manifest-path fuzz/Cargo.toml --locked
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz build
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz run graph -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz run sage -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz run prover_formats -- -max_total_time=180 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz run input_json -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
# The nested zkey matrix parser that Rust, C and WASM ship by default:
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz build --no-default-features
CARGO_NET_OFFLINE=true cargo +nightly-2026-08-15 fuzz run --no-default-features prover_formats -- -max_total_time=180 -timeout=10 -rss_limit_mb=1024 -max_len=65536
```

Targets:

- `graph` builds both evaluators from every input and asserts that they accept the same artifacts and produce the same assignment, directly and through a `WitnessWorkspace` reused across runs, and that the compiled SAGE program round-trips.
- `sage` reads raw and zstd-compressed programs and asserts that accepted programs re-encode canonically. A compressed program's source pin is recovered from the decompressed header.
- `prover_formats` selects a parser with its first byte modulo 5: WTNS, zkey, a mutated manifest over the fixture key, the one-pass resident parsers (`read_zkey_sequential`, `Prover::from_zkey_reader` with `zkey-single-pass`, and a manifest generated from the mutated key), or SPARROW streaming proofs over the mutated key (seekable and manifest-fed). Seeds include valid inputs for each branch and the noncanonical-G2 reproducer.
- `input_json` fuzzes the streaming JSON/decimal boundary against the authenticated multiplier graph and a built-in graph with scalar, one- and two-dimensional array inputs. It asserts that errors never repeat an object input or a planted `PRIVATE` sentinel outside an echoed signal name, and that echoed names stay within 128 bytes.

Graph and SAGE targets cap nodes, signals, input mappings, buffers, compressed bytes, and decompression windows. The proving-format target caps bytes.

The zkey matrix backend is a compile-time choice in curvy-prover, exposed here as the `compact-matrix` feature. It is on by default, so a plain build fuzzes the compact CSR parser that the Node binding ships; `--no-default-features` builds the nested `parse_matrices` path that Rust, C and WASM ship by default. Only `prover_formats` uses curvy-prover, so run it in both configurations. Every target must build in both.

Default cargo-fuzz builds enable AddressSanitizer, overflow checks, and debug assertions. These short runs are regression coverage, not exhaustive evidence of parser correctness.

The opt-in WASM SIMD kernels (curvy-prover `wasm-simd-msm`, `wasm-simd-fft`) are not fuzzed here: they compile only for wasm32 with simd128, and cargo-fuzz builds native binaries. `scripts/check.sh simd --stress SECONDS` checks them against arkworks inside the WASM module with randomized inputs instead (see [tools/browser/README.md](../tools/browser/README.md)).
