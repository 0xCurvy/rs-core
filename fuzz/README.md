# Parser fuzzing

This separate workspace keeps libFuzzer out of production dependencies. Its lockfile starts from the repository's dependency versions. The targets recompute artifact digests so mutations reach parsing after authentication instead of stopping at SHA-256 mismatch.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-07-03 fetch --manifest-path fuzz/Cargo.toml --locked
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz build
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run graph -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run sage -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-07-03 fuzz run prover_formats -- -max_total_time=180 -timeout=10 -rss_limit_mb=1024 -max_len=65536
```

Graph/SAGE targets cap nodes, signals, input mappings, buffers, compressed bytes, and decompression windows. The proving-format target caps bytes and selects WTNS, zkey, or manifest parsing with its first byte. Seeds include valid formats and the saved noncanonical-G2 reproducer. Default cargo-fuzz enables AddressSanitizer, overflow checks, and debug assertions. These short runs are regression coverage, not exhaustive evidence of parser correctness.

`input_json` fuzzes the streaming JSON/decimal boundary using a fixed authenticated
multiplier graph. Run it with the same sanitizer and byte/time limits above.
