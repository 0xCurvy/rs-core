# Curvy C ABI

`curvy-ffi` exposes the same synchronous crypto, note, stealth, and stateful
Merkle-tree boundary as `curvy-wasm`, plus the witness/prover handles needed by
native hosts. It is the maintained mobile/embedded binding for `rs-core`.

Scalar values use decimal strings. Bulk tree values use concatenated canonical
32-byte big-endian field elements. Rust-owned strings and byte buffers must be
released with `curvy_string_free` and `curvy_bytes_free`.

Every fallible call returns `CurvyStatus`; `curvy_last_error()` contains the
calling thread's latest message. Panics are caught before they cross the ABI.
Stateful objects use monotonically increasing `u64` handles that are never
reused.

Generate and verify the checked-in header with:

```sh
./scripts/generate-ffi-header.sh
node scripts/check-ffi-surface.mjs
node scripts/check-ffi-vectors.mjs
```
