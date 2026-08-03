# curvy-wasm

wasm-bindgen exports for `curvy-core`: Poseidon, seed-backed and direct-scalar
BabyJubjub signing, note encryption and commitments, Merkle trees, witness-input
builders, and stealth addressing.

This crate is the JavaScript binding for core cryptography and tree operations.
Groth16 proving is emitted as a separate WASM module by `curvy-prover`, allowing
applications to ship only the functionality they use.

## Build

Use the workspace scripts rather than invoking wasm-bindgen manually:

```bash
scripts/build.sh wasm-nodejs
scripts/build.sh wasm-web
scripts/build.sh wasm-bundler
scripts/build.sh wasm-web-threads
```

Portable builds are single-threaded. The threaded browser build exports
`initThreadPool(n)`, requires cross-origin isolation, and uses `n` as this
module's worker-pool size.

The generated TypeScript declarations are the JavaScript API reference for each
concrete output package. Rust item documentation on
[docs.rs/curvy-wasm](https://docs.rs/curvy-wasm) describes the underlying
wasm-bindgen exports and boundary validation.

Both signing profiles are supported:

| JavaScript API | Profile |
|---|---|
| `pubFromPrivateKey`, `sign` | Seed-backed BLAKE-512/prune derivation |
| `pubFromScalar`, `signWithScalar`, `verifyScalarSignature` | Checked direct-scalar derivation |

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for exact
output directories, per-target requirements, and worker-budget configuration.
