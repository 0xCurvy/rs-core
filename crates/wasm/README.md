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

All decimal crypto exports throw ordinary JavaScript errors for malformed
input, including `poseidon`, commitments, signing, ephemeral keys, cipher inputs,
and SHA-256 integers. Errors do not repeat the input. Poseidon requires 1–16
inputs. Reducing field strings are limited to 4096 characters; raw integers must
fit 256 bits and use at most 78 decimal digits. Valid results are unchanged.

`version()` reports the compiled workspace version. Rust-owned decimal/key
strings and witness JSON copies are wiped on normal return or error; JavaScript
strings, returned private data, and wasm-bindgen conversion temporaries are
outside that guarantee. The compatibility `get_meta` result includes both private
keys; treat it, `new_meta`, `scan`, and full-witness exports as secret data.
Unexpected `WebAssembly.RuntimeError` still requires discarding that instance;
checked input errors are ordinary `Error` values and the instance remains usable.

`verifyMerkleProof(depth, leaf, index, packedSiblings, root)` takes the
verifier's expected tree depth first. It returns `true` only for a proof with
exactly `depth` siblings that reaches `root`, so a truncated proof whose leaf is
an internal node, or a zero-sibling proof with `leaf == root`, returns `false`.
With the generated bindings, calls still using the earlier four-argument form
throw instead of verifying.
## Byte-based signing keys

`SeedSigner` imports a 32-byte seed. `ScalarSigner` imports a canonical nonzero
32-byte little-endian BabyJubjub scalar. Both constructors require a `Uint8Array`
and copy its contents into owned key storage.

```js
function importScalar(keyBytes) {
  try {
    return new ScalarSigner(keyBytes);
  } finally {
    keyBytes.fill(0);
  }
}

const signer = importScalar(keyBytes);
try {
  const publicKey = signer.publicKey(); // [x, y] decimal strings
  const signature = signer.sign("42"); // [R8.x, R8.y, S] decimal strings
} finally {
  signer.free();
}
```

`SeedSigner.sign` accepts unsigned decimal messages below `2^256`.
`ScalarSigner.sign` requires a canonical BN254 field message. `free()` erases
the owned key; subsequent method calls throw. Callers must erase their input
buffers themselves and avoid converting keys to JavaScript strings.
`ephemeralPubKeyBytes` accepts a 32-byte little-endian scalar, including zero,
and returns `[x, y]`. String-based APIs remain available.

Erasure covers owned buffers, not caller copies, compiler spills or runtime
copies. WASM timing resistance is best-effort at the engine level; source-level
fixed schedules do not establish a JIT-independent timing guarantee.

See the [application migration guide](../../bindings/SIGNER_MIGRATION.md) for
profile mapping, storage and worker ownership, cleanup and integration checks.
