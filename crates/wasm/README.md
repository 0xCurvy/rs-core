# curvy-wasm

wasm-bindgen exports for `curvy-core`: Poseidon, seed-backed and direct-scalar
BabyJubjub signing, note encryption and commitments, Merkle trees, witness-input
builders, and stealth addressing.

Groth16 proving is a separate WASM module built from `curvy-prover`.

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

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for output
directories, per-target requirements, and worker-budget configuration.

## API

The generated TypeScript declarations are the JavaScript API reference for each
output package. [docs.rs/curvy-wasm](https://docs.rs/curvy-wasm) documents the
underlying exports and their input validation.

| JavaScript API | Profile |
|---|---|
| `pubFromPrivateKey`, `sign` | Seed-backed BLAKE-512/prune derivation |
| `pubFromScalar`, `signWithScalar`, `verifyScalarSignature` | Checked direct-scalar derivation |

- Decimal crypto exports throw ordinary JavaScript errors for malformed input,
  including `poseidon`, commitments, signing, ephemeral keys, cipher inputs, and
  SHA-256 integers. Errors do not repeat the input.
- Poseidon requires 1–16 inputs. Reducing field strings are limited to 4096
  characters; raw integers must fit 256 bits and use at most 78 decimal digits.
- `version()` reports the compiled workspace version.
- `get_meta` returns both private keys. Treat it, `new_meta`, `scan`, and
  full-witness exports as secret data.
- After an unexpected `WebAssembly.RuntimeError`, discard the instance. Checked
  input errors are ordinary `Error` values and leave the instance usable.
- `verifyMerkleProof(depth, leaf, index, packedSiblings, root)` takes the
  verifier's expected tree depth first. It returns `true` only for a proof with
  exactly `depth` siblings that reaches `root`, so a truncated proof whose leaf
  is an internal node, or a zero-sibling proof with `leaf == root`, returns
  `false`. Four-argument calls without `depth` throw.

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

- `SeedSigner.sign` accepts unsigned decimal messages below `2^256`.
  `ScalarSigner.sign` requires a canonical BN254 field message.
- `free()` erases the owned key; later method calls throw.
- Callers must erase their own input buffers and avoid converting keys to
  JavaScript strings.
- `ephemeralPubKeyBytes` accepts a 32-byte little-endian scalar, including zero,
  and returns `[x, y]`.
- String-based APIs are also available.

See the [application migration guide](../../bindings/SIGNER_MIGRATION.md) for
profile mapping, storage and worker ownership, cleanup and integration checks.
