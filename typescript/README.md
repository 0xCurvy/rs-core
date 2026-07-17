# Scalar-signature TypeScript reference

Independent TypeScript implementation of `CURVY_BABYJUB_SCALAR_SIG_V1`.

It derives `A = scalar * Base8` directly, uses the specified HMAC-SHA-512
deterministic nonce, produces `S = r + 8*h*scalar mod l`, validates points, and
checks the result against circomlibjs's current `verifyPoseidon` implementation.

```sh
pnpm install --offline
pnpm typecheck
pnpm test
```

The Rust and TypeScript tests consume the same vector from
`crates/core/testdata/scalar_signature_vectors.json`.

This package is an interoperability/reference implementation. JavaScript
`bigint` values cannot be reliably zeroized, so reconstructed production signing
keys should remain in the Rust/WASM signer or another reviewed secret-handling
boundary rather than being long-lived TypeScript values.
