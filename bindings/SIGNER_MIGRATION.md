# Using byte-input signers in applications

The WASM and C APIs copy a signing key into an owned signer. Applications can
erase the import buffer immediately and release the signer when it is no longer
needed. Existing keys and signing profiles remain compatible.

## Match the existing key profile

| Existing WASM call | Replacement | Key encoding |
| --- | --- | --- |
| `sign(message, seedHex)` | `SeedSigner.sign(message)` | The same 32 seed bytes, in their original order |
| `pubFromPrivateKey(seedHex)` | `SeedSigner.publicKey()` | Same seed signer |
| `signWithScalar(message, scalarDecimal)` | `ScalarSigner.sign(message)` | Exactly 32 bytes, little-endian, canonical nonzero BabyJubjub scalar |
| `pubFromScalar(scalarDecimal)` | `ScalarSigner.publicKey()` | Same scalar signer |
| `ephemeralPubKey(scalarDecimal)` | `ephemeralPubKeyBytes(bytes)` | Exactly 32 bytes, little-endian; zero and all other 256-bit values are accepted |

A seed and a scalar are different key profiles even though both occupy 32 bytes.
Preserve the profile already used by the account. Stealth spend/view keys use
their own APIs.

## WASM ownership

Decrypt or load a key into a mutable `Uint8Array`, then import it once:

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
  const publicKey = signer.publicKey();
  const signature = signer.sign(message);
  // Use the public key and signature here.
} finally {
  signer.free();
}
```

Use `SeedSigner` in the same pattern for seed-backed accounts. For a signer kept
through an unlocked session, make account lock, logout, account replacement and
worker shutdown explicitly call `free()`. The worker that owns the WASM instance
also owns its signer. Keep only the opaque signer in application state.

Existing decimal/hex key storage can be imported during migration, but creating
those strings still creates copies that JavaScript cannot wipe. For the full
benefit, store encrypted key bytes and decrypt directly to mutable bytes. A
storage migration should verify that the derived public key is unchanged.

## C ownership

Use `curvy_seed_signer_new` or `curvy_scalar_signer_new` with the corresponding
32-byte buffer. Clear the caller buffer with the host's secure clearing routine
after the constructor returns, including on error. Check `CurvyStatus` before
using the returned handle.

Wrap the handle in one owning application object. Route signing/public-key calls
through it, release output JSON with `curvy_string_free`, and call the matching
`curvy_*_signer_free` on every successful construction's cleanup path. Mark the
wrapper closed after freeing it. C signer destruction waits for an active
operation and clears the key before returning.

## Integration checks

- Compare public keys and signatures with existing account vectors before
  switching callers. Include a scalar whose leading bytes differ so endian
  mistakes cannot pass unnoticed.
- Verify that clearing the import buffer does not break later signing.
- Exercise constructor/signing failures, lock/logout and account switching;
  every owned signer must be released exactly once.
- Remove plaintext key strings from application state, logs, errors and messages
  between workers. Keep key loading and signing in the owning worker where possible.

These signer APIs are available in `curvy-wasm` and the C ABI. The native Node
prover addon does not expose equivalent signer handles. Integrations using it
for signing would first need corresponding exports. Witness builders that still
take key strings need an adapter accepting a signer or signing callback; Rust's
`build_withdrawal_with_signer` and `build_aggregation_with_signer` already support
that pattern.

Shared-secret hash and cipher string APIs are separate from these signer APIs.
Eliminating secret strings from those calls would also require byte-input binding
variants. Signer migration does not erase old JavaScript strings, runtime copies
or private witness JSON.
