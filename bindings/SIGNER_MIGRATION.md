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
Keep the profile the account already uses. Stealth spend and view keys use their
own APIs.

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

- Use `SeedSigner` the same way for seed-backed accounts.
- For a signer kept for an unlocked session, call `free()` on account lock,
  logout, account replacement and worker shutdown.
- The worker that owns the WASM instance also owns its signer. Keep only the
  opaque signer in application state.
- Decimal or hex key strings can still be imported, but JavaScript cannot wipe
  them. Store encrypted key bytes and decrypt directly into mutable bytes.
- When migrating key storage, verify that the derived public key is unchanged.

## C ownership

- Call `curvy_seed_signer_new` or `curvy_scalar_signer_new` with the 32-byte
  buffer. Clear the buffer with the host's secure clearing routine after the
  constructor returns, including on error.
- Check `CurvyStatus` before using the returned handle.
- Wrap the handle in one owning application object. Route signing and
  public-key calls through it and release output JSON with `curvy_string_free`.
- Call the matching `curvy_*_signer_free` on the cleanup path of every
  successful construction, then mark the wrapper closed. Freeing waits for an
  active operation and clears the key before returning.

## Integration checks

- Compare public keys and signatures with existing account vectors before
  switching callers. Include a scalar whose leading bytes differ so endian
  mistakes cannot pass unnoticed.
- Verify that clearing the import buffer does not break later signing.
- Exercise constructor and signing failures, lock, logout and account switching;
  every owned signer must be released exactly once.
- Remove plaintext key strings from application state, logs, errors and messages
  between workers. Keep key loading and signing in the owning worker where
  possible.

## Scope

- Signer handles are available in `curvy-wasm` and the C ABI, not in the Node
  binding.
- In Rust, `build_withdrawal_with_signer` and `build_aggregation_with_signer`
  take a signer instead of a key string.
- Shared-secret hash and cipher APIs still take secret strings.
- Moving to signers does not erase existing JavaScript strings, runtime copies or
  private witness JSON.
