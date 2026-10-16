# Curvy C ABI

`curvy-ffi` exposes the same synchronous crypto, note, stealth, and stateful
Merkle-tree boundary as `curvy-wasm`, plus the witness and prover handles native
hosts need. It is the binding for mobile and embedded hosts.

Regenerate the checked-in header, and check it, the C surface against the WASM
API and both against the golden vectors:

```sh
scripts/build.sh ffi-header
scripts/build.sh wasm-nodejs && scripts/check.sh ffi
```

## Values and memory

- Scalar values use decimal strings. Bulk tree values use concatenated canonical
  32-byte big-endian field elements.
- Release Rust-owned strings and byte buffers with `curvy_string_free` and
  `curvy_bytes_free`. Both clear the memory they free. Caller-owned input
  buffers remain the caller's responsibility.
- `curvy_witness_graph_calculate_packed` returns the complete assignment in the
  same packed field format, without decimal formatting or JSON. The WASM
  `WasmWitnessGraph.calculatePacked` method uses the identical layout.
- Field strings are limited to 4096 characters; raw integers must fit 256 bits
  and 78 decimal digits.
- Output pointers may refer to unaligned storage, but must describe valid
  writable memory of the declared size. Input byte lengths above `isize::MAX` or
  whose address range wraps are rejected. C string termination, allocation
  extent, and output allocation lifetime remain host obligations.
- `curvy_new_meta`, `curvy_get_meta` (`[k, v, K, V]`) and `curvy_scan` return
  private keys. Do not log these outputs.
- `curvy_version` returns the compiled workspace version.

## Errors

Every fallible call returns `CurvyStatus`; `curvy_last_error()` holds the calling
thread's latest message. Panics are caught before they cross the ABI.

| Status | Meaning |
|---|---|
| `InvalidArgument` | A null or non-UTF-8 pointer, a null output pointer, or a malformed value: decimal, hex key, point, JSON string array, key length, or packed field encoding |
| `InvalidHandle` | An unknown, already freed, or wrong-type handle, including from `*_free` |
| `Error` | A well-formed argument the core rejected (full tree, unknown leaf, artifact, snapshot, or witness-input validation) or an internal failure such as unavailable randomness |
| `Panic` | A caught Rust panic; the message holds only its source location |

- Malformed scalar crypto inputs return `InvalidArgument` before reaching
  arithmetic or the panic hook. Error messages do not repeat input contents.
- Each fallible call invalidates the previous `curvy_last_error` pointer; copy
  an error before the next call. Successful calls clear it, and rejected calls
  replace it, including a null output pointer rejected before any work.
- The first guarded call installs a panic hook that records only the source
  location for panics inside C API calls and passes other panics to the previous
  hook. A host that later replaces the process hook must keep that redaction.
- Calls, including `*_free`, are safe from thread-local destructors (C++
  `thread_local` objects, Swift or Kotlin teardown). Once the library's
  per-thread error slot is destroyed, statuses are still returned but no message
  is recorded and `curvy_last_error()` returns null on that thread.

## Handles

- Stateful objects use `u64` handles that are unique across object types and
  never reused.
- Operations are serialized per handle, not globally: independent prover,
  witness, and tree handles run concurrently, and operations on the same handle
  are serialized.
- Object `*_free` functions return `CurvyStatus`, including `InvalidHandle` for
  a stale or wrong-type handle. Freeing waits for an active operation on that
  handle and does not block other handles.

## Merkle proofs

`curvy_verify_merkle_proof` takes the verifier's expected tree `depth` and
writes `1` only for a proof with exactly `depth` siblings that reaches the root.
Proofs for another depth, including truncated proofs whose leaf is an internal
node and zero-sibling proofs with `leaf == root`, write `0`.

## Resident prover

The full-key prover API is `curvy_resident_prover_*`;
`curvy_resident_prover_profile` reports `HAWK`. SPARROW streaming proving is not
exposed through the C ABI.

`curvy_resident_prover_new_sage` compiles an authenticated graph into SAGE
during initialization. `curvy_resident_prover_new_compiled_sage` loads a
compiled program using three trusted digests: zkey, compiled program, and
original source graph; it does not need the source graph bytes. Both apply client
limits and return handles usable by the resident prove and free functions. Build
with `--features signet-v2` to load version-2 source graphs.

## Byte-based signer handles

`curvy_seed_signer_new` imports a 32-byte seed; `curvy_scalar_signer_new` imports
a canonical nonzero 32-byte little-endian BabyJubjub scalar. Each copies the key
and returns a handle. The caller keeps ownership of the input buffer and may
wipe it after the constructor returns.

- `curvy_{seed,scalar}_signer_public_key` returns `[x, y]` and
  `curvy_{seed,scalar}_signer_sign` returns `[R8.x, R8.y, S]`, as JSON arrays of
  decimal strings freed with `curvy_string_free`.
- Seed messages are unsigned decimal integers below `2^256`; scalar-profile
  messages are canonical BN254 field elements.
- `curvy_{seed,scalar}_signer_free` erases the owned key after any active
  operation completes. Wrong-type or repeated frees return `InvalidHandle`.
- `curvy_ephemeral_pub_key_bytes` accepts a raw 32-byte little-endian scalar,
  including zero. String-based entry points are also available.

See the [application migration guide](../SIGNER_MIGRATION.md) for profile mapping,
caller-buffer ownership and handle cleanup.
