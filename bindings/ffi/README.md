# Curvy C ABI

`curvy-ffi` exposes the same synchronous crypto, note, stealth, and stateful
Merkle-tree boundary as `curvy-wasm`, plus the witness/prover handles needed by
native hosts. It is the maintained mobile/embedded binding for `rs-core`.

Scalar values use decimal strings. Bulk tree values use concatenated canonical
32-byte big-endian field elements. Rust-owned strings and byte buffers must be
released with `curvy_string_free` and `curvy_bytes_free`.

Witness-only hosts can call `curvy_witness_graph_calculate_packed` to receive
the complete assignment in that same packed field format, avoiding decimal
formatting and JSON parsing. The WASM `WasmWitnessGraph.calculatePacked` method
uses the identical layout.

Every fallible call returns `CurvyStatus`; `curvy_last_error()` contains the
calling thread's latest message. Panics are caught before they cross the ABI.
Stateful objects use monotonically increasing `u64` handles that are never
reused.

| Status | Meaning |
|---|---|
| `InvalidArgument` | A null or non-UTF-8 pointer, a null output pointer, or a malformed value: decimal, hex key, point, JSON string array, key length, or packed field encoding |
| `InvalidHandle` | An unknown, already freed, or wrong-type handle, including from `*_free` |
| `Error` | A well-formed argument the core rejected (full tree, unknown leaf, artifact, snapshot, or witness-input validation) or an internal failure such as unavailable randomness |
| `Panic` | A caught Rust panic; the message holds only its source location |

`curvy_verify_merkle_proof` takes the verifier's expected tree `depth` and
writes `1` only for a proof with exactly `depth` siblings that reaches the root.
Proofs for another depth, including truncated proofs whose leaf is an internal
node and zero-sibling proofs with `leaf == root`, write `0`.

Stateful handles are serialized per handle, not through one global operation
lock. Independent prover, witness, and tree handles can therefore make progress
concurrently; callers must still assume that operations on the same handle are
serialized.

The full-key API is named `curvy_resident_prover_*` and implements the HAWK
(High-throughput Authenticated Whole-Key prover) profile. SPARROW streaming is
currently exposed through Rust and the opt-in WASM surface, not this C ABI.

Generate and verify the checked-in header with:

```sh
./scripts/generate-ffi-header.sh
node scripts/check-ffi-surface.mjs
node scripts/check-ffi-vectors.mjs
```

## Resident SAGE

`curvy_resident_prover_new_sage` compiles an authenticated graph during resident
initialization. `curvy_resident_prover_new_compiled_sage` loads a cache using
three trusted digests: zkey, compiled program, and original source graph. Both
constructors apply client limits and return handles usable by the existing
resident prove and free functions. The compiled path does not require the
source graph bytes. Existing `curvy_resident_prover_new` behavior is unchanged.
Build with `--features signet-v2` when loading version-2 source graphs.

Malformed scalar crypto inputs return `InvalidArgument` before calling arithmetic
or the process panic hook, without repeating their contents. Field strings have
a 4096-character limit; raw integers must fit 256 bits and 78 decimal digits.
Handles are globally unique across object types. Object `*_free` functions return
`CurvyStatus`, including `InvalidHandle` for a stale or wrong-type handle; old
callers may ignore the return. Returned strings/bytes are cleared by their free
functions. Caller-owned input buffers remain the caller's responsibility.

`curvy_version` returns the compiled workspace version. Each fallible call
invalidates the previous `curvy_last_error` pointer; copy an error before making
another call. Successful calls clear it, and rejected calls replace it, including
a null output pointer rejected before any work. Freeing an object waits for an
active operation on that handle; it does not block unrelated handles.

Calls, including `*_free`, are safe from thread-local destructors (C++
`thread_local` objects, Swift or Kotlin teardown), even ones that run after the
library's own per-thread error slot is destroyed. Statuses are still returned;
once that slot is gone no message is recorded and `curvy_last_error()` returns
null on that thread.

Output pointers may refer to unaligned storage, but must still describe valid
writable memory of the declared size. Input byte lengths above `isize::MAX` or
whose address range wraps are rejected. C string termination, allocation extent,
and output allocation lifetime remain host obligations.

The first guarded call installs a panic hook that records only the source
location for panics inside C API calls; it delegates unrelated panics to the
previous host hook. A host that later replaces this process hook must preserve
that redaction. Malformed inputs follow checked error paths without panicking.

`get_meta` retains its compatibility return `[k, v, K, V]`, which contains private
keys, as do `new_meta` and `scan`. Do not log these outputs. Release every string
and byte output with its matching free function.
## Byte-based signer handles

`curvy_seed_signer_new` imports a 32-byte seed; `curvy_scalar_signer_new` imports
a canonical nonzero 32-byte little-endian BabyJubjub scalar. Each copies the key
and returns a handle. The caller retains ownership of the input buffer and may
wipe it after the constructor returns.

Use `curvy_{seed,scalar}_signer_public_key` for `[x, y]` and
`curvy_{seed,scalar}_signer_sign` for `[R8.x, R8.y, S]`; outputs are JSON arrays
of decimal strings freed with `curvy_string_free`. Seed messages are unsigned
decimal integers below `2^256`; scalar-profile messages are canonical BN254 field
elements. Release the key with the matching `curvy_{seed,scalar}_signer_free`,
which erases owned key storage after its active operation completes. Handles
are never reused, and wrong-type or repeated frees return `InvalidHandle`.

`curvy_ephemeral_pub_key_bytes` accepts a raw 32-byte little-endian scalar,
including zero. Existing string-based entry points remain available.

See the [application migration guide](../SIGNER_MIGRATION.md) for profile mapping,
caller-buffer ownership and handle cleanup.
