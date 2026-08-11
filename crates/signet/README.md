# curvy-signet

Builds the witness-graph artifacts `curvy-witness` evaluates.

Internal tooling - not published. The evaluator that reads what this produces is
the published crate.

## The pipeline

```text
 .circom  ──┬─ circom --r1cs --O2 ─────────► original R1CS  ─┐
            └─ + circomlib IsZero patch ───► patched R1CS  ──┴─► cmp, must be identical
            ── build_graph (C++) ──────────► graph.bin (postcard)
                                                  │
                            signet export ────────┴─────────► artifact + SHA-256
                            signet validate ────────────────► parity vs reference witness
```

The circuit half needs `circom`, a C++ toolchain, a circuits tree and
`node_modules/circomlib`. `scripts/build-graph.sh` drives it and takes
`CIRCUITS_DIR`. It runs the generator, [`curvy-signet-builder`], pinned with a
checksum in [`generator/Cargo.lock`](generator) and printed on every run - record
it with the artifact, because the generator version determines the operation
schema that `signet export --ops` must match.

Each invocation vendors that locked generator into its scratch directory and
uses an isolated Cargo target. This is a correctness requirement: the generator
dependency writes generated C++ beside its source and does not declare
`WITNESS_CPP` as an environment rerun input. Reusing a target could otherwise
silently emit the circuit from an earlier invocation. The scratch build also
avoids mutating Cargo's registry cache. Generate graphs sequentially; concurrent
C++ builds can consume several gigabytes each.

Everything after `graph.bin` is this crate: pure Rust, reading its tag table from
`curvy_witness::wire`.

[`curvy-signet-builder`]: https://crates.io/crates/curvy-signet-builder

## Building an artifact

```bash
CIRCUITS_DIR=/path/to/packages/zk-circuits \
  scripts/build-graph.sh path/to/circuit.circom /tmp/circuit.bin
# -> r1cs_sha256=150cc21f…

cargo run -p curvy-signet --release -- export \
  /tmp/circuit.bin artifacts/circuit.signet 150cc21f…
# -> graph_bytes=11978841
#    graph_sha256=cdbaa907…
#    artifact_bytes=…
#    artifact_sha256=…
#    pin=artifact_sha256
#    compressor=zstd -9
```

Pin whichever digest `export` labels `pin=`. With the default zstd output that is
`artifact_sha256`, the digest of the file on disk - the evaluator authenticates
the bytes it is handed, which for a compressed artifact is the frame. `--compress
none` makes `graph_sha256` the pinned value instead. The R1CS digest in the header
is provenance only and authenticates nothing.

`export` loads the bytes back through `WitnessGraph` before writing and prints
`round_trip=ok`. A failure writes nothing.

Then confirm it computes what the circuit computes:

```bash
cargo run -p curvy-signet --release -- validate \
  artifacts/circuit.signet cdbaa907… input.json reference.wtns
# -> parity=exact
```

`validate` compares every signal against the reference witness and loads through
`WitnessGraph`, so it accepts exactly what a client accepts.

## Envelope, version and compression

Defaults are `--envelope signet --version 1 --compress zstd`, which a default
`curvy-witness` build accepts. `--envelope cvywit` provides compatibility with
deployments that pin the `CVYWIT01` envelope. Only `--version 2` requires the
consumer's `signet-v2` feature.

| flag | effect |
|---|---|
| `--envelope cvywit` | `CVYWIT01` compatibility envelope |
| `--envelope signet` | `SIGNET01`, what the pipeline emits |
| `--version 1` | fixed-width references |
| `--version 2` | varint distances and ZigZag output deltas |
| `--compress none` | raw bytes |
| `--compress zstd` | a zstd frame around them, level 9 by default |
| `--level N` | zstd level in `1..=19`; only meaningful with `--compress zstd` |

A compressed artifact pins its **compressed** digest - the evaluator hashes
whatever bytes it is handed. `export` prints both and labels which one to pin.

Sizes for a representative 628,124-node graph:

| encoding | bytes |
|---:|---:|
| v1, raw | 7,063,377 |
| v2, raw | 2,782,671 |
| v2, zstd -9 | 871,833 |

### Version-2 deployment parity gate

`examples/v2_parity_matrix.rs` is the release gate for a deployment's postcard
sources and circuit inputs. For each manifest row it independently
encodes SIGNET v1 and v2, authenticates and decodes both with
`Limits::batch_prover()`, evaluates the complete assignment, and requires exact
field-by-field equality. It prints a canonical assignment SHA-256 so a release
record can identify the result without publishing private circuit inputs.

```bash
cargo run --release -p curvy-signet --example v2_parity_matrix -- \
  path/to/signet-v2-parity.json
```

Manifest paths are relative to the manifest file unless absolute:

```json
{
  "profiles": [{
    "id": "representative-small",
    "postcard": "artifacts/representative-small.postcard.bin",
    "input": "inputs/representative-small.json",
    "r1csSha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "operationSchema": "patched"
  }]
}
```

The assignment digest hashes each field's length-prefixed canonical
little-endian integer encoding. Store the generated report with the release
metadata. Run the matrix over every graph accepted by that deployment, not only
the largest or most frequently used circuit.

The native suite additionally rejects every strict byte-prefix truncation of raw
and zstd-wrapped v2 artifacts, pinned-digest corruption, non-canonical varints,
invalid tags and backward references, invalid signal deltas and mappings, and
trailing bytes. CI builds the same decoder for portable and threaded WASM; the
portable generated module executes v1/v2 parity plus corruption and truncation
cases through `WasmWitnessGraph`. SIGNET v2 remains an explicit feature during
deployment rollout and does not enable SAGE or SPARROW.

Compression uses the system `zstd` when available. The fallback encoder supports
only level 1. The command reports the selected compressor, and publication
automation should assert the expected implementation and level.

The zstd level sets the frame's window, and the consumer rejects windows above
8 MiB. Level 9 gives a 4 MiB window with 2× headroom; level 19 produces a 7.3 MB
artifact but lands exactly on the cap. Raising the level requires raising the
consumer's cap in the same change.

## Re-enveloping an artifact with no postcard source

```bash
signet reseal <artifact> <sha256> <out.bin> \
  [--envelope cvywit|signet] [--compress none|zstd] [--level N]
```

`reseal` rewrites the envelope and compression of an authenticated artifact while
copying the body untouched. Use it when the source postcard graph is unavailable
and the deployment only needs a different supported envelope or compression.

The body of an artifact does not depend on its envelope: `encode` writes the magic
first and nothing after it varies, so this is a splice of eight header bytes.
`the_envelope_only_changes_the_magic` holds the encoder to that invariant, and
`resealing_reproduces_a_native_export` checks that resealing equals a native
export from the same body.

It authenticates the input against its pinned digest before doing anything, and
refuses to write unless the result loads through the evaluator with the same signal
count and source R1CS digest. The operation is bidirectional and byte-exact, so a
resealed artifact fully contains the one it replaced.

What it cannot do is change what a graph computes. It will not repair an export made
under the wrong `--ops`, and it will not re-encode version 1 as version 2. Both need
the postcard source.

## Editing `src/postcard.rs`

It reproduces the `Node`, `Operation` and `HashSignalInfo` declarations that
define the input format. postcard encodes an enum variant as its **declaration
index**, so reordering `Operation` silently remaps every operation in every graph
instead of failing. `Bor`/`Bxor` sit between `Band` and `Neg` because that is
where the patch inserts them. Two tests pin the order.

## Tests

```bash
cargo test -p curvy-signet
```

The round-trips in `tests/roundtrip.rs` encode a graph exercising every node kind
and check the shipped evaluator computes the right assignment, across both
envelopes, both versions, and compressed and raw. The compression tests load
every artifact back through `WitnessGraph`, which is what catches a frame the
consumer would reject for window size, frame count, dictionaries or checksum.
The same file contains the exhaustive v2 truncation and structural-corruption
matrix. `crates/prover/js/signet-v2-cross-target.cjs` exercises the generated
portable-WASM binding; CI also compiles the threaded target from the same source.

An end-to-end check of the whole pipeline on a throwaway circuit:

```bash
scripts/smoke-generator.sh
```
