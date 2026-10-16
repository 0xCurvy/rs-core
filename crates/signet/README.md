# curvy-signet

Builds the witness-graph artifacts `curvy-witness` evaluates. Internal tooling;
not published.

## The pipeline

```text
.circom   ── curvy-signet-ir-builder ──► graph.bin (postcard), written only if it
                                         matches the proving key's R1CS
graph.bin ── signet export ────────────► artifact + SHA-256
artifact  ── signet validate ──────────► parity against a reference witness
```

`scripts/build-graph.sh` runs the circuit half. It needs cargo, a circuits tree,
and git until the builder is installed. It takes:

- `CIRCUITS_DIR`: the circuits package; circuit paths are relative to its
  `circuits/` directory.
- `PROVING_KEY_R1CS`: the R1CS the proving key was made from. The builder writes
  the graph only if its compilation has the same header, witness layout and
  constraints. Without it the script checks nothing and prints the builder's own
  R1CS digest for you to compare with the proving key's.

The script runs [`curvy-signet-ir-builder`], a separate program that compiles the
circuit with circom 2.2.3. [`scripts/ir-builder.pin`] fixes the circom-witness-rs
commit and the SHA-256 of the builder's `Cargo.lock`. The first run checks out
that commit, checks both and installs the builder with `cargo install --locked`.
Set `SIGNET_IR_BUILDER` to use an already built binary instead.

To run the pinned builder by itself, outside the pipeline, call
`scripts/ir-builder.sh` with the builder's own arguments:

```bash
scripts/ir-builder.sh path/to/circuit.circom -o graph.bin --expect-r1cs path/to/proving_key.r1cs
```

The builder is GPL-3.0. Run it as a separate program; do not link rs-core
against it.

The R1CS check does not cover values computed by hints (`<--`), which add no
constraints. `signet validate` against circom's witness does.

[`curvy-signet-ir-builder`]: https://github.com/0xCurvy/circom-witness-rs/blob/master/ir-builder/README.md
[`scripts/ir-builder.pin`]: scripts/ir-builder.pin

## Building an artifact

```bash
CIRCUITS_DIR=/path/to/packages/zk-circuits PROVING_KEY_R1CS=/path/to/circuit.r1cs \
  scripts/build-graph.sh v2/instances/circuit.circom /tmp/circuit.bin
# -> builder=…, builder_version=…, builder_sha256=…
#    r1cs_sha256=150cc21f…

cargo run -p curvy-signet --release -- export \
  /tmp/circuit.bin artifacts/circuit.signet 150cc21f…
# -> graph_bytes=11978841
#    graph_sha256=cdbaa907…
#    artifact_bytes=…
#    artifact_sha256=…
#    pin=artifact_sha256
#    compressor=zstd -9
```

Record with the artifact: the builder line (pin or override, version and binary
digest), the R1CS digest, and the digests `export` prints.

Pin the digest `export` labels `pin=`. With the default zstd output that is
`artifact_sha256`, the digest of the file on disk: the evaluator authenticates
the bytes it is handed, which for a compressed artifact is the frame. With
`--compress none` it is `graph_sha256`. The R1CS digest in the header is
provenance only and authenticates nothing.

`export` loads the artifact back through `WitnessGraph` before writing and prints
`round_trip=ok`. On failure it writes nothing. Neither `export` nor `reseal`
overwrites an existing output file.

`--ops` (default `patched`) must match the operation schema of the builder that
wrote the postcard graph; the builder writes `patched`. A wrong value is not
detected by `export`, only by `validate`.

Then confirm the artifact computes what the circuit computes:

```bash
cargo run -p curvy-signet --release -- validate \
  artifacts/circuit.signet cdbaa907… input.json reference.wtns
# -> parity=exact
```

`validate` compares every signal against the reference witness. It loads through
`WitnessGraph` with the batch-prover limits: the same structural checks as a
client, with larger size ceilings.

`signet inspect <artifact> <sha256>` prints the signal count and the source R1CS
digest.

## Envelope, version and compression

Defaults are `--envelope signet --version 1 --compress zstd`, which a default
`curvy-witness` build accepts. Only `--version 2` requires the consumer's
`signet-v2` feature.

| flag | effect |
|---|---|
| `--envelope cvywit` | `CVYWIT01` envelope, for deployments that pin it |
| `--envelope signet` | `SIGNET01` |
| `--version 1` | fixed-width references |
| `--version 2` | varint distances and ZigZag output deltas |
| `--compress none` | raw bytes |
| `--compress zstd` | a zstd frame around them, level 9 by default |
| `--level N` | zstd level in `1..=19`; only meaningful with `--compress zstd` |

Sizes for a representative 628,124-node graph:

| encoding | bytes |
|---:|---:|
| v1, raw | 7,063,377 |
| v2, raw | 2,782,671 |
| v2, zstd -9 | 871,833 |

Compression uses the system `zstd` when available; the fallback encoder supports
only level 1. `export` prints the compressor it used; publication automation
should assert the expected compressor and level.

The consumer rejects zstd windows above 8 MiB. Level 9 uses a 4 MiB window;
level 19 reaches the 8 MiB cap exactly.

### Version-2 parity gate

`examples/v2_parity_matrix.rs` is the release gate for version-2 artifacts. For
each manifest row it encodes v1 and v2, loads both under
`Limits::batch_prover()`, evaluates them, and requires identical assignments. It
prints an assignment SHA-256 that identifies the result without publishing the
circuit inputs.

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
little-endian integer encoding. Store the report with the release metadata, and
run the matrix over every graph the deployment accepts.

## Re-enveloping an artifact with no postcard source

```bash
signet reseal <artifact> <sha256> <out.bin> \
  [--envelope cvywit|signet] [--compress none|zstd] [--level N]
```

`reseal` changes the envelope and compression of an artifact and copies the body
unchanged; only the eight-byte magic differs. Use it when the postcard source is
unavailable. It authenticates the input against its digest first and writes
nothing unless the result loads with the same signal count and source R1CS
digest.

It cannot change what a graph computes: it will not fix an export made with the
wrong `--ops`, and it will not convert version 1 to version 2. Both need the
postcard source.

## Editing `src/postcard.rs`

It reproduces the `Node`, `Operation` and `HashSignalInfo` declarations that
define the input format. postcard encodes an enum variant as its declaration
index, so reordering `Operation` silently remaps every operation in every graph.
The order must match the builder's. Two tests pin it.

## Tests

```bash
cargo test -p curvy-signet
```

- `tests/roundtrip.rs` encodes a graph with every node kind and checks the
  evaluator's assignment across both envelopes, both versions, and raw and
  compressed output. It loads every compressed artifact back through
  `WitnessGraph`, and holds the v2 truncation and corruption cases.
- `tests/ir_builder_graph.rs` exports a graph the builder wrote and checks it
  against circom's witness for inputs on both sides of each select, offline.
- `scripts/check.sh wasm --signet-v2` runs the v2 cases through the portable
  WASM binding.

End-to-end check of the whole pipeline on a throwaway circuit, including parity
against circom's witness (needs circom 2.2.3, node, and the builder or the pin):

```bash
scripts/smoke-graph.sh
```
