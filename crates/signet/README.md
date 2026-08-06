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

Everything after `graph.bin` is this crate: pure Rust, reading its tag table from
`curvy_witness::wire`.

[`curvy-signet-builder`]: https://crates.io/crates/curvy-signet-builder

## Building an artifact

```bash
CIRCUITS_DIR=/path/to/packages/zk-circuits \
  scripts/build-graph.sh v2/instances/verifyPendingNotesCommitment_5_30.circom /tmp/pending.bin
# -> r1cs_sha256=150cc21f…

cargo run -p curvy-signet --release -- export \
  /tmp/pending.bin artifacts/pending-5-30.bin 150cc21f…
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
  artifacts/pending-5-30.bin cdbaa907… input.json reference.wtns
# -> parity=exact
```

`validate` compares every signal against the reference witness and loads through
`WitnessGraph`, so it accepts exactly what a client accepts.

## Envelope, version and compression

Defaults are `--envelope signet --version 1 --compress zstd`, which a stock
`curvy-witness` accepts. `--envelope cvywit` remains available for older
consumers. Only `--version 2` requires the consumer's `signet-v2` feature.

| flag | effect |
|---|---|
| `--envelope cvywit` | `CVYWIT01`, what every published artifact carries |
| `--envelope signet` | `SIGNET01`, the successor envelope |
| `--version 1` | fixed-width references |
| `--version 2` | varint distances and ZigZag output deltas |
| `--compress none` | raw bytes |
| `--compress zstd` | a zstd frame around them, level 9 by default |
| `--level N` | zstd level; only meaningful with `--compress zstd` |

A compressed artifact pins its **compressed** digest - the evaluator hashes
whatever bytes it is handed. `export` prints both and labels which one to pin.

Sizes on PIX withdrawal `(10,30)`, 628,124 nodes:

| encoding | bytes |
|---:|---:|
| v1, raw | 7,063,377 |
| v2, raw | 2,782,671 |
| v2, zstd -9 | 871,833 |

Compression requires the system `zstd`. Without it the tool falls back to ruzstd,
which only implements level 1 and produces 1,339,142 bytes for the same graph; it
reports which compressor ran and warns on fallback.

The zstd level sets the frame's window, and the consumer rejects windows above
8 MiB. Level 9 gives a 4 MiB window with 2× headroom; level 19 produces a 7.3 MB
artifact but lands exactly on the cap. Raising the level requires raising the
consumer's cap in the same change.

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

An end-to-end check of the whole pipeline on a throwaway circuit:

```bash
scripts/smoke-generator.sh
```
