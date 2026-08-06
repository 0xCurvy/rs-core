# curvy-signet

Builds the witness-graph artifacts `curvy-witness` evaluates.

Internal tooling - not published. The evaluator that reads what this produces is
the published crate.

## The pipeline

```text
 .circom  ──┬─ circom --r1cs --O2 ─────────► original R1CS  ─┐
            └─ + circomlib IsZero patch ───► patched R1CS  ──┴─► cmp, must be identical
            ── upstream build_graph (C++) ─► graph.bin (postcard)
                                                  │
                            signet export ────────┴─────────► artifact + SHA-256
                            signet validate ────────────────► parity vs reference witness
```

The two halves split at `graph.bin`, and they split for a reason.

**The circuit half** needs `circom`, a C++ toolchain, a circuits tree and
`node_modules/circomlib`. It is circuit tooling; `scripts/build-graph.sh` drives
it and takes `CIRCUITS_DIR` so it is not bound to one repository layout.

The generator itself is [`curvy-signet-builder`](https://crates.io/crates/curvy-signet-builder),
a normal cargo dependency of [`generator/`](generator), a small crate kept out of the
rs-core workspace because building it needs `circom`, a C++ toolchain and
`WITNESS_CPP`. Nothing clones a repository or executes code from a URL.

The pin lives in that crate's `Cargo.lock`:

```
curvy-signet-builder 0.1.0
sha256 b59d588a8daf232b8b1ebeab195b17c52dec79add33e15f6ca3ed4609dc1584e
```

`build-graph.sh` prints both with every run, and they belong in the artifact record
next to the graph and R1CS digests: the crate version determines the operation
schema, which is what `signet export --ops` has to match.

`curvy-signet-builder` is [Curvy's fork of `circom-witness-rs`](https://github.com/0xCurvy/circom-witness-rs),
republished under our own name so the pin is immutable - a crates.io version and its
checksum cannot move or disappear, which no git revision can promise. `patches/` now
holds only the circomlib change, which is circuit-side and cannot live in that fork.

**This crate** is everything after that: pure Rust, no C, and it reads its tag
table straight out of [`curvy_witness::wire`]. That shared table is why the crate
lives beside the evaluator - a renumbered tag breaks this crate's own tests
instead of silently producing artifacts that decode to different operations.

## Building an artifact

```bash
CIRCUITS_DIR=/path/to/packages/zk-circuits \
  scripts/build-graph.sh v2/instances/verifyPendingNotesCommitment_5_30.circom /tmp/pending.bin
# -> r1cs_sha256=150cc21f…

cargo run -p curvy-signet --release -- export \
  /tmp/pending.bin artifacts/pending-5-30.bin 150cc21f…
# -> graph_bytes=11978841
#    graph_sha256=cdbaa907…
```

`graph_sha256` is the value to pin in protocol metadata. Nothing else
authenticates the artifact - the R1CS digest in the header is provenance only.

Then prove it computes what the circuit computes:

```bash
cargo run -p curvy-signet --release -- validate \
  artifacts/pending-5-30.bin cdbaa907… input.json reference.wtns
# -> parity=exact
```

`validate` compares every signal against the reference witness, not a checksum: a
single wrong signal is a proof the deployed verifier rejects, and a checksum that
happened to collide would hide it. It loads through `WitnessGraph`, so it accepts
exactly what a client accepts and rejects everything a client rejects.

## Envelope and version

Defaults are `--envelope cvywit --version 1`, the only combination a stock
`curvy-witness` accepts. `SIGNET01` and version 2 both require the consumer's
`signet` feature, so emitting either by default would produce artifacts a normal
client refuses.

| flag | effect |
|---|---|
| `--envelope cvywit` | `CVYWIT01`, what every published artifact carries |
| `--envelope signet` | `SIGNET01`, the successor envelope |
| `--version 1` | fixed-width references |
| `--version 2` | varint distances and ZigZag output deltas |
| `--compress none` | raw bytes |
| `--compress zstd` | a zstd frame around them, level 9 by default |
| `--level N` | zstd level; only meaningful with `--compress zstd` |

Compression changes which digest authenticates the artifact: the evaluator hashes
whatever bytes it is handed, so a compressed artifact pins its **compressed**
digest. `export` prints both and labels which one to pin.

Measured on PIX withdrawal `(10,30)`, 628,124 nodes:

| encoding | bytes |
|---:|---:|
| v1, raw | 7,063,377 |
| v2, raw | 2,782,671 |
| v2, zstd -9 | 871,833 |

Compression shells out to the system `zstd`. ruzstd only implements level 1, and its
level 1 is itself ~39% weaker than libzstd's - the same graph comes out at 1,339,142
bytes. That is fine as a fallback but not what should be published, so the tool says
which compressor ran and warns when it had to fall back.

Requiring `zstd` costs nothing: compression is a build step in a pipeline that
already needs `circom`, `git` and a C++ toolchain. The pure-Rust constraint applies
to the *decoder*, which ships to wasm - not to the compressor.

### Why level 9 and not 19

Level 19 is another ~26% smaller, but the level sets the frame's window and the
consumer caps that at 8 MiB:

| level | pending-50 v2 | window |
|---|---:|---|
| 1 | 12,006,898 | 512 KiB |
| **9** | **9,886,524** | **4 MiB** |
| 19 | 7,349,911 | 8 MiB - exactly the cap |

Level 19 lands on the boundary with no margin, so a slightly larger graph or a zstd
release that chose a wider window would produce artifacts our own evaluator refuses.
The cap is real and reachable - `--ultra -22 --zstd=wlog=24` yields a 16 MiB window
and is rejected outright. Level 9 keeps 2× headroom. Going to 19 is a reasonable
trade, but it should come with raising the consumer's cap in the same change, and
that is a consumer-side decision rather than something a generator flag forces.

### Every export is verified

`export` loads the bytes it is about to write back through `WitnessGraph` and checks
the signal count before writing anything. That is what catches a frame whose window
exceeds the cap, or a header field at the wrong offset, at generation time instead of
at a client. It prints `round_trip=ok`; a failure writes nothing.

## What is vendored, and why

`src/postcard.rs` reproduces upstream's `Node`, `Operation` and `HashSignalInfo`
declarations from [`circom-witness-rs`](https://github.com/philsippl/circom-witness-rs)
(MIT), as carried by [Curvy's fork](https://github.com/0xCurvy/circom-witness-rs).
They are the input format, not a second
implementation of anything - the upstream evaluator is deliberately *not* carried
over, because validation runs through `curvy-witness` instead.

One thing to know before touching that file: postcard encodes an enum variant as
its **declaration index**. Reordering `Operation` silently remaps every operation
in every graph rather than failing, so `Bor`/`Bxor` sit between `Band` and `Neg`
because that is where the patch inserts them. Two tests pin it.

## Tests

```bash
cargo test -p curvy-signet
```

Twelve tests. The ones that matter are the round-trips in `tests/roundtrip.rs`:
they encode a graph exercising every node kind, hand it to the shipped evaluator,
and check it computes the right assignment - across both envelopes, both versions,
and both compressed and raw. A header field at the wrong offset or a varint with
the wrong sign passes every unit test and fails only when a real artifact ships;
this catches it here.

The compression tests exist for a specific failure: the consumer caps the zstd
window, requires a single frame, refuses dictionaries and checks the frame
checksum. An encoder that produced frames failing any of that would be quietly
useless, so the tests load every compressed artifact back through `WitnessGraph`
rather than just checking it shrank.
