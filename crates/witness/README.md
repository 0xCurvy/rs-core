# curvy-witness

Authenticated parser and evaluator for Curvy's offline-compiled
`curvy-graph-v1` Circom witness artifacts.

Use this crate when an integration needs the full BN254 witness assignment but
will perform proving elsewhere. Use `curvy-prover` when witness evaluation and
local Groth16 proving should be one operation.

## Install

```toml
[dependencies]
curvy-witness = "=0.1.5"
```

## Evaluate a graph

```rust,no_run
use curvy_witness::WitnessGraph;

let graph_bytes = std::fs::read("circuit.graph.bin")?;
let graph = WitnessGraph::from_bytes(
    &graph_bytes,
    "0000000000000000000000000000000000000000000000000000000000000000",
)?;
let assignment = graph.calculate_json(r#"{"amount":"42"}"#)?;

assert_eq!(assignment.len(), graph.assignment_size());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The expected SHA-256 is mandatory and is checked before parsing. For a
compressed artifact it authenticates the zstd frame bytes, before decoding.
Parsing also enforces graph and input size limits, canonical BN254 field values,
valid node references, and strict input names and shapes.

## Accepted artifacts

A default build reads the `SIGNET01` and `CVYWIT01` envelopes at body version 1,
raw or zstd-compressed.

| feature | adds |
|---|---|
| `signet-v2` | version-2 body encoding with varint distances and ZigZag output deltas |
| `sage` | `sage::SageGraph`, a second evaluator over the same artifacts (experimental) |

A default build refuses a version-2 artifact with
`WitnessError::UnsupportedVersion(2)` ("unsupported witness graph format version
2"); enabling `signet-v2` changes nothing for version 1. Ship the consumer
feature before the version-2 artifacts. A deployment that enables `signet-v2`
should run the SIGNET v1/v2 parity matrix over every graph it accepts.

## Limits

`Limits::client()` bounds what a pinned artifact can make a client do: its bytes,
compressed and not, its zstd window, its node, signal and input counts, and its
evaluation cost, summed over its nodes while they are decoded so that an
expensive graph fails before anything is evaluated. One unit is roughly a field
addition (about 16 ns natively); a comparison costs 3, a shift or bitwise
operation 24, an integer division 48, an inverse or field division 256 and an
exponentiation 768. The client budget is 32 million units, about five times what
the costliest shipped graph, pending(10,30), needs. `Limits::batch_prover()`
widens the node, byte and cost limits for the batch-50 pending commitment, and
only hosts that prove it should use them.

Input ranges may nest, as a bus or struct input's fields sit inside the whole,
but a mapping table in which two ranges partially overlap is refused.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for artifact
and build-target guidance.

## Circuit input JSON

- Duplicate signal names (including hash collisions) and surplus values are
  rejected.
- Missing inputs are zero, as in Circom; nested arrays flatten in order.
- Signed decimal strings reduce modulo BN254.
- JSON integer literals support the signed and unsigned 64-bit range (including
  `-0`); use decimal strings for larger integers.
- Non-zero fractional or exponent numbers are rejected.
- Error messages do not repeat invalid input values.
- Owned evaluation buffers are cleared on drop; returned assignments belong to
  the caller.
