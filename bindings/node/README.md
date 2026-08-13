# @0xcurvy/rs-core-node

Native Node-API bindings for the Curvy Rust core and authenticated Groth16
prover. Backend services should use this package instead of loading the browser
WASM package or spawning a separate prover process.

The package is artifact-driven: a `CircuitProver` accepts any compatible
`curvy-graph-v1` witness graph and matching snarkjs zkey.

```js
const { CircuitProver } = require("@0xcurvy/rs-core-node");

const prover = new CircuitProver({
  zkeyPath: "/var/lib/curvy/circuit.zkey",
  zkeySha256: "...64 lowercase hex characters...",
  witnessGraphPath: "/var/lib/curvy/circuit.graph.bin",
  witnessGraphSha256: "...64 lowercase hex characters...",
  threads: 1,
});

const result = await prover.prove(JSON.stringify(circuitInput));
const proof = JSON.parse(result.proofJson);
const publicSignals = JSON.parse(result.publicSignalsJson);
```

## Threads

`threads` defaults to `1`. Every prover owns a fixed Rayon pool, and concurrent
calls on that prover are serialized. This prevents a backend from consuming all
host cores by accident while still allowing an operator to opt into measured
multicore proving. The value must be between 1 and 64.

Tree construction remains serial even when proof generation uses more than one
thread. This is deliberate: the Node package does not enable `curvy-core`'s
global parallel feature.

## Supported artifacts

All artifact bytes are authenticated before use. A graph/zkey pair must match
in assignment size, and every proof is self-verified before it crosses the
Node-API boundary. Proving keys and witness graphs are deployment artifacts and
are not included in this npm package.

The prebuilt release targets are:

- macOS arm64 for local development;
- Linux x64 GNU for CI and x64 backend hosts;
- Linux arm64 GNU for Graviton staging and production hosts;
- Windows x64 MSVC for Windows backend and development hosts.

All binaries use Node-API 8.
