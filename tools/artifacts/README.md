# Artifact release validation

Run from the repository root:

```sh
npm ci --prefix tools/artifacts --ignore-scripts
cargo build --release --locked -p curvy-prover --example artifact_manifest_check --features sage,signet-v2
python3 tools/artifacts/validate_release.py \
  --zkey /path/circuit.zkey --graph /path/graph.bin \
  --wtns /path/reference.wtns --input /path/reference-input.json \
  --vk /path/verification-key.json --r1cs /path/circuit.r1cs \
  --ptau /path/ceremony.ptau --ptau-sha256 REVIEWED_CEREMONY_PIN \
  --output /path/new-release-bundle
```

Use the ceremony pin from independently reviewed protocol metadata. The command copies bounded regular files into a private staging directory, verifies the ceremony and circuit/witness relationships, and emits pins for those exact bytes. It does not publish, replace an existing bundle, or certify the ceremony's contributors. The bundle contains the witness/input fixture, so use an intended release fixture.

The standalone Rust example validates local compatibility and supports an optional input JSON for full graph/SAGE witness comparison. The Python command additionally requires the external transcript, R1CS, and SAGE gates; use it to create a release bundle.

Regression tests:

```sh
cargo build --locked -p curvy-prover --example artifact_manifest_check --features sage
python3 tools/artifacts/test_release.py
python3 tools/artifacts/test_pipeline.py
```

The full pipeline test generates a small ceremony with deliberately public test entropy. None of its outputs are suitable for production. Production PTAU/R1CS inputs are not checked into this repository.

The lockfile pins snarkjs 0.7.6. An override selects Underscore 1.13.8 for the transitive jsonpath dependency to address [GHSA-qpx9-hpmf-5gmw](https://github.com/advisories/GHSA-qpx9-hpmf-5gmw). These tools are development dependencies and are not part of Rust, Node, or WASM runtime packages.
