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

Take the ceremony pin from independently reviewed protocol metadata. The command copies bounded regular files into a private staging directory, verifies the ceremony and the circuit/witness relationships, and emits pins for those exact bytes. It does not publish, replace an existing bundle, or certify the ceremony's contributors. The bundle contains the witness and input fixture, so use an intended release fixture.

The `artifact_manifest_check` example on its own validates local compatibility and accepts an optional input JSON for a full graph/SAGE witness comparison. To create a release bundle, use the Python command, which also enforces the external transcript, R1CS, and SAGE gates.

Regression tests:

```sh
cargo build --locked -p curvy-prover --example artifact_manifest_check --features sage
python3 tools/artifacts/test_release.py
python3 tools/artifacts/test_pipeline.py
```

The pipeline test generates a small ceremony from public test entropy; none of its outputs are suitable for production. Production PTAU and R1CS inputs are not in this repository.

The lockfile pins snarkjs 0.7.6 and overrides Underscore to 1.13.8 for [GHSA-qpx9-hpmf-5gmw](https://github.com/advisories/GHSA-qpx9-hpmf-5gmw). These are development dependencies, not part of the Rust, Node, or WASM runtime packages.
