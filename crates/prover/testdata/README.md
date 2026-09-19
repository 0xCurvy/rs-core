# Prover test fixture

`multiplier.zkey` is the unmodified `test-vectors/test.zkey` fixture from
`ark-circom` 0.6.0. It describes the four-variable Circom circuit
`c <== a * b` and is used only by the prover integration test.

- SHA-256: `320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f`
- Upstream: <https://github.com/arkworks-rs/circom-compat>
- Upstream license: MIT OR Apache-2.0

`multiplier.vk.json` is the snarkjs verification-key export of that fixture.
`noncanonical-g2.zkey` is a malformed mutation retained from the September 2026
fuzzing run. It must be rejected before any unchecked field arithmetic. The
fuzz corpus stores the same input with the target's one-byte format selector.
