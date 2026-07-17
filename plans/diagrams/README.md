# Scalar-Native BabyJubJub Diagrams

These diagrams accompany the scalar-native signing proposal. They are review
aids rather than protocol specifications; the equations and requirements in
[`../curvy-scalar-signature-generation-proposal.md`](../curvy-scalar-signature-generation-proposal.md)
remain authoritative.

## Scalar-native signing flow

![Scalar-native Curvy signing flow](scalar-native-signing-flow.png)

The important compatibility equation is:

```text
[S]Base8 = R8 + [h][8]A
```

Using `S = r + 8*h*a mod l` lets a directly reconstructed scalar produce the
same signature wire format expected by the existing Curvy circuit.

## Two key profiles, one verifier

![Legacy seed and scalar-native key profiles](legacy-and-scalar-key-profiles.png)

Existing seed-derived accounts remain valid. The scalar-native API is additive:
it must not reinterpret legacy seed bytes, and reconstructed scalars must not be
passed through legacy `prv2pub` or signing functions.

## PIX-owned note lifecycle

![PIX-owned note allocation, proof, and settlement](pix-note-allocate-prove-settle.png)

The recovered signing scalar and the Curvy note `shared_secret` are distinct
values with distinct purposes. The end-to-end compatibility gate is complete
only when the proof reaches the deployed Solidity verifier and its nullifier is
accepted once and rejected on replay.

## Generation metadata

Mode: built-in image generation, one fresh generated asset per diagram.

### Prompt: scalar-native signing flow

```text
Create a polished, high-resolution technical infographic diagram for cryptography protocol documentation.

Asset type: landscape 16:9 documentation diagram.
Visual style: precise flat-vector systems diagram, dark navy background, white typography, cyan/teal accents, subtle amber only for cautions, crisp arrows, generous spacing, no gradients, no decorative illustrations, no logos, no watermark. Make every label highly legible. Use the exact text below verbatim and do not add other text.

Title: "Scalar-native Curvy signing"

Show a left-to-right signing flow with clean aligned boxes and arrows:

1. "PIX scalar a"
2. "A = [a]Base8"

From the public key and message, show a deterministic nonce box:
"HMAC-SHA-512"
with three smaller input labels:
"key = LE32(a)"
"data = label || A || M || counter"
"r mod l"

Then:
"R8 = [r]Base8"

Then a challenge box:
"h = Poseidon(R8, A, M)"

Then a response box:
"S = r + 8·h·a mod l"

Then an output capsule:
"(R8.x, R8.y, S)"

Along the bottom, show a verification lane pointing from the output and public key into:
"[S]Base8 = R8 + [h][8]A"

Add one small footer callout:
"No seed hash • No pruning • No clamping"

Clearly distinguish secret values a and r with small lock icons, and public values A, R8, M, h, S with open-circle markers. Keep formulas exactly as written.
```

### Prompt: compatible key profiles

```text
Create a polished, high-resolution technical infographic diagram for cryptography protocol documentation.

Asset type: landscape 16:9 comparison and convergence diagram.
Visual style: precise flat-vector systems diagram, dark navy background, white typography, legacy lane in amber, scalar-native lane in cyan/teal, crisp arrows, generous spacing, no gradients, no decorative illustrations, no logos, no watermark. Make every label highly legible. Use the exact text below verbatim and do not add other text.

Title: "Two key profiles, one verifier"

Create two horizontal lanes that converge.

Top amber lane title:
"Legacy seed profile"

Top lane boxes:
"Seed bytes"
→ "BLAKE-512"
→ "Prune / clamp"
→ "Effective scalar a"
→ "A = [a]Base8"
→ "Legacy nonce"
→ "Signature"

Bottom cyan lane title:
"Scalar-native profile"

Bottom lane boxes:
"Canonical scalar a"
→ "A = [a]Base8"
→ "HMAC nonce"
→ "Signature"

Converge both lanes into a centered shared pipeline:
"Same wire signature"
with a small second line:
"(R8.x, R8.y, S)"
→ "Same Curvy Circom verifier"
→ "Same Solidity Groth16 verifier"

Add three concise callout panels:
"Existing fee collector keys remain valid"
"Never reinterpret seed bytes as a scalar"
"Never feed a scalar to legacy prv2pub"

Use a green check icon beside the first callout and amber warning icons beside the other two. Make the convergence visually obvious.
```

### Prompt: allocate, prove, and settle

```text
Create a polished, high-resolution technical infographic diagram for cryptography protocol documentation.

Asset type: landscape 16:9 end-to-end protocol flow.
Visual style: precise flat-vector systems diagram, dark navy background, white typography, cyan/teal for cryptographic operations, violet for proving, green for on-chain acceptance, amber for warnings, crisp arrows, generous spacing, no gradients, no decorative illustrations, no logos, no watermark. Make every label highly legible. Use the exact text below verbatim and do not add other text.

Title: "PIX-owned note: allocate → prove → settle"

Divide the diagram into three clearly labeled vertical zones:
"PIX / wallet"
"Curvy prover"
"On-chain"

Show this left-to-right sequence with numbered boxes and arrows:

In "PIX / wallet":
"1. PIX shares"
→ "2. Reconstruct scalar a"
→ "3. A = [a]Base8"
→ "4. KnownOwner { A, shared_secret }"

Then:
"5. Allocate note"
→ "6. Commit note / Merkle root"

In "Curvy prover":
"7. Build message M"
→ "8. Scalar-native signature"
with a small second line:
"(R8.x, R8.y, S)"
→ "9. Verify signature + note ownership"
→ "10. Groth16 proof"

In "On-chain":
"11. Solidity verifier"
→ "12. Accept nullifier once"

Add one amber warning callout connected to the scalar and KnownOwner boxes:
"a ≠ shared_secret"

Add small boundary labels above the zones:
"secret reconstruction"
"witness + proof"
"public verification"

Make it visually clear that the private scalar a never enters the on-chain zone, while the proof and public inputs do.
```
