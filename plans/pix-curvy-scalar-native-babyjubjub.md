# PIX–Curvy Scalar-Native BabyJubJub Compatibility

## Status

Implementation proposal for allowing a BabyJubJub subgroup scalar reconstructed
from PIX shares to own and spend a Curvy note.

The first compatibility target is the existing deployed Curvy circuit and
Solidity verifier. Circuit hardening and transcript changes should be introduced
as a separately versioned protocol upgrade.

## Problem

Curvy currently treats a private key as seed material:

1. Hash the seed with BLAKE-512.
2. Prune the first half of the digest.
3. Derive the BabyJubJub secret scalar from the pruned value.
4. Use the second half of the digest as deterministic signing nonce material.

PIX reconstructs an actual scalar in the BabyJubJub prime-order subgroup. It
cannot invert Curvy's seed derivation and recover seed material that produces that
scalar.

The scalar and field types involved must remain distinct:

- `BabyJubScalar`: an integer modulo the BabyJubJub subgroup order `l`.
- `Bn254Fr`: an element of the BN254 scalar/base field used by Circom signals.
- `BabyJubPoint`: a checked affine point on BabyJubJub.

The subgroup order is:

```text
l = 2736030358979909402780800718157159386076813972158567259200215660948447373041
```

An incoming PIX scalar must be canonical and satisfy `1 <= a < l`. It must not be
silently parsed as a BN254 field element or silently reduced modulo `l`.

## Compatibility Result

No seed is required to derive the public key. Given a recovered scalar `a`, the
public key is directly:

```text
A = [a]Base8
```

`Base8` is Curvy/circomlib's prime-order BabyJubJub subgroup generator.

The currently deployed Circom verifier checks the following equation:

```text
[S]Base8 = R8 + h[8]A
```

where:

```text
h = Poseidon(R8.x, R8.y, A.x, A.y, M)
```

Therefore, a scalar-native signer can remain compatible with the existing
circuit by producing:

```text
A  = [a]Base8
r  = deterministic_nonce(a, A, M)
R8 = [r]Base8
h  = Poseidon(R8.x, R8.y, A.x, A.y, M)
S  = r + 8*h*a mod l
```

The factor `8` is required. A conventional Schnorr-style response
`S = r + h*a mod l` does not satisfy the deployed Curvy/circomlib equation.

This construction was checked against the installed
`circomlibjs.verifyPoseidon` implementation using a point derived directly from a
scalar. The signature verified successfully.

## Impact on Circom and Solidity

For the initial compatibility gate:

- No Circom change is required.
- No Groth16 setup or new `.zkey` is required.
- No Solidity verifier change is required.
- The existing signature wire representation `(R8.x, R8.y, S)` remains unchanged.
- The existing backend `verifyPoseidon` path can verify scalar-native signatures.

BLAKE-512 key derivation is not performed by the Circom or Solidity verifier. It
is only part of the existing off-chain seed-based public-key derivation and
signing implementation. The circuit receives `A`, `R8`, `S`, and `M` and verifies
their algebraic relationship.

The Solidity Groth16 verifier does not need BabyJubJub public-key derivation or
signature logic. It only verifies that the submitted proof satisfies the Circom
constraints.

## Rust Implementation

### Checked scalar type

Add a strict scalar type alongside the existing seed-based API:

```rust
pub struct BabyJubScalar(BigUint);

impl BabyJubScalar {
    pub fn try_from_biguint(value: BigUint) -> Result<Self, Error> {
        if value.is_zero() || value >= *SUB_ORDER {
            return Err(Error::InvalidBabyJubScalar);
        }
        Ok(Self(value))
    }

    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }
}
```

Boundary constructors must reject zero and values greater than or equal to `l`.
Reduction is appropriate only for explicit internal modular arithmetic, never for
parsing a claimed canonical PIX scalar.

### Public key derivation

The current implementation already has the required scalar multiplication under
the name `ephemeral_pub_key`. Add a checked, semantically named API:

```rust
pub fn public_key_from_scalar(a: &BabyJubScalar) -> BabyJubPoint {
    BabyJubPoint::new_internal(
        mul_point_escalar(*BASE8, a.as_biguint())
    )
}
```

Keep the legacy seed-based `derive_public_key` function for existing Curvy
accounts. Do not overload seed and scalar inputs into one ambiguous function.

### Scalar-native signing

Add a new signing entry point rather than changing the behavior of the legacy
seed signer:

```rust
pub fn sign_scalar_compat(
    message: Bn254Fr,
    scalar: &BabyJubScalar,
) -> Result<Signature, Error> {
    let public_key = public_key_from_scalar(scalar);
    let r = derive_deterministic_nonce(scalar, &public_key, message)?;
    let r8 = public_key_from_scalar(&r);

    let h = poseidon(&[
        r8.x(),
        r8.y(),
        public_key.x(),
        public_key.y(),
        message.into_inner(),
    ]);

    let s = (
        r.as_biguint()
        + BigUint::from(8u8) * fr_to_biguint(&h) * scalar.as_biguint()
    ) % &*SUB_ORDER;

    Ok(Signature { r8, s })
}
```

The new API should accept a canonical `Bn254Fr` message. It should not preserve
the legacy signer's distinction between different raw integers that reduce to the
same circuit field element.

### Deterministic nonce

The BLAKE-derived nonce prefix used by the seed signer cannot be recovered from
the scalar. Specify a new scalar-native deterministic nonce construction, for
example an HMAC-SHA-512/RFC6979-style derivation:

```text
key  = canonical_le32(a)
data = "CURVY_BABYJUB_SCALAR_NONCE_V1"
       || canonical(A.x)
       || canonical(A.y)
       || canonical(M)
       || counter
r    = HMAC-SHA-512(key, data) mod l
```

Retry with an incremented counter if `r == 0`.

This nonce-domain label only separates nonce derivation. It does not provide
cross-chain or cross-operation replay protection; those properties require
domain separation in the signed message transcript itself.

If the scalar remains distributed rather than being reconstructed, this
single-party deterministic nonce construction must not be independently applied
to individual shares. A real threshold signing protocol is required in that
case.

### Signer abstraction

The witness builders currently accept a private key and public key independently.
That permits accidental key/public-point mismatches. Replace those parameters
with a signer abstraction:

```rust
pub trait NoteSigner {
    fn public_key(&self) -> &BabyJubPoint;
    fn sign(&self, message: Bn254Fr) -> Result<Signature, Error>;
}
```

Provide at least two implementations:

- `SeedNoteSigner` for existing Curvy accounts.
- `ScalarNoteSigner` for a recovered PIX scalar.

Withdrawal and aggregation witness builders should obtain both the public point
and signature from the same signer.

## Checked Point Boundaries

The current `(Fr, Fr)` point alias should not cross untrusted boundaries. Replace
it with a checked type:

```rust
pub struct BabyJubPoint {
    x: Bn254Fr,
    y: Bn254Fr,
}
```

An untrusted point constructor must:

1. Parse both coordinates canonically without modular reduction.
2. Require both coordinates to be below the BN254 field modulus.
3. Check the BabyJubJub curve equation:

   ```text
   168700*x^2 + y^2 = 1 + 168696*x^2*y^2
   ```

4. Check `[l]P = identity` for subgroup membership.
5. Reject the identity for ownership keys and signing keys.

Field parsers that deliberately reduce modulo the BN254 modulus must not be used
for untrusted point coordinates.

The same validation rules should be implemented in Rust, TypeScript, Circom, and
any service boundary accepting points or signatures.

## Circuit Hardening

The current circomlib `EdDSAPoseidonVerifier` does not explicitly invoke
`BabyCheck` for `A` or `R8`. Multiplying `A` by eight does not prove that the
original input coordinates are on the curve.

This is an existing validation gap, independent of scalar-native signing. It does
not need to block the first deployed-verifier compatibility test, but it should be
fixed in a versioned production circuit.

### Enabled curve checks

Vendor the EdDSA verifier and add enabled-gated curve checks for `A` and `R8`.
Checks must be gated because padded zero-amount slots currently disable signature
verification and can contain dummy values.

Conceptually:

```text
enabled * curve_equation_residual(A)  == 0
enabled * curve_equation_residual(R8) == 0
```

Use intermediate signals so every Circom constraint remains quadratic.

### Strict subgroup check

To prove that `A` belongs to the prime-order subgroup without performing a full
`[l]A` variable-base multiplication, provide a private `A_div8` witness and
constrain:

```text
BabyCheck(A_div8)
A = [8]A_div8
```

The image of multiplication by eight is the prime-order subgroup. This requires
one curve check and three doublings.

The signature equation, combined with valid curve points and the subgroup result
for `8A`, constrains `R8` appropriately. Host-side verifiers should nevertheless
perform explicit validation for all received points.

### Verifier deployment consequence

Any additional Circom constraint changes the R1CS and verification key. A hardened
circuit therefore requires:

1. Recompile the circuit and witness graph.
2. Regenerate the circuit-specific `.zkey` using the approved setup process.
3. Regenerate the Solidity Groth16 verifier.
4. Deploy and register the new verifier version.
5. Keep the old verifier available during note/proof migration if required.

If the public signal list remains unchanged, the Solidity verifier ABI can remain
the same even though its verification-key constants and bytecode change.

## Known-Owner Note Construction

Scalar-native key derivation does not resolve Curvy's separate `sharedSecret`
semantics. PIX's recovered scalar must not be substituted for the shared secret.

Add an explicit construction path:

```rust
pub struct KnownOwner {
    pub owner: BabyJubPoint,
    pub shared_secret: Bn254Fr,
}
```

Allocation must specify how the recipient obtains or reconstructs the exact
`shared_secret`. The resulting note remains:

```text
ownerHash = Poseidon(owner.x, owner.y, shared_secret)
noteId    = Poseidon(ownerHash, amount, token)
nullifier = Poseidon(shared_secret, owner.x, owner.y)
```

The first kill-shot test may use a fixed, explicitly supplied test shared secret.
A production profile needs domain separation, confidentiality, lifecycle, and
recovery semantics for this value.

## Domain-Separated Protocol Upgrade

Domain separation for owner hashes, nullifiers, shared-secret derivation, proof of
possession, withdrawal, and aggregation should be introduced in a versioned
circuit/profile upgrade rather than mixed into the initial scalar compatibility
patch.

For example, the signature challenge can become:

```text
h = Poseidon(
    DOMAIN_EDDSA_V2,
    R8.x,
    R8.y,
    A.x,
    A.y,
    M
)
```

The operation message should separately bind an operation domain, chain ID,
verifier/profile ID, and all operation-specific fields. Changing these message
computations requires matching Rust, TypeScript, and Circom changes and a new
Groth16 verifier.

Owner-hash and nullifier domain changes also alter note commitments and therefore
require an explicit note-version and migration strategy.

## Compatibility Gate

The first end-to-end gate should use the existing deployed verifier:

1. Reconstruct a canonical `BabyJubScalar` from PIX shares.
2. Compute `A = [a]Base8` directly from that scalar.
3. Construct an allocated note using
   `KnownOwner { owner: A, shared_secret }`.
4. Commit the note through the real Curvy flow.
5. Build the real aggregation or withdrawal witness.
6. Sign its existing Curvy message with `sign_scalar_compat`.
7. Generate a proof using the production circuit artifacts.
8. Submit it to the real deployed Solidity verifier.
9. Confirm that the note is spent and its nullifier is accepted exactly once.

If this test fails, investigate serialization, scalar-generator conventions,
message construction, signature layout, proving artifacts, owner/shared-secret
construction, and deployed verifier provenance before changing the signature
equation.

## Cross-Language Vectors

Commit vectors containing at least:

- Canonical scalar encoding.
- Public key `A`.
- Canonical message `M`.
- Deterministic nonce `r`.
- Nonce point `R8`.
- Poseidon challenge `h`.
- Response scalar `S`.
- `ownerHash`, `noteId`, and `nullifier`.
- Full aggregation and withdrawal circuit inputs.
- Expected public signals and Solidity verification result.

Each vector must pass in:

- Rust.
- TypeScript/circomlibjs.
- Circom witness generation.
- Groth16 proof generation and off-chain verification.
- Solidity verification.

Negative vectors should cover:

- Scalars `0`, `l`, and `l + 1`.
- Non-canonical field coordinates.
- Off-curve points.
- The identity point.
- Small-order/torsion points.
- A valid subgroup point with a torsion component added.
- `S >= l`.
- Malformed or non-subgroup `R8`.
- A signer/public-key mismatch.
- A correct owner point with the wrong shared secret.

## Recommended Delivery Sequence

1. Add `BabyJubScalar`, `Bn254Fr`, and checked `BabyJubPoint` boundary types.
2. Add `public_key_from_scalar` and `sign_scalar_compat` without changing the
   legacy seed API.
3. Add `SeedNoteSigner` and `ScalarNoteSigner`; update witness builders to accept a
   signer rather than separate private/public inputs.
4. Add the explicit `KnownOwner` allocation path.
5. Produce Rust/TypeScript signature and note vectors.
6. Execute the deployed-verifier kill-shot test.
7. Introduce checked-point and subgroup constraints in versioned Circom circuits.
8. Regenerate and deploy the corresponding Solidity verifiers.
9. Add fully domain-separated note, nullifier, shared-secret, withdrawal,
   aggregation, and PoP transcripts in the versioned protocol profile.

This sequence separates the critical compatibility question from the broader
protocol-hardening work. A successful deployed-verifier test demonstrates that a
PIX-reconstructed scalar can control a real Curvy note without recovering or
emulating Curvy seed material.
