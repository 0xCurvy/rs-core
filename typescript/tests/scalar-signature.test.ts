import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildEddsa } from "circomlibjs";
import { describe, expect, it } from "vitest";
import {
  BABYJUB_SUBGROUP_ORDER,
  BN254_FIELD_MODULUS,
  bytesToHex,
  publicKeyFromBabyJubScalar,
  SCALAR_SIGNATURE_SCHEME,
  signWithBabyJubScalarTrace,
  verifyBabyJubScalarSignature,
} from "../src/scalar-signature.js";

type VectorFile = {
  scheme: string;
  vectors: Array<{
    scalar: string;
    message: string;
    publicKey: { x: string; y: string };
    nonceCounter: number;
    nonceHmacSha512: string;
    nonce: string;
    R8: { x: string; y: string };
    challenge: string;
    S: string;
  }>;
};

const vectorPath = fileURLToPath(
  new URL("../../crates/core/testdata/scalar_signature_vectors.json", import.meta.url),
);
const vectors = JSON.parse(readFileSync(vectorPath, "utf8")) as VectorFile;

describe("CURVY_BABYJUB_SCALAR_SIG_V1", () => {
  it("matches the shared Rust/TypeScript vector", async () => {
    expect(vectors.scheme).toBe(SCALAR_SIGNATURE_SCHEME);
    const vector = vectors.vectors[0];
    const scalar = BigInt(vector.scalar);
    const message = BigInt(vector.message);

    const publicKey = await publicKeyFromBabyJubScalar(scalar);
    expect(publicKey).toEqual({ x: BigInt(vector.publicKey.x), y: BigInt(vector.publicKey.y) });

    const trace = await signWithBabyJubScalarTrace(message, scalar);
    expect(trace.publicKey).toEqual(publicKey);
    expect(trace.nonceCounter).toBe(vector.nonceCounter);
    expect(bytesToHex(trace.nonceHmacSha512)).toBe(vector.nonceHmacSha512);
    expect(trace.nonce).toBe(BigInt(vector.nonce));
    expect(trace.signature.R8).toEqual({ x: BigInt(vector.R8.x), y: BigInt(vector.R8.y) });
    expect(trace.challenge).toBe(BigInt(vector.challenge));
    expect(trace.signature.S).toBe(BigInt(vector.S));
    expect(await verifyBabyJubScalarSignature(message, publicKey, trace.signature)).toBe(true);
  });

  it("is accepted by circomlibjs.verifyPoseidon", async () => {
    const vector = vectors.vectors[0];
    const trace = await signWithBabyJubScalarTrace(BigInt(vector.message), BigInt(vector.scalar));
    const eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;
    const publicInternal = [F.e(trace.publicKey.x), F.e(trace.publicKey.y)] as [Uint8Array, Uint8Array];
    const r8Internal = [F.e(trace.signature.R8.x), F.e(trace.signature.R8.y)] as [Uint8Array, Uint8Array];
    expect(
      eddsa.verifyPoseidon(
        F.e(BigInt(vector.message)),
        { R8: r8Internal, S: trace.signature.S },
        publicInternal,
      ),
    ).toBe(true);
  });

  it("rejects non-canonical scalars, messages, and modified signatures", async () => {
    await expect(publicKeyFromBabyJubScalar(0n)).rejects.toThrow(/non-zero/);
    await expect(publicKeyFromBabyJubScalar(BABYJUB_SUBGROUP_ORDER)).rejects.toThrow(/canonical/);
    await expect(signWithBabyJubScalarTrace(BN254_FIELD_MODULUS, 1n)).rejects.toThrow(/canonical/);

    const trace = await signWithBabyJubScalarTrace(424242n, 123456789012345678901234567890123456789n);
    expect(
      await verifyBabyJubScalarSignature(424243n, trace.publicKey, trace.signature),
    ).toBe(false);
    expect(
      await verifyBabyJubScalarSignature(424242n, trace.publicKey, {
        ...trace.signature,
        S: (trace.signature.S + 1n) % BABYJUB_SUBGROUP_ORDER,
      }),
    ).toBe(false);
  });

  it("rejects malformed and identity points", async () => {
    const trace = await signWithBabyJubScalarTrace(424242n, 1n);
    expect(
      await verifyBabyJubScalarSignature(424242n, { x: 0n, y: 1n }, trace.signature),
    ).toBe(false);
    expect(
      await verifyBabyJubScalarSignature(
        424242n,
        { x: BN254_FIELD_MODULUS, y: 1n },
        trace.signature,
      ),
    ).toBe(false);
  });
});
