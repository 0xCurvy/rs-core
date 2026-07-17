import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { buildEddsa, type Eddsa, type Point as CircomPoint } from "circomlibjs";

export const SCALAR_SIGNATURE_SCHEME = "CURVY_BABYJUB_SCALAR_SIG_V1" as const;
export const SCALAR_NONCE_LABEL = new TextEncoder().encode("CURVY_BABYJUB_SCALAR_NONCE_V1");

export const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const BABYJUB_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

export type BabyJubPoint = Readonly<{
  x: bigint;
  y: bigint;
}>;

export type ScalarSignature = Readonly<{
  scheme: typeof SCALAR_SIGNATURE_SCHEME;
  R8: BabyJubPoint;
  S: bigint;
}>;

export type ScalarSignatureTrace = Readonly<{
  signature: ScalarSignature;
  publicKey: BabyJubPoint;
  nonceCounter: number;
  nonceHmacSha512: Uint8Array;
  nonce: bigint;
  challenge: bigint;
}>;

let eddsaPromise: Promise<Eddsa> | undefined;

async function getEddsa(): Promise<Eddsa> {
  eddsaPromise ??= buildEddsa();
  return eddsaPromise;
}

function assertCanonicalUnsigned(value: bigint, modulus: bigint, label: string): void {
  if (value < 0n || value >= modulus) {
    throw new RangeError(`${label} must be canonical in [0, ${modulus})`);
  }
}

function assertSecretScalar(value: bigint): void {
  assertCanonicalUnsigned(value, BABYJUB_SUBGROUP_ORDER, "BabyJubJub scalar");
  if (value === 0n) {
    throw new RangeError("BabyJubJub secret scalar must be non-zero");
  }
}

function le32(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 256n) {
    throw new RangeError("LE32 value does not fit in 32 bytes");
  }
  const out = new Uint8Array(32);
  let work = value;
  for (let i = 0; i < out.length; i++) {
    out[i] = Number(work & 0xffn);
    work >>= 8n;
  }
  return out;
}

function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError("counter must be a uint32");
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function concatBytes(...values: Uint8Array[]): Uint8Array {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    out.set(value, offset);
    offset += value.length;
  }
  return out;
}

function bytesToBigIntLe(bytes: Uint8Array): bigint {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8n) | BigInt(bytes[i]);
  }
  return out;
}

function toBigInt(eddsa: Eddsa, value: Uint8Array): bigint {
  return BigInt(eddsa.babyJub.F.toObject(value));
}

function toExternalPoint(eddsa: Eddsa, point: CircomPoint): BabyJubPoint {
  return Object.freeze({ x: toBigInt(eddsa, point[0]), y: toBigInt(eddsa, point[1]) });
}

function toCheckedCircomPoint(eddsa: Eddsa, point: BabyJubPoint, label: string): CircomPoint {
  assertCanonicalUnsigned(point.x, BN254_FIELD_MODULUS, `${label}.x`);
  assertCanonicalUnsigned(point.y, BN254_FIELD_MODULUS, `${label}.y`);
  const internal: CircomPoint = [eddsa.babyJub.F.e(point.x), eddsa.babyJub.F.e(point.y)];
  if (!eddsa.babyJub.inCurve(internal)) {
    throw new RangeError(`${label} is not on BabyJubJub`);
  }
  if (!eddsa.babyJub.inSubgroup(internal)) {
    throw new RangeError(`${label} is not in the BabyJubJub prime-order subgroup`);
  }
  if (point.x === 0n && point.y === 1n) {
    throw new RangeError(`${label} must not be the identity`);
  }
  return internal;
}

function equalInternalPoints(eddsa: Eddsa, left: CircomPoint, right: CircomPoint): boolean {
  return eddsa.babyJub.F.eq(left[0], right[0]) && eddsa.babyJub.F.eq(left[1], right[1]);
}

function deriveNonce(
  scalar: bigint,
  publicKey: BabyJubPoint,
  message: bigint,
): { nonce: bigint; counter: number; digest: Uint8Array } {
  const two512 = 1n << 512n;
  const limit = two512 - (two512 % BABYJUB_SUBGROUP_ORDER);
  const key = le32(scalar);

  for (let counter = 0; counter <= 0xffff_ffff; counter++) {
    const data = concatBytes(
      SCALAR_NONCE_LABEL,
      le32(publicKey.x),
      le32(publicKey.y),
      le32(message),
      u32be(counter),
    );
    const digest = hmac(sha512, key, data);
    const candidate = bytesToBigIntLe(digest);
    if (candidate >= limit) continue;
    const nonce = candidate % BABYJUB_SUBGROUP_ORDER;
    if (nonce !== 0n) return { nonce, counter, digest };
  }
  throw new Error("deterministic nonce counter exhausted");
}

export async function publicKeyFromBabyJubScalar(scalar: bigint): Promise<BabyJubPoint> {
  assertSecretScalar(scalar);
  const eddsa = await getEddsa();
  return toExternalPoint(eddsa, eddsa.babyJub.mulPointEscalar(eddsa.babyJub.Base8, scalar));
}

/**
 * Produce the complete deterministic trace used by cross-language vectors.
 * Applications normally call {@link signWithBabyJubScalar}.
 */
export async function signWithBabyJubScalarTrace(
  message: bigint,
  scalar: bigint,
): Promise<ScalarSignatureTrace> {
  assertSecretScalar(scalar);
  assertCanonicalUnsigned(message, BN254_FIELD_MODULUS, "message");
  const eddsa = await getEddsa();
  const publicInternal = eddsa.babyJub.mulPointEscalar(eddsa.babyJub.Base8, scalar);
  const publicKey = toExternalPoint(eddsa, publicInternal);
  const derived = deriveNonce(scalar, publicKey, message);
  const r8Internal = eddsa.babyJub.mulPointEscalar(eddsa.babyJub.Base8, derived.nonce);
  const R8 = toExternalPoint(eddsa, r8Internal);
  const challenge = toBigInt(
    eddsa,
    eddsa.poseidon([r8Internal[0], r8Internal[1], publicInternal[0], publicInternal[1], eddsa.babyJub.F.e(message)]),
  );
  const response =
    (derived.nonce + 8n * challenge * scalar) % BABYJUB_SUBGROUP_ORDER;
  const signature: ScalarSignature = Object.freeze({
    scheme: SCALAR_SIGNATURE_SCHEME,
    R8,
    S: response,
  });
  if (!(await verifyBabyJubScalarSignature(message, publicKey, signature))) {
    throw new Error("scalar signature failed internal verification");
  }
  return Object.freeze({
    signature,
    publicKey,
    nonceCounter: derived.counter,
    nonceHmacSha512: derived.digest,
    nonce: derived.nonce,
    challenge,
  });
}

export async function signWithBabyJubScalar(
  message: bigint,
  scalar: bigint,
): Promise<ScalarSignature> {
  return (await signWithBabyJubScalarTrace(message, scalar)).signature;
}

export async function verifyBabyJubScalarSignature(
  message: bigint,
  publicKey: BabyJubPoint,
  signature: ScalarSignature,
): Promise<boolean> {
  try {
    assertCanonicalUnsigned(message, BN254_FIELD_MODULUS, "message");
    assertCanonicalUnsigned(signature.S, BABYJUB_SUBGROUP_ORDER, "signature.S");
    if (signature.scheme !== SCALAR_SIGNATURE_SCHEME) return false;

    const eddsa = await getEddsa();
    const publicInternal = toCheckedCircomPoint(eddsa, publicKey, "publicKey");
    const r8Internal = toCheckedCircomPoint(eddsa, signature.R8, "signature.R8");
    const challenge = toBigInt(
      eddsa,
      eddsa.poseidon([r8Internal[0], r8Internal[1], publicInternal[0], publicInternal[1], eddsa.babyJub.F.e(message)]),
    );
    const left = eddsa.babyJub.mulPointEscalar(eddsa.babyJub.Base8, signature.S);
    const eightA = eddsa.babyJub.mulPointEscalar(publicInternal, 8n);
    const right = eddsa.babyJub.addPoint(r8Internal, eddsa.babyJub.mulPointEscalar(eightA, challenge));
    return equalInternalPoints(eddsa, left, right);
  } catch {
    return false;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
