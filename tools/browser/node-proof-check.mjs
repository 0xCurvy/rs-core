// Prove the multiplier fixture through a wasm-bindgen prover package in Node.
//
// Usage: node tools/browser/node-proof-check.mjs [path/to/curvy_prover.js]
//
// The default is the `scripts/build.sh wasm-nodejs` output. scripts/smoke-npm.mjs
// reuses `checkResidentProver` for the portable entry of the packed npm tarball.
// `prove` only returns after the proof verifies against the key's own verifying
// key, so a returned bundle is a self-verified proof. The checks below pin that
// verifying key to the snarkjs export and show that a proof which fails
// verification is refused rather than returned.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fixture } from './fixture.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const testdata = resolve(root, 'crates/prover/testdata');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
// Pinned by crates/prover/tests/prove_verify.rs.
const FIXTURE_VK_DIGEST = 'b550c07c390e3122b682edc04afb8c590bbc66172f19d1a42ac7051f15442838';
const INPUT = JSON.stringify({ a: '3', b: '11' });

// Re-derive the CVYVK digest (crates/prover/src/lib.rs `verifying_key_digest`)
// from the independent snarkjs export of the fixture's verifying key.
function snarkjsVerifyingKeyDigest(vk) {
  const fq = value => {
    let n = BigInt(value);
    const out = Buffer.alloc(32);
    for (let i = 31; i >= 0; i--, n >>= 8n) out[i] = Number(n & 0xffn);
    assert.equal(n, 0n, 'coordinate exceeds 32 bytes');
    return out;
  };
  const g1 = ([x, y, z]) => (assert.equal(z, '1', 'expected an affine G1 point'), Buffer.concat([fq(x), fq(y)]));
  const g2 = ([[x0, x1], [y0, y1], z]) => (assert.deepEqual(z, ['1', '0'], 'expected an affine G2 point'),
    Buffer.concat([fq(x0), fq(x1), fq(y0), fq(y1)]));
  const count = Buffer.alloc(4);
  count.writeUInt32LE(vk.IC.length);
  return sha256(Buffer.concat([Buffer.from('CVYVK\0\0\0', 'latin1'), g1(vk.vk_alpha_1), g2(vk.vk_beta_2),
    g2(vk.vk_gamma_2), g2(vk.vk_delta_2), count, ...vk.IC.map(g1)]));
}

export function checkResidentProver(wasm) {
  assert.equal(typeof wasm.WasmResidentProver, 'function', 'package is missing WasmResidentProver');
  const zkey = readFileSync(resolve(testdata, 'multiplier.zkey'));
  const graph = Buffer.from(fixture.graph, 'base64');
  assert.equal(sha256(zkey), fixture.zkeySha256, 'multiplier.zkey does not match its pin');
  assert.equal(sha256(graph), fixture.graphSha256, 'fixture graph does not match its pin');
  const vk = JSON.parse(readFileSync(resolve(testdata, 'multiplier.vk.json'), 'utf8'));
  assert.equal(snarkjsVerifyingKeyDigest(vk), FIXTURE_VK_DIGEST, 'multiplier.vk.json does not match the pinned digest');

  const prover = new wasm.WasmResidentProver(zkey, fixture.zkeySha256, graph, fixture.graphSha256);
  let bundle;
  try {
    assert.equal(prover.numConstraints, 1);
    assert.equal(prover.numPublic, 1);
    assert.equal(prover.mode, 'resident');
    assert.equal(prover.verifyingKeyDigest, FIXTURE_VK_DIGEST, 'self-verification key differs from the snarkjs export');
    bundle = JSON.parse(prover.prove(INPUT));
    assert.equal(bundle.proof.protocol, 'groth16');
    assert.equal(bundle.proof.curve, 'bn128');
    for (const point of ['pi_a', 'pi_b', 'pi_c']) assert.ok(Array.isArray(bundle.proof[point]), `proof is missing ${point}`);
    assert.deepEqual(bundle.publicSignals, ['33']);
    assert.throws(() => prover.prove('{'), 'malformed input JSON was accepted');
  } finally { prover.free(); }

  assert.throws(() => new wasm.WasmResidentProver(zkey, '00'.repeat(32), graph, fixture.graphSha256).free(),
    'incorrect zkey pin was accepted');
  assert.throws(() => new wasm.WasmResidentProver(zkey, fixture.zkeySha256, graph, '00'.repeat(32)).free(),
    'incorrect graph pin was accepted');

  // Corrupt an interior H-query point (as prove_verify.rs does) and re-pin it,
  // so only parsing or self-verification can stop it. No proof may come back.
  const tampered = Buffer.from(zkey);
  tampered[1044 + 64] ^= 0x01;
  let tamperedProof;
  let tamperedError;
  try {
    const bad = new wasm.WasmResidentProver(tampered, sha256(tampered), graph, fixture.graphSha256);
    try { tamperedProof = bad.prove(INPUT); } finally { bad.free(); }
  } catch (error) { tamperedError = error; }
  assert.equal(tamperedProof, undefined, 'a corrupted proving key produced a proof');
  assert.ok(tamperedError, 'a corrupted proving key was not rejected');

  return { publicSignals: bundle.publicSignals, verifyingKeyDigest: FIXTURE_VK_DIGEST,
    selfVerified: true, corruptedKeyRejected: String(tamperedError.message ?? tamperedError) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const entry = resolve(process.argv[2] ?? resolve(root, 'crates/prover/pkg-node/curvy_prover.js'));
  const wasm = createRequire(import.meta.url)(entry);
  console.log(JSON.stringify({ package: entry, ...checkResidentProver(wasm) }));
}
