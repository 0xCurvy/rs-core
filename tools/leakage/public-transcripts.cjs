// Synthetic signing transcripts replayed using only public inputs.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const wasm = require('../../crates/wasm/pkg-node/curvy_wasm.js');

const output = process.argv[2];
if (!output) throw new Error('usage: node tools/leakage/public-transcripts.cjs OUTPUT.json');
const order = BigInt('0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1');
const weight = value => [...value.toString(2)].filter(bit => bit === '1').length;
const records = [];
for (const profile of ['seed', 'scalar']) {
  for (const [group, fill] of [['fixed', 0x42], ['sparse', 0], ['dense', 0xff]]) {
    const bytes = new Uint8Array(32).fill(fill);
    bytes[31] = (bytes[31] & 1) | 2;
    let signer;
    try {
      signer = profile === 'seed' ? new wasm.SeedSigner(bytes) : new wasm.ScalarSigner(bytes);
    } finally {
      bytes.fill(0);
    }
    let publicKey, signature;
    try {
      publicKey = signer.publicKey();
      signature = signer.sign('42');
    } finally {
      signer.free();
    }
    // The signer has been destroyed; verification below has no key handle.
    const challenge = BigInt(wasm.poseidon([...signature.slice(0, 2), ...publicKey, '42']));
    const e = challenge * 8n % order;
    const s = BigInt(signature[2]);
    const verified = wasm.verifyScalarSignature('42', ...publicKey, ...signature);
    assert.equal(verified, true);
    records.push({ profile, group, message: '42', publicKey, signature, challenge: challenge.toString(),
      verificationScalar: e.toString(), verified,
      publicScalarBits: [s.toString(2).length, e.toString(2).length],
      publicScalarSetBits: [weight(s), weight(e)],
      variablePointAdditions: weight(s) + weight(e),
      variablePointDoublings: s.toString(2).length + e.toString(2).length });
  }
}
const moduleFile = path.join(__dirname, '../../crates/wasm/pkg-node/curvy_wasm_bg.wasm');
const report = { wasmSha256: createHash('sha256').update(fs.readFileSync(moduleFile)).digest('hex'), records };
fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
console.log(`${records.length} public-only signature replays passed`);
