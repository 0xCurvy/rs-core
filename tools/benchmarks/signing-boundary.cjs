// Usage: node tools/benchmarks/signing-boundary.cjs BEFORE_PKG AFTER_PKG
// Both directories must contain curvy_wasm.js and curvy_wasm_bg.wasm.
const { resolve, join } = require('node:path');
const { readFileSync } = require('node:fs');
const { createHash } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const assert = require('node:assert/strict');
const paths = process.argv.slice(2).map(p => resolve(p));
assert.equal(paths.length, 2, 'supply before and after package directories');
const modules = paths.map(p => require(join(p, 'curvy_wasm.js')));
const seed = '01'.repeat(32);
const scalar = '123456789012345678901234567890123456789';
const cases = [
  ['seed-public', m => m.pubFromPrivateKey(seed)],
  ['seed-sign', m => m.sign('42', seed)],
  ['scalar-public', m => m.pubFromScalar(scalar)],
  ['scalar-sign', m => m.signWithScalar('42', scalar)],
];
const iterations = 100;
const report = { node: process.version, iterations, wasmSha256: paths.map(p => createHash('sha256').update(readFileSync(join(p, 'curvy_wasm_bg.wasm'))).digest('hex')), cases: [] };
for (const [name, operation] of cases) {
  assert.deepEqual(operation(modules[0]), operation(modules[1]), `${name} parity`);
  const milliseconds = modules.map(m => {
    for (let i = 0; i < 30; i++) operation(m);
    return Array.from({ length: 5 }, () => {
      const start = performance.now();
      for (let i = 0; i < iterations; i++) operation(m);
      return (performance.now() - start) / iterations;
    });
  });
  report.cases.push({ name, milliseconds });
}
console.log(JSON.stringify(report, null, 2));
