// Usage: node SCRIPT ARTIFACTS_JSON OUTPUT_JSON (build bindings/node first)
import assert from 'node:assert/strict';
import {readFile, writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {performance} from 'node:perf_hooks';
import os from 'node:os';
const require = createRequire(import.meta.url);
const {ResidentProver, IndexedMerkleTree} = require('../../bindings/node/index.js');
const [configPath, outputPath] = process.argv.slice(2);
const artifacts = JSON.parse(await readFile(configPath, 'utf8'));
const config = artifacts.find(c => c.notes === 10);
assert.ok(config, '10-note production fixture is required');
const threads = Number(process.env.CURVY_BENCH_THREADS || 13);
const prover = await ResidentProver.create({zkeyPath:config.zkey, zkeySha256:config.zkey_sha256,
  witnessGraphPath:config.graph, witnessGraphSha256:config.graph_sha256, threads, maxPendingProofs:8});
const input = new IndexedMerkleTree(30, '[]').buildPendingCommitment(10, '["1"]');
const modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const expected = [(BigInt(input.inputHash) % modulus).toString()];
const prove = async () => {
  const started = performance.now();
  const proof = await prover.prove(input.circuitInputJson);
  assert.deepEqual(JSON.parse(proof.publicSignalsJson), expected);
  return {responseMs: performance.now()-started, serviceMs: proof.witnessCalculationMs+proof.proofGenerationMs};
};
await prove();
const report = {platform:os.platform(), architecture:os.arch(), node:process.version, threads, notes:10,
  zkeySha256:config.zkey_sha256, graphSha256:config.graph_sha256, selfVerified:true, runs:[]};
const summary = values => {
  const sorted = values.toSorted((a,b)=>a-b);
  return {medianMs:(sorted[Math.floor((sorted.length-1)/2)]+sorted[Math.floor(sorted.length/2)])/2,
    p95Ms:sorted[Math.ceil(sorted.length*.95)-1]};
};
for (const concurrency of [1,2,4,8]) {
  const samples = [];
  const start = performance.now();
  for (let i=0; i<32/concurrency; i++) samples.push(...await Promise.all(Array.from({length:concurrency}, prove)));
  const elapsedMs = performance.now()-start;
  const run = {concurrency, samples, elapsedMs, proofsPerSecond: samples.length*1000/elapsedMs,
    response:summary(samples.map(s=>s.responseMs)),service:summary(samples.map(s=>s.serviceMs))};
  report.runs.push(run);
  await writeFile(outputPath, JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({concurrency, response:run.response, service:run.service, proofsPerSecond:run.proofsPerSecond}));
}
