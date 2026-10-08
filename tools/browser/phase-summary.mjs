#!/usr/bin/env node
// Median phase breakdown of tools/browser/measure.mjs output from `--bench`
// builds, whose runs carry `phases` (crates/prover/src/phase_timing.rs).
//
//   node tools/browser/phase-summary.mjs OUT.json [...]
//
// Per build, mode and circuit: the load spans with the remainder of parseMs
// (copying the artifacts into WASM memory), and each proof span with its share
// of the median proof. Nested spans are included in their parents
// (load.zkey contains load.sha256; proof.prove contains proof.qap and the
// MSMs).
import { readFileSync } from 'node:fs';

const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted.length ? sorted[Math.floor(sorted.length / 2)] : 0;
};
const merged = spans => {
  const out = {};
  for (const [name, ms] of spans) out[name] = (out[name] ?? 0) + ms;
  return out;
};

for (const path of process.argv.slice(2)) {
  const report = JSON.parse(readFileSync(path, 'utf8'));
  const groups = new Map();
  for (const run of report.runs.filter(run => run.phases)) {
    const key = `${run.scenario} notes, ${run.build} ${run.mode}, ${run.threads} thread(s)`;
    if (!groups.has(key)) groups.set(key, { load: [], proof: [], parse: [], total: [] });
    const group = groups.get(key);
    group.load.push(merged(run.phases.load));
    group.parse.push(run.parseMs);
    group.proof.push(...run.phases.proofs.map(merged));
    group.total.push(...run.proofMs);
  }
  for (const [key, group] of groups) {
    const parse = median(group.parse);
    const total = median(group.total);
    const names = rows => [...new Set(rows.flatMap(Object.keys))];
    const load = Object.fromEntries(names(group.load).map(name => [name, median(group.load.map(row => row[name] ?? 0))]));
    load['load.copy_and_other'] = parse - (load['load.zkey'] ?? 0) - (load['load.graph'] ?? 0);
    const proof = Object.fromEntries(names(group.proof).map(name => [name, median(group.proof.map(row => row[name] ?? 0))]));
    console.log(`\n## ${key}: parse ${parse.toFixed(0)} ms, proof ${total.toFixed(0)} ms (${group.total.length} proofs)`);
    console.log('  ' + Object.entries(load).map(([name, ms]) => `${name.slice(5)} ${ms.toFixed(0)}`).join(', '));
    console.log('  ' + Object.entries(proof).map(([name, ms]) => `${name.slice(6)} ${ms.toFixed(0)} (${(100 * ms / total).toFixed(0)}%)`).join(', '));
  }
}
