// Usage: CURVY_BROWSER_ARTIFACTS=cases.json node tools/browser/sparrow-window.mjs OUTPUT_JSON [SCENARIOS]
//
// Sweeps fixed SPARROW MSM window widths in Chromium with one-pass manifest
// proofs (sparrow-window.html). Cases need manifestUrl, manifestPath and
// manifestSha256 in addition to the serve.mjs fields. Point
// CURVY_BROWSER_PKG_WEB / CURVY_BROWSER_PKG_WEB_THREADS at
// `scripts/build-wasm.sh web [--threads] --sparrow` prover packages.
//
// Each run is a fresh Chromium process tree for one mode and scenario: one
// warm-up proof, then CURVY_BROWSER_SAMPLES (default 2) proofs per width in
// CURVY_SPARROW_WIDTHS (default 11,12,13,14), rotated per sample and per round
// so every width sees each position equally often. CURVY_SPARROW_CHUNK sets
// the MSM chunk (default 65,536 points, the browser default).
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import {chromium} from 'playwright';
const [output, scenarios = '2'] = process.argv.slice(2);
assert.ok(output, 'usage: node tools/browser/sparrow-window.mjs OUTPUT_JSON [SCENARIOS]');
assert.ok(process.env.CURVY_BROWSER_ARTIFACTS, 'CURVY_BROWSER_ARTIFACTS (serve.mjs case file with manifests) is required');
const integer = (name, fallback, max) => {
  const value = Number(process.env[name] || fallback);
  assert.ok(Number.isInteger(value) && value >= 1 && value <= max, `${name} must be an integer in 1..${max}`);
  return value;
};
const rounds = integer('CURVY_BROWSER_ROUNDS', 1, 100);
const samples = integer('CURVY_BROWSER_SAMPLES', 2, 30);
const threads = integer('CURVY_BROWSER_THREADS', 4, 16);
const chunk = integer('CURVY_SPARROW_CHUNK', 65536, 1048576);
const widths = (process.env.CURVY_SPARROW_WIDTHS || '11,12,13,14').split(',').map(Number);
const modes = (process.env.CURVY_BROWSER_MODES || 'portable,threaded').split(',');
const port = Number(process.env.PORT || 8137);
const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted.length % 2 ? sorted[(sorted.length - 1) / 2] : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
};
const report = {platform: os.platform(), architecture: os.arch(), cpus: os.cpus().length, loadAverageAtStart: os.loadavg(),
  rounds, samplesPerWidthPerRun: samples, threads, chunkPoints: chunk, widths, runs: [], summary: []};
const summarize = () => report.summary = [...new Set(report.runs.map(run => `${run.mode}:${run.scenario}`))].flatMap(key => {
  const runs = report.runs.filter(run => `${run.mode}:${run.scenario}` === key);
  const rows = widths.map(width => {
    const proofs = runs.flatMap(run => run.runs.filter(r => r.width === width).map(r => r.proofMs));
    return {mode: runs[0].mode, scenario: runs[0].scenario, width, proofs: proofs.length, medianProofMs: median(proofs),
      minProofMs: Math.min(...proofs), maxProofMs: Math.max(...proofs)};
  });
  const reference = rows.find(row => row.width === 13) || rows[0];
  for (const row of rows) row.changeVsReferencePercent = 100 * (row.medianProofMs / reference.medianProofMs - 1);
  return rows;
});
const server = spawn(process.execPath, [fileURLToPath(new URL('./serve.mjs', import.meta.url)), process.env.CURVY_BROWSER_ARTIFACTS],
  {stdio: ['ignore', 'pipe', 'inherit'], env: {...process.env, PORT: String(port)}});
try {
  await new Promise((resolve, reject) => { server.stdout.once('data', resolve); server.once('error', reject); server.once('exit', code => reject(new Error(`server exited: ${code}`))); });
  for (let round = 0; round < rounds; round++) {
    for (const scenario of scenarios.split(',')) {
      for (const mode of round % 2 ? [...modes].reverse() : modes) {
        const browser = await chromium.launch({headless: true});
        try {
          const page = await browser.newPage();
          await page.goto(`http://127.0.0.1:${port}/tools/browser/sparrow-window.html?scenario=${scenario}&mode=${mode}&threads=${threads}` +
            `&samples=${samples}&widths=${widths.join(',')}&offset=${round}&chunk=${chunk}`);
          await page.getByRole('button', {name: 'Run window sweep'}).click();
          await page.waitForFunction(() => !!document.querySelector('#result').dataset.state, undefined, {timeout: 1800000});
          const run = JSON.parse(await page.locator('#result').innerText());
          assert.equal(run.passed, true, JSON.stringify(run));
          report.runs.push({round, ...run, browserVersion: browser.version(), loadAverage: os.loadavg()});
          summarize();
          await writeFile(output, JSON.stringify(report, null, 2) + '\n');
          const byWidth = Object.fromEntries(widths.map(w => [w, median(run.runs.filter(r => r.width === w).map(r => r.proofMs))]));
          console.log(JSON.stringify({round, scenario, mode, compileMs: run.compileMs, warmupMs: run.warmupMs, medianByWidth: byWidth,
            wasmMemoryPeakMiB: run.wasmMemoryPeakBytes / 1024 ** 2}));
        } finally { await browser.close(); }
      }
    }
  }
  console.table(report.summary);
} finally { server.kill(); }
