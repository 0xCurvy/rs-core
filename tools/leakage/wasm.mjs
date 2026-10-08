import { createHash, randomBytes } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { cpus } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(here, '../browser/package.json'));
const playwright = require('playwright');
const [output, requested = '100000', ...selected] = process.argv.slice(2);
if (!output || !/^\d+$/.test(requested) || +requested < 30000 || +requested > 10000000) {
  throw new Error('usage: node tools/leakage/wasm.mjs OUTPUT [SAMPLES] [chromium firefox webkit] [--seconds-per-case=N] [--cases=CASE,...]');
}
const budgets = selected.filter(value => value.startsWith('--seconds-per-case='));
if (budgets.length > 1 || budgets.some(value => !/^--seconds-per-case=[1-9]\d{0,3}$/.test(value))) {
  throw new Error('seconds-per-case must be a positive integer below 10000');
}
const secondsPerCase = budgets.length ? Number(budgets[0].split('=')[1]) : null;
const caseOptions = selected.filter(value => value.startsWith('--cases='));
if (caseOptions.length > 1) throw new Error('provide --cases once');
const selectedCases = caseOptions.length ? caseOptions[0].slice('--cases='.length).split(',') : null;
if (selectedCases?.some(name => !/^[a-z_]+$/.test(name))) throw new Error('invalid case name');
const selectedEngines = selected.filter(value => !budgets.includes(value) && !caseOptions.includes(value));
const engines = selectedEngines.length ? selectedEngines : ['chromium', 'firefox'];
if (engines.some(name => !['chromium', 'firefox', 'webkit'].includes(name))) throw new Error('invalid engine');
const out = resolve(output);
await mkdir(dirname(out), { recursive: true });
await mkdir(out, { recursive: false });
const token = randomBytes(16).toString('hex');
const files = new Map([
  [`/${token}/`, { body: Buffer.from('<!doctype html><title>Curvy leakage assessment</title>'), type: 'text/html' }],
  [`/${token}/curvy_leakage.js`, { body: await readFile(join(here, 'pkg/curvy_leakage.js')), type: 'text/javascript' }],
  [`/${token}/curvy_leakage_bg.wasm`, { body: await readFile(join(here, 'pkg/curvy_leakage_bg.wasm')), type: 'application/wasm' }],
]);
const server = createServer((req, res) => {
  const file = files.get(req.url);
  if (req.method !== 'GET' || !file || req.headers.host !== `127.0.0.1:${server.address().port}`) {
    res.writeHead(404).end(); return;
  }
  res.writeHead(200, { 'Content-Type': file.type, 'Cache-Control': 'no-store',
    'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' }).end(file.body);
});
await new Promise(accept => server.listen(0, '127.0.0.1', accept));
const url = `http://127.0.0.1:${server.address().port}/${token}/`;
const report = { node: process.version, platform: process.platform, architecture: process.arch,
  cpu: cpus()[0]?.model,
  harnessSha256: createHash('sha256').update(await readFile(fileURLToPath(import.meta.url))).digest('hex'),
  wasmSha256: createHash('sha256').update(files.get(`/${token}/curvy_leakage_bg.wasm`).body).digest('hex'),
  warmupSamplesPerCase: 2000,
  secondsPerCase,
  selectedCases,
  minimumSamplesPerCase: 1024,
  scope: 'Best-effort engine timing; first-order Welch test only; not the full native dudect suite.', engines: [] };
let failed = false;
try {
  for (const name of engines) {
    const browser = await playwright[name].launch({ headless: true });
    try {
      const page = await browser.newPage();
      const engineResult = { name, version: browser.version(), status: 'running', results: [] };
      report.engines.push(engineResult);
      await page.exposeFunction('recordLeakageCase', async item => {
        engineResult.results.push(item);
        await writeFile(join(out, 'validation.json'), `${JSON.stringify(report, null, 2)}\n`);
        console.log(name, item.case, item.family, item.status);
      });
      await page.goto(url);
      const result = await page.evaluate(async ({ url, samples, secondsPerCase, selectedCases }) => {
        const wasm = await import(`${url}curvy_leakage.js`);
        await wasm.default();
        const names = wasm.caseNames();
        const operations = [...new Set(['control', ...(selectedCases ?? names.filter(name => name !== 'poseidon_vartime'))])]
          .map(name => {
            const index = names.indexOf(name);
            if (index < 0) throw new Error(`unknown leakage case: ${name}`);
            return index;
          });
        let state = 0x12345678;
        const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
        let minimumTick = Infinity;
        for (let i = 0; i < 10000; i++) {
          const start = performance.now();
          const delta = performance.now() - start;
          if (delta > 0) minimumTick = Math.min(minimumTick, delta);
        }
        const results = [];
        for (const operation of operations) {
          for (const family of ['fixed-random', 'sparse-dense']) {
            const input = new Uint8Array(samples * 96);
            const classes = new Uint8Array(samples);
            for (let i = 0; i < samples; i++) {
              classes[i] = random() & 1;
              const bytes = input.subarray(i * 96, i * 96 + 96);
              for (let j = 0; j < 96; j++) bytes[j] = random() & 255;
              if (family === 'sparse-dense') bytes.fill(classes[i] ? 255 : 0);
              else if (!classes[i]) bytes.fill(0x42);
              bytes[31] = (bytes[31] & 1) | 2;
              bytes[63] &= 127;
              if (operation === 8 || operation === 11) bytes[0] &= 31;
              if (operation === 9 || operation === 10) {
                for (let j = 0; j < 78; j++) bytes[j] = 48 + bytes[j] % 10;
                bytes[0] = bytes[1] = 48;
              }
            }
            for (let i = 0; i < 2000; i++) wasm.runCase(operation, input.subarray(i * 96, i * 96 + 96));
            const distributions = [{ n: 0, mean: 0, m2: 0 }, { n: 0, mean: 0, m2: 0 }];
            const measurementStarted = performance.now();
            let measured = 0;
            let sink = 0;
            for (let i = 0; i < samples; i++) {
              const bytes = input.subarray(i * 96, i * 96 + 96);
              const start = performance.now();
              const value = wasm.runCase(operation, bytes);
              const elapsed = performance.now() - start;
              sink ^= value[0];
              const group = distributions[classes[i]];
              group.n++;
              const delta = elapsed - group.mean;
              group.mean += delta / group.n;
              group.m2 += delta * (elapsed - group.mean);
              measured++;
              if (secondsPerCase !== null && measured >= 1024 && measured % 256 === 0
                  && performance.now() - measurementStarted >= secondsPerCase * 1000) break;
            }
            const [a, b] = distributions;
            const t = (a.mean - b.mean) / Math.sqrt(a.m2 / (a.n - 1) / a.n + b.m2 / (b.n - 1) / b.n);
            const status = !Number.isFinite(t) || a.n < 400 || b.n < 400 ? 'inconclusive' : Math.abs(t) > 10 ? 'timing_difference_detected' : 'no_timing_difference_detected';
            const item = { case: names[operation], family, requestedSamples: samples, samples: measured,
              stoppedByTimeBudget: measured < samples, t, status, distributions, sink };
            results.push(item);
            await window.recordLeakageCase(item);
            if (operation === 0 && status !== 'timing_difference_detected') {
              return { validControl: false, results, minimumTick, userAgent: navigator.userAgent };
            }
          }
        }
        return { validControl: true, results, minimumTick, userAgent: navigator.userAgent, crossOriginIsolated };
      }, { url, samples: +requested, secondsPerCase, selectedCases });
      Object.assign(engineResult, result, { status: 'completed' });
      failed ||= !result.validControl;
      await writeFile(join(out, 'validation.json'), `${JSON.stringify(report, null, 2)}\n`);
      console.log(name, result.validControl ? 'control detected; assessment recorded' : 'control not detected; assessment invalid');
    } finally { await browser.close(); }
  }
} finally { await new Promise(accept => server.close(accept)); }
if (failed) process.exitCode = 1;
