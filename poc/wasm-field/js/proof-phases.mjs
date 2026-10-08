// Amdahl input: phase times of real portable WASM proofs (production 2/5/10-note
// keys) from an instrumented copy of the repository (phase timers only; see
// README). Every proof self-verifies inside prove() and its public signals are
// checked against the case file.
//
// Usage: node js/proof-phases.mjs node|chromium PKG_WEB_DIR CASES_JSON NOTES SAMPLES
// PKG_WEB_DIR: the instrumented `scripts/build-wasm.sh web` prover package.
import {createServer} from 'node:http';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const [engine, pkg, casesPath, notesArg, samplesArg] = process.argv.slice(2);
const notes = notesArg.split(',').map(Number);
const samples = Number(samplesArg || 5);
const cases = JSON.parse(await readFile(casesPath, 'utf8'));
const PHASES = ['witness', 'prove', 'witnessMap', 'msmG1', 'msmG2', 'verify', 'g1Points', 'g2Points', 'g1Calls', 'g2Calls'];

// Runs in Node or in the page: one warm-up proof, then `samples` measured ones.
async function measure(wasm, zkey, graph, data, samples) {
  const parseStarted = performance.now();
  const prover = new wasm.WasmResidentProver(zkey, data.zkeySha256, graph, data.graphSha256);
  const parseMs = performance.now() - parseStarted;
  const runs = [];
  try {
    for (let i = 0; i <= samples; i++) {
      wasm.phaseTimings();
      wasm.msmCalls();
      const started = performance.now();
      const bundle = JSON.parse(prover.prove(JSON.stringify(data.input)));
      const totalMs = performance.now() - started;
      if (JSON.stringify(bundle.publicSignals) !== JSON.stringify(data.expectedPublics)) throw new Error('public signals mismatch');
      if (i) runs.push({totalMs, phases: Array.from(wasm.phaseTimings()), msmCalls: Array.from(wasm.msmCalls())});
    }
  } finally { prover.free(); }
  return {parseMs, runs};
}

function summarize(runs) {
  const median = v => { const s = [...v].sort((a, b) => a - b); return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2; };
  const out = {totalMs: median(runs.map(r => r.totalMs))};
  PHASES.forEach((name, i) => { out[name] = median(runs.map(r => r.phases[i])); });
  out.msmShare = median(runs.map(r => (r.phases[3] + r.phases[4]) / r.totalMs));
  out.msmG1Share = median(runs.map(r => r.phases[3] / r.totalMs));
  out.msmG2Share = median(runs.map(r => r.phases[4] / r.totalMs));
  return out;
}

const report = {engine: '', samples, results: []};
if (engine === 'node') {
  // The web target is an ES module; give Node a module-typed copy of its JS.
  const moduleCopy = path.join(pkg, 'curvy_prover.node-esm.mjs');
  await writeFile(moduleCopy, await readFile(path.join(pkg, 'curvy_prover.js')));
  const wasm = await import(pathToFileURL(moduleCopy));
  wasm.initSync({module: await readFile(path.join(pkg, 'curvy_prover_bg.wasm'))});
  report.engine = `node ${process.version}`;
  for (const n of notes) {
    const data = cases.find(c => c.notes === n);
    const [zkey, graph] = await Promise.all([readFile(data.zkeyPath), readFile(data.graphPath)]);
    const result = await measure(wasm, new Uint8Array(zkey), new Uint8Array(graph), data, samples);
    report.results.push({notes: n, parseMs: result.parseMs, ...summarize(result.runs), runs: result.runs});
    console.error(JSON.stringify({notes: n, ...summarize(result.runs)}));
  }
} else {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.resolve(here, '../../..');
  const {chromium} = await import(path.join(repo, 'tools/browser/node_modules/playwright/index.mjs'));
  const scratch = process.env.WASM_FIELD_SCRATCH || path.join(repo, 'target/claude-scratch/wasm-field');
  const files = new Map();
  for (const c of cases) {
    files.set(`/case/${c.notes}.zkey`, c.zkeyPath);
    files.set(`/case/${c.notes}.graph`, c.graphPath);
  }
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const headers = {'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp'};
    try {
      if (url.pathname.startsWith('/pkg/')) {
        const file = path.join(pkg, path.basename(url.pathname));
        res.writeHead(200, {...headers, 'Content-Type': file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript'});
        return res.end(await readFile(file));
      }
      if (files.has(url.pathname)) {
        res.writeHead(200, {...headers, 'Content-Type': 'application/octet-stream'});
        return res.end(await readFile(files.get(url.pathname)));
      }
      res.writeHead(200, {...headers, 'Content-Type': 'text/html'});
      res.end('<!doctype html><title>proof phases</title>');
    } catch (error) { res.writeHead(500); res.end(String(error)); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const n of notes) {
      // A fresh browser process tree per circuit, as tools/browser/measure.mjs.
      const profile = await mkdtemp(path.join(scratch, 'chromium-profile-'));
      const context = await chromium.launchPersistentContext(profile, {headless: true});
      try {
        const page = context.pages()[0] || await context.newPage();
        await page.goto(`${origin}/`);
        const data = cases.find(c => c.notes === n);
        const result = await page.evaluate(async ([source, data, samples]) => {
          const wasm = await import('/pkg/curvy_prover.js');
          await wasm.default({module_or_path: '/pkg/curvy_prover_bg.wasm'});
          const bytes = async url => new Uint8Array(await (await fetch(url)).arrayBuffer());
          const [zkey, graph] = await Promise.all([bytes(`/case/${data.notes}.zkey`), bytes(`/case/${data.notes}.graph`)]);
          const measure = new Function(`return (${source})`)();
          return measure(wasm, zkey, graph, data, samples);
        }, [measure.toString(), {notes: data.notes, zkeySha256: data.zkeySha256, graphSha256: data.graphSha256, input: data.input, expectedPublics: data.expectedPublics}, samples]);
        report.engine = `chromium ${context.browser()?.version() ?? ''}`.trim();
        report.results.push({notes: n, parseMs: result.parseMs, ...summarize(result.runs), runs: result.runs});
        console.error(JSON.stringify({notes: n, ...summarize(result.runs)}));
      } finally {
        await context.close();
        await rm(profile, {recursive: true, force: true});
      }
    }
  } finally { server.close(); }
}
console.log(JSON.stringify(report));
