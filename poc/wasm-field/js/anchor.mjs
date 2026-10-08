// Experiment C (iii): time the production SPARROW G1 kernel through the
// phase-bench export of `scripts/build-wasm.sh {nodejs,web} --bench`
// (benchG1Msm: every base is the generator, scalars index * 0x9e3779b97f4a7c15 + 1).
//
// Usage: node js/anchor.mjs node     ANCHOR_DIR LOGS WIDTHS REPS
//        node js/anchor.mjs chromium ANCHOR_DIR LOGS WIDTHS REPS
// ANCHOR_DIR is the CURVY_WASM_OUT_DIR of the build (contains prover/pkg-node
// and prover/pkg-web). Prints one JSON line.
import {createRequire} from 'node:module';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const [engine, dir, logsArg, widthsArg, repsArg] = process.argv.slice(2);
const logs = logsArg.split(',').map(Number);
const widths = widthsArg.split(',').map(Number);
const reps = Number(repsArg || 3);

// Runs in Node or in the page: warm-up once per (log, width), then `reps` timed calls.
function sweep(bench, logs, widths, reps) {
  const rows = [];
  for (const log of logs) {
    for (const width of widths) {
      bench(log, width);
      const times = [];
      for (let i = 0; i < reps; i++) {
        const started = performance.now();
        bench(log, width);
        times.push(performance.now() - started);
      }
      times.sort((a, b) => a - b);
      rows.push({log, width, ms: times[Math.floor(times.length / 2)], minMs: times[0]});
    }
  }
  return rows;
}

let result;
if (engine === 'node') {
  const require = createRequire(import.meta.url);
  const wasm = require(path.resolve(dir, 'prover/pkg-node/curvy_prover.js'));
  result = {engine: `node ${process.version}`, rows: sweep(wasm.benchG1Msm, logs, widths, reps)};
} else {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.resolve(here, '../../..');
  const {chromium} = await import(path.join(repo, 'tools/browser/node_modules/playwright/index.mjs'));
  const scratch = process.env.WASM_FIELD_SCRATCH || path.join(repo, 'target/claude-scratch/wasm-field');
  const pkg = path.resolve(dir, 'prover/pkg-web');
  const profile = await mkdtemp(path.join(scratch, 'chromium-profile-'));
  const context = await chromium.launchPersistentContext(profile, {headless: true});
  try {
    const page = context.pages()[0] || await context.newPage();
    const headers = {'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp'};
    await page.route('http://poc.localhost/**', async route => {
      const name = new URL(route.request().url()).pathname.slice(1);
      if (name.startsWith('pkg/')) {
        const file = path.join(pkg, name.slice(4));
        const type = file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript';
        return route.fulfill({body: await readFile(file), contentType: type, headers});
      }
      return route.fulfill({body: '<!doctype html><title>anchor</title>', contentType: 'text/html', headers});
    });
    await page.goto('http://poc.localhost/');
    const rows = await page.evaluate(async ([source, logs, widths, reps]) => {
      const wasm = await import('/pkg/curvy_prover.js');
      await wasm.default({module_or_path: '/pkg/curvy_prover_bg.wasm'});
      const sweep = new Function(`return (${source})`)();
      return sweep(wasm.benchG1Msm, logs, widths, reps);
    }, [sweep.toString(), logs, widths, reps]);
    result = {engine: `chromium ${context.browser()?.version() ?? ''}`.trim(), rows};
  } finally {
    await context.close();
    await rm(profile, {recursive: true, force: true});
  }
}
console.log(JSON.stringify(result));
