// Usage: node js/chromium.mjs WASM_FILE COMMAND...   (prints the JSON result)
//
// Runs the command on the main thread of a headless Chromium page (Playwright
// from tools/browser). The page is served through request interception with
// COOP/COEP headers (cross-origin isolated, so performance.now() is not
// coarsened to 100 us). The browser profile lives under
// WASM_FIELD_SCRATCH (default: target/claude-scratch/wasm-field).
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../../..');
const {chromium} = await import(path.join(repo, 'tools/browser/node_modules/playwright/index.mjs'));
const scratch = process.env.WASM_FIELD_SCRATCH || path.join(repo, 'target/claude-scratch/wasm-field');

const [wasmPath, ...command] = process.argv.slice(2);
const wasm = await readFile(wasmPath);
const harness = await readFile(path.join(here, 'harness.mjs'));
const profile = await mkdtemp(path.join(scratch, 'chromium-profile-'));
const context = await chromium.launchPersistentContext(profile, {headless: true});
try {
  const page = context.pages()[0] || await context.newPage();
  const headers = {'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp'};
  await page.route('http://poc.localhost/**', route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/poc.wasm') return route.fulfill({body: wasm, contentType: 'application/wasm', headers});
    if (url.pathname === '/harness.mjs') return route.fulfill({body: harness, contentType: 'text/javascript', headers});
    return route.fulfill({body: '<!doctype html><title>wasm-field</title>', contentType: 'text/html', headers});
  });
  const logs = [];
  page.on('console', message => logs.push(message.text()));
  await page.goto('http://poc.localhost/');
  const result = await page.evaluate(async command => {
    const {createRunner} = await import('/harness.mjs');
    const bytes = await (await fetch('/poc.wasm')).arrayBuffer();
    const runner = await createRunner(bytes, message => console.error(message));
    const result = runner.run(command);
    result.crossOriginIsolated = self.crossOriginIsolated;
    return result;
  }, command.join(' ')).catch(error => {
    throw new Error(`${error.message}\n${logs.join('\n')}`);
  });
  result.engine = `chromium ${context.browser()?.version() ?? ''}`.trim();
  console.log(JSON.stringify(result));
} finally {
  await context.close();
  await rm(profile, {recursive: true, force: true});
}
