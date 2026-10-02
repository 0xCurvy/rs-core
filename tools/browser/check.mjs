// CI driver. The interactive local check uses the Browser skill's live browser.
//
// Usage: node tools/browser/check.mjs [threaded] [portable]
//
// `threaded` proves with crates/prover/pkg-web-threads (scripts/build.sh
// wasm-web-threads) on two Rayon workers; `portable` proves with
// crates/prover/pkg-web (scripts/build.sh wasm-web). With no argument both run,
// so both packages must already be built. CURVY_BROWSER_PKG_WEB and
// CURVY_BROWSER_PKG_WEB_THREADS substitute other prover package directories.
// CURVY_BROWSER_ENGINES picks the browsers (default chromium,firefox; webkit
// also works, after `npx --prefix tools/browser playwright install webkit`).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import { chromium, firefox, webkit } from 'playwright';
const port = 8127;
const origin = `http://127.0.0.1:${port}`;
const modes = process.argv.slice(2).flatMap(arg => arg.split(',')).filter(Boolean);
if (!modes.length) modes.push('threaded', 'portable');
for (const mode of modes) assert.ok(['threaded', 'portable'].includes(mode), `unknown mode ${mode} (use threaded or portable)`);
const expectedThreads = {threaded: 2, portable: 1};
const server = process.env.CURVY_BROWSER_EXTERNAL_SERVER ? null : spawn(process.execPath, ['tools/browser/serve.mjs'], { stdio: ['ignore', 'pipe', 'inherit'], env: {...process.env, PORT: String(port)} });
try {
  if (server) await new Promise((resolve, reject) => { server.stdout.once('data', resolve); server.once('error', reject); server.once('exit', code => reject(new Error(`server exited: ${code}`))); });
  const status = (headers, method = 'GET') => new Promise((resolve, reject) => {
    const req = request(`${origin}/tools/browser/proof-check.html`, { headers, method }, response => {
      response.resume(); resolve(response.statusCode);
    });
    req.on('error', reject).end();
  });
  for (const headers of [{ Host: 'attacker.invalid' }, { Origin: 'https://attacker.invalid' }]) {
    assert.equal(await status(headers), 403);
  }
  assert.equal(await status({}, 'POST'), 405);
  const engines = process.env.CURVY_BROWSER_ENGINES?.split(',') || ['chromium', 'firefox'];
  for (const name of engines) {
    const engine = {chromium, firefox, webkit}[name];
    assert.ok(engine, `unknown browser ${name}`);
    const browser = await engine.launch({headless: true});
    try {
      for (const mode of modes) {
        const page = await browser.newPage();
        try {
          const errors = [];
          page.on('pageerror', error => { errors.push(String(error)); console.error(error); });
          page.on('console', message => console.error(`browser ${message.type()}: ${message.text()}`));
          page.on('requestfailed', request => console.error(`request failed: ${request.url()} ${request.failure()?.errorText}`));
          const query = new URLSearchParams({mode});
          if (mode === 'threaded') query.set('threads', String(expectedThreads.threaded));
          await page.goto(`${origin}/tools/browser/proof-check.html?${query}`);
          await page.getByRole('button', {name: 'Run proof checks'}).click();
          try {
            await page.waitForFunction(() => !!document.querySelector('#result').dataset.state, undefined, {timeout: 120000});
          } catch (error) {
            console.error('Last browser state:', await page.locator('#result').innerText({timeout: 5000}).catch(String));
            throw error;
          }
          const report = JSON.parse(await page.locator('#result').innerText());
          assert.equal(report.passed, true, JSON.stringify(report));
          assert.equal(report.mode, mode);
          assert.equal(report.threads, expectedThreads[mode]);
          assert.equal(report.selfVerified, true);
          assert.deepEqual(report.publicSignals, ['33']);
          assert.deepEqual(errors, []);
          console.log(JSON.stringify({browser: name, ...report}));
        } finally { await page.close(); }
      }
    } finally { await browser.close(); }
  }
} finally { server?.kill(); }
