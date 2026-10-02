#!/usr/bin/env node
// Run the opt-in WASM SIMD features' differential self-tests, randomized
// stress rounds and relative kernel benchmark (curvy-prover
// `wasm-simd-selftest`; suite: tools/browser/simd-selftest-suite.mjs).
//
//   scripts/build-wasm.sh nodejs --sparrow --simd --simd-selftest
//   node scripts/simd-selftest.mjs                      # Node, portable build
//   node scripts/simd-selftest.mjs --stress 60          # plus 60 s of stress
//
//   scripts/build-wasm.sh web --threads --sparrow --simd --simd-selftest
//   node scripts/simd-selftest.mjs --engine chromium --mode threaded
//   node scripts/simd-selftest.mjs --engine webkit --mode portable
//
// Options:
//   --engine node|chromium|webkit|firefox  (default node)
//   --mode portable|threaded   browser package (default portable); Node runs
//                              only the portable nodejs build
//   --pkg DIR                  prover package (default crates/prover/pkg-node,
//                              or pkg-web / pkg-web-threads in a browser)
//   --threads N                threaded Rayon workers (default 2; the SIMD FFT
//                              runs only on pools of at most 4)
//   --seed N --seeds N         fixed-suite seeds N, N+1, ... (default 1, 3)
//   --stress SECONDS           time-bounded randomized stress (default 0)
//   --stress-seed N            first stress seed (default random, printed)
//   --bench-rounds N           SIMD vs arkworks MSM rounds (default 5; 0 skips)
//   --min-speedup X            fail below this median speedup (default 1.4)
//   --expect msm,sparrow,fft   self-tests the build must export (default all)
//   --repro KIND:SEED:ARG      rerun one failing call, as a failure prints it
//
// Why not cargo-fuzz: the SIMD kernels exist only for wasm32 with simd128
// (core::arch::wasm32 intrinsics, cfg-gated in curvy-prover), and cargo-fuzz
// drives native libFuzzer binaries, which never compile them. The stress
// mode is the substitute: random seeds pick sizes, widths, batch sizes,
// chunk sizes and adversarial base/scalar/field-value mixes, every result is
// compared with arkworks inside the real WASM module, and each failure prints
// the seed that reproduces it. It is randomized differential testing, not
// coverage-guided fuzzing.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { calls, defaults, runSuite } from '../tools/browser/simd-selftest-suite.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const flags = {};
for (let i = 0; i < args.length; i++) {
  const match = /^--([a-z-]+)$/.exec(args[i]);
  assert.ok(match && i + 1 < args.length, `bad argument ${args[i]} (see the header of scripts/simd-selftest.mjs)`);
  flags[match[1]] = args[++i];
}
const known = ['engine', 'mode', 'pkg', 'threads', 'seed', 'seeds', 'stress', 'stress-seed', 'bench-rounds', 'min-speedup', 'expect', 'repro', 'port'];
for (const key of Object.keys(flags)) assert.ok(known.includes(key), `unknown option --${key}`);
const number = (key, fallback) => {
  if (!(key in flags)) return fallback;
  const value = Number(flags[key]);
  assert.ok(Number.isFinite(value) && value >= 0, `--${key} must be a non-negative number`);
  return value;
};
const engine = flags.engine || 'node';
const mode = flags.mode || 'portable';
assert.ok(['node', 'chromium', 'webkit', 'firefox'].includes(engine), `unknown engine ${engine}`);
assert.ok(['portable', 'threaded'].includes(mode), `unknown mode ${mode}`);
assert.ok(engine !== 'node' || mode === 'portable', 'threaded builds need a browser engine (wasm-bindgen-rayon spawns Web Workers)');
const options = {
  seed: number('seed', defaults.seed),
  seeds: number('seeds', defaults.seeds),
  stressSeconds: number('stress', 0),
  stressSeed: 'stress-seed' in flags ? number('stress-seed') : null,
  benchRounds: number('bench-rounds', defaults.benchRounds),
  minSpeedup: number('min-speedup', defaults.minSpeedup),
  expect: flags.expect ? flags.expect.split(',').filter(Boolean) : defaults.expect,
};
let repro = null;
if (flags.repro) {
  const [kind, seed, arg] = flags.repro.split(':');
  assert.ok(kind in calls && seed && arg, `--repro takes KIND:SEED:ARG with KIND one of ${Object.keys(calls).join(', ')}`);
  repro = {kind, seed: Number(seed), arg: Number(arg)};
}

const print = report => {
  console.log(JSON.stringify(report));
  if (report.passed) console.log(`SIMD self-tests passed (${engine}, ${mode})`);
  else {
    console.error(`SIMD self-tests FAILED (${engine}, ${mode}): ${report.error}`);
    if (report.repro) console.error(`reproduce: node scripts/simd-selftest.mjs --engine ${engine} --mode ${mode} ${report.repro}`);
  }
  process.exitCode = report.passed ? 0 : 1;
};

if (engine === 'node') {
  const pkg = resolve(flags.pkg || resolve(root, 'crates/prover/pkg-node'));
  const wasm = createRequire(import.meta.url)(resolve(pkg, 'curvy_prover.js'));
  if (repro) {
    wasm.simdSelfTestInit?.();
    try {
      console.log(`${flags.repro}: ${calls[repro.kind](wasm, repro.seed, repro.arg)} compared`);
    } catch (error) {
      console.error(`${flags.repro} FAILED: ${error?.message ?? error} ${wasm.simdSelfTestPanic?.() ?? ''}`);
      process.exitCode = 1;
    }
  } else {
    print({engine, mode, pkg, ...await runSuite(wasm, options, line => console.log(line))});
  }
} else {
  assert.ok(!repro, '--repro runs under Node; use the browser page directly otherwise');
  const playwright = createRequire(resolve(root, 'tools/browser/package.json'))('playwright');
  const port = number('port', 8128);
  const env = {...process.env, PORT: String(port)};
  if (flags.pkg) env[mode === 'threaded' ? 'CURVY_BROWSER_PKG_WEB_THREADS' : 'CURVY_BROWSER_PKG_WEB'] = resolve(flags.pkg);
  const server = spawn(process.execPath, [resolve(root, 'tools/browser/serve.mjs')], {stdio: ['ignore', 'pipe', 'inherit'], env, cwd: root});
  try {
    await new Promise((resolveStart, reject) => {
      server.stdout.once('data', resolveStart);
      server.once('error', reject);
      server.once('exit', code => reject(new Error(`server exited: ${code}`)));
    });
    const browser = await playwright[engine].launch({headless: true});
    try {
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', error => { errors.push(String(error)); console.error(error); });
      page.on('console', message => console.log(`[${engine}] ${message.text()}`));
      const query = new URLSearchParams({mode, options: JSON.stringify(options), autorun: '1'});
      if (mode === 'threaded') query.set('threads', String(number('threads', 2)));
      await page.goto(`http://127.0.0.1:${port}/tools/browser/simd-selftest.html?${query}`);
      const timeout = (options.stressSeconds + 900) * 1000;
      await page.waitForFunction(() => !!document.querySelector('#result').dataset.state, undefined, {timeout, polling: 1000});
      const report = JSON.parse(await page.locator('#result').innerText());
      if (errors.length && report.passed) Object.assign(report, {passed: false, error: `page errors: ${errors.join('; ')}`});
      print({engine, browserVersion: browser.version(), ...report});
    } finally { await browser.close(); }
  } finally { server.kill(); }
}
