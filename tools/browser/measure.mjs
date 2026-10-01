// Usage: node tools/browser/measure.mjs OUTPUT_JSON [SCENARIOS]
//
// Default: measures the in-tree packages through an already running
// `serve.mjs ARTIFACTS_JSON` on port 8127, once per scenario and mode in
// CURVY_BROWSER_MODES (default portable,threaded).
//
// Build comparison: CURVY_BROWSER_BUILDS=label=mode:DIR[,label=mode:DIR...]
// names prover package directories (for example scripts/build-wasm.sh output
// written under CURVY_WASM_OUT_DIR). This script then starts one serve.mjs per
// build with CURVY_BROWSER_ARTIFACTS and that build's package override, and
// alternates the builds (ABBA order) in each of CURVY_BROWSER_ROUNDS rounds.
//
// Every run uses a fresh Chromium process tree, one warm-up proof, and
// CURVY_BROWSER_SAMPLES (default 5) measured proofs on CURVY_BROWSER_THREADS
// (default 4) workers in threaded mode.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {execFile, spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import {chromium} from 'playwright';
const exec = promisify(execFile);
const [output, scenarios = '2'] = process.argv.slice(2);
assert.ok(output, 'usage: node tools/browser/measure.mjs OUTPUT_JSON [SCENARIOS]');
const integer = (name, fallback, max) => {
  const value = Number(process.env[name] || fallback);
  assert.ok(Number.isInteger(value) && value >= 1 && value <= max, `${name} must be an integer in 1..${max}`);
  return value;
};
const rounds = integer('CURVY_BROWSER_ROUNDS', 1, 100);
const samples = integer('CURVY_BROWSER_SAMPLES', 5, 30);
const threads = integer('CURVY_BROWSER_THREADS', 4, 16);
const packageEnv = {portable: 'CURVY_BROWSER_PKG_WEB', threaded: 'CURVY_BROWSER_PKG_WEB_THREADS'};
const packageUrl = {portable: '/crates/prover/pkg-web/', threaded: '/crates/prover/pkg-web-threads/'};
const builds = process.env.CURVY_BROWSER_BUILDS
  ? process.env.CURVY_BROWSER_BUILDS.split(',').map((entry, index) => {
    const match = /^([^=]+)=(portable|threaded):(.+)$/.exec(entry);
    assert.ok(match, `invalid CURVY_BROWSER_BUILDS entry ${entry} (use label=portable|threaded:DIR)`);
    return {label: match[1], mode: match[2], dir: match[3], port: 8127 + index};
  })
  : (process.env.CURVY_BROWSER_MODES || 'portable,threaded').split(',').map(mode => ({label: mode, mode, dir: null, port: 8127}));
assert.ok(!process.env.CURVY_BROWSER_BUILDS || process.env.CURVY_BROWSER_ARTIFACTS,
  'CURVY_BROWSER_BUILDS requires CURVY_BROWSER_ARTIFACTS (the serve.mjs benchmark case file)');
const report = {platform:os.platform(), architecture:os.arch(), cpus:os.cpus().length, loadAverageAtStart:os.loadavg(),
  warmup:1, samplesPerRun:samples, rounds, threads,
  buildProfile:process.env.CURVY_BROWSER_BUILD_PROFILE || (process.env.CURVY_BROWSER_BUILDS ? 'see builds' : 'portable release / threaded release (scripts/build.sh wasm-web, wasm-web-threads)'),
  rssMethod:'50 ms samples of summed RSS for this isolated Chromium process tree; shared pages are counted per process, so this is not unique physical memory',
  builds:[], runs:[], summary:[]};
const servers = [];
const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted.length % 2 ? sorted[(sorted.length - 1) / 2] : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
};
const MiB = 1024 ** 2;
const summarize = () => {
  const summary = [];
  for (const scenario of new Set(report.runs.map(run => run.scenario))) {
    let reference;
    for (const build of builds) {
      const runs = report.runs.filter(run => run.scenario === scenario && run.build === build.label);
      if (!runs.length) continue;
      const row = {scenario, build: build.label, mode: build.mode, runs: runs.length,
        proofs: runs.reduce((n, run) => n + run.proofMs.length, 0),
        medianProofMs: median(runs.flatMap(run => run.proofMs)),
        runMedianProofMs: {min: Math.min(...runs.map(run => run.medianMs)), median: median(runs.map(run => run.medianMs)), max: Math.max(...runs.map(run => run.medianMs))},
        medianInitMs: median(runs.map(run => run.initMs)),
        medianParseMs: median(runs.map(run => run.parseMs)),
        medianLoadMs: median(runs.map(run => run.loadMs)),
        medianPeakAggregateRssMiB: median(runs.map(run => run.peakAggregateRssBytes)) / MiB,
        maxPeakAggregateRssMiB: Math.max(...runs.map(run => run.peakAggregateRssBytes)) / MiB,
        medianPeakAboveBaselineRssMiB: median(runs.map(run => run.peakAggregateRssBytes - run.baselineRssBytes)) / MiB,
        medianWasmMemoryPeakMiB: median(runs.map(run => run.wasmMemoryPeakBytes)) / MiB};
      if (!reference) reference = row;
      else {
        const change = key => 100 * (row[key] / reference[key] - 1);
        row.changeVs = {build: reference.build,
          medianProofPercent: change('medianProofMs'), medianInitPercent: change('medianInitMs'),
          medianParsePercent: change('medianParseMs'), medianPeakAggregateRssPercent: change('medianPeakAggregateRssMiB'),
          medianPeakAboveBaselineRssPercent: change('medianPeakAboveBaselineRssMiB'), medianWasmMemoryPeakPercent: change('medianWasmMemoryPeakMiB')};
      }
      summary.push(row);
    }
  }
  return summary;
};
const sha256 = async (port, url) => createHash('sha256').update(Buffer.from(await (await fetch(`http://127.0.0.1:${port}${url}`)).arrayBuffer())).digest('hex');
try {
  if (process.env.CURVY_BROWSER_BUILDS) {
    for (const build of builds) {
      const server = spawn(process.execPath, [fileURLToPath(new URL('./serve.mjs', import.meta.url)), process.env.CURVY_BROWSER_ARTIFACTS],
        {stdio: ['ignore', 'pipe', 'inherit'], env: {...process.env, PORT: String(build.port), [packageEnv[build.mode]]: build.dir}});
      servers.push(server);
      await new Promise((resolve, reject) => { server.stdout.once('data', resolve); server.once('error', reject); server.once('exit', code => reject(new Error(`server exited: ${code}`))); });
    }
  }
  for (const build of builds) {
    report.builds.push({label: build.label, mode: build.mode, packageDir: build.dir || `in-tree ${packageUrl[build.mode]}`,
      proverWasmSha256: await sha256(build.port, `${packageUrl[build.mode]}curvy_prover_bg.wasm`)});
  }
  for (let round = 0; round < rounds; round++) {
    for (const scenario of scenarios.split(',')) {
      for (const build of round % 2 ? [...builds].reverse() : builds) {
        const browser = await chromium.launch({headless:true});
        let interval;
        try {
          const cdp = await browser.newBrowserCDPSession();
          let peakRssBytes = 0, rssSamples = 0, polling = false;
          const poll = async () => {
            if (polling) return;
            polling = true;
            try {
              const {processInfo} = await cdp.send('SystemInfo.getProcessInfo');
              const ids = processInfo.map(p=>p.id).filter(Number.isSafeInteger);
              const {stdout} = await exec('ps',['-o','rss=','-p',ids.join(',')]);
              const rss = stdout.trim().split(/\s+/).reduce((sum,n)=>sum+Number(n)*1024,0);
              peakRssBytes = Math.max(peakRssBytes,rss);
              rssSamples++;
            } finally { polling = false; }
          };
          const page = await browser.newPage();
          await page.goto(`http://127.0.0.1:${build.port}/tools/browser/proof-check.html?scenario=${scenario}&mode=${build.mode}&threads=${threads}&samples=${samples}`);
          await poll();
          const baselineRssBytes = peakRssBytes;
          interval = setInterval(()=>poll().catch(()=>{}),50);
          await page.getByRole('button',{name:'Run proof checks'}).click();
          await page.waitForFunction(()=>!!document.querySelector('#result').dataset.state,undefined,{timeout:600000});
          const run = JSON.parse(await page.locator('#result').innerText());
          assert.equal(run.passed,true,JSON.stringify(run));
          clearInterval(interval);
          await poll();
          report.runs.push({build:build.label,round,...run,browserVersion:await browser.version(),baselineRssBytes,peakAggregateRssBytes:peakRssBytes,rssSamples,loadAverage:os.loadavg()});
          report.summary = summarize();
          await writeFile(output,JSON.stringify(report,null,2)+'\n');
          console.log(JSON.stringify({round,scenario,build:build.label,mode:build.mode,medianMs:run.medianMs,initMs:run.initMs,parseMs:run.parseMs,
            peakAggregateRssMiB:peakRssBytes/MiB,wasmMemoryPeakMiB:run.wasmMemoryPeakBytes/MiB}));
        } finally { clearInterval(interval); await browser.close(); }
      }
    }
  }
  console.table(report.summary.map(({runMedianProofMs, changeVs, ...row}) => ({...row,
    proofChangePercent: changeVs?.medianProofPercent, peakRssChangePercent: changeVs?.medianPeakAggregateRssPercent,
    peakAboveBaselineChangePercent: changeVs?.medianPeakAboveBaselineRssPercent, wasmMemoryChangePercent: changeVs?.medianWasmMemoryPeakPercent})));
} finally { for (const server of servers) server.kill(); }
