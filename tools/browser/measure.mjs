// Usage: node tools/browser/measure.mjs OUTPUT_JSON [SCENARIOS]
// Requires serve.mjs with a production artifact configuration on port 8127.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import os from 'node:os';
import {chromium} from 'playwright';
const exec = promisify(execFile);
const [output, scenarios = '2'] = process.argv.slice(2);
const report = {platform:os.platform(), architecture:os.arch(), warmup:1,
  buildProfile:process.env.CURVY_BROWSER_BUILD_PROFILE || 'portable release / threaded release (scripts/build.sh wasm-web, wasm-web-threads)',
  rssMethod:'50 ms samples of summed RSS for this isolated Chromium process tree; shared pages are counted per process, so this is not unique physical memory', runs:[]};
for (const scenario of scenarios.split(',')) {
  for (const mode of (process.env.CURVY_BROWSER_MODES || 'portable,threaded').split(',')) {
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
      await page.goto(`http://127.0.0.1:8127/tools/browser/proof-check.html?scenario=${scenario}&mode=${mode}&threads=4&samples=5`);
      await poll();
      const baselineRssBytes = peakRssBytes;
      interval = setInterval(()=>poll().catch(()=>{}),50);
      await page.getByRole('button',{name:'Run proof checks'}).click();
      await page.waitForFunction(()=>!!document.querySelector('#result').dataset.state,undefined,{timeout:240000});
      const run = JSON.parse(await page.locator('#result').innerText());
      assert.equal(run.passed,true,JSON.stringify(run));
      await poll();
      report.runs.push({...run,browserVersion:await browser.version(),baselineRssBytes,peakAggregateRssBytes:peakRssBytes,rssSamples});
      await writeFile(output,JSON.stringify(report,null,2)+'\n');
      console.log(JSON.stringify({scenario,mode,medianMs:run.medianMs,p95Ms:run.p95Ms,peakAggregateRssMiB:peakRssBytes/1024**2}));
    } finally { clearInterval(interval); await browser.close(); }
  }
}
