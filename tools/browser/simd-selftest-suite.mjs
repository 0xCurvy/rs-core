// The SIMD self-test suite, shared by scripts/simd-selftest.mjs (Node) and
// simd-selftest.html (browsers). `wasm` is an initialized curvy-prover module
// built with `--simd-selftest` (curvy-prover `wasm-simd-selftest`).
//
// 1. Fixed suite: simdMsmSelfTest, simdSparrowSelfTest and simdFftSelfTest,
//    each with `seeds` consecutive seeds from `seed`.
// 2. Stress (stressSeconds > 0): randomized differential rounds against
//    arkworks (simdFieldStress, simdMsmStress, simdFftStress) with
//    consecutive seeds from `stressSeed`, rotating kinds until the time budget
//    runs out. Every failure names the call that reproduces it.
// 3. Bench (benchRounds > 0): SimdMsmBench for G1 and G2, SIMD kernel and
//    arkworks batch-affine path timed alternately (ABBA) on one input in one
//    process; fails when the median per-round speedup is below minSpeedup.
//
// A failing self-test can trap (a Rust panic aborts), which may leave the
// module unusable, so the suite stops at the first failure.

export const defaults = {
  expect: ['msm', 'sparrow', 'fft'],
  seed: 1,
  seeds: 3,
  msmSize: 64,
  sparrowSize: 32,
  fftMinLog: 3,
  fftMaxLog: 12,
  stressSeconds: 0,
  stressSeed: null,
  stressMsmSize: 512,
  stressFftMaxLog: 14,
  stressFieldRounds: 50,
  benchRounds: 5,
  benchLog: 12,
  minSpeedup: 1.4,
};

const exportsFor = {
  msm: ['simdMsmSelfTest', 'simdFieldStress', 'simdMsmStress', 'SimdMsmBench'],
  sparrow: ['simdSparrowSelfTest'],
  fft: ['simdFftSelfTest', 'simdFftStress'],
};

// Let the page repaint and the driver poll between long synchronous calls.
const yieldNow = () => new Promise(resolve => setTimeout(resolve, 0));
const now = () => performance.now();
const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
};

/// One call by name, as the repro command names it.
export const calls = {
  msm: (wasm, seed, arg) => wasm.simdMsmSelfTest(arg, seed),
  sparrow: (wasm, seed, arg) => wasm.simdSparrowSelfTest(arg, seed),
  fft: (wasm, seed, arg) => wasm.simdFftSelfTest(3, arg, seed),
  'field-stress': (wasm, seed, arg) => wasm.simdFieldStress(seed, arg),
  'msm-stress': (wasm, seed, arg) => wasm.simdMsmStress(seed, arg),
  'fft-stress': (wasm, seed, arg) => wasm.simdFftStress(seed, arg),
};

export async function runSuite(wasm, options = {}, log = () => {}) {
  const o = {...defaults, ...options};
  const report = {passed: false, options: o, available: [], tests: [], stress: null, bench: []};
  const available = Object.keys(exportsFor).filter(kind => exportsFor[kind].every(name => name in wasm));
  report.available = available;
  let current = null;
  try {
    wasm.simdSelfTestInit?.();
    const missing = o.expect.filter(kind => !available.includes(kind));
    if (missing.length) throw new Error(`build lacks the ${missing.join(', ')} self-tests (exports ${missing.flatMap(k => exportsFor[k]).join(', ')}); build with --simd --sparrow --simd-selftest`);
    if (!available.length) throw new Error('no SIMD self-test exports; build with --simd-selftest');

    // 1. Fixed suite.
    const fixed = [
      ['msm', o.msmSize, 'simdMsmSelfTest'],
      ['sparrow', o.sparrowSize, 'simdSparrowSelfTest'],
      ['fft', o.fftMaxLog, 'simdFftSelfTest'],
    ].filter(([kind]) => available.includes(kind));
    for (const [kind, arg, name] of fixed) {
      for (let i = 0; i < o.seeds; i++) {
        const seed = (o.seed + i) >>> 0;
        current = {kind, seed, arg};
        await yieldNow();
        const started = now();
        const compared = kind === 'fft' ? wasm.simdFftSelfTest(o.fftMinLog, arg, seed) : calls[kind](wasm, seed, arg);
        const ms = now() - started;
        report.tests.push({name, seed, arg, compared, ms});
        log(`${name}(seed ${seed}, ${kind === 'fft' ? `2^${o.fftMinLog}..2^${arg}` : `size ${arg}`}): ${compared} compared in ${ms.toFixed(0)} ms`);
      }
    }

    // 2. Stress.
    if (o.stressSeconds > 0) {
      const kinds = [
        ['field-stress', o.stressFieldRounds, 'msm'],
        ['msm-stress', o.stressMsmSize, 'msm'],
        ['fft-stress', o.stressFftMaxLog, 'fft'],
      ].filter(([, , needs]) => available.includes(needs));
      const start = o.stressSeed ?? (Math.random() * 2 ** 32) >>> 0;
      const stress = {seconds: o.stressSeconds, startSeed: start, rounds: 0, byKind: {}};
      report.stress = stress;
      log(`stress: ${o.stressSeconds} s from seed ${start} (${kinds.map(([k]) => k).join(', ')})`);
      const deadline = now() + o.stressSeconds * 1000;
      for (let i = 0; now() < deadline; i++) {
        const [kind, arg] = kinds[i % kinds.length];
        const seed = (start + Math.floor(i / kinds.length)) >>> 0;
        current = {kind, seed, arg};
        if (i % 16 === 0) await yieldNow();
        const compared = calls[kind](wasm, seed, arg);
        const entry = stress.byKind[kind] ??= {rounds: 0, compared: 0};
        entry.rounds++;
        entry.compared += compared;
        stress.rounds++;
      }
      stress.lastSeed = (start + Math.floor((stress.rounds - 1) / kinds.length)) >>> 0;
      log(`stress: ${stress.rounds} rounds, seeds ${start}..${stress.lastSeed}: ${JSON.stringify(stress.byKind)}`);
    }

    // 3. Bench.
    if (o.benchRounds > 0 && available.includes('msm')) {
      for (const curve of [1, 2]) {
        current = {kind: 'bench', curve};
        await yieldNow();
        const bench = new wasm.SimdMsmBench(curve, o.benchLog, 0x5eed);
        try {
          bench.check();
          const time = f => { const started = now(); f(); return now() - started; };
          bench.simd(); bench.ark(); // warm-up
          const simd = [], ark = [];
          for (let round = 0; round < o.benchRounds; round++) {
            // ABBA: neither path always runs first.
            if (round % 2) { simd.push(time(() => bench.simd())); ark.push(time(() => bench.ark())); }
            else { ark.push(time(() => bench.ark())); simd.push(time(() => bench.simd())); }
            await yieldNow();
          }
          const ratios = simd.map((s, i) => ark[i] / s);
          const result = {curve: `G${curve}`, points: 2 ** o.benchLog, width: bench.width, simdMs: median(simd), arkMs: median(ark),
            speedup: median(ratios), minSpeedup: o.minSpeedup, roundSpeedups: ratios.map(r => +r.toFixed(3))};
          report.bench.push(result);
          log(`bench G${curve} 2^${o.benchLog} w=${bench.width}: SIMD ${result.simdMs.toFixed(1)} ms, arkworks ${result.arkMs.toFixed(1)} ms, speedup ${result.speedup.toFixed(2)}x (gate ${o.minSpeedup}x)`);
          if (result.speedup < o.minSpeedup) throw new Error(`SIMD MSM G${curve} speedup ${result.speedup.toFixed(2)}x is below ${o.minSpeedup}x (codegen regression? see scripts/check-simd-codegen.mjs)`);
        } finally { bench.free(); }
      }
    }
    report.passed = true;
  } catch (error) {
    report.error = String(error?.message ?? error);
    // A failed Rust assertion traps ("unreachable"); its message was kept.
    try { const panic = wasm.simdSelfTestPanic?.(); if (panic) report.error += `: ${panic}`; } catch {}
    report.failed = current;
    if (current && current.kind in calls) report.repro = `--repro ${current.kind}:${current.seed}:${current.arg}`;
  }
  return report;
}
