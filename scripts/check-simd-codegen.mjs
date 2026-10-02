#!/usr/bin/env node
// Codegen guard for the opt-in WASM SIMD kernels (curvy-prover
// `wasm-simd-msm`, `wasm-simd-fft`).
//
//   node scripts/check-simd-codegen.mjs [--expect msm,fft] [MODULE.wasm ...]
//
// MODULE defaults to the cargo output of the last WASM build,
// ${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/curvy_prover.wasm,
// which still has its `name` section (wasm-opt drops it from the packaged
// module; wasm-bindgen and wasm-opt do not change instruction selection).
// Needs `wasm-tools` on PATH or in $WASM_TOOLS (CI pins 1.260.0).
//
// Why: each Montgomery product of the 4-lane kernels (gen_u29.rs `mul4`,
// `sqr4`) is meant to be one `i64x2.extmul_{low,high}_i32x4_u` pair, which
// V8 lowers to UMULL/UMULL2 on arm64 and PMULUDQ on x64. core::arch's
// extmul is a generic `mul(zext, zext)`, so when LLVM can see an operand as a
// 64-bit constant or splat it emits `i64x2.mul` instead, which neither ISA
// has: V8 emulates it with several multiplies and shuffles. The PoC measured
// that as a 2x slower MSM kernel on arm64 (poc/wasm-field/README.md), and
// self-tests still pass because the result is identical.
//
// Rules, per function of the demangled module:
// - MSM (`msm_simd::`): every function that contains extmul has zero
//   `i64x2.mul`; no function has 81 or more `i64x2.mul` (half of one 162-product
//   kernel copy, so a copy whose extmuls all became `i64x2.mul` cannot hide by
//   having none left); and the namespace has at least MSM_EXTMUL_FLOOR
//   extmuls: one copy each of `mul4` in `lanes::mul4_call` and
//   `fq2::simd::mul4` (2 x 324) and of `sqr4` in `lanes::sqr4_call` (252).
//   The kernels are `#[inline(never)]`, so these copies have stable names.
//   Scalar code may still contain a few SLP-vectorized `i64x2.mul` (two scalar
//   Montgomery steps fused); they are reported, not failed.
// - FFT (`simd_fft::`): at least FFT_EXTMUL_FLOOR extmuls (one `mul4` copy),
//   and at most FFT_I64X2_MUL_MAX `i64x2.mul`. KNOWN ISSUE: `mul4` is inlined
//   into the NTT, and where its second operand is a splatted twiddle or scale
//   factor (ntt.rs `splat`, `lanes2`) LLVM emits `i64x2.mul` for the products
//   with it, exactly the regression above. October 2026: 648 (portable) and
//   810 (threaded) of the 1,782 products in `ntt::dif`, `ntt::pack` and the
//   unpack inlined into `ntt::ntt`. The allowance is the larger count, so the
//   FFT cannot get worse unnoticed; lower it to 0 once the splats are hidden
//   from LLVM like `p_splat`.
// Development-only self-test code (`self_test` modules, `wasm-simd-selftest`)
// is skipped: its scalar arithmetic on constants is freely SLP-vectorized.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, unlinkSync } from 'node:fs';
import { resolve } from 'node:path';

const MSM_EXTMUL_FLOOR = 2 * 324 + 252;
const MSM_FULLY_CONVERTED = 81;
const FFT_EXTMUL_FLOOR = 324;
const FFT_I64X2_MUL_MAX = 810;

const args = process.argv.slice(2);
let expect = ['msm', 'fft'];
const modules = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--expect') expect = args[++i].split(',').filter(Boolean);
  else modules.push(args[i]);
}
for (const kind of expect) assert.ok(['msm', 'fft'].includes(kind), `unknown --expect ${kind}`);
if (!modules.length) modules.push(resolve(process.env.CARGO_TARGET_DIR || 'target', 'wasm32-unknown-unknown/release/curvy_prover.wasm'));
const wasmTools = process.env.WASM_TOOLS || 'wasm-tools';

const annotate = (level, message) => console.log(process.env.GITHUB_ACTIONS ? `::${level}::${message}` : `${level}: ${message}`);

function functions(module) {
  const demangled = `${module}.demangled-${process.pid}.wasm`;
  try {
    execFileSync(wasmTools, ['demangle', module, '-o', demangled]);
    const text = execFileSync(wasmTools, ['print', demangled], {maxBuffer: 1 << 30, encoding: 'utf8'});
    const result = [];
    let current = null;
    for (const line of text.split('\n')) {
      if (line.startsWith('  (func ')) {
        // `(func $name` or `(func $"name with spaces"`; unnamed: `(func (;12;)`.
        const match = /^ {2}\(func (?:\$"((?:[^"\\]|\\.)*)"|\$(\S+)|(\(;\d+;\)))/.exec(line);
        current = {name: match[1] ?? match[2] ?? match[3], named: !match[3], extmul: 0, i64x2mul: 0};
        result.push(current);
      } else if (current) {
        if (line.includes('i64x2.extmul_')) current.extmul++;
        else if (/\bi64x2\.mul\b/.test(line)) current.i64x2mul++;
      }
    }
    return result;
  } finally {
    if (existsSync(demangled)) unlinkSync(demangled);
  }
}

let failed = false;
const fail = message => { failed = true; annotate('error', message); };
for (const module of modules) {
  assert.ok(existsSync(module), `${module} does not exist; build with scripts/build-wasm.sh ... --simd first`);
  const all = functions(module);
  const named = all.filter(f => f.named).length;
  console.log(`${module}: ${all.length} functions, ${named} named, extmul ${all.reduce((n, f) => n + f.extmul, 0)}, i64x2.mul ${all.reduce((n, f) => n + f.i64x2mul, 0)}`);
  if (named < all.length / 2) {
    fail(`${module} has no usable name section; check the cargo output, not the wasm-opt'd package`);
    continue;
  }
  const scope = prefix => all.filter(f => f.name.includes(prefix) && !f.name.includes('self_test'));
  const show = list => list.filter(f => f.extmul || f.i64x2mul)
    .map(f => `    extmul ${String(f.extmul).padStart(4)}  i64x2.mul ${String(f.i64x2mul).padStart(4)}  ${f.name.slice(0, 140)}`).join('\n');

  if (expect.includes('msm')) {
    const msm = scope('msm_simd::');
    const extmul = msm.reduce((n, f) => n + f.extmul, 0);
    console.log(`  MSM (msm_simd::): extmul ${extmul} (floor ${MSM_EXTMUL_FLOOR})\n${show(msm)}`);
    if (extmul < MSM_EXTMUL_FLOOR) fail(`MSM kernels have ${extmul} i64x2.extmul, expected at least ${MSM_EXTMUL_FLOOR}: products were lost or turned into i64x2.mul`);
    for (const f of msm) {
      if (f.extmul && f.i64x2mul) fail(`${f.name}: ${f.i64x2mul} i64x2.mul next to ${f.extmul} extmul: a SIMD kernel product lost its extmul`);
      else if (f.i64x2mul >= MSM_FULLY_CONVERTED) fail(`${f.name}: ${f.i64x2mul} i64x2.mul and no extmul: a SIMD kernel copy emitted with emulated 64-bit multiplies (or unusually heavy SLP vectorization of scalar code; inspect it)`);
      else if (f.i64x2mul) annotate('notice', `${f.name}: ${f.i64x2mul} i64x2.mul in scalar code (SLP-vectorized), below the ${MSM_FULLY_CONVERTED} kernel threshold`);
    }
  }
  if (expect.includes('fft')) {
    const fft = scope('simd_fft::');
    const extmul = fft.reduce((n, f) => n + f.extmul, 0);
    const mul = fft.reduce((n, f) => n + f.i64x2mul, 0);
    console.log(`  FFT (simd_fft::): extmul ${extmul} (floor ${FFT_EXTMUL_FLOOR}), i64x2.mul ${mul} (allowance ${FFT_I64X2_MUL_MAX})\n${show(fft)}`);
    if (extmul < FFT_EXTMUL_FLOOR) fail(`FFT has ${extmul} i64x2.extmul, expected at least ${FFT_EXTMUL_FLOOR}`);
    if (mul > FFT_I64X2_MUL_MAX) fail(`FFT has ${mul} i64x2.mul, above the known ${FFT_I64X2_MUL_MAX}: more products lost their extmul`);
    else if (mul > 0) annotate('warning', `FFT still has ${mul} emulated i64x2.mul products (known splat issue; allowance ${FFT_I64X2_MUL_MAX})`);
    if (mul < FFT_I64X2_MUL_MAX) annotate('notice', `FFT i64x2.mul is ${mul}: lower FFT_I64X2_MUL_MAX in scripts/check-simd-codegen.mjs to ${mul}`);
  }
}
if (failed) process.exit(1);
console.log('SIMD codegen guard passed');
