#!/usr/bin/env python3
"""Generate the fully unrolled 9x29-bit Montgomery kernels of the opt-in WASM
SIMD features (curvy-prover `wasm-simd-msm` and `wasm-simd-fft`).

One preset per BN254 field, each naming its modulus, the Rust module holding
its limb constants, the output file and the functions emitted:

    fq  base field, the MSM kernel   -> src/msm_simd/gen_u29.rs
    fr  scalar field, the FFT        -> src/simd_fft/gen_u29.rs

Usage, from anywhere in the repository:

    python3 crates/prover/scripts/gen_simd_u29.py            # rewrite both
    python3 crates/prover/scripts/gen_simd_u29.py --check    # CI: no diff
    python3 crates/prover/scripts/gen_simd_u29.py --field fr # one preset

Columns are named by absolute index (c0..c17), so the operand-scanning "shift
down one limb" of the loop form becomes plain variable renaming: no array
stays in memory and nothing moves. The emitted code names the modulus only
symbolically (`P`, `MU` from the constants module); the generator derives the
limb constants from the preset's modulus and checks that module against them,
so a wrong constant fails here rather than in a differential test. The
readable loop forms (`mont_mul_ref`, `mul4_ref`, ...) and the PoC's
differential tests live in poc/wasm-field/src (u29x9.rs, simd.rs, check.rs).

Moved from poc/wasm-field/gen.py. Changes since: field presets and the
constants check; `p_splat` reads through `black_box` (the crate forbids
`unsafe`; the PoC used a volatile load); the PoC-only `mul4_split` variant is
gone.
"""

import argparse
import difflib
import pathlib
import re
import sys

N = 9
W = 29
CRATE = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = "crates/prover/scripts/gen_simd_u29.py"

FIELDS = {
    "fq": {
        "title": "BN254 base field Fq",
        "modulus": 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47,
        "constants": "crate::msm_simd::u29x9",
        "constants_file": "src/msm_simd/u29x9.rs",
        "output": "src/msm_simd/gen_u29.rs",
        "functions": ("mont_mul", "mont_sqr", "mul4", "sqr4"),
    },
    "fr": {
        "title": "BN254 scalar field Fr",
        "modulus": 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001,
        "constants": "super::fr29",
        "constants_file": "src/simd_fft/fr29.rs",
        "output": "src/simd_fft/gen_u29.rs",
        "functions": ("mont_mul", "mul4"),
    },
}


class Emitter:
    def __init__(self, simd):
        self.simd = simd
        self.lines = []
        self.defined = set()

    def emit(self, line):
        self.lines.append(line)

    def acc(self, name, expr):
        """name += expr (declaring name on first use)."""
        if self.simd:
            for h in ("lo", "hi"):
                var = f"{name}{h}"
                e = expr(h)
                if var in self.defined:
                    self.emit(f"{var} = u64x2_add({var}, {e});")
                else:
                    self.emit(f"let mut {var} = {e};")
                    self.defined.add(var)
        else:
            if name in self.defined:
                self.emit(f"{name} += {expr};")
            else:
                self.emit(f"let mut {name} = {expr};")
                self.defined.add(name)


def extmul(h, x, y):
    return f"u64x2_extmul_{'low' if h == 'lo' else 'high'}_u32x4({x}, {y})"


def scalar_mul():
    e = Emitter(False)
    for j in range(N):
        e.emit(f"let b{j} = b[{j}] as u64;")
    for i in range(N):
        e.emit(f"let a{i} = a[{i}] as u64;")
        for j in range(N):
            e.acc(f"c{i + j}", f"a{i} * b{j}")
        e.emit(f"let q{i} = ((c{i} as u32).wrapping_mul(MU) & MASK) as u64;")
        for j in range(N):
            e.acc(f"c{i + j}", f"q{i} * P{j}")
        e.acc(f"c{i + 1}", f"c{i} >> W")
    return e, [f"c{9 + k}" if 9 + k <= 16 else "0" for k in range(N)]


def scalar_sqr():
    e = Emitter(False)
    for i in range(N):
        e.emit(f"let a{i} = a[{i}] as u64;")
    for i in range(N):
        for j in range(i + 1, N):
            e.acc(f"c{i + j}", f"a{i} * a{j}")
    for k in range(1, 16):
        e.emit(f"c{k} <<= 1;")
    for i in range(N):
        e.acc(f"c{2 * i}", f"a{i} * a{i}")
    for i in range(N):
        e.emit(f"let q{i} = ((c{i} as u32).wrapping_mul(MU) & MASK) as u64;")
        for j in range(N):
            e.acc(f"c{i + j}", f"q{i} * P{j}")
        e.acc(f"c{i + 1}", f"c{i} >> W")
    return e, [f"c{9 + k}" if 9 + k <= 16 else "0" for k in range(N)]


def simd_mul():
    e = Emitter(True)
    for i in range(N):
        e.emit(f"let a{i} = a[{i}];")
        for j in range(N):
            e.acc(f"c{i + j}", lambda h, i=i, j=j: extmul(h, f"a{i}", f"b[{j}]"))
        e.emit(f"let q{i} = v128_and(i32x4_mul(i32x4_shuffle::<0, 2, 4, 6>(c{i}lo, c{i}hi), mu), mask);")
        for j in range(N):
            e.acc(f"c{i + j}", lambda h, i=i, j=j: extmul(h, f"q{i}", f"p{j}"))
        e.acc(f"c{i + 1}", lambda h, i=i: f"u64x2_shr(c{i}{h}, W)")
    return e, [f"c{9 + k}" if 9 + k <= 16 else None for k in range(N)]


def simd_sqr():
    e = Emitter(True)
    for i in range(N):
        for j in range(i + 1, N):
            e.acc(f"c{i + j}", lambda h, i=i, j=j: extmul(h, f"a[{i}]", f"a[{j}]"))
    for k in range(1, 16):
        for h in ("lo", "hi"):
            e.emit(f"c{k}{h} = u64x2_shl(c{k}{h}, 1);")
    for i in range(N):
        e.acc(f"c{2 * i}", lambda h, i=i: extmul(h, f"a[{i}]", f"a[{i}]"))
    for i in range(N):
        e.emit(f"let q{i} = v128_and(i32x4_mul(i32x4_shuffle::<0, 2, 4, 6>(c{i}lo, c{i}hi), mu), mask);")
        for j in range(N):
            e.acc(f"c{i + j}", lambda h, i=i, j=j: extmul(h, f"q{i}", f"p{j}"))
        e.acc(f"c{i + 1}", lambda h, i=i: f"u64x2_shr(c{i}{h}, W)")
    return e, [f"c{9 + k}" if 9 + k <= 16 else None for k in range(N)]


def scalar_fn(name, args, body_fn):
    e, cols = body_fn()
    out = [f"#[inline(always)]\npub fn {name}({args}) -> [u32; 9] {{"]
    out += [f"    {l}" for l in e.lines]
    out.append("    let mut r = [0u32; 9];")
    out.append("    let mut carry = 0u64;")
    for k, col in enumerate(cols):
        out.append(f"    let v = {col} + carry;")
        out.append(f"    r[{k}] = (v & MASK64) as u32;")
        if k < N - 1:
            out.append("    carry = v >> W;")
    out.append("    r\n}")
    return "\n".join(out)


def simd_fn(name, args, body_fn):
    e, cols = body_fn()
    out = [f"#[inline(always)]\npub fn {name}({args}) -> [v128; 9] {{"]
    out.append("    let mu = u32x4_splat(MU);")
    out.append("    let mask = u32x4_splat(MASK);")
    out.append("    let mask64 = u64x2_splat(MASK as u64);")
    out += [f"    let p{j} = p_splat({j});" for j in range(N)]
    out += [f"    {l}" for l in e.lines]
    out.append("    let mut r = [u32x4_splat(0); 9];")
    out.append("    let (mut clo, mut chi) = (u64x2_splat(0), u64x2_splat(0));")
    for k, col in enumerate(cols):
        if col is None:
            out.append("    let (vlo, vhi) = (clo, chi);")
        else:
            out.append(f"    let (vlo, vhi) = (u64x2_add({col}lo, clo), u64x2_add({col}hi, chi));")
        out.append(f"    r[{k}] = i32x4_shuffle::<0, 2, 4, 6>(v128_and(vlo, mask64), v128_and(vhi, mask64));")
        if k < N - 1:
            out.append("    (clo, chi) = (u64x2_shr(vlo, W), u64x2_shr(vhi, W));")
    out.append("    r\n}")
    return "\n".join(out)


P_SPLAT = '''/// p limbs splatted to all four lanes. Read through `black_box` so LLVM
/// cannot fold the splat into a 64-bit constant: core::arch's extmul is a
/// generic `mul(zext, zext)`, and once one operand becomes a u64x2 constant
/// the backend emits `i64x2.mul`, which V8 emulates on arm64 (NEON has no
/// 64-bit lane multiply) instead of a single UMULL.
/// scripts/check-simd-codegen.mjs guards this in CI.
static P_SPLAT: [v128; 9] = [
    u32x4(P[0], P[0], P[0], P[0]), u32x4(P[1], P[1], P[1], P[1]), u32x4(P[2], P[2], P[2], P[2]),
    u32x4(P[3], P[3], P[3], P[3]), u32x4(P[4], P[4], P[4], P[4]), u32x4(P[5], P[5], P[5], P[5]),
    u32x4(P[6], P[6], P[6], P[6]), u32x4(P[7], P[7], P[7], P[7]), u32x4(P[8], P[8], P[8], P[8]),
];

#[inline(always)]
fn p_splat(j: usize) -> v128 {
    core::hint::black_box(P_SPLAT[j])
}
'''

BODIES = {
    "mont_mul": lambda: scalar_fn("mont_mul", "a: &[u32; 9], b: &[u32; 9]", scalar_mul),
    "mont_sqr": lambda: scalar_fn("mont_sqr", "a: &[u32; 9]", scalar_sqr),
    "mul4": lambda: simd_fn("mul4", "a: &[v128; 9], b: &[v128; 9]", simd_mul),
    "sqr4": lambda: simd_fn("sqr4", "a: &[v128; 9]", simd_sqr),
}


def limbs(value):
    assert 0 <= value < 1 << (N * W)
    return [(value >> (W * i)) & ((1 << W) - 1) for i in range(N)]


def expected_constants(p):
    """The limb constants the kernels and their callers rely on."""
    # The bounds argument (u29x9.rs) needs p < 2^254, so that R = 2^261 > 4p
    # with room for the lazily reduced sums the kernels accept.
    assert p.bit_length() <= 254 and p % 2 == 1, "unsupported modulus"
    return {
        "P": limbs(p),
        "P2": limbs(2 * p),
        "MU": (-pow(p, -1, 1 << W)) % (1 << W),
        "ONE": limbs(pow(2, N * W, p)),
        "TO": limbs(pow(2, N * W + 5, p)),
        "FROM": limbs(pow(2, 256, p)),
    }


def check_constants(preset):
    """Compare every limb constant the constants module defines with the
    values derived from the preset's modulus. Returns a list of errors."""
    path = CRATE / preset["constants_file"]
    text = path.read_text()
    path = path.relative_to(CRATE.parent.parent)
    found = {}
    for name, body in re.findall(r"const (\w+): \[u32; 9\] = \[([^\]]*)\];", text):
        found[name] = [int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", body)]
    for name, value in re.findall(r"const (\w+): u32 = (0x[0-9a-fA-F]+|\d+);", text):
        found[name] = int(value, 0)
    errors = []
    expected = expected_constants(preset["modulus"])
    for name in ("P", "P2", "MU"):
        if name not in found:
            errors.append(f"{path}: missing constant {name}")
    for name, value in found.items():
        if name in expected and value != expected[name]:
            errors.append(f"{path}: {name} does not match the modulus 0x{preset['modulus']:x}")
    return errors


def render(name):
    preset = FIELDS[name]
    fns = preset["functions"]
    scalar = [f for f in fns if not f.endswith("4")]
    simd = [f for f in fns if f.endswith("4")]
    header = f'''//! GENERATED by {SCRIPT} - do not edit.
//! Regenerate with `python3 {SCRIPT}`; CI runs it with `--check`.
//! Field preset `{name}`: {preset["title"]},
//! p = 0x{preset["modulus"]:064x},
//! limb constants from `{preset["constants"]}` (checked against p).
//!
//! Fully unrolled 9x29 Montgomery kernels: {", ".join(f"`{f}`" for f in fns)}
//! (scalar, and 4-way simd128 for wasm32). Same algorithms and bounds as the
//! loop forms in poc/wasm-field/src (u29x9.rs, simd.rs).
#![allow(unused_mut, unused_assignments, clippy::all)]

use {preset["constants"]}::{{MASK, MU, P, W}};
const MASK64: u64 = MASK as u64;
'''
    consts = "\n".join(f"const P{j}: u64 = P[{j}] as u64;" for j in range(N))
    src = [header, consts]
    for f in scalar:
        src += ["", BODIES[f]()]
    src += [
        "",
        "#[cfg(target_arch = \"wasm32\")]\npub use simd_gen::*;",
        "#[cfg(target_arch = \"wasm32\")]\nmod simd_gen {",
        "use core::arch::wasm32::*;\nuse super::{MASK, MU, P, W};\n",
        P_SPLAT,
    ]
    src.append("\n\n".join(BODIES[f]() for f in simd))
    src.append("}\n")
    return "\n".join(src)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--field", choices=sorted(FIELDS), action="append",
                        help="preset to generate (default: all)")
    parser.add_argument("--check", action="store_true",
                        help="write nothing; fail if a file differs from its generated form")
    args = parser.parse_args()
    failed = False
    for name in args.field or sorted(FIELDS):
        preset = FIELDS[name]
        errors = check_constants(preset)
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        failed |= bool(errors)
        path = CRATE / preset["output"]
        text = render(name)
        current = path.read_text() if path.exists() else ""
        rel = path.relative_to(CRATE.parent.parent)
        if args.check:
            if current != text:
                failed = True
                print(f"error: {rel} is stale; run python3 {SCRIPT}", file=sys.stderr)
                sys.stderr.writelines(list(difflib.unified_diff(
                    current.splitlines(True), text.splitlines(True),
                    f"{rel} (committed)", f"{rel} (generated)"))[:80])
            else:
                print(f"{rel}: up to date ({name})")
        elif not errors:
            if current != text:
                path.write_text(text)
                print(f"wrote {rel} ({name})")
            else:
                print(f"{rel}: unchanged ({name})")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
