#!/usr/bin/env python3
"""Generate fully unrolled 9x29 Montgomery multiplication and squaring.

Writes src/gen_u29.rs. Columns are named by absolute index (c0..c17), so the
operand-scanning "shift down one limb" of the loop form becomes plain variable
renaming: no array stays in memory and nothing moves. The loop forms in
u29x9.rs / simd.rs are the readable reference; the differential tests check
both against arkworks and against each other.

    python3 gen.py   (from poc/wasm-field)
"""

N = 9


class Emitter:
    def __init__(self, simd):
        self.simd = simd
        self.lines = []
        self.defined = set()

    def emit(self, line):
        self.lines.append(line)

    def acc(self, name, expr, half=None):
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


def simd_mul_split(half):
    """One half (elements 0,1 via extmul_low or 2,3 via extmul_high) of a
    4-way multiplication: 9 accumulators instead of 18, so the working set
    (accumulators, b, p splats) fits in 32 NEON registers."""
    e = Emitter(False)
    ext = "low" if half == "lo" else "high"
    for i in range(N):
        for j in range(N):
            name = f"c{i + j}"
            expr = f"u64x2_extmul_{ext}_u32x4(a[{i}], b[{j}])"
            if name in e.defined:
                e.emit(f"{name} = u64x2_add({name}, {expr});")
            else:
                e.emit(f"let mut {name} = {expr};")
                e.defined.add(name)
        e.emit(f"let q{i} = v128_and(i32x4_mul(i32x4_shuffle::<0, 2, 0, 2>(c{i}, c{i}), mu), mask);")
        for j in range(N):
            name = f"c{i + j}"
            e.emit(f"{name} = u64x2_add({name}, u64x2_extmul_{ext}_u32x4(q{i}, p{j}));")
        e.emit(f"c{i + 1} = u64x2_add(c{i + 1}, u64x2_shr(c{i}, W));")
    return e


def simd_mul_split_fn():
    out = ["#[inline(always)]\npub fn mul4_split(a: &[v128; 9], b: &[v128; 9]) -> [v128; 9] {",
           "    let lo = mul2_half_lo(a, b);",
           "    let hi = mul2_half_hi(a, b);",
           "    let mut r = [u32x4_splat(0); 9];",
           "    for k in 0..9 {",
           "        r[k] = i32x4_shuffle::<0, 2, 4, 6>(lo[k], hi[k]);",
           "    }",
           "    r\n}"]
    for half in ("lo", "hi"):
        e = simd_mul_split(half)
        out.append(f"#[inline(always)]\nfn mul2_half_{half}(a: &[v128; 9], b: &[v128; 9]) -> [v128; 9] {{")
        out.append("    let mu = u32x4_splat(MU);")
        out.append("    let mask = u32x4_splat(MASK);")
        out.append("    let mask64 = u64x2_splat(MASK as u64);")
        out += [f"    let p{j} = p_splat({j});" for j in range(N)]
        out += [f"    {l}" for l in e.lines]
        out.append("    let mut r = [u64x2_splat(0); 9];")
        out.append("    let mut carry = u64x2_splat(0);")
        for k in range(N):
            col = f"c{9 + k}" if 9 + k <= 16 else None
            out.append(f"    let v = {'u64x2_add(' + col + ', carry)' if col else 'carry'};")
            out.append(f"    r[{k}] = v128_and(v, mask64);")
            if k < N - 1:
                out.append("    carry = u64x2_shr(v, W);")
        out.append("    r\n}")
    return "\n".join(out)


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


P_SPLAT = '''/// p limbs splatted to all four lanes. Read through a volatile load so LLVM
/// cannot fold the splat into a 64-bit constant: core::arch's extmul is a
/// generic `mul(zext, zext)`, and once one operand becomes a u64x2 constant
/// the backend emits `i64x2.mul`, which V8 emulates on arm64 (NEON has no
/// 64-bit lane multiply) instead of a single UMULL.
static P_SPLAT: [v128; 9] = [
    u32x4(P[0], P[0], P[0], P[0]), u32x4(P[1], P[1], P[1], P[1]), u32x4(P[2], P[2], P[2], P[2]),
    u32x4(P[3], P[3], P[3], P[3]), u32x4(P[4], P[4], P[4], P[4]), u32x4(P[5], P[5], P[5], P[5]),
    u32x4(P[6], P[6], P[6], P[6]), u32x4(P[7], P[7], P[7], P[7]), u32x4(P[8], P[8], P[8], P[8]),
];

#[inline(always)]
fn p_splat(j: usize) -> v128 {
    unsafe { core::ptr::read_volatile(P_SPLAT.as_ptr().add(j)) }
}
'''

header = '''//! GENERATED by gen.py - do not edit. Fully unrolled 9x29 Montgomery
//! multiplication and squaring (scalar, and 4-way simd128 for wasm32).
//! Same algorithms and bounds as the loop forms in u29x9.rs and simd.rs.
#![allow(unused_mut, unused_assignments, clippy::all)]

use crate::u29x9::{MASK, MU, P, W};
const MASK64: u64 = MASK as u64;
'''
consts = "\n".join(f"const P{j}: u64 = P[{j}] as u64;" for j in range(N))

src = [header, consts, "",
       scalar_fn("mont_mul", "a: &[u32; 9], b: &[u32; 9]", scalar_mul), "",
       scalar_fn("mont_sqr", "a: &[u32; 9]", scalar_sqr), "",
       "#[cfg(target_arch = \"wasm32\")]\npub use simd_gen::*;",
       "#[cfg(target_arch = \"wasm32\")]\nmod simd_gen {",
       "use core::arch::wasm32::*;\nuse super::{MASK, MU, P, W};\n",
       P_SPLAT,
       simd_fn("mul4", "a: &[v128; 9], b: &[v128; 9]", simd_mul), "",
       simd_fn("sqr4", "a: &[v128; 9]", simd_sqr), "",
       simd_mul_split_fn(),
       "}\n"]
open("src/gen_u29.rs", "w").write("\n".join(src))
print("wrote src/gen_u29.rs")
