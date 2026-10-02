//! Radix-2 NTT over BN254 Fr with the 4-lane simd128 9x29 multiply, as the
//! fused witness-map step: inverse transform, coset scaling, forward
//! transform.
//!
//! Layout: n elements as q = n/4 limb-sliced vectors, vector k holding
//! elements k, k+q, k+2q, k+3q ("strided lanes").
//!
//! The inverse transform is a decimation in frequency (natural in,
//! bit-reversed out):
//! - stages with half-size n/2 and n/4 pair lanes inside one vector; they
//!   run fused as one radix-4 pass with lane shuffles, fused with the pack;
//! - every later stage pairs whole vectors k, k+m with ONE twiddle shared by
//!   all four lanes (a splat), so four butterflies per vector op.
//!
//! Afterwards vector k, lane l holds coefficient 4*rev(k) + [0, 2, 1, 3][l],
//! which the coset scaling multiplies by n^-1 g^i in place. The forward
//! transform is the transpose of the same DIF (DFT matrices are symmetric):
//! decimation in time, the stages in reverse order with butterflies
//! (a + w b, a - w b). It takes that bit-reversed order back to natural, so
//! no bit reversal is ever materialized and the unpack is the pack's inverse.
//!
//! The vector stages run depth-first: a block of 2m vectors gets its DIF
//! stage, its halves recurse independently (concurrently under `parallel`),
//! then it gets its DIT stage. Blocks of `LEAF` vectors run every stage below
//! them, the scaling and the DIT stages back up while in cache, so the large
//! levels stream the data twice each instead of once per stage and
//! transform. Under `parallel` every streaming pass (pack, the large DIF and
//! DIT stages, unpack) is also split into chunks on the Rayon pool.
//!
//! Data stays in arkworks' Montgomery integer (see fr29.rs), so packing is
//! limb repacking only; twiddles and scale factors are in the 2^261 form.

use ark_bn254::Fr;
use ark_ff::{Field, One};
use core::arch::wasm32::*;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::fr29::{MASK, P2, W, const_from_ark, mont_mul, raw_from_ark, raw_to_ark};
use super::gen_u29;

// Out of line: V8 allocates registers better for the ~700-instruction body on
// its own than inlined into every butterfly (as in msm_simd::lanes).
#[inline(never)]
fn mul4(a: &V, b: &V) -> V {
    gen_u29::mul4(a, b)
}

pub type V = [v128; 9];

/// Vectors per leaf block (144 bytes each).
pub const LEAF: usize = 512;
/// Vectors per Rayon task in the streaming passes.
#[cfg(feature = "parallel")]
const CHUNK: usize = 1024;
/// Twiddles per Rayon task when building a plan.
const TWIDDLE_CHUNK: usize = 4096;

#[inline(always)]
fn splat(c: &[u32; 9]) -> V {
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = u32x4_splat(c[i]);
    }
    v
}

#[inline(always)]
fn lanes2(a: &[u32; 9], b: &[u32; 9]) -> V {
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = u32x4(a[i], b[i], a[i], b[i]);
    }
    v
}

#[inline(always)]
fn lanes4(e: &[[u32; 9]; 4]) -> V {
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = u32x4(e[0][i], e[1][i], e[2][i], e[3][i]);
    }
    v
}

#[inline(always)]
fn add4(a: &V, b: &V) -> V {
    let mask = u32x4_splat(MASK);
    let mut s = [u32x4_splat(0); 9];
    let mut carry = u32x4_splat(0);
    for i in 0..9 {
        let v = u32x4_add(u32x4_add(a[i], b[i]), carry);
        s[i] = v128_and(v, mask);
        carry = u32x4_shr(v, W);
    }
    let mut d = [u32x4_splat(0); 9];
    let mut borrow = i32x4_splat(0);
    for i in 0..9 {
        let v = i32x4_add(i32x4_sub(s[i], u32x4_splat(P2[i])), borrow);
        d[i] = v128_and(v, mask);
        borrow = i32x4_shr(v, W);
    }
    for i in 0..9 {
        d[i] = v128_bitselect(s[i], d[i], borrow);
    }
    d
}

#[inline(always)]
fn sub4(a: &V, b: &V) -> V {
    let mask = u32x4_splat(MASK);
    let mut d = [u32x4_splat(0); 9];
    let mut borrow = i32x4_splat(0);
    for i in 0..9 {
        let v = i32x4_add(i32x4_sub(a[i], b[i]), borrow);
        d[i] = v128_and(v, mask);
        borrow = i32x4_shr(v, W);
    }
    let mut carry = u32x4_splat(0);
    for i in 0..9 {
        let v = u32x4_add(u32x4_add(d[i], v128_and(u32x4_splat(P2[i]), borrow)), carry);
        d[i] = v128_and(v, mask);
        carry = u32x4_shr(v, W);
    }
    d
}

/// DIF butterfly: (x, y) -> (x + y, (x - y) w).
#[inline(always)]
fn dif(a: &mut V, b: &mut V, w: Option<&[u32; 9]>) {
    let (x, y) = (*a, *b);
    *a = add4(&x, &y);
    let d = sub4(&x, &y);
    *b = match w {
        Some(w) => mul4(&d, &splat(w)),
        None => d,
    };
}

/// DIT butterfly, the DIF's transpose: (x, y) -> (x + w y, x - w y).
#[inline(always)]
fn dit(a: &mut V, b: &mut V, w: Option<&[u32; 9]>) {
    let (x, y) = (*a, *b);
    let t = match w {
        Some(w) => mul4(&y, &splat(w)),
        None => y,
    };
    *a = add4(&x, &t);
    *b = sub4(&x, &t);
}

/// Twiddles for one domain size and direction: omega^k, k < n/2, 2^261 form.
pub struct Plan {
    pub tw: Vec<[u32; 9]>,
}

impl Plan {
    pub fn new(n: usize, omega: Fr) -> Self {
        assert!(n.is_power_of_two() && n >= 8);
        let w = const_from_ark(&omega);
        let mut tw = vec![[0u32; 9]; n / 2];
        let fill = |(c, chunk): (usize, &mut [[u32; 9]])| {
            let mut cur = const_from_ark(&omega.pow([(c * TWIDDLE_CHUNK) as u64]));
            for t in chunk {
                *t = cur;
                cur = mont_mul(&cur, &w);
            }
        };
        #[cfg(feature = "parallel")]
        tw.par_chunks_mut(TWIDDLE_CHUNK).enumerate().for_each(fill);
        #[cfg(not(feature = "parallel"))]
        tw.chunks_mut(TWIDDLE_CHUNK).enumerate().for_each(fill);
        Plan { tw }
    }
}

#[inline(always)]
fn rev(k: usize, bits: u32) -> usize {
    if bits == 0 {
        0
    } else {
        k.reverse_bits() >> (usize::BITS - bits)
    }
}

fn join(a: impl FnOnce() + Send, b: impl FnOnce() + Send) {
    #[cfg(feature = "parallel")]
    rayon::join(a, b);
    #[cfg(not(feature = "parallel"))]
    {
        a();
        b();
    }
}

/// `f(j0, a_chunk, b_chunk)` over aligned chunks of two equal halves.
fn pass(a: &mut [V], b: &mut [V], f: impl Fn(usize, &mut [V], &mut [V]) + Send + Sync) {
    #[cfg(feature = "parallel")]
    a.par_chunks_mut(CHUNK)
        .zip(b.par_chunks_mut(CHUNK))
        .enumerate()
        .for_each(|(c, (a, b))| f(c * CHUNK, a, b));
    #[cfg(not(feature = "parallel"))]
    f(0, a, b);
}

/// `ifft`, `distribute_powers_and_mul_by_const(g, n^-1)` and `fft` over one
/// domain of size n, on packed data.
pub struct Step {
    n: usize,
    leaf: usize,
    inv: Plan,
    fwd: Plan,
    /// n^-1 g^(4 rev(r)) times the lane factors g^[0, 2, 1, 3], per offset
    /// r inside a leaf block.
    scale_leaf: Vec<V>,
    /// g^(4 rev(b * leaf)) per leaf block b.
    scale_block: Vec<[u32; 9]>,
}

impl Step {
    /// `leaf` (a power of two >= 2, clamped to n/4) only changes the
    /// schedule: production passes [`LEAF`]; the self-test uses small ones to
    /// reach the recursive levels on small domains.
    pub fn with_leaf(n: usize, omega: Fr, omega_inv: Fr, g: Fr, size_inv: Fr, leaf: usize) -> Self {
        assert!(n.is_power_of_two() && n >= 8);
        assert!(leaf.is_power_of_two() && leaf >= 2);
        let q = n / 4;
        let leaf = leaf.min(q);
        let blocks = q / leaf;
        let mut plans = (None, None);
        join(
            || plans.0 = Some(Plan::new(n, omega_inv)),
            || plans.1 = Some(Plan::new(n, omega)),
        );
        let (inv, fwd) = (plans.0.expect("plan"), plans.1.expect("plan"));
        let powers = |base: Fr, count: usize| {
            let mut out = Vec::with_capacity(count);
            let mut cur = Fr::one();
            for _ in 0..count {
                out.push(cur);
                cur *= base;
            }
            out
        };
        // For r < leaf, rev_q(r) = rev_leaf(r) * (q / leaf); for a block
        // start, rev_q(b * leaf) = rev_blocks(b).
        let in_leaf = powers(g.pow([(4 * blocks) as u64]), leaf);
        let lane = [Fr::one(), g.square(), g, g.square() * g];
        let scale_leaf = (0..leaf)
            .map(|r| {
                let s = size_inv * in_leaf[rev(r, leaf.trailing_zeros())];
                lanes4(&core::array::from_fn(|l| const_from_ark(&(s * lane[l]))))
            })
            .collect();
        let per_block = powers(g.pow([4]), blocks);
        let scale_block = (0..blocks)
            .map(|b| const_from_ark(&per_block[rev(b, blocks.trailing_zeros())]))
            .collect();
        Step {
            n,
            leaf,
            inv,
            fwd,
            scale_leaf,
            scale_block,
        }
    }

    /// Applies the step to `x` (length n) in place.
    pub fn apply(&self, x: &mut [Fr]) {
        assert_eq!(x.len(), self.n);
        let mut buf = Vec::new();
        self.pack(x, &mut buf);
        self.recurse(&mut buf, 0);
        self.unpack(&buf, x);
        // The packed copy is witness-derived: wipe it like `qap::WipeOnDrop`
        // (best effort; `black_box` keeps the stores before the free).
        #[cfg(feature = "parallel")]
        buf.par_chunks_mut(CHUNK)
            .for_each(|c| c.fill([u32x4_splat(0); 9]));
        #[cfg(not(feature = "parallel"))]
        buf.fill([u32x4_splat(0); 9]);
        core::hint::black_box(&buf);
    }

    /// Pack, fused with the inverse transform's two cross-lane stages.
    fn pack(&self, x: &[Fr], buf: &mut Vec<V>) {
        let q = self.n / 4;
        let tw = &self.inv.tw;
        let one = |k: usize| {
            let v = lanes4(&[
                raw_from_ark(&x[k]),
                raw_from_ark(&x[k + q]),
                raw_from_ark(&x[k + 2 * q]),
                raw_from_ark(&x[k + 3 * q]),
            ]);
            dif_lanes(v, tw, k, q)
        };
        #[cfg(feature = "parallel")]
        (0..q)
            .into_par_iter()
            .with_min_len(CHUNK)
            .map(one)
            .collect_into_vec(buf);
        #[cfg(not(feature = "parallel"))]
        {
            buf.clear();
            buf.reserve_exact(q);
            buf.extend((0..q).map(one));
        }
    }

    /// The forward transform's two cross-lane stages, fused with the unpack
    /// (natural order).
    fn unpack(&self, buf: &[V], x: &mut [Fr]) {
        let q = self.n / 4;
        let tw = &self.fwd.tw;
        let (x01, x23) = x.split_at_mut(2 * q);
        let (x0, x1) = x01.split_at_mut(q);
        let (x2, x3) = x23.split_at_mut(q);
        let run = |k0: usize, b: &[V], y: [&mut [Fr]; 4]| {
            let [y0, y1, y2, y3] = y;
            for (i, v) in b.iter().enumerate() {
                let v = dit_lanes(*v, tw, k0 + i, q);
                let mut e = [[0u32; 9]; 4];
                for j in 0..9 {
                    e[0][j] = u32x4_extract_lane::<0>(v[j]);
                    e[1][j] = u32x4_extract_lane::<1>(v[j]);
                    e[2][j] = u32x4_extract_lane::<2>(v[j]);
                    e[3][j] = u32x4_extract_lane::<3>(v[j]);
                }
                y0[i] = raw_to_ark(&e[0]);
                y1[i] = raw_to_ark(&e[1]);
                y2[i] = raw_to_ark(&e[2]);
                y3[i] = raw_to_ark(&e[3]);
            }
        };
        #[cfg(feature = "parallel")]
        buf.par_chunks(CHUNK)
            .zip(x0.par_chunks_mut(CHUNK))
            .zip(x1.par_chunks_mut(CHUNK))
            .zip(x2.par_chunks_mut(CHUNK))
            .zip(x3.par_chunks_mut(CHUNK))
            .enumerate()
            .for_each(|(c, ((((b, y0), y1), y2), y3))| run(c * CHUNK, b, [y0, y1, y2, y3]));
        #[cfg(not(feature = "parallel"))]
        run(0, buf, [x0, x1, x2, x3]);
    }

    /// The vector stages of a block of vectors starting at `k0`: DIF stage,
    /// both halves, DIT stage.
    fn recurse(&self, buf: &mut [V], k0: usize) {
        if buf.len() <= self.leaf {
            self.leaf_block(buf, k0);
            return;
        }
        let m = buf.len() / 2;
        let stride = self.n / (2 * m);
        let (a, b) = buf.split_at_mut(m);
        let (inv, fwd) = (&self.inv.tw, &self.fwd.tw);
        pass(a, b, |j0, a, b| {
            for (j, (a, b)) in (j0..).zip(a.iter_mut().zip(b.iter_mut())) {
                dif(a, b, (j != 0).then(|| &inv[j * stride]));
            }
        });
        join(|| self.recurse(a, k0), || self.recurse(b, k0 + m));
        pass(a, b, |j0, a, b| {
            for (j, (a, b)) in (j0..).zip(a.iter_mut().zip(b.iter_mut())) {
                dit(a, b, (j != 0).then(|| &fwd[j * stride]));
            }
        });
    }

    /// Every remaining DIF stage of one leaf block, the coset scaling, and
    /// the DIT stages back up to the leaf size.
    fn leaf_block(&self, buf: &mut [V], k0: usize) {
        let len = buf.len();
        debug_assert_eq!(len, self.leaf);
        let (inv, fwd) = (&self.inv.tw, &self.fwd.tw);
        let mut m = len / 2;
        while m >= 1 {
            let stride = self.n / (2 * m);
            for block in buf.chunks_exact_mut(2 * m) {
                let (a, b) = block.split_at_mut(m);
                dif(&mut a[0], &mut b[0], None);
                for j in 1..m {
                    dif(&mut a[j], &mut b[j], Some(&inv[j * stride]));
                }
            }
            m /= 2;
        }
        let g = splat(&self.scale_block[k0 / len]);
        for (v, s) in buf.iter_mut().zip(&self.scale_leaf) {
            *v = mul4(&mul4(v, s), &g);
        }
        let mut m = 1;
        while m < len {
            let stride = self.n / (2 * m);
            for block in buf.chunks_exact_mut(2 * m) {
                let (a, b) = block.split_at_mut(m);
                dit(&mut a[0], &mut b[0], None);
                for j in 1..m {
                    dit(&mut a[j], &mut b[j], Some(&fwd[j * stride]));
                }
            }
            m *= 2;
        }
    }
}

/// The DIF stages with half-size n/2 (lanes 0-2, 1-3, twiddles w^k,
/// w^(k+q)) and n/4 (lanes 0-1, 2-3, twiddle w^(2k)) of vector k.
#[inline(always)]
fn dif_lanes(v: V, tw: &[[u32; 9]], k: usize, q: usize) -> V {
    let mut lo = [u32x4_splat(0); 9];
    let mut hi = lo;
    for i in 0..9 {
        lo[i] = i32x4_shuffle::<0, 1, 0, 1>(v[i], v[i]);
        hi[i] = i32x4_shuffle::<2, 3, 2, 3>(v[i], v[i]);
    }
    let s = add4(&lo, &hi);
    let d = mul4(&sub4(&lo, &hi), &lanes2(&tw[k], &tw[k + q]));
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = i32x4_shuffle::<0, 1, 6, 7>(s[i], d[i]);
    }
    for i in 0..9 {
        lo[i] = i32x4_shuffle::<0, 0, 2, 2>(v[i], v[i]);
        hi[i] = i32x4_shuffle::<1, 1, 3, 3>(v[i], v[i]);
    }
    let s = add4(&lo, &hi);
    let d = mul4(&sub4(&lo, &hi), &splat(&tw[2 * k]));
    for i in 0..9 {
        v[i] = i32x4_shuffle::<0, 5, 2, 7>(s[i], d[i]);
    }
    v
}

/// Transpose of [`dif_lanes`]: the n/4 stage's DIT butterflies, then the
/// n/2 stage's.
#[inline(always)]
fn dit_lanes(v: V, tw: &[[u32; 9]], k: usize, q: usize) -> V {
    let mut lo = [u32x4_splat(0); 9];
    let mut hi = lo;
    for i in 0..9 {
        lo[i] = i32x4_shuffle::<0, 0, 2, 2>(v[i], v[i]);
        hi[i] = i32x4_shuffle::<1, 1, 3, 3>(v[i], v[i]);
    }
    let t = mul4(&hi, &splat(&tw[2 * k]));
    let (s, d) = (add4(&lo, &t), sub4(&lo, &t));
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = i32x4_shuffle::<0, 5, 2, 7>(s[i], d[i]);
    }
    for i in 0..9 {
        lo[i] = i32x4_shuffle::<0, 1, 0, 1>(v[i], v[i]);
        hi[i] = i32x4_shuffle::<2, 3, 2, 3>(v[i], v[i]);
    }
    let t = mul4(&hi, &lanes2(&tw[k], &tw[k + q]));
    let (s, d) = (add4(&lo, &t), sub4(&lo, &t));
    for i in 0..9 {
        v[i] = i32x4_shuffle::<0, 1, 6, 7>(s[i], d[i]);
    }
    v
}
