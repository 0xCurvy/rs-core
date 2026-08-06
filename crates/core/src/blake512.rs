//! Original **BLAKE-512** (the SHA-3 finalist, *not* BLAKE2) - a faithful port of
//! `@zk-kit/eddsa-poseidon`'s `blake.ts` (itself adapted from the `blake-hash` npm
//! package). EdDSA-Poseidon's default entry uses this to hash the private key, so
//! the Rust core must reproduce it exactly. Validated by direct golden vectors.
//!
//! This module is a traceable Rust port of the protocol's established JavaScript
//! reference; cross-language parity vectors pin its behavior and prevent an
//! accidental substitution with the incompatible BLAKE2 family.

/// BLAKE-512 initial hash value (IV).
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// BLAKE-512 constants (the `u512` table, as sixteen 64-bit words).
const C: [u64; 16] = [
    0x243f6a8885a308d3,
    0x13198a2e03707344,
    0xa4093822299f31d0,
    0x082efa98ec4e6c89,
    0x452821e638d01377,
    0xbe5466cf34e90c6c,
    0xc0ac29b7c97c50dd,
    0x3f84d5b5b5470917,
    0x9216d5d98979fb1b,
    0xd1310ba698dfb5ac,
    0x2ffd72dbd01adfb7,
    0xb8e1afed6a267e96,
    0xba7c9045f12c7f99,
    0x24a19947b3916cf7,
    0x0801f2e2858efc16,
    0x636920d871574e69,
];

/// Message permutation schedule (`sigma`), 16 rounds × 16.
const SIGMA: [[usize; 16]; 16] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
];

const BLOCK_BYTES: usize = 128;

/// The 0x80…0x01 padding bytes (`padding` in the reference).
const PADDING: [u8; BLOCK_BYTES] = {
    let mut p = [0u8; BLOCK_BYTES];
    p[0] = 0x80;
    p
};

// Mirrors the reference BLAKE-512 G mixing function's signature exactly.
#[allow(clippy::too_many_arguments)]
#[inline]
fn g(
    v: &mut [u64; 16],
    m: &[u64; 16],
    round: usize,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
) {
    let se = SIGMA[round][e];
    let se1 = SIGMA[round][e + 1];
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[se] ^ C[se1]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(25);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[se1] ^ C[se]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(11);
}

// The reference keeps the 128-bit bit-counter as four 32-bit limbs and lets the
// low limb go transiently negative while padding, so we mirror it with i64 limbs
// (values are always small & non-negative at the moment a block is compressed).
fn length_carry(arr: &mut [i64; 4]) {
    for j in 0..3 {
        if arr[j] < 0x1_0000_0000 {
            break;
        }
        arr[j] -= 0x1_0000_0000;
        arr[j + 1] += 1;
    }
}

/// Incremental BLAKE-512 state.
pub struct Blake512 {
    h: [u64; 8],
    block: [u8; BLOCK_BYTES],
    block_offset: usize,
    length: [i64; 4],
    nullt: bool,
}

impl Default for Blake512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake512 {
    pub fn new() -> Self {
        Self {
            h: IV,
            block: [0u8; BLOCK_BYTES],
            block_offset: 0,
            length: [0; 4],
            nullt: false,
        }
    }

    fn compress(&mut self) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.block[i * 8..i * 8 + 8]);
            *word = u64::from_be_bytes(b);
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&C[..8]); // salt is zero: v[8..12] = s ^ C[0..4] = C[0..4]

        if !self.nullt {
            let t0 = ((self.length[1] as u64) << 32) | (self.length[0] as u64 & 0xffff_ffff);
            let t1 = ((self.length[3] as u64) << 32) | (self.length[2] as u64 & 0xffff_ffff);
            v[12] ^= t0;
            v[13] ^= t0;
            v[14] ^= t1;
            v[15] ^= t1;
        }

        for round in 0..16 {
            // column step
            g(&mut v, &m, round, 0, 4, 8, 12, 0);
            g(&mut v, &m, round, 1, 5, 9, 13, 2);
            g(&mut v, &m, round, 2, 6, 10, 14, 4);
            g(&mut v, &m, round, 3, 7, 11, 15, 6);
            // diagonal step
            g(&mut v, &m, round, 0, 5, 10, 15, 8);
            g(&mut v, &m, round, 1, 6, 11, 12, 10);
            g(&mut v, &m, round, 2, 7, 8, 13, 12);
            g(&mut v, &m, round, 3, 4, 9, 14, 14);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8]; // salt mixing is zero
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        while self.block_offset + (data.len() - offset) >= BLOCK_BYTES {
            while self.block_offset < BLOCK_BYTES {
                self.block[self.block_offset] = data[offset];
                self.block_offset += 1;
                offset += 1;
            }
            self.length[0] += (BLOCK_BYTES as i64) * 8;
            length_carry(&mut self.length);
            self.compress();
            self.block_offset = 0;
        }
        while offset < data.len() {
            self.block[self.block_offset] = data[offset];
            self.block_offset += 1;
            offset += 1;
        }
    }

    fn padding(&mut self) {
        let mut len = self.length;
        len[0] += (self.block_offset as i64) * 8;
        length_carry(&mut len);

        // 128-bit big-endian message length: limbs [3,2,1,0].
        let mut msglen = [0u8; 16];
        for i in 0..4 {
            msglen[i * 4..i * 4 + 4].copy_from_slice(&(len[3 - i] as u32).to_be_bytes());
        }

        if self.block_offset == 111 {
            self.length[0] -= 8;
            self.update(&[0x81]); // `oo`
        } else {
            if self.block_offset < 111 {
                if self.block_offset == 0 {
                    self.nullt = true;
                }
                self.length[0] -= ((111 - self.block_offset) as i64) * 8;
                self.update(&PADDING[0..111 - self.block_offset]);
            } else {
                self.length[0] -= ((128 - self.block_offset) as i64) * 8;
                self.update(&PADDING[0..128 - self.block_offset]);
                self.length[0] -= 111 * 8;
                self.update(&PADDING[1..1 + 111]);
                self.nullt = true;
            }
            self.update(&[0x01]); // `zo`
            self.length[0] -= 8;
        }

        self.length[0] -= 128;
        self.update(&msglen);
    }

    pub fn digest(mut self) -> [u8; 64] {
        self.padding();
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

/// One-shot BLAKE-512.
pub fn blake512(data: &[u8]) -> [u8; 64] {
    let mut h = Blake512::new();
    h.update(data);
    h.digest()
}
