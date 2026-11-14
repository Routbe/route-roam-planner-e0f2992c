//! Shamir secret sharing over GF(2^8) (Stap 6, recovery v4).
//!
//! Field: GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
//! Constant time: multiplication is a fixed 8-round shift-and-add with masks,
//! inversion is the fixed addition chain a^254; no lookup tables, no branch or
//! index depends on a secret byte (only on the public k, n, length and x).
//!
//! Share i (x = i + 1) is `x || y[0..len]`. Each share gets a commitment
//! SHA-256("rout.sss.commit.v1" || len(ctx) || ctx || x || y) so a corrupted,
//! swapped or foreign share is refused before interpolation ("invalid hash"),
//! instead of silently combining into noise.
//!
//! Every coefficient and intermediate lives on the stack of this module and is
//! zeroized before return; the host zero-fills the whole linear memory after.
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const MAX_SECRET: usize = 64;
pub const MAX_SHARES: usize = 16;
pub const COMMIT_LEN: usize = 32;
pub const CONTEXT_MAX: usize = 256;

#[inline(never)]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        r ^= a & 0u8.wrapping_sub(b & 1);
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & hi);
        b >>= 1;
        i += 1;
    }
    r
}

/// a^254 = a^-1 for a != 0 (and 0 for 0), by a fixed addition chain.
pub fn gf_inv(a: u8) -> u8 {
    let x2 = gf_mul(a, a);
    let x3 = gf_mul(x2, a);
    let x6 = gf_mul(x3, x3);
    let x12 = gf_mul(x6, x6);
    let x15 = gf_mul(x12, x3);
    let x30 = gf_mul(x15, x15);
    let x60 = gf_mul(x30, x30);
    let x120 = gf_mul(x60, x60);
    let x240 = gf_mul(x120, x120);
    gf_mul(gf_mul(x240, x12), x2)
}

pub fn commitment(ctx: &[u8], x: u8, y: &[u8], out: &mut [u8; COMMIT_LEN]) {
    let mut h = Sha256::new();
    h.update(b"rout.sss.commit.v1");
    h.update([ctx.len() as u8]);
    h.update(ctx);
    h.update([x]);
    h.update(y);
    out.copy_from_slice(&h.finalize());
}

fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d
}

pub fn args_ok(len: usize, k: usize, n: usize, ctx: usize) -> bool {
    len >= 1 && len <= MAX_SECRET && k >= 2 && k <= n && n <= MAX_SHARES && ctx >= 1 && ctx <= CONTEXT_MAX
}

/// Splits `secret` into n shares of threshold k. `random` must hold
/// (k - 1) * len fresh random bytes (the coefficients); it is zeroized here.
/// `shares` gets n * (1 + len) bytes, `commits` n * 32.
pub fn split(secret: &[u8], k: usize, n: usize, ctx: &[u8], random: &mut [u8], shares: &mut [u8], commits: &mut [u8]) -> bool {
    let len = secret.len();
    if !args_ok(len, k, n, ctx.len()) || random.len() != (k - 1) * len || shares.len() != n * (1 + len) || commits.len() != n * COMMIT_LEN {
        random.zeroize();
        return false;
    }
    let mut c = [0u8; COMMIT_LEN];
    for i in 0..n {
        let x = (i + 1) as u8;
        let rec = &mut shares[i * (1 + len)..(i + 1) * (1 + len)];
        rec[0] = x;
        for j in 0..len {
            // Horner from the top coefficient c_{k-1} down to the secret c_0.
            let mut y = random[(k - 2) * len + j];
            let mut t = k - 2;
            while t > 0 {
                y = gf_mul(y, x) ^ random[(t - 1) * len + j];
                t -= 1;
            }
            y = gf_mul(y, x) ^ secret[j];
            rec[1 + j] = y;
        }
        commitment(ctx, x, &rec[1..], &mut c);
        commits[i * COMMIT_LEN..(i + 1) * COMMIT_LEN].copy_from_slice(&c);
    }
    random.zeroize();
    c.zeroize();
    true
}

pub const E_THRESHOLD: i32 = -5;
pub const E_COMMIT: i32 = -6;

/// Lagrange interpolation at 0 over m >= k shares (each 1 + len bytes) whose
/// commitments must all match. Writes len bytes to `out`.
pub fn combine(shares: &[u8], m: usize, len: usize, k: usize, commits: &[u8], ctx: &[u8], out: &mut [u8]) -> Result<(), i32> {
    if !args_ok(len, k, MAX_SHARES, ctx.len()) || m > MAX_SHARES || shares.len() != m * (1 + len) || commits.len() != m * COMMIT_LEN || out.len() != len {
        return Err(-1);
    }
    if m < k {
        return Err(E_THRESHOLD);
    }
    // x values are public: distinct and non-zero.
    let mut xs = [0u8; MAX_SHARES];
    for i in 0..m {
        let x = shares[i * (1 + len)];
        if x == 0 {
            return Err(-1);
        }
        for l in 0..i {
            if xs[l] == x {
                return Err(-1);
            }
        }
        xs[i] = x;
    }
    // Every commitment is checked (no early exit) before any secret arithmetic.
    let mut bad = 0u8;
    let mut c = [0u8; COMMIT_LEN];
    for i in 0..m {
        let rec = &shares[i * (1 + len)..(i + 1) * (1 + len)];
        commitment(ctx, rec[0], &rec[1..], &mut c);
        bad |= ct_eq(&c, &commits[i * COMMIT_LEN..(i + 1) * COMMIT_LEN]);
    }
    c.zeroize();
    if bad != 0 {
        return Err(E_COMMIT);
    }
    // Basis values at 0 depend only on the public x's.
    let mut basis = [0u8; MAX_SHARES];
    for i in 0..m {
        let mut num = 1u8;
        let mut den = 1u8;
        for l in 0..m {
            if l != i {
                num = gf_mul(num, xs[l]);
                den = gf_mul(den, xs[l] ^ xs[i]);
            }
        }
        basis[i] = gf_mul(num, gf_inv(den));
    }
    for j in 0..len {
        let mut acc = 0u8;
        for i in 0..m {
            acc ^= gf_mul(shares[i * (1 + len) + 1 + j], basis[i]);
        }
        out[j] = acc;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inverse_and_field() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
        assert_eq!(gf_mul(0x57, 0x83), 0xc1); // FIPS-197 §4.2
    }
}
