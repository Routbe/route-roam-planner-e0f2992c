//! Bulletproofs range proofs (Bünz et al., IEEE S&P 2018, sections 4.1–4.2
//! with the inner-product argument of section 3) over G1 of BLS12-381,
//! proving that a Pedersen commitment V = v·g + γ·h hides v ∈ [0, 2^64 - 1].
//!
//! Fixed shape: n = 64 bits, log2(n) = 6 inner-product rounds, one proof is
//! always exactly PROOF_LEN = 928 octets:
//!   A | S | T1 | T2 | L_1..L_6 | R_1..R_6   (16 compressed G1 points)
//!   τx | μ | t̂ | a | b                    (5 big-endian scalars)
//!
//! Memory: every vector (a_L, a_R, s_L, s_R, l, r and the folded generator
//! vectors of the inner-product reduction) lives in one fixed-size `Arena`
//! on the stack of the imported linear memory; nothing is allocated. The
//! arena and every intermediate secret scalar (α, ρ, τ1, τ2, t1, t2, the
//! blinding γ, the bit vectors) are overwritten with volatile writes before
//! the prover returns, on success and on error alike (`Drop`).
//!
//! Side channels: the bits of v select points with `conditional_select`
//! (complete projective addition, no secret-dependent branch); scalar
//! multiplication in `bls12_381` is constant-time. The verifier only handles
//! public data. Every point of a proof is decoded with on-curve, subgroup
//! and identity checks, and every scalar must be canonical (< q).
//!
//! Fiat–Shamir: a SHA-256 running transcript that starts from a fixed domain,
//! the bit length and a caller context (for example the booking id), and
//! absorbs V, A, S, T1, T2, τx, μ, t̂ and every L_j, R_j before the
//! challenge that depends on them. Challenges are hash_to_scalar outputs
//! (expand_message_xmd, 48 octets mod q) and must be non-zero.

use crate::codec::{g1_bytes, g1_from_bytes, scalar_from_be, scalar_to_be, G1_LEN, SCALAR_LEN};
use crate::limits::MAX_OCTETS;
use crate::pedersen::{generator, value_u64, Commitment, PedersenGens};
use crate::random::ScalarSource;
use crate::xmd::Xmd;
use crate::{wipe, Error, Result};
use bls12_381::{G1Projective, Scalar};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Bit length of the range: v ∈ [0, 2^N - 1].
pub const N: usize = 64;
/// Inner-product rounds.
pub const LOG_N: usize = 6;
/// Points and scalars of one proof.
const POINTS: usize = 4 + 2 * LOG_N;
const SCALARS: usize = 5;
pub const PROOF_LEN: usize = POINTS * G1_LEN + SCALARS * SCALAR_LEN;
/// Random scalars per proof: α, ρ, τ1, τ2, s_L (n), s_R (n).
pub const RANDOM_SCALARS: usize = 4 + 2 * N;

const TRANSCRIPT_DOMAIN: &[u8] = b"ROUT_ZK_V1_BULLETPROOFS_RANGE_BLS12381G1_SHA-256";
const CHALLENGE_DST: &[u8] = b"ROUT_ZK_V1_BULLETPROOFS_RANGE_BLS12381G1_XMD:SHA-256_H2S_";

/// The vector generators G_1..G_n, H_1..H_n and the inner-product base u.
pub struct BulletproofGens {
    pub g: [G1Projective; N],
    pub h: [G1Projective; N],
    pub u: G1Projective,
}

impl BulletproofGens {
    pub fn canonical() -> Self {
        let mut g = [G1Projective::identity(); N];
        let mut h = [G1Projective::identity(); N];
        for i in 0..N {
            g[i] = generator(b'G', i as u32);
            h[i] = generator(b'H', i as u32);
        }
        BulletproofGens { g, h, u: generator(b'u', 0) }
    }
}

/// A range proof (public).
#[derive(Clone, Copy, Debug)]
pub struct RangeProof {
    pub a: G1Projective,
    pub s: G1Projective,
    pub t1: G1Projective,
    pub t2: G1Projective,
    pub l: [G1Projective; LOG_N],
    pub r: [G1Projective; LOG_N],
    pub tau_x: Scalar,
    pub mu: Scalar,
    pub t_hat: Scalar,
    pub ipa_a: Scalar,
    pub ipa_b: Scalar,
}

impl RangeProof {
    pub fn to_bytes(&self) -> [u8; PROOF_LEN] {
        let mut out = [0u8; PROOF_LEN];
        let mut at = 0;
        let mut put = |b: &[u8]| {
            out[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        };
        put(&g1_bytes(&self.a));
        put(&g1_bytes(&self.s));
        put(&g1_bytes(&self.t1));
        put(&g1_bytes(&self.t2));
        for p in self.l.iter() {
            put(&g1_bytes(p));
        }
        for p in self.r.iter() {
            put(&g1_bytes(p));
        }
        for s in [&self.tau_x, &self.mu, &self.t_hat, &self.ipa_a, &self.ipa_b] {
            put(&scalar_to_be(s));
        }
        out
    }

    /// Strict decoding: exact length, every point on the curve, in the
    /// prime-order subgroup and not the identity, every scalar canonical.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != PROOF_LEN {
            return Err(Error::Invalid);
        }
        let pt = |i: usize| -> Result<G1Projective> { Ok(G1Projective::from(g1_from_bytes(&b[i * G1_LEN..(i + 1) * G1_LEN])?)) };
        let off = POINTS * G1_LEN;
        let sc = |i: usize| scalar_from_be(&b[off + i * SCALAR_LEN..off + (i + 1) * SCALAR_LEN]);
        let mut l = [G1Projective::identity(); LOG_N];
        let mut r = [G1Projective::identity(); LOG_N];
        for j in 0..LOG_N {
            l[j] = pt(4 + j)?;
            r[j] = pt(4 + LOG_N + j)?;
        }
        Ok(RangeProof {
            a: pt(0)?,
            s: pt(1)?,
            t1: pt(2)?,
            t2: pt(3)?,
            l,
            r,
            tau_x: sc(0)?,
            mu: sc(1)?,
            t_hat: sc(2)?,
            ipa_a: sc(3)?,
            ipa_b: sc(4)?,
        })
    }
}

/// Running Fiat–Shamir transcript (SHA-256 chaining).
struct Transcript {
    st: [u8; 32],
}

impl Transcript {
    fn new(ctx: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(TRANSCRIPT_DOMAIN);
        h.update((N as u64).to_be_bytes());
        h.update((ctx.len() as u64).to_be_bytes());
        h.update(ctx);
        Transcript { st: h.finalize().into() }
    }

    fn append(&mut self, label: u8, bytes: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.st);
        h.update([label]);
        h.update(bytes);
        self.st = h.finalize().into();
    }

    fn point(&mut self, label: u8, p: &G1Projective) {
        self.append(label, &g1_bytes(p));
    }

    fn scalar(&mut self, label: u8, s: &Scalar) {
        self.append(label, &scalar_to_be(s));
    }

    fn challenge(&mut self, label: u8) -> Result<Scalar> {
        let mut x = Xmd::new();
        x.update(&self.st).update(&[label]);
        let c = x.to_scalar(CHALLENGE_DST)?;
        if bool::from(c.ct_eq(&Scalar::zero())) {
            return Err(Error::Rejected);
        }
        self.scalar(label, &c);
        Ok(c)
    }
}

/// All prover buffers in one fixed block; wiped (volatile) on drop.
struct Arena {
    /// α, ρ, τ1, τ2, s_L[n], s_R[n].
    rand: [Scalar; RANDOM_SCALARS],
    a_l: [Scalar; N],
    a_r: [Scalar; N],
    /// l(x), then the folded inner-product vector a.
    l: [Scalar; N],
    /// r(x), then the folded inner-product vector b.
    r: [Scalar; N],
    y_pow: [Scalar; N],
    /// Folded G and H' vectors of the inner-product reduction (public).
    g: [G1Projective; N],
    h: [G1Projective; N],
    /// Loose secret scalars: γ, t1, t2, c_L, c_R, scratch.
    tmp: [Scalar; 8],
}

impl Arena {
    fn new() -> Self {
        Arena {
            rand: [Scalar::zero(); RANDOM_SCALARS],
            a_l: [Scalar::zero(); N],
            a_r: [Scalar::zero(); N],
            l: [Scalar::zero(); N],
            r: [Scalar::zero(); N],
            y_pow: [Scalar::zero(); N],
            g: [G1Projective::identity(); N],
            h: [G1Projective::identity(); N],
            tmp: [Scalar::zero(); 8],
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        wipe::scalars(&mut self.rand);
        wipe::scalars(&mut self.a_l);
        wipe::scalars(&mut self.a_r);
        wipe::scalars(&mut self.l);
        wipe::scalars(&mut self.r);
        wipe::scalars(&mut self.y_pow);
        wipe::scalars(&mut self.tmp);
        for p in self.g.iter_mut().chain(self.h.iter_mut()) {
            unsafe { core::ptr::write_volatile(p, G1Projective::identity()) };
        }
    }
}

/// Test hook: true once every secret buffer of the arena is zero.
#[cfg(test)]
fn arena_is_zero(a: &Arena) -> bool {
    let z = Scalar::zero();
    a.rand.iter().chain(a.a_l.iter()).chain(a.a_r.iter()).chain(a.l.iter()).chain(a.r.iter()).chain(a.tmp.iter()).all(|s| *s == z)
}

fn inner(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut acc = Scalar::zero();
    for (x, y) in a.iter().zip(b.iter()) {
        acc += x * y;
    }
    acc
}

fn powers(base: &Scalar, out: &mut [Scalar]) {
    let mut p = Scalar::one();
    for o in out.iter_mut() {
        *o = p;
        p *= base;
    }
}

fn inverse(x: &Scalar) -> Result<Scalar> {
    Option::<Scalar>::from(x.invert()).ok_or(Error::Rejected)
}

/// Σ 2^i for i < 64 = 2^64 - 1.
fn sum_two_powers() -> Scalar {
    Scalar::from(u64::MAX)
}

/// δ(y, z) = (z - z²)·⟨1, y^n⟩ - z³·⟨1, 2^n⟩.
fn delta(y: &Scalar, z: &Scalar) -> Scalar {
    let mut sum_y = Scalar::zero();
    let mut p = Scalar::one();
    for _ in 0..N {
        sum_y += p;
        p *= y;
    }
    let z2 = z.square();
    (z - z2) * sum_y - z2 * z * sum_two_powers()
}

/// Proves that `commitment = value·g + blinding·h` hides a value in
/// [0, 2^64 - 1]. A value outside the range (including any "negative"
/// field element q - k) is refused with INVALID before anything is computed.
pub fn prove<R: ScalarSource>(
    pg: &PedersenGens,
    bg: &BulletproofGens,
    value: &Scalar,
    blinding: &Scalar,
    ctx: &[u8],
    rng: &mut R,
) -> Result<(Commitment, RangeProof)> {
    let mut v = value_u64(value).ok_or(Error::Invalid)?;
    let v_commit = pg.commit(value, blinding);
    let p = prove_bits(pg, bg, v, &v_commit, blinding, ctx, rng);
    unsafe { core::ptr::write_volatile(&mut v, 0) };
    Ok((v_commit, p?))
}

/// The protocol itself, for a commitment the caller claims hides the bits
/// `v`. `prove` only calls it with the matching commitment; the unit tests
/// call it with a commitment to an out-of-range value to show the verifier
/// rejects such a (cheating) proof.
fn prove_bits<R: ScalarSource>(
    pg: &PedersenGens,
    bg: &BulletproofGens,
    v: u64,
    v_commit: &Commitment,
    blinding: &Scalar,
    ctx: &[u8],
    rng: &mut R,
) -> Result<RangeProof> {
    let mut arena = Arena::new();
    let mut bits = v;
    let r = prove_in(&mut arena, pg, bg, bits, v_commit, blinding, ctx, rng);
    unsafe { core::ptr::write_volatile(&mut bits, 0) };
    drop(arena); // volatile wipe of every secret buffer
    r
}

#[allow(clippy::too_many_arguments)]
fn prove_in<R: ScalarSource>(
    w: &mut Arena,
    pg: &PedersenGens,
    bg: &BulletproofGens,
    v: u64,
    v_commit: &Commitment,
    blinding: &Scalar,
    ctx: &[u8],
    rng: &mut R,
) -> Result<RangeProof> {
    if ctx.len() > MAX_OCTETS {
        return Err(Error::TooLarge);
    }
    rng.fill(&mut w.rand)?;
    w.tmp[0] = *blinding;
    // α = rand[0], ρ = rand[1], τ1 = rand[2], τ2 = rand[3]; read in place so
    // no copy outlives the arena.
    let one = Scalar::one();

    // a_L = bits(v), a_R = a_L - 1^n; A = α·h + Σ a_L,i·G_i + Σ a_R,i·H_i
    // with a_L,i ∈ {0, 1} and a_R,i ∈ {-1, 0}, selected without branching.
    let id = G1Projective::identity();
    let mut a_pt = pg.h * w.rand[0];
    for i in 0..N {
        let bit = Choice::from(((v >> i) & 1) as u8);
        w.a_l[i] = Scalar::conditional_select(&Scalar::zero(), &one, bit);
        w.a_r[i] = w.a_l[i] - one;
        a_pt += G1Projective::conditional_select(&id, &bg.g[i], bit);
        a_pt -= G1Projective::conditional_select(&bg.h[i], &id, bit);
    }
    // S = ρ·h + Σ s_L,i·G_i + Σ s_R,i·H_i
    let mut s_pt = pg.h * w.rand[1];
    for i in 0..N {
        s_pt += bg.g[i] * w.rand[4 + i];
        s_pt += bg.h[i] * w.rand[4 + N + i];
    }

    let mut t = Transcript::new(ctx);
    t.point(b'V', &v_commit.0);
    t.point(b'A', &a_pt);
    t.point(b'S', &s_pt);
    let y = t.challenge(1)?;
    let z = t.challenge(2)?;
    let z2 = z.square();
    powers(&y, &mut w.y_pow);

    // l0 = a_L - z·1, r0 = y^n ∘ (a_R + z·1) + z²·2^n (kept in l, r);
    // l1 = s_L, r1 = y^n ∘ s_R; t1 = ⟨l0, r1⟩ + ⟨l1, r0⟩, t2 = ⟨l1, r1⟩.
    let mut two = Scalar::one();
    w.tmp[1] = Scalar::zero(); // t1
    w.tmp[2] = Scalar::zero(); // t2
    for i in 0..N {
        w.l[i] = w.a_l[i] - z;
        w.r[i] = w.y_pow[i] * (w.a_r[i] + z) + z2 * two;
        two = two.double();
        w.tmp[5] = w.y_pow[i] * w.rand[4 + N + i]; // r1,i
        w.tmp[1] += w.l[i] * w.tmp[5] + w.rand[4 + i] * w.r[i];
        w.tmp[2] += w.rand[4 + i] * w.tmp[5];
    }
    let t1_pt = pg.g * w.tmp[1] + pg.h * w.rand[2];
    let t2_pt = pg.g * w.tmp[2] + pg.h * w.rand[3];
    t.point(b'1', &t1_pt);
    t.point(b'2', &t2_pt);
    let x = t.challenge(3)?;

    // l = l0 + x·l1, r = r0 + x·r1, t̂ = ⟨l, r⟩.
    for i in 0..N {
        w.l[i] += x * w.rand[4 + i];
        w.r[i] += x * w.y_pow[i] * w.rand[4 + N + i];
    }
    let t_hat = inner(&w.l, &w.r);
    let tau_x = w.rand[3] * x.square() + w.rand[2] * x + z2 * w.tmp[0];
    let mu = w.rand[0] + w.rand[1] * x;
    t.scalar(b't', &tau_x);
    t.scalar(b'm', &mu);
    t.scalar(b'h', &t_hat);
    let ww = t.challenge(4)?;
    let q = bg.u * ww;

    // Inner-product argument for P' = ⟨l, G⟩ + ⟨r, H'⟩ + ⟨l, r⟩·Q with
    // H'_i = y^{-i}·H_i; generators and vectors fold in place in the arena.
    let y_inv = inverse(&y)?;
    let mut yi = Scalar::one();
    for i in 0..N {
        w.g[i] = bg.g[i];
        w.h[i] = bg.h[i] * yi;
        yi *= y_inv;
    }
    let mut l_pts = [G1Projective::identity(); LOG_N];
    let mut r_pts = [G1Projective::identity(); LOG_N];
    let mut n = N;
    for j in 0..LOG_N {
        let m = n / 2;
        w.tmp[3] = inner(&w.l[..m], &w.r[m..n]); // c_L
        w.tmp[4] = inner(&w.l[m..n], &w.r[..m]); // c_R
        let mut lp = q * w.tmp[3];
        let mut rp = q * w.tmp[4];
        for i in 0..m {
            lp += w.g[m + i] * w.l[i] + w.h[i] * w.r[m + i];
            rp += w.g[i] * w.l[m + i] + w.h[m + i] * w.r[i];
        }
        t.point(b'L', &lp);
        t.point(b'R', &rp);
        let xj = t.challenge(16 + j as u8)?;
        let xj_inv = inverse(&xj)?;
        for i in 0..m {
            w.l[i] = w.l[i] * xj + w.l[m + i] * xj_inv;
            w.r[i] = w.r[i] * xj_inv + w.r[m + i] * xj;
            w.g[i] = w.g[i] * xj_inv + w.g[m + i] * xj;
            w.h[i] = w.h[i] * xj + w.h[m + i] * xj_inv;
        }
        l_pts[j] = lp;
        r_pts[j] = rp;
        n = m;
    }

    Ok(RangeProof {
        a: a_pt,
        s: s_pt,
        t1: t1_pt,
        t2: t2_pt,
        l: l_pts,
        r: r_pts,
        tau_x,
        mu,
        t_hat,
        ipa_a: w.l[0],
        ipa_b: w.r[0],
    })
}

/// Verifies that `commitment` hides a value in [0, 2^64 - 1] under the
/// canonical generators and the caller context. Rejection is coarse.
pub fn verify(pg: &PedersenGens, bg: &BulletproofGens, commitment: &Commitment, proof: &RangeProof, ctx: &[u8]) -> Result<()> {
    if ctx.len() > MAX_OCTETS {
        return Err(Error::TooLarge);
    }
    let mut t = Transcript::new(ctx);
    t.point(b'V', &commitment.0);
    t.point(b'A', &proof.a);
    t.point(b'S', &proof.s);
    let y = t.challenge(1)?;
    let z = t.challenge(2)?;
    t.point(b'1', &proof.t1);
    t.point(b'2', &proof.t2);
    let x = t.challenge(3)?;
    t.scalar(b't', &proof.tau_x);
    t.scalar(b'm', &proof.mu);
    t.scalar(b'h', &proof.t_hat);
    let ww = t.challenge(4)?;
    let mut xs = [Scalar::zero(); LOG_N];
    let mut xs_inv = [Scalar::zero(); LOG_N];
    for j in 0..LOG_N {
        t.point(b'L', &proof.l[j]);
        t.point(b'R', &proof.r[j]);
        xs[j] = t.challenge(16 + j as u8)?;
        xs_inv[j] = inverse(&xs[j])?;
    }
    let z2 = z.square();

    // (1) t̂·g + τx·h == z²·V + δ(y,z)·g + x·T1 + x²·T2
    let lhs = pg.g * proof.t_hat + pg.h * proof.tau_x;
    let rhs = commitment.0 * z2 + pg.g * delta(&y, &z) + proof.t1 * x + proof.t2 * x.square();
    let ok1 = (lhs - rhs).is_identity();

    // (2) A + x·S - z·ΣG_i + Σ(z + z²·2^i·y^{-i} - b·s_i^{-1}·y^{-i})·H_i
    //     - Σ a·s_i·G_i - μ·h + (t̂ - a·b)·w·u + Σ(x_j²·L_j + x_j^{-2}·R_j) == 0
    // with s_i = Π_j x_j^{±1} (+1 where bit (LOG_N - 1 - j) of i is set).
    let mut s = [Scalar::one(); N];
    for (i, si) in s.iter_mut().enumerate() {
        for j in 0..LOG_N {
            let bit = (i >> (LOG_N - 1 - j)) & 1;
            *si *= if bit == 1 { xs[j] } else { xs_inv[j] };
        }
    }
    let y_inv = inverse(&y)?;
    let mut acc = proof.a + proof.s * x - pg.h * proof.mu + bg.u * ((proof.t_hat - proof.ipa_a * proof.ipa_b) * ww);
    for j in 0..LOG_N {
        acc += proof.l[j] * xs[j].square() + proof.r[j] * xs_inv[j].square();
    }
    let mut yi = Scalar::one();
    let mut two = Scalar::one();
    for i in 0..N {
        let gc = -z - proof.ipa_a * s[i];
        // s_i^{-1} = s_{n-1-i}: flipping every bit flips every exponent.
        let hc = z + (z2 * two - proof.ipa_b * s[N - 1 - i]) * yi;
        acc += bg.g[i] * gc + bg.h[i] * hc;
        yi *= y_inv;
        two = two.double();
    }
    let ok2 = acc.is_identity();
    if bool::from(ok1 & ok2) {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::Opening;
    use crate::random::Seeded;

    const SEED: &[u8] = b"rout-zk 7b unit test seed";
    const DST: &[u8] = b"ROUT_ZK_TEST_RANDOM_SCALARS_";

    fn rng() -> Seeded<'static> {
        Seeded { seed: SEED, dst: DST }
    }

    #[test]
    fn arena_wipes_on_drop() {
        let mut a = Arena::new();
        a.rand[3] = Scalar::from(9u64);
        a.l[7] = Scalar::from(5u64);
        a.tmp[0] = Scalar::from(1u64);
        let p: *const Arena = &a;
        // Drop in place and inspect the same storage afterwards.
        unsafe { core::ptr::drop_in_place(&mut a as *mut Arena) };
        assert!(arena_is_zero(unsafe { &*p }));
        core::mem::forget(a);
    }

    #[test]
    fn cheating_prover_cannot_prove_minus_one() {
        // C = commit(-1, γ) = commit(q - 1, γ): the prover lies that it hides
        // the 64 one-bits of u64::MAX. The verifier must reject.
        let pg = PedersenGens::canonical();
        let bg = BulletproofGens::canonical();
        let gamma = Scalar::from(12345u64);
        let c = pg.commit(&(-Scalar::one()), &gamma);
        let p = prove_bits(&pg, &bg, u64::MAX, &c, &gamma, b"ctx", &mut rng()).unwrap();
        assert_eq!(verify(&pg, &bg, &c, &p, b"ctx"), Err(Error::Rejected));
    }

    #[test]
    fn cheating_prover_cannot_prove_two_pow_64() {
        // C hides 2^64 (one past the range); the prover claims the low 64 bits (0).
        let pg = PedersenGens::canonical();
        let bg = BulletproofGens::canonical();
        let gamma = Scalar::from(777u64);
        let two64 = Scalar::from(u64::MAX) + Scalar::one();
        let c = pg.commit(&two64, &gamma);
        let p = prove_bits(&pg, &bg, 0, &c, &gamma, b"ctx", &mut rng()).unwrap();
        assert_eq!(verify(&pg, &bg, &c, &p, b"ctx"), Err(Error::Rejected));
        let p = prove_bits(&pg, &bg, u64::MAX, &c, &gamma, b"ctx", &mut rng()).unwrap();
        assert_eq!(verify(&pg, &bg, &c, &p, b"ctx"), Err(Error::Rejected));
    }

    #[test]
    fn overbooked_remainder_cannot_be_proven_even_by_a_cheater() {
        let pg = PedersenGens::canonical();
        let bg = BulletproofGens::canonical();
        let cap = Opening::from_u64(3, Scalar::from(11u64));
        let booking = Opening::from_u64(5, Scalar::from(4u64));
        let rem = cap.sub(&booking); // 3 - 5 = q - 2
        let c_rem = pg.commit(&cap.value, &cap.blinding).sub(&pg.commit(&booking.value, &booking.blinding));
        assert!(pg.opens(&c_rem, &rem));
        let p = prove_bits(&pg, &bg, u64::MAX - 1, &c_rem, &rem.blinding, b"slot", &mut rng()).unwrap();
        assert_eq!(verify(&pg, &bg, &c_rem, &p, b"slot"), Err(Error::Rejected));
    }
}
