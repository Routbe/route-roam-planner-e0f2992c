//! Core BBS operations (draft-irtf-cfrg-bbs-signatures): KeyGen, SkToPk,
//! CoreSign, CoreVerify, CoreProofGen, CoreProofVerify, and the BBS
//! signature interface (api_id = ciphersuite_id || "H2G_HM2S_").
//!
//! The core functions take the generators and message scalars explicitly so
//! that the Blind BBS interface (blind.rs) reuses them unchanged.

use crate::codec::{
    g1_from_bytes, pubkey_from_bytes, scalar_eq, scalar_from_be, scalar_from_be_nonzero, scalar_from_raw, scalar_to_be,
    Absorb, Out, G1_LEN, G2_LEN, SCALAR_LEN,
};
use crate::generators::{create_generators, p1, API_ID_BBS, CIPHERSUITE_ID};
use crate::limits::{MAX_GENERATORS, MAX_MESSAGES, MAX_RANDOM, MAX_SIGNER_MESSAGES};
use crate::random::ScalarSource;
use crate::xmd::{Dst, Xmd};
use crate::{wipe, Error, Result};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use subtle::ConstantTimeEq;

pub const SIGNATURE_LEN: usize = G1_LEN + SCALAR_LEN;
pub const PUBLIC_KEY_LEN: usize = G2_LEN;
/// Proof without undisclosed messages: 3 points and 4 scalars.
pub const PROOF_MIN_LEN: usize = 3 * G1_LEN + 4 * SCALAR_LEN;

/// A message as the Blind BBS draft encodes it: hashed to a scalar, or a raw
/// scalar value. The core BBS interface only uses `Hash`.
#[derive(Clone, Copy, Debug)]
pub enum Msg<'a> {
    Hash(&'a [u8]),
    Raw(&'a [u8]),
}

/// messages_to_scalars (hash: MAP_MSG_TO_SCALAR_AS_HASH_; raw: OS2IP).
pub fn messages_to_scalars(msgs: &[Msg<'_>], api_id: &[u8], out: &mut [Scalar]) -> Result<()> {
    if msgs.len() > out.len() {
        return Err(Error::TooLarge);
    }
    let dst = Dst::new(&[api_id, b"MAP_MSG_TO_SCALAR_AS_HASH_"])?;
    for (m, s) in msgs.iter().zip(out.iter_mut()) {
        *s = match m {
            Msg::Hash(b) => {
                let mut x = Xmd::new();
                x.update(b);
                x.to_scalar(dst.as_bytes())?
            }
            Msg::Raw(b) => scalar_from_raw(b)?,
        };
    }
    Ok(())
}

fn h2s_dst(api_id: &[u8]) -> Result<Dst> {
    Dst::new(&[api_id, b"H2S_"])
}

/// KeyGen(key_material, key_info, key_dst).
pub fn keygen(key_material: &[u8], key_info: &[u8], key_dst: Option<&[u8]>) -> Result<Scalar> {
    if key_material.len() < 32 || key_info.len() > 65_535 {
        return Err(Error::Invalid);
    }
    let default_dst = Dst::new(&[CIPHERSUITE_ID, b"KEYGEN_DST_"])?;
    let dst = key_dst.unwrap_or(default_dst.as_bytes());
    let mut x = Xmd::new();
    x.update(key_material).update(&(key_info.len() as u16).to_be_bytes()).update(key_info);
    let sk = x.to_scalar(dst)?;
    if scalar_eq(&sk, &Scalar::zero()) {
        return Err(Error::Invalid);
    }
    Ok(sk)
}

/// SkToPk(SK) = point_to_octets_E2(SK * BP2).
pub fn sk_to_pk(sk: &Scalar) -> [u8; PUBLIC_KEY_LEN] {
    G2Affine::from(G2Projective::generator() * sk).to_compressed()
}

/// calculate_domain(PK, generators, header, api_id).
pub fn calculate_domain(pk: &[u8], gens: &[G1Projective], header: &[u8], api_id: &[u8]) -> Result<Scalar> {
    if gens.is_empty() {
        return Err(Error::Invalid);
    }
    let mut x = Xmd::new();
    x.absorb(pk);
    x.int((gens.len() - 1) as u64);
    for g in gens {
        x.g1(g);
    }
    x.absorb(api_id);
    x.int(header.len() as u64);
    x.absorb(header);
    x.to_scalar(h2s_dst(api_id)?.as_bytes())
}

/// B = P1 + Q_1 * domain + H_1 * msg_1 + ... (generators = (Q_1, H_1, ...)).
pub fn b_value(gens: &[G1Projective], domain: &Scalar, scalars: &[Scalar]) -> Result<G1Projective> {
    if gens.len() != scalars.len() + 1 {
        return Err(Error::Invalid);
    }
    let mut b = G1Projective::from(p1()) + gens[0] * domain;
    for (h, m) in gens[1..].iter().zip(scalars) {
        b += h * m;
    }
    Ok(b)
}

/// A = B * 1/(SK + e); refuses SK + e = 0 and A = identity.
pub fn finalize_signature(sk: &Scalar, e: &Scalar, b: &G1Projective) -> Result<[u8; SIGNATURE_LEN]> {
    let mut denom = sk + e;
    let inv = denom.invert();
    wipe::scalar(&mut denom);
    let mut inv = Option::<Scalar>::from(inv).ok_or(Error::Invalid)?;
    let a = b * inv;
    wipe::scalar(&mut inv);
    if bool::from(a.is_identity()) {
        return Err(Error::Invalid);
    }
    let mut out = [0u8; SIGNATURE_LEN];
    out[..G1_LEN].copy_from_slice(&G1Affine::from(a).to_compressed());
    out[G1_LEN..].copy_from_slice(&scalar_to_be(e));
    Ok(out)
}

/// CoreSign(SK, PK, generators, header, messages, api_id).
pub fn core_sign(sk: &Scalar, pk: &[u8], gens: &[G1Projective], header: &[u8], scalars: &[Scalar], api_id: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
    let domain = calculate_domain(pk, gens, header, api_id)?;
    let mut x = Xmd::new();
    x.scalar(sk);
    for m in scalars {
        x.scalar(m);
    }
    x.scalar(&domain);
    let mut e = x.to_scalar(h2s_dst(api_id)?.as_bytes())?;
    let b = b_value(gens, &domain, scalars)?;
    let sig = finalize_signature(sk, &e, &b);
    wipe::scalar(&mut e);
    sig
}

/// octets_to_signature: A valid in G1 and not identity, 0 < e < r.
pub fn octets_to_signature(sig: &[u8]) -> Result<(G1Affine, Scalar)> {
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::Invalid);
    }
    let a = g1_from_bytes(&sig[..G1_LEN])?;
    let e = scalar_from_be_nonzero(&sig[G1_LEN..])?;
    Ok((a, e))
}

/// e(P, W) * e(Q, BP2) == 1_GT, as two pairings (no allocator for a
/// multi-Miller loop). Every input point is already subgroup-checked.
fn pairing_product_is_one(p: &G1Affine, w: &G2Affine, q: &G1Affine) -> bool {
    let lhs = pairing(p, w) + pairing(q, &G2Affine::generator());
    bool::from(lhs.ct_eq(&Gt::identity()))
}

/// CoreVerify(PK, signature, generators, header, messages, api_id).
pub fn core_verify(pk: &[u8], sig: &[u8], gens: &[G1Projective], header: &[u8], scalars: &[Scalar], api_id: &[u8]) -> Result<()> {
    let (a, e) = octets_to_signature(sig)?;
    let w = pubkey_from_bytes(pk)?;
    let domain = calculate_domain(pk, gens, header, api_id)?;
    let b = b_value(gens, &domain, scalars)?;
    let q = G1Affine::from(a * e - b);
    if pairing_product_is_one(&a, &w, &q) {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}

/// Strictly ascending indexes below `l`.
pub fn check_indexes(idx: &[usize], l: usize) -> Result<()> {
    let mut prev: Option<usize> = None;
    for &i in idx {
        if i >= l || prev.is_some_and(|p| i <= p) {
            return Err(Error::Invalid);
        }
        prev = Some(i);
    }
    Ok(())
}

/// The complement of `disclosed` in 0..l, in ascending order; returns U.
pub fn undisclosed_of(disclosed: &[usize], l: usize, out: &mut [usize]) -> Result<usize> {
    let mut u = 0;
    let mut d = 0;
    for i in 0..l {
        if d < disclosed.len() && disclosed[d] == i {
            d += 1;
            continue;
        }
        if u >= out.len() {
            return Err(Error::TooLarge);
        }
        out[u] = i;
        u += 1;
    }
    Ok(u)
}

/// ProofInitRes (points and domain).
#[derive(Clone, Copy)]
pub struct InitRes {
    pub abar: G1Projective,
    pub bbar: G1Projective,
    pub d: G1Projective,
    pub t1: G1Projective,
    pub t2: G1Projective,
    pub domain: Scalar,
}

/// One committed disclosure in the challenge: (proof index, C_i, C~_i).
#[derive(Clone, Copy)]
pub struct CommitTerm {
    pub index: usize,
    pub c: G1Projective,
    pub c_tilde: G1Projective,
}

/// ProofInit with explicit random scalars (r1, r2, e~, r1~, r3~, m~_j1, ...).
#[allow(clippy::too_many_arguments)]
pub fn proof_init(
    pk: &[u8],
    a: &G1Affine,
    e: &Scalar,
    gens: &[G1Projective],
    header: &[u8],
    scalars: &[Scalar],
    undisclosed: &[usize],
    rnd: &[Scalar],
    api_id: &[u8],
) -> Result<InitRes> {
    if rnd.len() != 5 + undisclosed.len() {
        return Err(Error::Invalid);
    }
    let (r1, r2, e_t, r1_t, r3_t) = (&rnd[0], &rnd[1], &rnd[2], &rnd[3], &rnd[4]);
    let domain = calculate_domain(pk, gens, header, api_id)?;
    let b = b_value(gens, &domain, scalars)?;
    let d = b * r2;
    let mut r1r2 = r1 * r2;
    let abar = a * r1r2;
    wipe::scalar(&mut r1r2);
    let bbar = d * r1 - abar * e;
    let t1 = abar * e_t + d * r1_t;
    let mut t2 = d * r3_t;
    for (k, &j) in undisclosed.iter().enumerate() {
        t2 += gens[j + 1] * rnd[5 + k];
    }
    Ok(InitRes { abar, bbar, d, t1, t2, domain })
}

/// ProofChallengeCalculate. `commitments` is `None` for core BBS and
/// `Some(..)` (possibly empty) for Blind BBS, whose challenge always absorbs
/// the commitment array.
pub fn challenge(
    init: &InitRes,
    disclosed_idx: &[usize],
    disclosed: &[Scalar],
    commitments: Option<&[CommitTerm]>,
    ph: &[u8],
    api_id: &[u8],
) -> Result<Scalar> {
    if disclosed_idx.len() != disclosed.len() {
        return Err(Error::Invalid);
    }
    let mut x = Xmd::new();
    x.int(disclosed_idx.len() as u64);
    for (i, m) in disclosed_idx.iter().zip(disclosed) {
        x.int(*i as u64);
        x.scalar(m);
    }
    x.g1(&init.abar);
    x.g1(&init.bbar);
    x.g1(&init.d);
    x.g1(&init.t1);
    x.g1(&init.t2);
    x.scalar(&init.domain);
    if let Some(cs) = commitments {
        x.int(cs.len() as u64);
        for t in cs {
            x.int(t.index as u64);
            x.g1(&t.c);
            x.g1(&t.c_tilde);
        }
    }
    x.int(ph.len() as u64);
    x.absorb(ph);
    x.to_scalar(h2s_dst(api_id)?.as_bytes())
}

/// ProofFinalize: writes (Abar, Bbar, D, e^, r1^, r3^, m^..., c).
pub fn proof_finalize(init: &InitRes, c: &Scalar, e: &Scalar, rnd: &[Scalar], undisclosed_scalars: &[Scalar], out: &mut Out<'_>) -> Result<()> {
    if rnd.len() != 5 + undisclosed_scalars.len() {
        return Err(Error::Invalid);
    }
    let (r1, r2, e_t, r1_t, r3_t) = (&rnd[0], &rnd[1], &rnd[2], &rnd[3], &rnd[4]);
    let mut r3 = Option::<Scalar>::from(r2.invert()).ok_or(Error::Invalid)?;
    let mut e_hat = e_t + e * c;
    let mut r1_hat = r1_t - r1 * c;
    let mut r3_hat = r3_t - r3 * c;
    out.g1(&init.abar);
    out.g1(&init.bbar);
    out.g1(&init.d);
    out.scalar(&e_hat);
    out.scalar(&r1_hat);
    out.scalar(&r3_hat);
    for (k, m) in undisclosed_scalars.iter().enumerate() {
        let mut h = rnd[5 + k] + m * c;
        out.scalar(&h);
        wipe::scalar(&mut h);
    }
    out.scalar(c);
    wipe::scalar(&mut r3);
    wipe::scalar(&mut e_hat);
    wipe::scalar(&mut r1_hat);
    wipe::scalar(&mut r3_hat);
    Ok(())
}

/// A decoded BBS proof (octets_to_proof).
pub struct Proof {
    pub abar: G1Affine,
    pub bbar: G1Affine,
    pub d: G1Affine,
    pub e_hat: Scalar,
    pub r1_hat: Scalar,
    pub r3_hat: Scalar,
    pub hats: [Scalar; MAX_MESSAGES],
    pub u: usize,
    pub c: Scalar,
}

/// octets_to_proof: three valid non-identity G1 points, then scalars in 1..r-1.
pub fn octets_to_proof(b: &[u8]) -> Result<Proof> {
    if b.len() < PROOF_MIN_LEN || (b.len() - 3 * G1_LEN) % SCALAR_LEN != 0 {
        return Err(Error::Invalid);
    }
    let n_scalars = (b.len() - 3 * G1_LEN) / SCALAR_LEN;
    let u = n_scalars - 4;
    if u > MAX_MESSAGES {
        return Err(Error::TooLarge);
    }
    let abar = g1_from_bytes(&b[0..G1_LEN])?;
    let bbar = g1_from_bytes(&b[G1_LEN..2 * G1_LEN])?;
    let d = g1_from_bytes(&b[2 * G1_LEN..3 * G1_LEN])?;
    let s = |k: usize| scalar_from_be_nonzero(&b[3 * G1_LEN + k * SCALAR_LEN..3 * G1_LEN + (k + 1) * SCALAR_LEN]);
    let mut hats = [Scalar::zero(); MAX_MESSAGES];
    for (k, h) in hats.iter_mut().take(u).enumerate() {
        *h = s(3 + k)?;
    }
    Ok(Proof { abar, bbar, d, e_hat: s(0)?, r1_hat: s(1)?, r3_hat: s(2)?, hats, u, c: s(3 + u)? })
}

/// ProofVerifyInit.
pub fn proof_verify_init(
    pk: &[u8],
    proof: &Proof,
    gens: &[G1Projective],
    header: &[u8],
    disclosed: &[Scalar],
    disclosed_idx: &[usize],
    api_id: &[u8],
) -> Result<InitRes> {
    let r = disclosed_idx.len();
    if disclosed.len() != r {
        return Err(Error::Invalid);
    }
    let l = r + proof.u;
    check_indexes(disclosed_idx, l)?;
    if gens.len() != l + 1 {
        return Err(Error::Invalid);
    }
    let mut undisclosed = [0usize; MAX_MESSAGES];
    let u = undisclosed_of(disclosed_idx, l, &mut undisclosed)?;
    if u != proof.u {
        return Err(Error::Invalid);
    }
    let domain = calculate_domain(pk, gens, header, api_id)?;
    let abar = G1Projective::from(proof.abar);
    let bbar = G1Projective::from(proof.bbar);
    let d = G1Projective::from(proof.d);
    let t1 = bbar * proof.c + abar * proof.e_hat + d * proof.r1_hat;
    let mut bv = G1Projective::from(p1()) + gens[0] * domain;
    for (i, m) in disclosed_idx.iter().zip(disclosed) {
        bv += gens[i + 1] * m;
    }
    let mut t2 = bv * proof.c + d * proof.r3_hat;
    for (k, &j) in undisclosed[..u].iter().enumerate() {
        t2 += gens[j + 1] * proof.hats[k];
    }
    Ok(InitRes { abar, bbar, d, t1, t2, domain })
}

/// The final checks of CoreProofVerify: cp == challenge (constant time) and
/// e(Abar, W) * e(Bbar, -BP2) == 1.
pub fn proof_accept(pk: &[u8], proof: &Proof, challenge: &Scalar) -> Result<()> {
    let w = pubkey_from_bytes(pk)?;
    if !scalar_eq(&proof.c, challenge) {
        return Err(Error::Rejected);
    }
    let neg_bbar = -proof.bbar;
    if pairing_product_is_one(&proof.abar, &w, &neg_bbar) {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}

/// CoreProofGen with an explicit random source; returns the proof length.
#[allow(clippy::too_many_arguments)]
pub fn core_proof_gen(
    pk: &[u8],
    sig: &[u8],
    gens: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    scalars: &[Scalar],
    disclosed_idx: &[usize],
    api_id: &[u8],
    rng: &mut dyn ScalarSource,
    out: &mut [u8],
) -> Result<usize> {
    let (a, e) = octets_to_signature(sig)?;
    let l = scalars.len();
    check_indexes(disclosed_idx, l)?;
    // A prover must hold a valid signature before presenting it.
    core_verify(pk, sig, gens, header, scalars, api_id)?;
    let mut undisclosed = [0usize; MAX_MESSAGES];
    let u = undisclosed_of(disclosed_idx, l, &mut undisclosed)?;
    let mut rnd = [Scalar::zero(); MAX_RANDOM];
    let mut und_scalars = [Scalar::zero(); MAX_MESSAGES];
    let mut dis_scalars = [Scalar::zero(); MAX_MESSAGES];
    let result = (|| {
        rng.fill(&mut rnd[..5 + u])?;
        for (k, &j) in undisclosed[..u].iter().enumerate() {
            und_scalars[k] = scalars[j];
        }
        for (k, &i) in disclosed_idx.iter().enumerate() {
            dis_scalars[k] = scalars[i];
        }
        let init = proof_init(pk, &a, &e, gens, header, scalars, &undisclosed[..u], &rnd[..5 + u], api_id)?;
        let c = challenge(&init, disclosed_idx, &dis_scalars[..disclosed_idx.len()], None, ph, api_id)?;
        let mut w = Out::new(out);
        proof_finalize(&init, &c, &e, &rnd[..5 + u], &und_scalars[..u], &mut w)?;
        w.finish()
    })();
    wipe::scalars(&mut rnd);
    wipe::scalars(&mut und_scalars);
    wipe::scalars(&mut dis_scalars);
    result
}

/// CoreProofVerify.
pub fn core_proof_verify(
    pk: &[u8],
    proof: &[u8],
    gens: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    disclosed: &[Scalar],
    disclosed_idx: &[usize],
    api_id: &[u8],
) -> Result<()> {
    let p = octets_to_proof(proof)?;
    pubkey_from_bytes(pk)?;
    let init = proof_verify_init(pk, &p, gens, header, disclosed, disclosed_idx, api_id)?;
    let c = challenge(&init, disclosed_idx, disclosed, None, ph, api_id)?;
    proof_accept(pk, &p, &c)
}

// ------------------------------------------------------------ interface

fn hashed<'a>(msgs: &[&'a [u8]], out: &mut [Msg<'a>; MAX_SIGNER_MESSAGES]) -> Result<usize> {
    if msgs.len() > MAX_SIGNER_MESSAGES {
        return Err(Error::TooLarge);
    }
    for (m, o) in msgs.iter().zip(out.iter_mut()) {
        *o = Msg::Hash(m);
    }
    Ok(msgs.len())
}

struct Prepared {
    gens: [G1Projective; MAX_GENERATORS],
    scalars: [Scalar; MAX_MESSAGES],
    n: usize,
}

impl Prepared {
    fn new(msgs: &[&[u8]]) -> Result<Prepared> {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = hashed(msgs, &mut m)?;
        let mut p = Prepared { gens: [G1Projective::identity(); MAX_GENERATORS], scalars: [Scalar::zero(); MAX_MESSAGES], n };
        create_generators(n + 1, API_ID_BBS, &mut p.gens)?;
        messages_to_scalars(&m[..n], API_ID_BBS, &mut p.scalars)?;
        Ok(p)
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        wipe::scalars(&mut self.scalars);
    }
}

/// Sign(SK, PK, header, messages).
pub fn sign(sk: &Scalar, pk: &[u8], header: &[u8], msgs: &[&[u8]]) -> Result<[u8; SIGNATURE_LEN]> {
    let p = Prepared::new(msgs)?;
    core_sign(sk, pk, &p.gens[..p.n + 1], header, &p.scalars[..p.n], API_ID_BBS)
}

/// Verify(PK, signature, header, messages).
pub fn verify(pk: &[u8], sig: &[u8], header: &[u8], msgs: &[&[u8]]) -> Result<()> {
    let p = Prepared::new(msgs)?;
    core_verify(pk, sig, &p.gens[..p.n + 1], header, &p.scalars[..p.n], API_ID_BBS)
}

/// ProofGen(PK, signature, header, ph, messages, disclosed_indexes).
#[allow(clippy::too_many_arguments)]
pub fn proof_gen(pk: &[u8], sig: &[u8], header: &[u8], ph: &[u8], msgs: &[&[u8]], disclosed_idx: &[usize], rng: &mut dyn ScalarSource, out: &mut [u8]) -> Result<usize> {
    let p = Prepared::new(msgs)?;
    core_proof_gen(pk, sig, &p.gens[..p.n + 1], header, ph, &p.scalars[..p.n], disclosed_idx, API_ID_BBS, rng, out)
}

/// ProofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes).
pub fn proof_verify(pk: &[u8], proof: &[u8], header: &[u8], ph: &[u8], disclosed_msgs: &[&[u8]], disclosed_idx: &[usize]) -> Result<()> {
    if proof.len() < PROOF_MIN_LEN {
        return Err(Error::Invalid);
    }
    let u = (proof.len() - 3 * G1_LEN) / SCALAR_LEN - 4;
    let l = disclosed_msgs.len() + u;
    if l > MAX_SIGNER_MESSAGES || disclosed_idx.len() != disclosed_msgs.len() {
        return Err(Error::Invalid);
    }
    let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
    let r = hashed(disclosed_msgs, &mut m)?;
    let mut gens = [G1Projective::identity(); MAX_GENERATORS];
    create_generators(l + 1, API_ID_BBS, &mut gens)?;
    let mut scalars = [Scalar::zero(); MAX_MESSAGES];
    messages_to_scalars(&m[..r], API_ID_BBS, &mut scalars)?;
    core_proof_verify(pk, proof, &gens[..l + 1], header, ph, &scalars[..r], disclosed_idx, API_ID_BBS)
}

/// Decodes a 32-octet big-endian secret key (0 < SK < r).
pub fn secret_key_from_bytes(b: &[u8]) -> Result<Scalar> {
    scalar_from_be_nonzero(b)
}

/// Re-export for callers that parse scalars of fixtures.
pub fn scalar_from_bytes(b: &[u8]) -> Result<Scalar> {
    scalar_from_be(b)
}
