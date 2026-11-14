//! Blind BBS signatures (draft-irtf-cfrg-bbs-blind-signatures):
//! Commit / commitment validation, BlindSign, VerifyBlindSign,
//! BlindProofGen and BlindProofVerify with committed disclosure.
//! api_id = ciphersuite_id || "BLIND_H2G_HM2S_".

use crate::codec::{g1_from_bytes, scalar_eq, scalar_from_be_nonzero, Absorb, Out, G1_LEN, SCALAR_LEN};
use crate::core_bbs::{
    b_value, calculate_domain, challenge, check_indexes, core_verify, finalize_signature, messages_to_scalars,
    octets_to_proof, octets_to_signature, proof_accept, proof_finalize, proof_init, proof_verify_init, undisclosed_of,
    CommitTerm, Msg, PROOF_MIN_LEN, SIGNATURE_LEN,
};
use crate::generators::{create_blind_generators, create_generators, API_ID_BLIND};
use crate::limits::{MAX_BLIND_MESSAGES, MAX_GENERATORS, MAX_MESSAGES, MAX_RANDOM, MAX_SIGNER_MESSAGES};
use crate::random::ScalarSource;
use crate::xmd::{Dst, Xmd};
use crate::{wipe, Error, Result};
use bls12_381::{G1Projective, Scalar};

/// What a holder does with one signed message in a presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disclosure {
    Disclose,
    Hide,
    /// Hidden, but bound to a Pedersen commitment C = Y_0 * s + Y_1 * m that
    /// later proofs (range, capacity) can reuse.
    Commit,
}

/// Commitment with proof: C (48) || s^ || m^_1..m^_M || challenge.
pub const fn commitment_len(m: usize) -> usize {
    G1_LEN + (m + 2) * SCALAR_LEN
}

fn h2s(api_id: &[u8]) -> Result<Dst> {
    Dst::new(&[api_id, b"H2S_"])
}

/// calculate_blind_challenge(C, Cbar, blind_generators, api_id).
fn blind_challenge(c: &G1Projective, cbar: &G1Projective, gens: &[G1Projective], api_id: &[u8]) -> Result<Scalar> {
    if gens.is_empty() {
        return Err(Error::Invalid);
    }
    let mut x = Xmd::new();
    x.int((gens.len() - 1) as u64);
    for g in gens {
        x.g1(g);
    }
    x.g1(c);
    x.g1(cbar);
    x.to_scalar(h2s(api_id)?.as_bytes())
}

/// Commit(committed_messages): writes commitment_with_proof into `out` and
/// returns its length together with secret_prover_blind (the caller keeps
/// and later wipes it).
pub fn commit(blind_msgs: &[Msg<'_>], rng: &mut dyn ScalarSource, out: &mut [u8]) -> Result<(usize, Scalar)> {
    let api_id = API_ID_BLIND;
    let m = blind_msgs.len();
    if m > MAX_BLIND_MESSAGES {
        return Err(Error::TooLarge);
    }
    let mut gens = [G1Projective::identity(); MAX_BLIND_MESSAGES + 1];
    create_blind_generators(m + 1, api_id, &mut gens)?;
    let mut msgs = [Scalar::zero(); MAX_BLIND_MESSAGES];
    let mut rnd = [Scalar::zero(); MAX_BLIND_MESSAGES + 2];
    let result = (|| {
        messages_to_scalars(blind_msgs, api_id, &mut msgs)?;
        rng.fill(&mut rnd[..m + 2])?;
        let (pb, s_t) = (rnd[0], rnd[1]);
        let mut c = gens[0] * pb;
        let mut cbar = gens[0] * s_t;
        for i in 0..m {
            c += gens[i + 1] * msgs[i];
            cbar += gens[i + 1] * rnd[2 + i];
        }
        let ch = blind_challenge(&c, &cbar, &gens[..m + 1], api_id)?;
        let mut w = Out::new(out);
        w.g1(&c);
        let mut s_hat = s_t + pb * ch;
        w.scalar(&s_hat);
        wipe::scalar(&mut s_hat);
        for i in 0..m {
            let mut h = rnd[2 + i] + msgs[i] * ch;
            w.scalar(&h);
            wipe::scalar(&mut h);
        }
        w.scalar(&ch);
        Ok((w.finish()?, pb))
    })();
    wipe::scalars(&mut msgs);
    // rnd[0] is returned as the prover blind; every copy here is wiped.
    wipe::scalars(&mut rnd);
    result
}

/// deserialize_and_validate_commit: Identity for an empty commitment,
/// otherwise a verified commitment point.
pub fn validate_commitment(cwp: &[u8], blind_gens: &[G1Projective], api_id: &[u8]) -> Result<G1Projective> {
    if cwp.is_empty() {
        return Ok(G1Projective::identity());
    }
    if cwp.len() < commitment_len(0) || (cwp.len() - G1_LEN) % SCALAR_LEN != 0 {
        return Err(Error::Invalid);
    }
    let j = (cwp.len() - G1_LEN) / SCALAR_LEN;
    let m = j - 2;
    if m + 1 != blind_gens.len() {
        return Err(Error::Invalid);
    }
    let c = G1Projective::from(g1_from_bytes(&cwp[..G1_LEN])?);
    let s = |k: usize| scalar_from_be_nonzero(&cwp[G1_LEN + k * SCALAR_LEN..G1_LEN + (k + 1) * SCALAR_LEN]);
    let s_hat = s(0)?;
    let cp = s(j - 1)?;
    let mut cbar = blind_gens[0] * s_hat - c * cp;
    for i in 0..m {
        cbar += blind_gens[i + 1] * s(1 + i)?;
    }
    let cv = blind_challenge(&c, &cbar, blind_gens, api_id)?;
    if !scalar_eq(&cv, &cp) {
        return Err(Error::Rejected);
    }
    Ok(c)
}

/// Number of committed messages in a commitment_with_proof (BlindSign step 2-5).
fn committed_count(cwp: &[u8]) -> Result<usize> {
    if cwp.is_empty() {
        return Ok(0);
    }
    if cwp.len() < commitment_len(0) || (cwp.len() - G1_LEN) % SCALAR_LEN != 0 {
        return Err(Error::Invalid);
    }
    let m = (cwp.len() - G1_LEN - 2 * SCALAR_LEN) / SCALAR_LEN;
    if m > MAX_BLIND_MESSAGES {
        return Err(Error::TooLarge);
    }
    Ok(m)
}

/// Generators (Q_1, H_1..H_L) followed by blind generators (Q_2, J_1..J_M).
fn all_generators(l: usize, m: usize, out: &mut [G1Projective; MAX_GENERATORS]) -> Result<usize> {
    if l > MAX_SIGNER_MESSAGES || m > MAX_BLIND_MESSAGES {
        return Err(Error::TooLarge);
    }
    create_generators(l + 1, API_ID_BLIND, &mut out[..l + 1])?;
    create_blind_generators(m + 1, API_ID_BLIND, &mut out[l + 1..l + m + 2])?;
    Ok(l + m + 2)
}

/// BlindSign(SK, PK, commitment_with_proof, header, messages).
pub fn blind_sign(sk: &Scalar, pk: &[u8], cwp: &[u8], header: &[u8], msgs: &[Msg<'_>]) -> Result<[u8; SIGNATURE_LEN]> {
    let api_id = API_ID_BLIND;
    let l = msgs.len();
    let m = committed_count(cwp)?;
    let mut gens = [G1Projective::identity(); MAX_GENERATORS];
    let n = all_generators(l, m, &mut gens)?;
    let commitment = validate_commitment(cwp, &gens[l + 1..n], api_id)?;
    let mut scalars = [Scalar::zero(); MAX_SIGNER_MESSAGES];
    let result = (|| {
        messages_to_scalars(msgs, api_id, &mut scalars)?;
        // B_calculate: the domain covers (Q_1, H.., Q_2, J..); B adds the commitment.
        let domain = calculate_domain(pk, &gens[..n], header, api_id)?;
        let b = b_value(&gens[..l + 1], &domain, &scalars[..l])? + commitment;
        if bool::from(b.is_identity()) {
            return Err(Error::Invalid);
        }
        // FinalizeBlindSign: e = hash_to_scalar(serialize((SK, B))).
        let mut x = Xmd::new();
        x.scalar(sk);
        x.g1(&b);
        let mut e = x.to_scalar(h2s(api_id)?.as_bytes())?;
        let sig = finalize_signature(sk, &e, &b);
        wipe::scalar(&mut e);
        sig
    })();
    wipe::scalars(&mut scalars);
    result
}

/// Proof scalars: signer messages, the prover blind, then committed messages.
struct Scalars {
    s: [Scalar; MAX_MESSAGES],
    n: usize,
}

impl Drop for Scalars {
    fn drop(&mut self) {
        wipe::scalars(&mut self.s);
    }
}

fn proof_scalars(signer: &[Msg<'_>], blind: &[Msg<'_>], prover_blind: &Scalar) -> Result<Scalars> {
    let (l, m) = (signer.len(), blind.len());
    if l > MAX_SIGNER_MESSAGES || m > MAX_BLIND_MESSAGES {
        return Err(Error::TooLarge);
    }
    let mut out = Scalars { s: [Scalar::zero(); MAX_MESSAGES], n: l + 1 + m };
    messages_to_scalars(signer, API_ID_BLIND, &mut out.s[..l])?;
    out.s[l] = *prover_blind;
    messages_to_scalars(blind, API_ID_BLIND, &mut out.s[l + 1..l + 1 + m])?;
    Ok(out)
}

/// VerifyBlindSign(PK, signature, header, messages, blind_messages, secret_prover_blind).
pub fn verify_blind_sign(pk: &[u8], sig: &[u8], header: &[u8], msgs: &[Msg<'_>], blind_msgs: &[Msg<'_>], prover_blind: &Scalar) -> Result<()> {
    let (l, m) = (msgs.len(), blind_msgs.len());
    let mut gens = [G1Projective::identity(); MAX_GENERATORS];
    let n = all_generators(l, m, &mut gens)?;
    let s = proof_scalars(msgs, blind_msgs, prover_blind)?;
    core_verify(pk, sig, &gens[..n], header, &s.s[..s.n], API_ID_BLIND)
}

/// Y_0, Y_1 = create_generators(2, "COM_DIS_" || api_id).
fn com_dis_generators(api_id: &[u8]) -> Result<(G1Projective, G1Projective)> {
    let id = Dst::new(&[b"COM_DIS_", api_id])?;
    let mut y = [G1Projective::identity(); 2];
    create_generators(2, id.as_bytes(), &mut y)?;
    Ok((y[0], y[1]))
}

/// Position of `idx` among the undisclosed indexes.
fn position(undisclosed: &[usize], idx: usize) -> Result<usize> {
    undisclosed.iter().position(|&j| j == idx).ok_or(Error::Invalid)
}

fn disjoint(a: &[usize], b: &[usize]) -> bool {
    a.iter().all(|x| !b.contains(x))
}

/// Core proof generation with committed disclosure; returns the proof length.
/// `commit_rands`, when given, receives s_1..s_N (add_zkp_info).
#[allow(clippy::too_many_arguments)]
fn core_blind_proof_gen(
    pk: &[u8],
    sig: &[u8],
    gens: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    scalars: &[Scalar],
    disclosed_idx: &[usize],
    commit_idx: &[usize],
    rng: &mut dyn ScalarSource,
    out: &mut [u8],
    commit_rands: Option<&mut [Scalar]>,
) -> Result<usize> {
    let api_id = API_ID_BLIND;
    let (a, e) = octets_to_signature(sig)?;
    let l = scalars.len();
    check_indexes(commit_idx, l)?;
    check_indexes(disclosed_idx, l)?;
    if !disjoint(disclosed_idx, commit_idx) {
        return Err(Error::Invalid);
    }
    core_verify(pk, sig, gens, header, scalars, api_id)?;
    let (n, r) = (commit_idx.len(), disclosed_idx.len());
    let mut undisclosed = [0usize; MAX_MESSAGES];
    let u = undisclosed_of(disclosed_idx, l, &mut undisclosed)?;
    debug_assert_eq!(u, l - r);
    let (y0, y1) = com_dis_generators(api_id)?;
    let mut rnd = [Scalar::zero(); MAX_RANDOM];
    let mut und_scalars = [Scalar::zero(); MAX_MESSAGES];
    let mut dis_scalars = [Scalar::zero(); MAX_MESSAGES];
    let result = (|| {
        if 5 + u + 2 * n > MAX_RANDOM {
            return Err(Error::TooLarge);
        }
        rng.fill(&mut rnd[..5 + u + 2 * n])?;
        for (k, &j) in undisclosed[..u].iter().enumerate() {
            und_scalars[k] = scalars[j];
        }
        for (k, &i) in disclosed_idx.iter().enumerate() {
            dis_scalars[k] = scalars[i];
        }
        let init_rnd = &rnd[..5 + u];
        let init = proof_init(pk, &a, &e, gens, header, scalars, &undisclosed[..u], init_rnd, api_id)?;
        let mut terms = [CommitTerm { index: 0, c: G1Projective::identity(), c_tilde: G1Projective::identity() }; MAX_MESSAGES];
        for (i, &idx) in commit_idx.iter().enumerate() {
            let k = position(&undisclosed[..u], idx)?;
            let s_i = rnd[5 + u + i];
            let s_t = rnd[5 + u + n + i];
            terms[i] = CommitTerm { index: idx, c: y0 * s_i + y1 * scalars[idx], c_tilde: y0 * s_t + y1 * rnd[5 + k] };
        }
        let c = challenge(&init, disclosed_idx, &dis_scalars[..r], Some(&terms[..n]), ph, api_id)?;
        if out.len() < 8 {
            return Err(Error::TooLarge);
        }
        let (prefix, rest) = out.split_at_mut(8);
        let mut w = Out::new(rest);
        proof_finalize(&init, &c, &e, init_rnd, &und_scalars[..u], &mut w)?;
        let bbs_len = w.finish()?;
        prefix.copy_from_slice(&(bbs_len as u64).to_be_bytes());
        let mut w = Out::new(&mut rest[bbs_len..]);
        for t in &terms[..n] {
            w.g1(&t.c);
        }
        for i in 0..n {
            let mut s_hat = rnd[5 + u + n + i] + c * rnd[5 + u + i];
            w.scalar(&s_hat);
            wipe::scalar(&mut s_hat);
        }
        let tail = w.finish()?;
        if let Some(dst) = commit_rands {
            if dst.len() < n {
                return Err(Error::TooLarge);
            }
            dst[..n].copy_from_slice(&rnd[5 + u..5 + u + n]);
        }
        Ok(8 + bbs_len + tail)
    })();
    wipe::scalars(&mut rnd);
    wipe::scalars(&mut und_scalars);
    wipe::scalars(&mut dis_scalars);
    result
}

/// BlindProofGen. Indexes in the disclosures are positions within the
/// signer messages and within the blind messages respectively; the prover
/// blind is never disclosed.
#[allow(clippy::too_many_arguments)]
pub fn blind_proof_gen(
    pk: &[u8],
    sig: &[u8],
    header: &[u8],
    ph: &[u8],
    signer_msgs: &[Msg<'_>],
    blind_msgs: &[Msg<'_>],
    signer_disclosures: &[Disclosure],
    blind_disclosures: &[Disclosure],
    prover_blind: &Scalar,
    rng: &mut dyn ScalarSource,
    out: &mut [u8],
    commit_rands: Option<&mut [Scalar]>,
) -> Result<usize> {
    let (l, m) = (signer_msgs.len(), blind_msgs.len());
    if signer_disclosures.len() != l || blind_disclosures.len() != m {
        return Err(Error::Invalid);
    }
    let mut gens = [G1Projective::identity(); MAX_GENERATORS];
    let g = all_generators(l, m, &mut gens)?;
    let s = proof_scalars(signer_msgs, blind_msgs, prover_blind)?;
    let mut dis = [0usize; MAX_MESSAGES];
    let mut com = [0usize; MAX_MESSAGES];
    let (mut nd, mut nc) = (0, 0);
    let all = signer_disclosures.iter().enumerate().map(|(i, d)| (i, d)).chain(blind_disclosures.iter().enumerate().map(|(i, d)| (i + l + 1, d)));
    for (idx, d) in all {
        match d {
            Disclosure::Disclose => {
                dis[nd] = idx;
                nd += 1;
            }
            Disclosure::Commit => {
                com[nc] = idx;
                nc += 1;
            }
            Disclosure::Hide => {}
        }
    }
    core_blind_proof_gen(pk, sig, &gens[..g], header, ph, &s.s[..s.n], &dis[..nd], &com[..nc], rng, out, commit_rands)
}

/// BlindProofVerify(PK, proof, header, ph, issuer_known_messages_no,
/// disclosed_messages, message_disclosures). `disclosures` covers signer
/// messages then blind messages (the prover blind is not listed).
#[allow(clippy::too_many_arguments)]
pub fn blind_proof_verify(
    pk: &[u8],
    proof: &[u8],
    header: &[u8],
    ph: &[u8],
    issuer_known: usize,
    disclosed_msgs: &[Msg<'_>],
    disclosures: &[Disclosure],
) -> Result<()> {
    let api_id = API_ID_BLIND;
    if proof.len() < 8 {
        return Err(Error::Invalid);
    }
    let bbs_len = u64::from_be_bytes(proof[..8].try_into().map_err(|_| Error::Invalid)?);
    if bbs_len < PROOF_MIN_LEN as u64 || bbs_len > (proof.len() - 8) as u64 {
        return Err(Error::Invalid);
    }
    let bbs_len = bbs_len as usize;
    if (bbs_len - 3 * G1_LEN) % SCALAR_LEN != 0 {
        return Err(Error::Invalid);
    }
    let undisclosed_no = (bbs_len - 3 * G1_LEN - 4 * SCALAR_LEN) / SCALAR_LEN;
    let proof_msgs = undisclosed_no + disclosed_msgs.len();
    if proof_msgs == 0 {
        return Err(Error::Invalid);
    }
    let total = proof_msgs - 1;
    if issuer_known > total || disclosures.len() != total {
        return Err(Error::Invalid);
    }
    let blind_no = total - issuer_known;
    if issuer_known > MAX_SIGNER_MESSAGES || blind_no > MAX_BLIND_MESSAGES {
        return Err(Error::TooLarge);
    }
    let pidx = |i: usize| if i < issuer_known { i } else { i + 1 };
    let mut dis = [0usize; MAX_MESSAGES];
    let mut com = [0usize; MAX_MESSAGES];
    let (mut nd, mut nc) = (0, 0);
    for (i, d) in disclosures.iter().enumerate() {
        match d {
            Disclosure::Disclose => {
                dis[nd] = pidx(i);
                nd += 1;
            }
            Disclosure::Commit => {
                com[nc] = pidx(i);
                nc += 1;
            }
            Disclosure::Hide => {}
        }
    }
    if nd != disclosed_msgs.len() {
        return Err(Error::Invalid);
    }
    let mut gens = [G1Projective::identity(); MAX_GENERATORS];
    let g = all_generators(issuer_known, blind_no, &mut gens)?;
    let mut scalars = [Scalar::zero(); MAX_MESSAGES];
    messages_to_scalars(disclosed_msgs, api_id, &mut scalars)?;

    // octets_to_proof(proof, N)
    let n = nc;
    let bbs = octets_to_proof(&proof[8..8 + bbs_len])?;
    let tail = &proof[8 + bbs_len..];
    if tail.len() != n * (G1_LEN + SCALAR_LEN) {
        return Err(Error::Invalid);
    }
    let l = nd + bbs.u;
    check_indexes(&com[..n], l)?;
    check_indexes(&dis[..nd], l)?;
    if !disjoint(&dis[..nd], &com[..n]) {
        return Err(Error::Invalid);
    }
    let mut undisclosed = [0usize; MAX_MESSAGES];
    let u = undisclosed_of(&dis[..nd], l, &mut undisclosed)?;
    let init = proof_verify_init(pk, &bbs, &gens[..g], header, &scalars[..nd], &dis[..nd], api_id)?;
    let (y0, y1) = com_dis_generators(api_id)?;
    let mut terms = [CommitTerm { index: 0, c: G1Projective::identity(), c_tilde: G1Projective::identity() }; MAX_MESSAGES];
    for i in 0..n {
        let c_i = G1Projective::from(g1_from_bytes(&tail[i * G1_LEN..(i + 1) * G1_LEN])?);
        let off = n * G1_LEN + i * SCALAR_LEN;
        let s_hat = scalar_from_be_nonzero(&tail[off..off + SCALAR_LEN])?;
        let k = position(&undisclosed[..u], com[i])?;
        terms[i] = CommitTerm { index: com[i], c: c_i, c_tilde: y0 * s_hat + y1 * bbs.hats[k] - c_i * bbs.c };
    }
    let c = challenge(&init, &dis[..nd], &scalars[..nd], Some(&terms[..n]), ph, api_id)?;
    proof_accept(pk, &bbs, &c)
}
