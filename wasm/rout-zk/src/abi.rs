//! wasm32 exports. All pointers address the host-provided, fixed-size imported
//! memory; nothing is allocated. Return codes: >= 0 success (a length where
//! one is produced), -1 invalid input, -2 rejected, -3 capacity exceeded.
//!
//! Packed message list: repeated `kind (u8: 0 = HASH, 1 = RAW) || len (u32 LE) || bytes`.
//! Index list: `count` u32 LE values.

use crate::blind;
use crate::bulletproofs::{self, BulletproofGens, RangeProof, PROOF_LEN};
use crate::pedersen::{value_u64, Commitment, PedersenGens};
use crate::random::ScalarSource;
use crate::codec::{scalar_from_be, scalar_to_be};
use bls12_381::Scalar;
use crate::core_bbs::{self, Msg};
use crate::forward_secure::{self as fs, EpochKey, STATE_LEN};
use crate::limits::{MAX_BLIND_MESSAGES, MAX_MESSAGES, MAX_SIGNER_MESSAGES};
use crate::pseudonym;
use crate::smt::{self, NODE_LEN, NULLIFIER_LEN, PATH_LEN, SIBLINGS_LEN};
use crate::random::FromOctets;
use crate::{wipe, Error};

#[link(wasm_import_module = "env")]
extern "C" {
    /// Fills `len` bytes at `ptr` from the host CSPRNG (crypto.getRandomValues).
    fn rout_random(ptr: *mut u8, len: usize);
}

extern "C" {
    static __heap_base: u8;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

fn code(r: Result<i32, Error>) -> i32 {
    match r {
        Ok(v) => v,
        Err(Error::Invalid) => -1,
        Err(Error::Rejected) => -2,
        Err(Error::TooLarge) => -3,
    }
}

unsafe fn input<'a>(ptr: usize, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(ptr as *const u8, len)
    }
}

unsafe fn output<'a>(ptr: usize, len: usize) -> &'a mut [u8] {
    core::slice::from_raw_parts_mut(ptr as *mut u8, len)
}

fn host_rng() -> FromOctets<impl FnMut(&mut [u8])> {
    FromOctets(|b: &mut [u8]| unsafe { rout_random(b.as_mut_ptr(), b.len()) })
}

fn messages<'a, const N: usize>(mut b: &'a [u8], out: &mut [Msg<'a>; N]) -> Result<usize, Error> {
    let mut n = 0;
    while !b.is_empty() {
        if n == N || b.len() < 5 {
            return Err(if n == N { Error::TooLarge } else { Error::Invalid });
        }
        let len = u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as usize;
        if b.len() - 5 < len {
            return Err(Error::Invalid);
        }
        let body = &b[5..5 + len];
        out[n] = match b[0] {
            0 => Msg::Hash(body),
            1 => Msg::Raw(body),
            _ => return Err(Error::Invalid),
        };
        n += 1;
        b = &b[5 + len..];
    }
    Ok(n)
}

fn hashed_only<'a>(m: &[Msg<'a>], out: &mut [&'a [u8]; MAX_SIGNER_MESSAGES]) -> Result<usize, Error> {
    for (i, x) in m.iter().enumerate() {
        out[i] = match x {
            Msg::Hash(b) => b,
            Msg::Raw(_) => return Err(Error::Invalid),
        };
    }
    Ok(m.len())
}

fn indexes(b: &[u8], out: &mut [usize; MAX_MESSAGES]) -> Result<usize, Error> {
    if b.len() % 4 != 0 || b.len() / 4 > MAX_MESSAGES {
        return Err(Error::Invalid);
    }
    for (i, c) in b.chunks_exact(4).enumerate() {
        out[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as usize;
    }
    Ok(b.len() / 4)
}

#[no_mangle]
pub extern "C" fn rout_zk_abi_version() -> u32 {
    // 1 = BBS / Blind BBS / pseudonym (7a); 2 = + Pedersen and range proofs (7b);
    // 3 = + Poseidon SMT nullifiers with signed roots (7c);
    // 4 = + forward-secure host keys per epoch (7d).
    4
}

#[no_mangle]
pub extern "C" fn rout_zk_heap_base() -> usize {
    unsafe { &__heap_base as *const u8 as usize }
}

/// seed (32) | host_id | nonce (32) -> out (32).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_pseudonym(seed: usize, host: usize, host_len: usize, nonce: usize, out: usize) -> i32 {
    code((|| {
        let p = pseudonym::derive(input(seed, 32), input(host, host_len), input(nonce, 32))?;
        output(out, 32).copy_from_slice(&p);
        Ok(0)
    })())
}

/// KeyGen with the default key_dst -> sk (32) and pk (96).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_keygen(km: usize, km_len: usize, info: usize, info_len: usize, out_sk: usize, out_pk: usize) -> i32 {
    code((|| {
        let mut sk = core_bbs::keygen(input(km, km_len), input(info, info_len), None)?;
        output(out_sk, 32).copy_from_slice(&scalar_to_be(&sk));
        output(out_pk, 96).copy_from_slice(&core_bbs::sk_to_pk(&sk));
        wipe::scalar(&mut sk);
        Ok(0)
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_zk_sign(sk: usize, pk: usize, h: usize, h_len: usize, msgs: usize, msgs_len: usize, out: usize) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut r = [&[][..]; MAX_SIGNER_MESSAGES];
        let n = hashed_only(&m[..n], &mut r)?;
        let mut s = core_bbs::secret_key_from_bytes(input(sk, 32))?;
        let sig = core_bbs::sign(&s, input(pk, 96), input(h, h_len), &r[..n]);
        wipe::scalar(&mut s);
        output(out, 80).copy_from_slice(&sig?);
        Ok(0)
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_zk_verify(pk: usize, sig: usize, h: usize, h_len: usize, msgs: usize, msgs_len: usize) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut r = [&[][..]; MAX_SIGNER_MESSAGES];
        let n = hashed_only(&m[..n], &mut r)?;
        core_bbs::verify(input(pk, 96), input(sig, 80), input(h, h_len), &r[..n])?;
        Ok(0)
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_zk_proof_gen(
    pk: usize, sig: usize, h: usize, h_len: usize, ph: usize, ph_len: usize,
    msgs: usize, msgs_len: usize, idx: usize, idx_len: usize, out: usize, out_cap: usize,
) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut r = [&[][..]; MAX_SIGNER_MESSAGES];
        let n = hashed_only(&m[..n], &mut r)?;
        let mut ix = [0usize; MAX_MESSAGES];
        let k = indexes(input(idx, idx_len), &mut ix)?;
        let len = core_bbs::proof_gen(input(pk, 96), input(sig, 80), input(h, h_len), input(ph, ph_len), &r[..n], &ix[..k], &mut host_rng(), output(out, out_cap))?;
        Ok(len as i32)
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_zk_proof_verify(
    pk: usize, proof: usize, proof_len: usize, h: usize, h_len: usize, ph: usize, ph_len: usize,
    msgs: usize, msgs_len: usize, idx: usize, idx_len: usize,
) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut r = [&[][..]; MAX_SIGNER_MESSAGES];
        let n = hashed_only(&m[..n], &mut r)?;
        let mut ix = [0usize; MAX_MESSAGES];
        let k = indexes(input(idx, idx_len), &mut ix)?;
        core_bbs::proof_verify(input(pk, 96), input(proof, proof_len), input(h, h_len), input(ph, ph_len), &r[..n], &ix[..k])?;
        Ok(0)
    })())
}

/// Commit -> commitment_with_proof (returns its length) and prover blind (32).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_commit(msgs: usize, msgs_len: usize, out: usize, out_cap: usize, out_blind: usize) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_BLIND_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let (len, mut pb) = blind::commit(&m[..n], &mut host_rng(), output(out, out_cap))?;
        output(out_blind, 32).copy_from_slice(&scalar_to_be(&pb));
        wipe::scalar(&mut pb);
        Ok(len as i32)
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_zk_blind_sign(sk: usize, pk: usize, cwp: usize, cwp_len: usize, h: usize, h_len: usize, msgs: usize, msgs_len: usize, out: usize) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut s = core_bbs::secret_key_from_bytes(input(sk, 32))?;
        let sig = blind::blind_sign(&s, input(pk, 96), input(cwp, cwp_len), input(h, h_len), &m[..n]);
        wipe::scalar(&mut s);
        output(out, 80).copy_from_slice(&sig?);
        Ok(0)
    })())
}

#[no_mangle]
pub unsafe extern "C" fn rout_zk_verify_blind_sign(
    pk: usize, sig: usize, h: usize, h_len: usize, msgs: usize, msgs_len: usize, bmsgs: usize, bmsgs_len: usize, prover_blind: usize,
) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut b = [Msg::Hash(&[]); MAX_BLIND_MESSAGES];
        let k = messages(input(bmsgs, bmsgs_len), &mut b)?;
        let mut pb = scalar_from_be(input(prover_blind, 32))?;
        let r = blind::verify_blind_sign(input(pk, 96), input(sig, 80), input(h, h_len), &m[..n], &b[..k], &pb);
        wipe::scalar(&mut pb);
        r?;
        Ok(0)
    })())
}

/// A value of the 7b interface: 32 octets big-endian, which must lie in
/// [0, 2^64 - 1]; anything else (including "negative" q - k) is INVALID.
fn range_value(b: &[u8]) -> Result<Scalar, Error> {
    let s = scalar_from_be(b)?;
    if value_u64(&s).is_none() {
        let mut s = s;
        wipe::scalar(&mut s);
        return Err(Error::Invalid);
    }
    Ok(s)
}

/// value (32) | blinding (32) -> commitment (48).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_pedersen_commit(value: usize, blind: usize, out: usize) -> i32 {
    code((|| {
        let mut v = range_value(input(value, 32))?;
        let mut r = match scalar_from_be(input(blind, 32)) {
            Ok(r) => r,
            Err(e) => {
                wipe::scalar(&mut v);
                return Err(e);
            }
        };
        let c = PedersenGens::canonical().commit(&v, &r).to_bytes();
        wipe::scalar(&mut v);
        wipe::scalar(&mut r);
        output(out, 48).copy_from_slice(&c);
        Ok(0)
    })())
}

/// value (32) -> fresh blinding from the host CSPRNG (32) and commitment (48).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_pedersen_commit_fresh(value: usize, out_blind: usize, out: usize) -> i32 {
    code((|| {
        let mut v = range_value(input(value, 32))?;
        let mut r = [Scalar::zero(); 1];
        let filled = host_rng().fill(&mut r);
        let c = PedersenGens::canonical().commit(&v, &r[0]).to_bytes();
        let rb = scalar_to_be(&r[0]);
        wipe::scalar(&mut v);
        wipe::scalars(&mut r);
        filled?;
        output(out_blind, 32).copy_from_slice(&rb);
        output(out, 48).copy_from_slice(&c);
        Ok(0)
    })())
}

/// a (48), b (48), op (0 = a·b, 1 = a·b^{-1}) -> out (48). Both inputs pass
/// the subgroup checks; an identity result is refused.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_pedersen_combine(a: usize, b: usize, op: u32, out: usize) -> i32 {
    code((|| {
        let x = Commitment::from_bytes(input(a, 48))?;
        let y = Commitment::from_bytes(input(b, 48))?;
        let c = match op {
            0 => x.add(&y),
            1 => x.sub(&y),
            _ => return Err(Error::Invalid),
        };
        if bool::from(c.0.is_identity()) {
            return Err(Error::Invalid);
        }
        output(out, 48).copy_from_slice(&c.to_bytes());
        Ok(0)
    })())
}

/// value (32) | blinding (32) | ctx -> commitment (48) and proof (928).
/// Returns the proof length.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_range_prove(value: usize, blind: usize, ctx: usize, ctx_len: usize, out_commit: usize, out_proof: usize) -> i32 {
    code((|| {
        let mut v = range_value(input(value, 32))?;
        let mut r = match scalar_from_be(input(blind, 32)) {
            Ok(r) => r,
            Err(e) => {
                wipe::scalar(&mut v);
                return Err(e);
            }
        };
        let res = bulletproofs::prove(&PedersenGens::canonical(), &BulletproofGens::canonical(), &v, &r, input(ctx, ctx_len), &mut host_rng());
        wipe::scalar(&mut v);
        wipe::scalar(&mut r);
        let (c, p) = res?;
        output(out_commit, 48).copy_from_slice(&c.to_bytes());
        output(out_proof, PROOF_LEN).copy_from_slice(&p.to_bytes());
        Ok(PROOF_LEN as i32)
    })())
}

/// commitment (48) | ctx | proof -> 0 or -2 (rejected) / -1 (malformed).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_range_verify(commit: usize, ctx: usize, ctx_len: usize, proof: usize, proof_len: usize) -> i32 {
    code((|| {
        let c = Commitment::from_bytes(input(commit, 48))?;
        let p = RangeProof::from_bytes(input(proof, proof_len))?;
        bulletproofs::verify(&PedersenGens::canonical(), &BulletproofGens::canonical(), &c, &p, input(ctx, ctx_len))?;
        Ok(0)
    })())
}

// ---- Stap 7c: nullifier SMT with enclave-signed roots ---------------------
// Root (32) and nodes are big-endian scalars; signature 80; public key 96;
// nullifier 32; siblings 256 x 32 (leaf level first); path 257 x 32 (leaf
// first, root last). The signer key is derived from `km` inside each call and
// wiped before it returns.

/// out (257 x 32): the empty subtree value at every height, leaf (0) first,
/// the empty root last. Public constants for the untrusted node store.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_smt_empty_path(out: usize) -> i32 {
    smt::empty_path(output(out, PATH_LEN));
    0
}

/// km -> signer public key (96).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_smt_signer_pk(km: usize, km_len: usize, out_pk: usize) -> i32 {
    code((|| {
        output(out_pk, 96).copy_from_slice(&smt::signer_public_key(input(km, km_len))?);
        Ok(0)
    })())
}

/// km | tree -> empty root (32) signed at epoch 0 (80).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_smt_genesis(km: usize, km_len: usize, tree: usize, tree_len: usize, out_root: usize, out_sig: usize) -> i32 {
    code((|| {
        let (root, sig) = smt::genesis(input(km, km_len), input(tree, tree_len))?;
        output(out_root, NODE_LEN).copy_from_slice(&root);
        output(out_sig, 80).copy_from_slice(&sig);
        Ok(0)
    })())
}

/// pk (96) | tree | root (32) | epoch | sig (80) -> 0, -2 (rejected), -1 (malformed).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_smt_verify_root(pk: usize, tree: usize, tree_len: usize, root: usize, epoch: u64, sig: usize) -> i32 {
    code((|| {
        smt::verify_root(input(pk, 96), input(tree, tree_len), input(root, NODE_LEN), epoch, input(sig, 80))?;
        Ok(0)
    })())
}

/// Signed root, then NonExist (member = 0) or Exist (member = 1) of the nullifier.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_smt_verify(
    pk: usize, tree: usize, tree_len: usize, root: usize, epoch: u64, sig: usize, nf: usize, siblings: usize, member: u32,
) -> i32 {
    code((|| {
        if member > 1 {
            return Err(Error::Invalid);
        }
        smt::verify_signed(
            input(pk, 96), input(tree, tree_len), input(root, NODE_LEN), epoch, input(sig, 80),
            input(nf, NULLIFIER_LEN), input(siblings, SIBLINGS_LEN), member == 1,
        )?;
        Ok(0)
    })())
}

/// km | tree | signed old root | nullifier | siblings -> new root (32), its
/// signature at epoch + 1 (80) and the new path (257 x 32).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_smt_insert(
    km: usize, km_len: usize, tree: usize, tree_len: usize, root: usize, epoch: u64, sig: usize, nf: usize, siblings: usize,
    out_root: usize, out_sig: usize, out_path: usize,
) -> i32 {
    code((|| {
        let r = smt::insert_signed(
            input(km, km_len), input(tree, tree_len), input(root, NODE_LEN), epoch, input(sig, 80),
            input(nf, NULLIFIER_LEN), input(siblings, SIBLINGS_LEN), output(out_path, PATH_LEN),
        )?;
        output(out_root, NODE_LEN).copy_from_slice(&r.root);
        output(out_sig, 80).copy_from_slice(&r.signature);
        Ok(0)
    })())
}

// ---- Stap 7d: forward-secure host keys per epoch -------------------------
// State 32 octets (SK_t), public key 96, signature 80. Every state region
// handed in is read once into an EpochKey and then volatile-wiped in the
// arena, so no copy of a key outlives the call even before the host's
// zero-fill; the EpochKey itself is wiped on drop.

unsafe fn take_key(state: usize, epoch: u64) -> Result<EpochKey, Error> {
    let region = output(state, STATE_LEN);
    let k = EpochKey::from_state(region, epoch);
    wipe::bytes(region);
    k
}

/// key_id -> SK_0 (32) and PK_0 (96). The seed comes from the host CSPRNG and is wiped.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_hostkey_init(kid: usize, kid_len: usize, out_state: usize, out_pk: usize) -> i32 {
    code((|| {
        let mut seed = [0u8; fs::SEED_LEN];
        rout_random(seed.as_mut_ptr(), seed.len());
        let k = EpochKey::from_seed(&seed);
        wipe::bytes(&mut seed);
        let k = k?;
        let pk = k.public_key(input(kid, kid_len))?;
        k.export_state(output(out_state, STATE_LEN))?;
        output(out_pk, 96).copy_from_slice(&pk);
        Ok(0)
    })())
}

/// state (32, wiped) | epoch | key_id -> PK_epoch (96).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_hostkey_public_key(state: usize, epoch: u64, kid: usize, kid_len: usize, out_pk: usize) -> i32 {
    code((|| {
        let k = take_key(state, epoch)?;
        output(out_pk, 96).copy_from_slice(&k.public_key(input(kid, kid_len))?);
        Ok(0)
    })())
}

/// state (32, in/out) | epoch | to | key_id -> SK_to written over the old state,
/// PK_to (96) and the link signature by the old epoch key (80). On error the
/// state region is left wiped.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_hostkey_advance(state: usize, epoch: u64, to: u64, kid: usize, kid_len: usize, out_pk: usize, out_sig: usize) -> i32 {
    code((|| {
        let mut k = take_key(state, epoch)?;
        let link = k.advance(input(kid, kid_len), to)?;
        k.export_state(output(state, STATE_LEN))?;
        output(out_pk, 96).copy_from_slice(&link.public_key);
        output(out_sig, 80).copy_from_slice(&link.signature);
        Ok(0)
    })())
}

/// state (32, wiped) | epoch | key_id | commitment_with_proof | packed HASH
/// messages -> credential signature (80).
#[no_mangle]
pub unsafe extern "C" fn rout_zk_hostkey_sign(
    state: usize, epoch: u64, kid: usize, kid_len: usize, cwp: usize, cwp_len: usize, msgs: usize, msgs_len: usize, out_sig: usize,
) -> i32 {
    code((|| {
        let k = take_key(state, epoch)?;
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut r = [&[][..]; MAX_SIGNER_MESSAGES];
        let n = hashed_only(&m[..n], &mut r)?;
        let sig = k.sign_credential(input(kid, kid_len), input(cwp, cwp_len), &r[..n])?;
        output(out_sig, 80).copy_from_slice(&sig);
        Ok(0)
    })())
}

/// pk_from (96) | key_id | from | to | pk_to (96) | sig (80) -> 0, -2 rejected, -1 malformed.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_hostkey_verify_link(pk_from: usize, kid: usize, kid_len: usize, from: u64, to: u64, pk_to: usize, sig: usize) -> i32 {
    code((|| {
        fs::verify_link(input(pk_from, 96), input(kid, kid_len), from, to, input(pk_to, 96), input(sig, 80))?;
        Ok(0)
    })())
}

/// pk (96) | key_id | epoch | sig (80) | packed HASH messages | packed HASH
/// committed messages | prover blind (32, zero when not blind) -> 0, -2, -1.
#[no_mangle]
pub unsafe extern "C" fn rout_zk_hostkey_verify_credential(
    pk: usize, kid: usize, kid_len: usize, epoch: u64, sig: usize, msgs: usize, msgs_len: usize, bmsgs: usize, bmsgs_len: usize, prover_blind: usize,
) -> i32 {
    code((|| {
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = messages(input(msgs, msgs_len), &mut m)?;
        let mut r = [&[][..]; MAX_SIGNER_MESSAGES];
        let n = hashed_only(&m[..n], &mut r)?;
        let mut b = [Msg::Hash(&[]); MAX_BLIND_MESSAGES];
        let k = messages(input(bmsgs, bmsgs_len), &mut b)?;
        let mut rb = [&[][..]; MAX_SIGNER_MESSAGES];
        let k = hashed_only(&b[..k], &mut rb)?;
        let mut pb = scalar_from_be(input(prover_blind, 32))?;
        let res = fs::verify_credential(input(pk, 96), input(kid, kid_len), epoch, input(sig, 80), &r[..n], &rb[..k], &pb);
        wipe::scalar(&mut pb);
        res?;
        Ok(0)
    })())
}
