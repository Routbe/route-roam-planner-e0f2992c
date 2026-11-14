//! Forward-secure host keys per epoch (Stap 7d).
//!
//! State ratchet (HKDF-SHA256, RFC 5869; one step per epoch):
//!   SK_t = HKDF(IKM = SK_{t-1} || I2OSP(t, 8), salt = RATCHET_SALT, info = RATCHET_INFO, L = 32)
//!        = HMAC(HMAC(RATCHET_SALT, SK_{t-1} || I2OSP(t, 8)), RATCHET_INFO || 0x01)
//! SK_0 is the same step applied to a fresh 32-octet seed from the host
//! CSPRNG (the seed plays SK_{-1}); it is never derived from a long-lived
//! secret, so no stored key can recompute it. The state is overwritten in
//! place: the previous value is volatile-wiped before the new one is written,
//! and a key that is dropped is wiped too.
//!
//! Signing key of epoch t (BBS, the fixture-checked BLS12-381-SHA-256 suite):
//!   x_t  = KeyGen(SK_t, KEY_INFO || I2OSP(t, 8) || key_id)
//!   PK_t = x_t · BP2
//! x_t exists only inside one call and is wiped before it returns.
//!
//! One-way. Computing SK_{t-1} from SK_t means finding an HMAC-SHA256 input
//! for a given output, and x_{t-1} is a hash of SK_{t-1}; nothing in this
//! module runs the ratchet backwards. So a compromised SK_t (and every later
//! key) yields neither an earlier state, nor an earlier signing key, nor a
//! signature that verifies under an earlier PK.
//!
//! Epoch link. Moving from epoch t to t' (> t, intermediate epochs are ratcheted
//! through and wiped unpublished) signs, with x_t and before SK_t is wiped,
//!   BBS(header LINK_HEADER, [key_id, I2OSP(t, 8), I2OSP(t', 8), PK_t'])
//! A verifier that trusts the anchor PK_0 follows the links; whoever holds a
//! later key cannot link a different key into an earlier epoch.
//!
//! Credential. A Blind BBS signature (draft-irtf-cfrg-bbs-blind-signatures) of
//! x_t over [key_id, I2OSP(t, 8), m_1..m_L] under CREDENTIAL_HEADER, with the
//! guest's optional commitment. Key id and epoch are signed messages, so a
//! credential never verifies for another host chain or another epoch, and a
//! signature by any other epoch's key fails under PK_t.

use crate::blind;
use crate::codec::pubkey_from_bytes;
use crate::core_bbs::{self, Msg, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::limits::{MAX_BLIND_MESSAGES, MAX_SIGNER_MESSAGES};
use crate::pseudonym::hmac_sha256;
use crate::{wipe, Error, Result};
use bls12_381::Scalar;
use subtle::ConstantTimeEq;

pub const STATE_LEN: usize = 32;
pub const SEED_LEN: usize = 32;
pub const MAX_KEY_ID: usize = 256;
/// Largest jump of one advance (ratchet steps run inside one call).
pub const MAX_ADVANCE: u64 = 1 << 16;
/// Messages the engine binds into every credential: key id and epoch.
pub const BOUND_MESSAGES: usize = 2;
pub const MAX_CREDENTIAL_MESSAGES: usize = MAX_SIGNER_MESSAGES - BOUND_MESSAGES;

pub const RATCHET_SALT: &[u8] = b"ROUT-HOST-EPOCH-RATCHET-V1";
pub const RATCHET_INFO: &[u8] = b"rout.v1.host.epoch.state";
pub const KEY_INFO: &[u8] = b"ROUT-HOST-EPOCH-KEY-V1";
pub const LINK_HEADER: &[u8] = b"ROUT-HOST-EPOCH-LINK-V1";
pub const CREDENTIAL_HEADER: &[u8] = b"ROUT-HOST-CREDENTIAL-V1";

fn key_id(k: &[u8]) -> Result<&[u8]> {
    if k.is_empty() || k.len() > MAX_KEY_ID {
        return Err(Error::Invalid);
    }
    Ok(k)
}

/// One ratchet step in place: state <- HKDF(state || I2OSP(epoch, 8)). The old
/// state is volatile-wiped before the new one is written.
pub fn ratchet(state: &mut [u8; STATE_LEN], epoch: u64) {
    let e = epoch.to_be_bytes();
    let mut prk = hmac_sha256(RATCHET_SALT, &[&state[..], &e]);
    let mut next = hmac_sha256(&prk, &[RATCHET_INFO, &[1u8]]);
    wipe::bytes(&mut prk);
    wipe::bytes(&mut state[..]);
    state.copy_from_slice(&next);
    wipe::bytes(&mut next);
}

/// x_t = KeyGen(SK_t, KEY_INFO || I2OSP(t, 8) || key_id).
fn signing_key(state: &[u8; STATE_LEN], epoch: u64, kid: &[u8]) -> Result<Scalar> {
    const HEAD: usize = KEY_INFO.len() + 8;
    let mut info = [0u8; HEAD + MAX_KEY_ID];
    info[..KEY_INFO.len()].copy_from_slice(KEY_INFO);
    info[KEY_INFO.len()..HEAD].copy_from_slice(&epoch.to_be_bytes());
    info[HEAD..HEAD + kid.len()].copy_from_slice(kid);
    core_bbs::keygen(state, &info[..HEAD + kid.len()], None)
}

/// A signed step of the public key chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub from: u64,
    pub to: u64,
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

/// The ratchet state of one host key chain at one epoch. Wiped on drop.
pub struct EpochKey {
    state: [u8; STATE_LEN],
    epoch: u64,
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        wipe::bytes(&mut self.state);
    }
}

impl EpochKey {
    /// SK_0 from a fresh seed (all zeros is refused: a failed CSPRNG).
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != SEED_LEN || bool::from(seed.ct_eq(&[0u8; SEED_LEN][..])) {
            return Err(Error::Invalid);
        }
        let mut k = EpochKey { state: [0u8; STATE_LEN], epoch: 0 };
        k.state.copy_from_slice(seed);
        ratchet(&mut k.state, 0);
        Ok(k)
    }

    /// Resumes a state held by the worker.
    pub fn from_state(state: &[u8], epoch: u64) -> Result<Self> {
        if state.len() != STATE_LEN {
            return Err(Error::Invalid);
        }
        let mut k = EpochKey { state: [0u8; STATE_LEN], epoch };
        k.state.copy_from_slice(state);
        Ok(k)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Writes the current state for the worker's store (32 octets).
    pub fn export_state(&self, out: &mut [u8]) -> Result<()> {
        if out.len() != STATE_LEN {
            return Err(Error::Invalid);
        }
        out.copy_from_slice(&self.state);
        Ok(())
    }

    /// PK_t of the current epoch.
    pub fn public_key(&self, kid: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN]> {
        let mut x = signing_key(&self.state, self.epoch, key_id(kid)?)?;
        let pk = core_bbs::sk_to_pk(&x);
        wipe::scalar(&mut x);
        Ok(pk)
    }

    /// Ratchets to epoch `to` (> current, at most MAX_ADVANCE ahead) and returns
    /// the link signed by the current epoch's key. On error nothing changes.
    pub fn advance(&mut self, kid: &[u8], to: u64) -> Result<Link> {
        let kid = key_id(kid)?;
        let from = self.epoch;
        if to <= from || to - from > MAX_ADVANCE {
            return Err(Error::Invalid);
        }
        let mut next = self.state;
        for e in from + 1..=to {
            ratchet(&mut next, e);
        }
        let mut x_from = match signing_key(&self.state, from, kid) {
            Ok(x) => x,
            Err(e) => {
                wipe::bytes(&mut next);
                return Err(e);
            }
        };
        let res = (|| {
            let pk_from = core_bbs::sk_to_pk(&x_from);
            let mut x_to = signing_key(&next, to, kid)?;
            let pk_to = core_bbs::sk_to_pk(&x_to);
            wipe::scalar(&mut x_to);
            let signature = sign_link(&x_from, &pk_from, kid, from, to, &pk_to)?;
            Ok(Link { from, to, public_key: pk_to, signature })
        })();
        wipe::scalar(&mut x_from);
        if res.is_ok() {
            wipe::bytes(&mut self.state);
            self.state.copy_from_slice(&next);
            self.epoch = to;
        }
        wipe::bytes(&mut next);
        res
    }

    /// Credential of the current epoch over [key_id, I2OSP(epoch, 8), msgs..],
    /// blind when `cwp` (commitment_with_proof) is not empty.
    pub fn sign_credential(&self, kid: &[u8], cwp: &[u8], msgs: &[&[u8]]) -> Result<[u8; SIGNATURE_LEN]> {
        let kid = key_id(kid)?;
        if msgs.len() > MAX_CREDENTIAL_MESSAGES {
            return Err(Error::TooLarge);
        }
        let e = self.epoch.to_be_bytes();
        let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
        let n = bound(kid, &e, msgs, &mut m);
        let mut x = signing_key(&self.state, self.epoch, kid)?;
        let pk = core_bbs::sk_to_pk(&x);
        let sig = blind::blind_sign(&x, &pk, cwp, CREDENTIAL_HEADER, &m[..n]);
        wipe::scalar(&mut x);
        sig
    }
}

fn bound<'a>(kid: &'a [u8], epoch: &'a [u8; 8], msgs: &[&'a [u8]], out: &mut [Msg<'a>; MAX_SIGNER_MESSAGES]) -> usize {
    out[0] = Msg::Hash(kid);
    out[1] = Msg::Hash(epoch);
    for (i, m) in msgs.iter().enumerate() {
        out[BOUND_MESSAGES + i] = Msg::Hash(*m);
    }
    BOUND_MESSAGES + msgs.len()
}

fn sign_link(x: &Scalar, pk: &[u8; PUBLIC_KEY_LEN], kid: &[u8], from: u64, to: u64, pk_to: &[u8; PUBLIC_KEY_LEN]) -> Result<[u8; SIGNATURE_LEN]> {
    core_bbs::sign(x, pk, LINK_HEADER, &[kid, &from.to_be_bytes(), &to.to_be_bytes(), pk_to])
}

/// Ok only if `sig` is the link from (from, pk_from) to (to, pk_to) of this
/// key chain. Both keys pass the G2 decoding, subgroup and identity checks;
/// a link to the same key is refused.
pub fn verify_link(pk_from: &[u8], kid: &[u8], from: u64, to: u64, pk_to: &[u8], sig: &[u8]) -> Result<()> {
    let kid = key_id(kid)?;
    if to <= from || pk_to.len() != PUBLIC_KEY_LEN || pk_from.len() != PUBLIC_KEY_LEN {
        return Err(Error::Invalid);
    }
    pubkey_from_bytes(pk_to)?;
    pubkey_from_bytes(pk_from)?;
    if bool::from(pk_to.ct_eq(pk_from)) {
        return Err(Error::Rejected);
    }
    core_bbs::verify(pk_from, sig, LINK_HEADER, &[kid, &from.to_be_bytes(), &to.to_be_bytes(), pk_to])
}

/// Ok only for a credential of PK_epoch on exactly (key_id, epoch, msgs) and
/// the committed messages opened by `prover_blind` (zero and none when the
/// credential was not blind).
pub fn verify_credential(pk: &[u8], kid: &[u8], epoch: u64, sig: &[u8], msgs: &[&[u8]], blind_msgs: &[&[u8]], prover_blind: &Scalar) -> Result<()> {
    let kid = key_id(kid)?;
    if msgs.len() > MAX_CREDENTIAL_MESSAGES || blind_msgs.len() > MAX_BLIND_MESSAGES {
        return Err(Error::TooLarge);
    }
    let e = epoch.to_be_bytes();
    let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
    let n = bound(kid, &e, msgs, &mut m);
    let mut b = [Msg::Hash(&[]); MAX_BLIND_MESSAGES];
    for (i, x) in blind_msgs.iter().enumerate() {
        b[i] = Msg::Hash(*x);
    }
    blind::verify_blind_sign(pk, sig, CREDENTIAL_HEADER, &m[..n], &b[..blind_msgs.len()], prover_blind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_advance_leaves_the_state_untouched() {
        let mut k = EpochKey::from_seed(&[7u8; 32]).unwrap();
        let before = k.state;
        assert_eq!(k.advance(b"kid", 0), Err(Error::Invalid));
        assert_eq!(k.advance(b"", 1), Err(Error::Invalid));
        assert_eq!(k.advance(b"kid", MAX_ADVANCE + 1), Err(Error::Invalid));
        assert_eq!(k.state, before);
        assert_eq!(k.epoch, 0);
    }

    #[test]
    fn advance_replaces_the_state_in_place() {
        let mut k = EpochKey::from_seed(&[7u8; 32]).unwrap();
        let old = k.state;
        let at = k.state.as_ptr();
        k.advance(b"kid", 1).unwrap();
        // Same storage, new contents: no second copy of SK_0 is kept.
        assert_eq!(k.state.as_ptr(), at);
        assert_ne!(k.state, old);
        let mut expect = old;
        ratchet(&mut expect, 1);
        assert_eq!(k.state, expect);
    }
}
