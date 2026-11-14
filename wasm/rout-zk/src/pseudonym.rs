//! Per-booking guest pseudonym.
//!
//!   derived_seed = HKDF-Expand(PRK = master_seed, info = "rout.v1.booking.pseudonym", L = 32)
//!   pseudonym    = HMAC-SHA256(derived_seed, host_id || booking_nonce)
//!
//! booking_nonce has a fixed length (32 octets), so `host_id || booking_nonce`
//! is unambiguous for any host_id length. A fresh nonce per booking makes two
//! bookings of the same guest at the same host unlinkable for anyone without
//! the master seed.

use crate::{wipe, Error, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const INFO: &[u8] = b"rout.v1.booking.pseudonym";
pub const SEED_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const PSEUDONYM_LEN: usize = 32;
pub const MAX_HOST_ID_LEN: usize = 256;

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let d: [u8; 32] = Sha256::digest(key).into();
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut pad = [0u8; 64];
    for i in 0..64 {
        pad[i] = k[i] ^ 0x36;
    }
    let mut h = Sha256::new();
    h.update(pad);
    for p in parts {
        h.update(p);
    }
    let mut inner: [u8; 32] = h.finalize().into();
    for i in 0..64 {
        pad[i] = k[i] ^ 0x5c;
    }
    let mut h = Sha256::new();
    h.update(pad);
    h.update(inner);
    let out: [u8; 32] = h.finalize().into();
    wipe::bytes(&mut k);
    wipe::bytes(&mut pad);
    wipe::bytes(&mut inner);
    out
}

/// HKDF-Expand (RFC 5869) for L = 32: T(1) = HMAC(PRK, info || 0x01).
pub fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    hmac_sha256(prk, &[info, &[1u8]])
}

/// The pseudonym of one booking.
pub fn derive(master_seed: &[u8], host_id: &[u8], booking_nonce: &[u8]) -> Result<[u8; PSEUDONYM_LEN]> {
    if master_seed.len() != SEED_LEN || booking_nonce.len() != NONCE_LEN || host_id.is_empty() || host_id.len() > MAX_HOST_ID_LEN {
        return Err(Error::Invalid);
    }
    let mut seed = hkdf_expand_32(master_seed, INFO);
    let p = hmac_sha256(&seed, &[host_id, booking_nonce]);
    wipe::bytes(&mut seed);
    Ok(p)
}

/// Recomputes the pseudonym and compares it in constant time.
pub fn matches(master_seed: &[u8], host_id: &[u8], booking_nonce: &[u8], claimed: &[u8]) -> Result<bool> {
    if claimed.len() != PSEUDONYM_LEN {
        return Err(Error::Invalid);
    }
    let mut p = derive(master_seed, host_id, booking_nonce)?;
    let ok = bool::from(p.ct_eq(claimed));
    wipe::bytes(&mut p);
    Ok(ok)
}
