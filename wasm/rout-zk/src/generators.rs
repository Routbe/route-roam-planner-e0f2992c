//! create_generators (BBS, "H2G_") and the ciphersuite constants.

use crate::codec::g1_from_bytes;
use crate::xmd::{expand, Dst, EXPAND_LEN};
use crate::{Error, Result};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective};

pub const CIPHERSUITE_ID: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// api_id of the core BBS interface: ciphersuite_id || "H2G_HM2S_".
pub const API_ID_BBS: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
/// api_id of the Blind BBS interface: ciphersuite_id || "BLIND_H2G_HM2S_".
pub const API_ID_BLIND: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_";

/// P1 of the BLS12-381-SHA-256 ciphersuite (compressed).
const P1_BYTES: [u8; 48] = [
    0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46, 0x62,
    0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1, 0xfd, 0x22,
    0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b, 0x4e, 0x28, 0xc9,
];

pub fn p1() -> G1Affine {
    // A fixed, validated constant: decoding cannot fail.
    g1_from_bytes(&P1_BYTES).unwrap_or(G1Affine::generator())
}

/// create_generators(count, api_id) written into `out[..count]`.
pub fn create_generators(count: usize, api_id: &[u8], out: &mut [G1Projective]) -> Result<()> {
    if count > out.len() {
        return Err(Error::TooLarge);
    }
    let seed_dst = Dst::new(&[api_id, b"SIG_GENERATOR_SEED_"])?;
    let generator_dst = Dst::new(&[api_id, b"SIG_GENERATOR_DST_"])?;
    let generator_seed = Dst::new(&[api_id, b"MESSAGE_GENERATOR_SEED"])?;
    let mut v = [0u8; EXPAND_LEN];
    expand(generator_seed.as_bytes(), seed_dst.as_bytes(), &mut v)?;
    let mut input = [0u8; EXPAND_LEN + 8];
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        input[..EXPAND_LEN].copy_from_slice(&v);
        input[EXPAND_LEN..].copy_from_slice(&((i as u64) + 1).to_be_bytes());
        expand(&input, seed_dst.as_bytes(), &mut v)?;
        *slot = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(v, generator_dst.as_bytes());
    }
    Ok(())
}

/// Blind generators: create_generators(count, "BLIND_" || api_id).
pub fn create_blind_generators(count: usize, api_id: &[u8], out: &mut [G1Projective]) -> Result<()> {
    let id = Dst::new(&[b"BLIND_", api_id])?;
    create_generators(count, id.as_bytes(), out)
}
