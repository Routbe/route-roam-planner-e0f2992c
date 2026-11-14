//! Octet encodings of the BLS12-381 ciphersuite (big-endian scalars,
//! compressed points) with strict validation of everything that enters.

use crate::xmd::Xmd;
use crate::{wipe, Error, Result};
use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};
use subtle::{Choice, ConstantTimeEq};

pub const SCALAR_LEN: usize = 32;
pub const G1_LEN: usize = 48;
pub const G2_LEN: usize = 96;

/// I2OSP(s, 32).
pub fn scalar_to_be(s: &Scalar) -> [u8; SCALAR_LEN] {
    let mut b = s.to_bytes();
    b.reverse();
    b
}

/// OS2IP of exactly 32 octets; INVALID unless 0 < s < r.
pub fn scalar_from_be_nonzero(b: &[u8]) -> Result<Scalar> {
    let s = scalar_from_be(b)?;
    if bool::from(s.ct_eq(&Scalar::zero())) {
        return Err(Error::Invalid);
    }
    Ok(s)
}

/// OS2IP of exactly 32 octets; INVALID if s >= r.
pub fn scalar_from_be(b: &[u8]) -> Result<Scalar> {
    if b.len() != SCALAR_LEN {
        return Err(Error::Invalid);
    }
    let mut le = [0u8; SCALAR_LEN];
    for i in 0..SCALAR_LEN {
        le[i] = b[SCALAR_LEN - 1 - i];
    }
    let s = Scalar::from_bytes(&le);
    wipe::bytes(&mut le);
    Option::<Scalar>::from(s).ok_or(Error::Invalid)
}

/// OS2IP(bytes) mod r for at most 64 octets.
pub fn scalar_from_be_wide(b: &[u8]) -> Scalar {
    debug_assert!(b.len() <= 64);
    let n = core::cmp::min(b.len(), 64);
    let mut le = [0u8; 64];
    for i in 0..n {
        le[i] = b[n - 1 - i];
    }
    let s = Scalar::from_bytes_wide(&le);
    wipe::bytes(&mut le);
    s
}

/// Raw message (Blind BBS "RAW" flag): OS2IP of at most 32 octets, which must
/// already be below r. Larger values are refused instead of reduced.
pub fn scalar_from_raw(b: &[u8]) -> Result<Scalar> {
    if b.len() > SCALAR_LEN {
        return Err(Error::Invalid);
    }
    let mut padded = [0u8; SCALAR_LEN];
    padded[SCALAR_LEN - b.len()..].copy_from_slice(b);
    let s = scalar_from_be(&padded);
    wipe::bytes(&mut padded);
    s
}

/// Subgroup validation of a G1 point: on the curve, in the prime-order
/// subgroup and not the identity.
pub fn g1_is_valid(p: &G1Affine) -> Choice {
    p.is_on_curve() & p.is_torsion_free() & !p.is_identity()
}

/// Subgroup validation of a G2 point: on the curve, in the prime-order
/// subgroup and not the identity.
pub fn g2_is_valid(p: &G2Affine) -> Choice {
    p.is_on_curve() & p.is_torsion_free() & !p.is_identity()
}

/// octets_to_point_E1 + subgroup_check_G1 + identity check.
pub fn g1_from_bytes(b: &[u8]) -> Result<G1Affine> {
    let arr: &[u8; G1_LEN] = b.try_into().map_err(|_| Error::Invalid)?;
    let p = Option::<G1Affine>::from(G1Affine::from_compressed(arr)).ok_or(Error::Invalid)?;
    if !bool::from(g1_is_valid(&p)) {
        return Err(Error::Invalid);
    }
    Ok(p)
}

/// octets_to_pubkey: a valid, non-identity point of the G2 subgroup.
pub fn pubkey_from_bytes(b: &[u8]) -> Result<G2Affine> {
    let arr: &[u8; G2_LEN] = b.try_into().map_err(|_| Error::Invalid)?;
    let p = Option::<G2Affine>::from(G2Affine::from_compressed(arr)).ok_or(Error::Invalid)?;
    if !bool::from(g2_is_valid(&p)) {
        return Err(Error::Invalid);
    }
    Ok(p)
}

pub fn g1_bytes(p: &G1Projective) -> [u8; G1_LEN] {
    G1Affine::from(p).to_compressed()
}

/// Constant-time equality of two scalars.
pub fn scalar_eq(a: &Scalar, b: &Scalar) -> bool {
    bool::from(a.ct_eq(b))
}

/// BBS `serialize` into a running hash.
pub trait Absorb {
    fn absorb(&mut self, bytes: &[u8]);

    fn int(&mut self, v: u64) {
        self.absorb(&v.to_be_bytes());
    }
    fn scalar(&mut self, s: &Scalar) {
        let mut b = scalar_to_be(s);
        self.absorb(&b);
        wipe::bytes(&mut b);
    }
    fn g1(&mut self, p: &G1Projective) {
        self.absorb(&g1_bytes(p));
    }
    fn g1a(&mut self, p: &G1Affine) {
        self.absorb(&p.to_compressed());
    }
}

impl Absorb for Xmd {
    fn absorb(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// BBS `serialize` into a caller-provided output region.
pub struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflow: bool,
}

impl<'a> Out<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Out { buf, len: 0, overflow: false }
    }

    pub fn finish(self) -> Result<usize> {
        if self.overflow {
            wipe::bytes(self.buf);
            return Err(Error::TooLarge);
        }
        Ok(self.len)
    }
}

impl Absorb for Out<'_> {
    fn absorb(&mut self, bytes: &[u8]) {
        if self.overflow || self.len + bytes.len() > self.buf.len() {
            self.overflow = true;
            return;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
}
