//! Pedersen commitments over G1 of BLS12-381 (Stap 7b).
//!
//! Written multiplicatively as in the specification, `C = g^v · h^r`; in the
//! additive notation of the curve code this is `C = v·g + r·h`, with `v` and
//! `r` in the scalar field F_r. The commitment is perfectly hiding and
//! computationally binding as long as nobody knows log_g(h).
//!
//! Generators are nothing-up-my-sleeve points from hash_to_curve
//! (BLS12381G1_XMD:SHA-256_SSWU_RO_) under a ROUT-specific DST, so nobody can
//! know a discrete log between them. Generators supplied from outside are
//! accepted only when they are valid subgroup points *and* byte-equal to the
//! canonical pair: a manipulated g or h (for example h = k·g) is refused.
//!
//! Homomorphism: commit(v1, r1) + commit(v2, r2) = commit(v1 + v2, r1 + r2)
//! and C_rem' = C_rem · C_i^{-1} = commit(v_rem - v_i, r_rem - r_i). Together
//! with a range proof on C_rem' this proves the remaining capacity is >= 0.

use crate::codec::{g1_bytes, g1_from_bytes, scalar_from_be, scalar_to_be, G1_LEN, SCALAR_LEN};
use crate::{wipe, Error, Result};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective, Scalar};
use subtle::ConstantTimeEq;

/// Domain separation tag for every generator of the 7b engine.
pub const GENERATOR_DST: &[u8] = b"ROUT_ZK_V1_BLS12381G1_XMD:SHA-256_SSWU_RO_PEDERSEN_BULLETPROOFS_";

pub const COMMITMENT_LEN: usize = G1_LEN;

/// hash_to_curve(tag || I2OSP(index, 4), GENERATOR_DST).
pub fn generator(tag: u8, index: u32) -> G1Projective {
    let i = index.to_be_bytes();
    let msg = [tag, i[0], i[1], i[2], i[3]];
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, GENERATOR_DST)
}

/// The Pedersen pair (g, h).
#[derive(Clone, Copy, Debug)]
pub struct PedersenGens {
    pub g: G1Projective,
    pub h: G1Projective,
}

impl PedersenGens {
    pub fn canonical() -> Self {
        PedersenGens { g: generator(b'g', 0), h: generator(b'h', 0) }
    }

    /// Generators handed in from outside: each must decode to a valid,
    /// non-identity point of the prime-order subgroup and be equal (in
    /// constant time) to the canonical one. Anything else is REJECTED.
    pub fn from_bytes(g: &[u8], h: &[u8]) -> Result<Self> {
        let ga = g1_from_bytes(g)?;
        let ha = g1_from_bytes(h)?;
        let c = Self::canonical();
        let same = ga.to_compressed().ct_eq(&G1Affine::from(c.g).to_compressed())
            & ha.to_compressed().ct_eq(&G1Affine::from(c.h).to_compressed());
        if !bool::from(same) {
            return Err(Error::Rejected);
        }
        Ok(c)
    }

    pub fn to_bytes(&self) -> ([u8; G1_LEN], [u8; G1_LEN]) {
        (g1_bytes(&self.g), g1_bytes(&self.h))
    }

    /// C = v·g + r·h.
    pub fn commit(&self, value: &Scalar, blinding: &Scalar) -> Commitment {
        Commitment(self.g * value + self.h * blinding)
    }

    /// Commitment to a 64-bit value.
    pub fn commit_u64(&self, value: u64, blinding: &Scalar) -> Commitment {
        let mut v = Scalar::from(value);
        let c = self.commit(&v, blinding);
        wipe::scalar(&mut v);
        c
    }

    /// Constant-time check that `opening` opens `c`.
    pub fn opens(&self, c: &Commitment, opening: &Opening) -> bool {
        let mine = self.commit(&opening.value, &opening.blinding);
        bool::from(mine.to_bytes().ct_eq(&c.to_bytes()))
    }
}

/// A commitment (a G1 point; public).
#[derive(Clone, Copy, Debug)]
pub struct Commitment(pub G1Projective);

impl Commitment {
    pub fn to_bytes(&self) -> [u8; COMMITMENT_LEN] {
        g1_bytes(&self.0)
    }

    /// Decoding with on-curve, subgroup and identity checks.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(Commitment(G1Projective::from(g1_from_bytes(b)?)))
    }

    /// Homomorphic addition: commit(v1 + v2, r1 + r2).
    pub fn add(&self, other: &Commitment) -> Commitment {
        Commitment(self.0 + other.0)
    }

    /// Homomorphic subtraction ("division" C · D^{-1}): commit(v1 - v2, r1 - r2).
    pub fn sub(&self, other: &Commitment) -> Commitment {
        Commitment(self.0 - other.0)
    }

    pub fn ct_eq(&self, other: &Commitment) -> bool {
        bool::from(self.to_bytes().ct_eq(&other.to_bytes()))
    }
}

/// The secret opening (v, r) of a commitment. Wiped (volatile) on drop.
pub struct Opening {
    pub value: Scalar,
    pub blinding: Scalar,
}

impl Opening {
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        Opening { value, blinding }
    }

    pub fn from_u64(value: u64, blinding: Scalar) -> Self {
        Opening { value: Scalar::from(value), blinding }
    }

    /// Opening of `self + other`.
    pub fn add(&self, other: &Opening) -> Opening {
        Opening { value: self.value + other.value, blinding: self.blinding + other.blinding }
    }

    /// Opening of `self - other` (C_rem' = C_rem · C_i^{-1}).
    pub fn sub(&self, other: &Opening) -> Opening {
        Opening { value: self.value - other.value, blinding: self.blinding - other.blinding }
    }

    /// The value as u64 if it lies in [0, 2^64 - 1] (the 24 high octets of the
    /// canonical encoding are zero). The check runs in constant time; only the
    /// in-range bit is revealed.
    pub fn value_u64(&self) -> Option<u64> {
        value_u64(&self.value)
    }
}

impl Drop for Opening {
    fn drop(&mut self) {
        wipe::scalar(&mut self.value);
        wipe::scalar(&mut self.blinding);
    }
}

/// The value as u64 if it lies in [0, 2^64 - 1].
pub fn value_u64(v: &Scalar) -> Option<u64> {
    let mut le = v.to_bytes();
    let mut high = 0u8;
    for b in le[8..].iter() {
        high |= *b;
    }
    let ok = high.ct_eq(&0u8);
    let mut low = [0u8; 8];
    low.copy_from_slice(&le[..8]);
    let out = u64::from_le_bytes(low);
    wipe::bytes(&mut le);
    wipe::bytes(&mut low);
    if bool::from(ok) {
        Some(out)
    } else {
        None
    }
}

/// I2OSP of a u64 value as a 32-octet scalar (ABI helper).
pub fn scalar_bytes_of_u64(v: u64) -> [u8; SCALAR_LEN] {
    scalar_to_be(&Scalar::from(v))
}

/// Canonical 32-octet blinding factor (0 <= r < q).
pub fn blinding_from_bytes(b: &[u8]) -> Result<Scalar> {
    scalar_from_be(b)
}
