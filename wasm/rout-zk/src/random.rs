//! Sources of the random scalars a proof or a commitment needs.
//!
//! BBS asks for all of an operation's scalars at once (`calculate_random_scalars(count)`),
//! so a source fills a whole slice in one call. The host source draws
//! `expand_len` (48) octets per scalar from the platform CSPRNG and reduces
//! them mod r; the seeded source is the specification's mocked generator and
//! exists only for the official fixtures.

use crate::codec::scalar_from_be_wide;
use crate::xmd::{expand, EXPAND_LEN};
use crate::{wipe, Error, Result};
use bls12_381::Scalar;

pub trait ScalarSource {
    fn fill(&mut self, out: &mut [Scalar]) -> Result<()>;
}

/// seeded_random_scalars(SEED, DST, count) from the BBS fixtures section.
pub struct Seeded<'a> {
    pub seed: &'a [u8],
    pub dst: &'a [u8],
}

/// 170 scalars of 48 octets is the expand_message_xmd limit (8160 octets).
const MAX_SEEDED: usize = 170;

impl ScalarSource for Seeded<'_> {
    fn fill(&mut self, out: &mut [Scalar]) -> Result<()> {
        if out.len() > MAX_SEEDED {
            return Err(Error::TooLarge);
        }
        if out.is_empty() {
            return Ok(());
        }
        let mut v = [0u8; MAX_SEEDED * EXPAND_LEN];
        let n = out.len() * EXPAND_LEN;
        let r = expand(self.seed, self.dst, &mut v[..n]);
        if r.is_ok() {
            for (i, s) in out.iter_mut().enumerate() {
                *s = scalar_from_be_wide(&v[i * EXPAND_LEN..(i + 1) * EXPAND_LEN]);
            }
        }
        wipe::bytes(&mut v[..n]);
        r
    }
}

/// Fixed scalars (tests): hands out the given values in order.
pub struct Fixed<'a>(pub &'a [Scalar]);

impl ScalarSource for Fixed<'_> {
    fn fill(&mut self, out: &mut [Scalar]) -> Result<()> {
        if out.len() != self.0.len() {
            return Err(Error::Invalid);
        }
        out.copy_from_slice(self.0);
        Ok(())
    }
}

/// Uniform scalars from an octet source: 48 octets per scalar, reduced mod r.
pub struct FromOctets<F: FnMut(&mut [u8])>(pub F);

impl<F: FnMut(&mut [u8])> ScalarSource for FromOctets<F> {
    fn fill(&mut self, out: &mut [Scalar]) -> Result<()> {
        let mut b = [0u8; EXPAND_LEN];
        for s in out.iter_mut() {
            (self.0)(&mut b);
            *s = scalar_from_be_wide(&b);
        }
        wipe::bytes(&mut b);
        Ok(())
    }
}
