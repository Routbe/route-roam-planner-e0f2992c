//! expand_message_xmd (RFC 9380, section 5.3.1) with SHA-256, with a
//! streaming message so that `serialize(...)` inputs never need a buffer, and
//! BBS hash_to_scalar on top of it.

use crate::codec::scalar_from_be_wide;
use crate::{wipe, Error, Result};
use bls12_381::Scalar;
use sha2::{Digest, Sha256};

const B_IN_BYTES: usize = 32;
const S_IN_BYTES: usize = 64;
/// expand_len of the BLS12-381-SHA-256 ciphersuite.
pub const EXPAND_LEN: usize = 48;

/// A message being absorbed into b_0 of expand_message_xmd.
pub struct Xmd {
    h: Sha256,
}

impl Default for Xmd {
    fn default() -> Self {
        Self::new()
    }
}

impl Xmd {
    pub fn new() -> Self {
        let mut h = Sha256::new();
        h.update([0u8; S_IN_BYTES]); // Z_pad
        Xmd { h }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.h.update(data);
        self
    }

    /// Finishes with the domain separation tag and fills `out`.
    pub fn finish(self, dst: &[u8], out: &mut [u8]) -> Result<()> {
        let len = out.len();
        let ell = (len + B_IN_BYTES - 1) / B_IN_BYTES;
        if len == 0 || ell > 255 || len > 65_535 || dst.len() > 255 {
            return Err(Error::Invalid);
        }
        let dst_len = [dst.len() as u8];
        let mut h = self.h;
        h.update((len as u16).to_be_bytes());
        h.update([0u8]);
        h.update(dst);
        h.update(dst_len);
        let mut b0: [u8; B_IN_BYTES] = h.finalize().into();

        let mut h = Sha256::new();
        h.update(b0);
        h.update([1u8]);
        h.update(dst);
        h.update(dst_len);
        let mut bi: [u8; B_IN_BYTES] = h.finalize().into();

        let mut offset = 0;
        let mut i: u16 = 1;
        loop {
            let take = core::cmp::min(B_IN_BYTES, len - offset);
            out[offset..offset + take].copy_from_slice(&bi[..take]);
            offset += take;
            if offset == len {
                break;
            }
            i += 1;
            let mut x = [0u8; B_IN_BYTES];
            for j in 0..B_IN_BYTES {
                x[j] = b0[j] ^ bi[j];
            }
            let mut h = Sha256::new();
            h.update(x);
            h.update([i as u8]);
            h.update(dst);
            h.update(dst_len);
            wipe::bytes(&mut bi);
            bi = h.finalize().into();
            wipe::bytes(&mut x);
        }
        wipe::bytes(&mut b0);
        wipe::bytes(&mut bi);
        Ok(())
    }

    /// BBS hash_to_scalar: OS2IP(expand_message(msg, dst, 48)) mod r.
    pub fn to_scalar(self, dst: &[u8]) -> Result<Scalar> {
        let mut u = [0u8; EXPAND_LEN];
        self.finish(dst, &mut u)?;
        let s = scalar_from_be_wide(&u);
        wipe::bytes(&mut u);
        Ok(s)
    }
}

/// expand_message_xmd over a single message.
pub fn expand(msg: &[u8], dst: &[u8], out: &mut [u8]) -> Result<()> {
    let mut x = Xmd::new();
    x.update(msg);
    x.finish(dst, out)
}

/// hash_to_scalar over a single message.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Scalar> {
    let mut x = Xmd::new();
    x.update(msg);
    x.to_scalar(dst)
}

/// A domain separation tag assembled from parts without an allocator.
#[derive(Clone, Copy)]
pub struct Dst {
    buf: [u8; 128],
    len: usize,
}

impl Dst {
    pub fn new(parts: &[&[u8]]) -> Result<Dst> {
        let mut d = Dst { buf: [0u8; 128], len: 0 };
        for p in parts {
            if d.len + p.len() > d.buf.len() {
                return Err(Error::TooLarge);
            }
            d.buf[d.len..d.len + p.len()].copy_from_slice(p);
            d.len += p.len();
        }
        Ok(d)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
