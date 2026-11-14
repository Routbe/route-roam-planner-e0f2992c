//! Volatile overwrite of secrets. The compiler may not elide these writes, and
//! the fence keeps them ordered before the function returns.

use bls12_381::Scalar;
use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrites the bytes with zeros (volatile).
pub fn bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrites the scalar with zero (volatile).
pub fn scalar(s: &mut Scalar) {
    unsafe { core::ptr::write_volatile(s, Scalar::zero()) };
    compiler_fence(Ordering::SeqCst);
}

/// Overwrites every scalar of the slice with zero (volatile).
pub fn scalars(s: &mut [Scalar]) {
    for x in s.iter_mut() {
        unsafe { core::ptr::write_volatile(x, Scalar::zero()) };
    }
    compiler_fence(Ordering::SeqCst);
}
