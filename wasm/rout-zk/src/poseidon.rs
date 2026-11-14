//! Poseidon permutation over the BLS12-381 scalar field (Stap 7c).
//!
//! Instance: the reference "poseidonperm_x5_255_3" of Grassi, Khovratovich,
//! Rechberger, Roy and Schofnegger (USENIX Security 2021, hadeshash):
//! width t = 3, S-box x^5, R_F = 8 full rounds (4 + 4), R_P = 57 partial
//! rounds, 195 round constants and a 3x3 Cauchy MDS matrix, all produced by the
//! reference Grain LFSR (src/poseidon_constants.rs, regenerated and checked by
//! tools/poseidon_params.py; the published permutation vector is checked in
//! tests/poseidon.rs).
//!
//! Constant time: every round runs the same field operations whatever the
//! state holds (the full/partial schedule depends only on the public round
//! number); Scalar addition and multiplication in bls12_381 are constant time,
//! and comparisons go through `subtle`. The state lives in one fixed array on
//! the stack and is overwritten (volatile) before every return.
//!
//! Sponge use (2-to-1 compression, the paper's domain separation, §4.2):
//!   hash2(tag, a, b) = Permutation([tag, a, b])[1]
//! with the capacity element set to a tag:
//!   * Merkle tree node, arity 2: tag = 2^2 - 1 = 3;
//!   * fixed-length hash of 2 elements to 1 output: tag = 2 · 2^64 + (1 - 1).

use crate::poseidon_constants::{MDS, ROUND_CONSTANTS};
use crate::wipe;
use bls12_381::Scalar;

pub const WIDTH: usize = 3;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;

/// Capacity tag of an arity-2 Merkle tree node.
pub const TAG_MERKLE_2: Scalar = Scalar::from_raw([3, 0, 0, 0]);
/// Capacity tag of a fixed-length hash of two elements to one output.
pub const TAG_FIXED_2: Scalar = Scalar::from_raw([0, 2, 0, 0]);

#[inline(always)]
fn sbox(x: &Scalar) -> Scalar {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

#[inline(always)]
fn mix(state: &mut [Scalar; WIDTH]) {
    let mut out = [Scalar::zero(); WIDTH];
    for i in 0..WIDTH {
        for j in 0..WIDTH {
            out[i] += MDS[i][j] * state[j];
        }
    }
    *state = out;
    wipe::scalars(&mut out);
}

/// The Poseidon permutation, in place.
pub fn permute(state: &mut [Scalar; WIDTH]) {
    let half = FULL_ROUNDS / 2;
    for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
        let k = round * WIDTH;
        for i in 0..WIDTH {
            state[i] += ROUND_CONSTANTS[k + i];
        }
        if round < half || round >= half + PARTIAL_ROUNDS {
            for i in 0..WIDTH {
                state[i] = sbox(&state[i]);
            }
        } else {
            state[0] = sbox(&state[0]);
        }
        mix(state);
    }
}

/// Permutation([tag, a, b])[1].
pub fn hash2(tag: &Scalar, a: &Scalar, b: &Scalar) -> Scalar {
    let mut state = [*tag, *a, *b];
    permute(&mut state);
    let out = state[1];
    wipe::scalars(&mut state);
    out
}
