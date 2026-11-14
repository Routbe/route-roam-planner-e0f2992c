//! ROUT anonymous booking engine. Part 7a: BBS signatures and Blind BBS
//! signatures over BLS12-381 (ciphersuite BLS12-381-SHA-256) and the
//! per-booking guest pseudonym. Part 7b: Pedersen commitments with
//! homomorphic add/sub and 64-bit Bulletproofs range proofs over G1
//! (`pedersen`, `bulletproofs`). Part 7c: the Poseidon permutation over the
//! BLS12-381 scalar field and a 256-deep Sparse Merkle Tree of nullifiers
//! with enclave-signed roots (`poseidon`, `smt`). Part 7d: forward-secure
//! host keys, an HKDF-SHA256 ratchet per epoch with signed epoch links and
//! epoch-bound credentials (`forward_secure`).
//!
//! Specifications followed (editor's copies, see tests/fixtures/SOURCE.md):
//!   * draft-irtf-cfrg-bbs-signatures (core BBS: KeyGen, SkToPk, Sign, Verify,
//!     ProofGen, ProofVerify);
//!   * draft-irtf-cfrg-bbs-blind-signatures (Commit, BlindSign,
//!     VerifyBlindSign, BlindProofGen, BlindProofVerify, committed disclosure).
//! Both are checked byte for byte against the official fixture files.
//!
//! Memory model (owner rules F.2, H.1, I.6):
//!   * no allocator: every buffer is a fixed-size stack value or a region of
//!     the imported linear memory handed in by the host; the module has no
//!     `memory.grow`;
//!   * secret scalars and byte buffers created here are overwritten with
//!     volatile writes before every return (`wipe`); the host zero-fills the
//!     whole linear memory after each call;
//!   * every G1/G2 point that enters from outside is decoded with an on-curve
//!     check, an explicit prime-order subgroup check and an identity check
//!     before it is used in arithmetic or a pairing;
//!   * comparisons of scalars, challenges and pseudonyms use
//!     `subtle::ConstantTimeEq`.
// Native builds (cargo test) link std for the test harness; the shipped
// wasm32 module is no_std with no allocator.
#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod blind;
pub mod bulletproofs;
pub mod codec;
pub mod core_bbs;
pub mod forward_secure;
pub mod generators;
pub mod limits;
pub mod pedersen;
pub mod poseidon;
pub mod poseidon_constants;
pub mod pseudonym;
pub mod random;
pub mod smt;
pub mod wipe;
pub mod xmd;

#[cfg(target_arch = "wasm32")]
mod abi;

/// Errors are deliberately coarse: callers learn that an input is invalid,
/// not which internal check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed or out-of-range input (lengths, indexes, encodings).
    Invalid,
    /// A signature, proof or commitment did not verify.
    Rejected,
    /// A fixed capacity of this module would be exceeded.
    TooLarge,
}

pub type Result<T> = core::result::Result<T, Error>;
