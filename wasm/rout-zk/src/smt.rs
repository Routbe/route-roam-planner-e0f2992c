//! 256-deep Sparse Merkle Tree of booking nullifiers with enclave-signed
//! roots (Stap 7c).
//!
//! Tree. Every 32-octet nullifier owns one leaf: its path is the nullifier
//! itself read as a 256-bit big-endian integer, bit d (counted from the least
//! significant bit) choosing the side at height d (0 = left). Because the tree
//! is full depth there are no shortcut leaves: two different nullifiers never
//! share a leaf.
//!   empty leaf           = 0
//!   occupied leaf        = Poseidon(TAG_FIXED_2, hi, lo)   (hi, lo = the two
//!                          16-octet halves of the nullifier, both < 2^128 < r)
//!   node                 = Poseidon(TAG_MERKLE_2, left, right)
//! An inclusion or exclusion proof is the 256 sibling values from the leaf up
//! (8192 octets, each a canonical big-endian scalar < r). Fixed size: the
//! proof says nothing about how full the tree is.
//!
//! NonExist(nf, R): folding the empty leaf with the siblings gives R.
//! Insert(nf): NonExist(nf, R) must hold, then the same siblings with the
//! occupied leaf give R'. A reused nullifier has an occupied leaf, so no
//! sibling list reproduces R from an empty one and the insert is REJECTED
//! (finding one would be a Poseidon collision).
//!
//! The nodes themselves live in an untrusted store (later: the database). The
//! enclave never trusts it: every proof is checked against a root that the
//! enclave signed itself.
//!
//! Signed root. Sign_enclave(R || epoch) is a BBS signature (core_bbs, the
//! fixture-checked BLS12-381-SHA-256 suite) over three messages
//!   [tree id, R (32 octets), I2OSP(epoch, 8)]
//! under header ROOT_HEADER, with a key from KeyGen(key_material,
//! SIGNER_KEY_INFO). The secret key exists only inside one call of this module
//! and is wiped before it returns. An insert verifies the signature on the old
//! root under the caller's own key and signs R' with epoch + 1, so a database
//! admin who edits a root, its epoch, the tree id, the signature or the public
//! key is refused. Replaying an *older* genuine signed root (rollback) cannot
//! be detected by a signature alone; the worker keeps a high-water mark per
//! tree and anchoring is planned (see src/lib/crypto-enclave/smt.ts).

use crate::codec::{scalar_from_be, scalar_to_be, SCALAR_LEN};
use crate::core_bbs::{self, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::poseidon::{hash2, TAG_FIXED_2, TAG_MERKLE_2};
use crate::{wipe, Error, Result};
use bls12_381::Scalar;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub const DEPTH: usize = 256;
pub const NODE_LEN: usize = SCALAR_LEN;
pub const NULLIFIER_LEN: usize = 32;
pub const SIBLINGS_LEN: usize = DEPTH * NODE_LEN;
/// Leaf plus every ancestor up to and including the root.
pub const PATH_NODES: usize = DEPTH + 1;
pub const PATH_LEN: usize = PATH_NODES * NODE_LEN;
pub const MAX_TREE_ID: usize = 256;

pub const ROOT_HEADER: &[u8] = b"ROUT-SMT-ROOT-V1";
pub const SIGNER_KEY_INFO: &[u8] = b"ROUT-SMT-ROOT-SIGNER-V1";

/// Node value of two children.
pub fn node(left: &Scalar, right: &Scalar) -> Scalar {
    hash2(&TAG_MERKLE_2, left, right)
}

/// Occupied leaf of a nullifier.
pub fn leaf(nullifier: &[u8; NULLIFIER_LEN]) -> Scalar {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&nullifier[..16]);
    lo.copy_from_slice(&nullifier[16..]);
    let h = u128::from_be_bytes(hi);
    let l = u128::from_be_bytes(lo);
    let a = Scalar::from_raw([h as u64, (h >> 64) as u64, 0, 0]);
    let b = Scalar::from_raw([l as u64, (l >> 64) as u64, 0, 0]);
    wipe::bytes(&mut hi);
    wipe::bytes(&mut lo);
    hash2(&TAG_FIXED_2, &a, &b)
}

/// Root of the empty tree (256 compressions of the empty subtree).
pub fn empty_root() -> Scalar {
    let mut h = Scalar::zero();
    for _ in 0..DEPTH {
        h = node(&h, &h);
    }
    h
}

/// Empty subtree value at every height (leaf first, root last) into `out`
/// (PATH_LEN octets).
pub fn empty_path(out: &mut [u8]) {
    let mut h = Scalar::zero();
    out[..NODE_LEN].copy_from_slice(&scalar_to_be(&h));
    for height in 1..=DEPTH {
        h = node(&h, &h);
        out[height * NODE_LEN..(height + 1) * NODE_LEN].copy_from_slice(&scalar_to_be(&h));
    }
}

/// Bit `height` of the nullifier read as a big-endian integer.
fn bit(nullifier: &[u8; NULLIFIER_LEN], height: usize) -> Choice {
    Choice::from((nullifier[NULLIFIER_LEN - 1 - height / 8] >> (height % 8)) & 1)
}

fn nullifier_of(b: &[u8]) -> Result<[u8; NULLIFIER_LEN]> {
    if b.len() != NULLIFIER_LEN {
        return Err(Error::Invalid);
    }
    let mut n = [0u8; NULLIFIER_LEN];
    n.copy_from_slice(b);
    Ok(n)
}

/// Folds `leaf` with the siblings up to the root. Every sibling must be a
/// canonical scalar. With `path`, writes the leaf and each ancestor
/// (index 0 = leaf, DEPTH = root) as big-endian octets.
pub fn fold(nullifier: &[u8; NULLIFIER_LEN], leaf: &Scalar, siblings: &[u8], mut path: Option<&mut [u8]>) -> Result<Scalar> {
    if siblings.len() != SIBLINGS_LEN {
        return Err(Error::Invalid);
    }
    if let Some(p) = path.as_deref_mut() {
        if p.len() != PATH_LEN {
            return Err(Error::Invalid);
        }
        p[..NODE_LEN].copy_from_slice(&scalar_to_be(leaf));
    }
    let mut cur = *leaf;
    for height in 0..DEPTH {
        let mut s = match scalar_from_be(&siblings[height * NODE_LEN..(height + 1) * NODE_LEN]) {
            Ok(s) => s,
            Err(e) => {
                wipe::scalar(&mut cur);
                return Err(e);
            }
        };
        let right_side = bit(nullifier, height);
        let mut l = Scalar::conditional_select(&cur, &s, right_side);
        let mut r = Scalar::conditional_select(&s, &cur, right_side);
        cur = node(&l, &r);
        wipe::scalar(&mut l);
        wipe::scalar(&mut r);
        wipe::scalar(&mut s);
        if let Some(p) = path.as_deref_mut() {
            let at = (height + 1) * NODE_LEN;
            p[at..at + NODE_LEN].copy_from_slice(&scalar_to_be(&cur));
        }
    }
    Ok(cur)
}

fn same(a: &Scalar, b: &Scalar) -> bool {
    bool::from(a.ct_eq(b))
}

/// NonExist(nullifier, root): Ok if the leaf is empty under `root`.
pub fn verify_non_membership(root: &Scalar, nullifier: &[u8], siblings: &[u8]) -> Result<()> {
    let n = nullifier_of(nullifier)?;
    let mut got = fold(&n, &Scalar::zero(), siblings, None)?;
    let ok = same(&got, root);
    wipe::scalar(&mut got);
    if ok { Ok(()) } else { Err(Error::Rejected) }
}

/// Exist(nullifier, root): Ok if the leaf is occupied under `root`.
pub fn verify_membership(root: &Scalar, nullifier: &[u8], siblings: &[u8]) -> Result<()> {
    let n = nullifier_of(nullifier)?;
    let mut got = fold(&n, &leaf(&n), siblings, None)?;
    let ok = same(&got, root);
    wipe::scalar(&mut got);
    if ok { Ok(()) } else { Err(Error::Rejected) }
}

/// R' after occupying the nullifier's leaf; REJECTED unless NonExist holds.
pub fn insert(root: &Scalar, nullifier: &[u8], siblings: &[u8], path: Option<&mut [u8]>) -> Result<Scalar> {
    verify_non_membership(root, nullifier, siblings)?;
    let n = nullifier_of(nullifier)?;
    fold(&n, &leaf(&n), siblings, path)
}

// ---- Signed roots ---------------------------------------------------------

fn tree_id(t: &[u8]) -> Result<&[u8]> {
    if t.is_empty() || t.len() > MAX_TREE_ID {
        return Err(Error::Invalid);
    }
    Ok(t)
}

/// The signer key pair from `key_material` (>= 32 octets).
pub fn signer(key_material: &[u8]) -> Result<(Scalar, [u8; PUBLIC_KEY_LEN])> {
    let sk = core_bbs::keygen(key_material, SIGNER_KEY_INFO, None)?;
    let pk = core_bbs::sk_to_pk(&sk);
    Ok((sk, pk))
}

pub fn signer_public_key(key_material: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let (mut sk, pk) = signer(key_material)?;
    wipe::scalar(&mut sk);
    Ok(pk)
}

/// Sign_enclave(tree || R || epoch).
pub fn sign_root(sk: &Scalar, pk: &[u8; PUBLIC_KEY_LEN], tree: &[u8], root: &Scalar, epoch: u64) -> Result<[u8; SIGNATURE_LEN]> {
    let r = scalar_to_be(root);
    let e = epoch.to_be_bytes();
    core_bbs::sign(sk, pk, ROOT_HEADER, &[tree_id(tree)?, &r, &e])
}

/// Ok only for a signature of `pk` on exactly (tree, root, epoch). The public
/// key passes the G2 subgroup checks inside core_bbs::verify.
pub fn verify_root(pk: &[u8], tree: &[u8], root: &[u8], epoch: u64, sig: &[u8]) -> Result<()> {
    let r = scalar_from_be(root)?;
    let rb = scalar_to_be(&r);
    let e = epoch.to_be_bytes();
    core_bbs::verify(pk, sig, ROOT_HEADER, &[tree_id(tree)?, &rb, &e])
}

/// Empty root signed at epoch 0.
pub fn genesis(key_material: &[u8], tree: &[u8]) -> Result<([u8; NODE_LEN], [u8; SIGNATURE_LEN])> {
    tree_id(tree)?;
    let (mut sk, pk) = signer(key_material)?;
    let root = empty_root();
    let sig = sign_root(&sk, &pk, tree, &root, 0);
    wipe::scalar(&mut sk);
    Ok((scalar_to_be(&root), sig?))
}

/// Result of a signed insert: R', its epoch, the signature and the new path.
pub struct Inserted {
    pub root: [u8; NODE_LEN],
    pub epoch: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Verifies the old signed root under the caller's own key, proves NonExist,
/// occupies the leaf and signs (R', epoch + 1). `path` receives the new leaf
/// and ancestors for the untrusted store.
pub fn insert_signed(
    key_material: &[u8], tree: &[u8], root: &[u8], epoch: u64, sig: &[u8], nullifier: &[u8], siblings: &[u8], path: &mut [u8],
) -> Result<Inserted> {
    tree_id(tree)?;
    let next = epoch.checked_add(1).ok_or(Error::TooLarge)?;
    let (mut sk, pk) = signer(key_material)?;
    let res = (|| {
        verify_root(&pk, tree, root, epoch, sig)?;
        let old = scalar_from_be(root)?;
        let new = insert(&old, nullifier, siblings, Some(&mut *path))?;
        let signature = sign_root(&sk, &pk, tree, &new, next)?;
        Ok(Inserted { root: scalar_to_be(&new), epoch: next, signature })
    })();
    wipe::scalar(&mut sk);
    if res.is_err() {
        wipe::bytes(path);
    }
    res
}

/// Verifies a signed root under `pk` and then NonExist / Exist.
pub fn verify_signed(pk: &[u8], tree: &[u8], root: &[u8], epoch: u64, sig: &[u8], nullifier: &[u8], siblings: &[u8], member: bool) -> Result<()> {
    verify_root(pk, tree, root, epoch, sig)?;
    let r = scalar_from_be(root)?;
    if member {
        verify_membership(&r, nullifier, siblings)
    } else {
        verify_non_membership(&r, nullifier, siblings)
    }
}
