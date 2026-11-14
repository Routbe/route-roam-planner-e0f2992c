//! Sparse Merkle Tree of nullifiers and enclave-signed roots (Stap 7c).
//!
//! `Store` plays the untrusted node store (later: the database). It is
//! deliberately simple and only used to produce sibling lists; every check is
//! done by rout_zk::smt against a signed root.

use bls12_381::Scalar;
use rout_zk::codec::scalar_to_be;
use rout_zk::smt::{self, DEPTH, NODE_LEN, PATH_LEN, SIBLINGS_LEN};
use rout_zk::Error;
use std::collections::HashMap;

struct Store {
    nodes: HashMap<(usize, [u8; 32]), [u8; 32]>,
    empty: Vec<[u8; 32]>,
}

fn prefix(n: &[u8; 32], height: usize) -> [u8; 32] {
    let mut p = *n;
    for h in 0..height {
        p[31 - h / 8] &= !(1 << (h % 8));
    }
    p
}

impl Store {
    fn new() -> Self {
        let mut empty = vec![scalar_to_be(&Scalar::zero())];
        let mut h = Scalar::zero();
        for _ in 0..DEPTH {
            h = smt::node(&h, &h);
            empty.push(scalar_to_be(&h));
        }
        Store { nodes: HashMap::new(), empty }
    }
    fn get(&self, height: usize, p: [u8; 32]) -> [u8; 32] {
        *self.nodes.get(&(height, p)).unwrap_or(&self.empty[height])
    }
    fn siblings(&self, n: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIBLINGS_LEN);
        for h in 0..DEPTH {
            let mut p = prefix(n, h);
            p[31 - h / 8] ^= 1 << (h % 8);
            out.extend_from_slice(&self.get(h, p));
        }
        out
    }
    fn root(&self) -> [u8; 32] {
        self.get(DEPTH, [0u8; 32])
    }
    fn apply(&mut self, n: &[u8; 32], path: &[u8]) {
        for h in 0..=DEPTH {
            let mut v = [0u8; 32];
            v.copy_from_slice(&path[h * NODE_LEN..(h + 1) * NODE_LEN]);
            self.nodes.insert((h, prefix(n, h)), v);
        }
    }
}

fn nf(i: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (j, b) in n.iter_mut().enumerate() {
        *b = i.wrapping_mul(37).wrapping_add(j as u8).rotate_left(3) ^ 0xa5;
    }
    n
}

fn s(b: &[u8; 32]) -> Scalar {
    rout_zk::codec::scalar_from_be(b).unwrap()
}

const KM: &[u8] = b"rout-zk test signer key material, 32+ octets long";
const ADMIN_KM: &[u8] = b"a database admin's own key material, also 32+ long";
const TREE: &[u8] = b"host:00000000-0000-4000-8000-0000000000aa/slot:2026-11-20T10:00Z";

/// Signed tree state as a store would hold it.
struct Signed {
    root: [u8; 32],
    epoch: u64,
    sig: [u8; 80],
}

fn insert(store: &mut Store, st: &Signed, n: &[u8; 32]) -> Result<Signed, Error> {
    let mut path = vec![0u8; PATH_LEN];
    let r = smt::insert_signed(KM, TREE, &st.root, st.epoch, &st.sig, n, &store.siblings(n), &mut path)?;
    store.apply(n, &path);
    Ok(Signed { root: r.root, epoch: r.epoch, sig: r.signature })
}

#[test]
fn empty_root_is_the_folded_empty_tree() {
    let st = Store::new();
    assert_eq!(scalar_to_be(&smt::empty_root()), st.root());
    // Pinned regression value; the worker adapter (smt.ts) checks the same one.
    assert_eq!(hex::encode(st.root()), include_str!("fixtures/smt/empty_root.hex").trim());
}

#[test]
fn empty_path_lists_every_empty_subtree() {
    let st = Store::new();
    let mut out = vec![0u8; PATH_LEN];
    smt::empty_path(&mut out);
    for h in 0..=DEPTH {
        assert_eq!(&out[h * NODE_LEN..(h + 1) * NODE_LEN], &st.empty[h]);
    }
}

#[test]
fn non_membership_holds_for_unspent_nullifiers() {
    let mut st = Store::new();
    let pk = smt::signer_public_key(KM).unwrap();
    let (root, sig) = smt::genesis(KM, TREE).unwrap();
    let mut cur = Signed { root, epoch: 0, sig };
    for i in 0..5 {
        cur = insert(&mut st, &cur, &nf(i)).unwrap();
    }
    assert_eq!(cur.epoch, 5);
    assert_eq!(cur.root, st.root());
    for i in 5..12 {
        let n = nf(i);
        smt::verify_non_membership(&s(&cur.root), &n, &st.siblings(&n)).unwrap();
        smt::verify_signed(&pk, TREE, &cur.root, cur.epoch, &cur.sig, &n, &st.siblings(&n), false).unwrap();
    }
    for i in 0..5 {
        let n = nf(i);
        smt::verify_membership(&s(&cur.root), &n, &st.siblings(&n)).unwrap();
        smt::verify_signed(&pk, TREE, &cur.root, cur.epoch, &cur.sig, &n, &st.siblings(&n), true).unwrap();
    }
}

#[test]
fn a_reused_nullifier_is_rejected() {
    let mut st = Store::new();
    let (root, sig) = smt::genesis(KM, TREE).unwrap();
    let g = Signed { root, epoch: 0, sig };
    let n = nf(42);
    let after = insert(&mut st, &g, &n).unwrap();
    // Second spend against the current root: the leaf is occupied.
    assert_eq!(insert(&mut st, &after, &n).err(), Some(Error::Rejected));
    assert_eq!(smt::verify_non_membership(&s(&after.root), &n, &st.siblings(&n)), Err(Error::Rejected));
    // Lying about the siblings (claiming the empty-tree path) does not help.
    let fresh = Store::new();
    let mut path = vec![0u8; PATH_LEN];
    assert_eq!(
        smt::insert_signed(KM, TREE, &after.root, after.epoch, &after.sig, &n, &fresh.siblings(&n), &mut path).err(),
        Some(Error::Rejected)
    );
    assert!(path.iter().all(|b| *b == 0), "path wiped on rejection");
    // Every single-node edit of the honest siblings fails too.
    let honest = st.siblings(&n);
    for h in [0usize, 1, 7, 128, 255] {
        let mut bad = honest.clone();
        bad[h * NODE_LEN + 31] ^= 1;
        assert_eq!(smt::verify_non_membership(&s(&after.root), &n, &bad), Err(Error::Rejected));
    }
}

#[test]
fn admin_manipulated_roots_are_rejected() {
    let mut st = Store::new();
    let pk = smt::signer_public_key(KM).unwrap();
    let (root, sig) = smt::genesis(KM, TREE).unwrap();
    let mut cur = Signed { root, epoch: 0, sig };
    for i in 0..3 {
        cur = insert(&mut st, &cur, &nf(i)).unwrap();
    }
    let n = nf(9);
    let sib = st.siblings(&n);
    let mut path = vec![0u8; PATH_LEN];
    let try_insert = |root: &[u8; 32], epoch: u64, sig: &[u8; 80], sib: &[u8], path: &mut [u8]| smt::insert_signed(KM, TREE, root, epoch, sig, &n, sib, path).err();

    // 1. The admin rewinds the root to the empty tree (dropping spent nullifiers) but keeps the signature.
    let empty = scalar_to_be(&smt::empty_root());
    assert_eq!(try_insert(&empty, cur.epoch, &cur.sig, &Store::new().siblings(&n), &mut path), Some(Error::Rejected));
    // 2. One flipped bit in the root.
    let mut r = cur.root;
    r[31] ^= 1;
    assert_eq!(try_insert(&r, cur.epoch, &cur.sig, &sib, &mut path), Some(Error::Rejected));
    // 3. Another epoch for the same root.
    assert_eq!(try_insert(&cur.root, cur.epoch + 1, &cur.sig, &sib, &mut path), Some(Error::Rejected));
    // 4. A flipped bit in the signature (still a valid point or not: refused either way).
    let mut bad = cur.sig;
    bad[79] ^= 1;
    assert!(try_insert(&cur.root, cur.epoch, &bad, &sib, &mut path).is_some());
    // 5. The admin signs a forged empty root with a key of their own.
    let (mut ask, apk) = smt::signer(ADMIN_KM).unwrap();
    let forged = smt::sign_root(&ask, &apk, TREE, &smt::empty_root(), cur.epoch + 1).unwrap();
    rout_zk::wipe::scalar(&mut ask);
    smt::verify_root(&apk, TREE, &empty, cur.epoch + 1, &forged).unwrap(); // valid for the admin's key ...
    assert_eq!(smt::verify_root(&pk, TREE, &empty, cur.epoch + 1, &forged), Err(Error::Rejected)); // ... not for the enclave's
    assert_eq!(try_insert(&empty, cur.epoch + 1, &forged, &Store::new().siblings(&n), &mut path), Some(Error::Rejected));
    // 6. The genuine root moved to another tree (another host or slot).
    assert_eq!(smt::verify_root(&pk, b"host:other/slot:x", &cur.root, cur.epoch, &cur.sig), Err(Error::Rejected));
    assert!(path.iter().all(|b| *b == 0));
    // The untouched state still works.
    insert(&mut st, &cur, &n).unwrap();
}

#[test]
fn enclave_root_signature_validates_and_refuses_bad_keys() {
    let pk = smt::signer_public_key(KM).unwrap();
    let (root, sig) = smt::genesis(KM, TREE).unwrap();
    smt::verify_root(&pk, TREE, &root, 0, &sig).unwrap();
    // Deterministic: same key material, same key and same signature.
    assert_eq!(smt::genesis(KM, TREE).unwrap(), (root, sig));
    assert_eq!(smt::signer_public_key(KM).unwrap(), pk);
    // Malformed public keys: wrong length, identity, not a point.
    assert_eq!(smt::verify_root(&pk[..95], TREE, &root, 0, &sig), Err(Error::Invalid));
    let mut identity = [0u8; 96];
    identity[0] = 0xc0;
    assert_eq!(smt::verify_root(&identity, TREE, &root, 0, &sig), Err(Error::Invalid));
    assert_eq!(smt::verify_root(&[0x80; 96], TREE, &root, 0, &sig), Err(Error::Invalid));
    // Non-canonical root encoding (>= r) and bad tree ids.
    assert_eq!(smt::verify_root(&pk, TREE, &[0xff; 32], 0, &sig), Err(Error::Invalid));
    assert_eq!(smt::verify_root(&pk, b"", &root, 0, &sig), Err(Error::Invalid));
    assert_eq!(smt::verify_root(&pk, &[b'x'; 257], &root, 0, &sig), Err(Error::Invalid));
    // Too little key material.
    assert_eq!(smt::genesis(&KM[..31], TREE).err(), Some(Error::Invalid));
}

#[test]
fn malformed_proofs_are_invalid_not_rejected() {
    let st = Store::new();
    let n = nf(1);
    let root = s(&st.root());
    assert_eq!(smt::verify_non_membership(&root, &n[..31], &st.siblings(&n)), Err(Error::Invalid));
    assert_eq!(smt::verify_non_membership(&root, &n, &st.siblings(&n)[..SIBLINGS_LEN - 1]), Err(Error::Invalid));
    let mut big = st.siblings(&n);
    big[..32].copy_from_slice(&[0xff; 32]);
    assert_eq!(smt::verify_non_membership(&root, &n, &big), Err(Error::Invalid));
}

#[test]
fn the_root_does_not_depend_on_insertion_order_and_paths_match_the_store() {
    let order_a: Vec<u8> = (0..6).collect();
    let order_b: Vec<u8> = vec![5, 2, 0, 4, 1, 3];
    let mut roots = vec![];
    for order in [order_a, order_b] {
        let mut st = Store::new();
        let mut root = s(&st.root());
        for i in order {
            let n = nf(i);
            let mut path = vec![0u8; PATH_LEN];
            root = smt::insert(&root, &n, &st.siblings(&n), Some(&mut path)).unwrap();
            assert_eq!(&path[DEPTH * NODE_LEN..], &scalar_to_be(&root));
            assert_eq!(&path[..NODE_LEN], &scalar_to_be(&smt::leaf(&n)));
            st.apply(&n, &path);
            assert_eq!(st.root(), scalar_to_be(&root));
        }
        roots.push(root);
    }
    assert_eq!(roots[0], roots[1]);
}

#[test]
fn neighbouring_nullifiers_get_their_own_leaves() {
    // Two nullifiers that differ only in the last bit share 255 ancestors.
    let mut st = Store::new();
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[31] = 1;
    let mut root = s(&st.root());
    for n in [a, b] {
        let mut path = vec![0u8; PATH_LEN];
        root = smt::insert(&root, &n, &st.siblings(&n), Some(&mut path)).unwrap();
        st.apply(&n, &path);
    }
    smt::verify_membership(&root, &a, &st.siblings(&a)).unwrap();
    smt::verify_membership(&root, &b, &st.siblings(&b)).unwrap();
    let mut c = [0u8; 32];
    c[0] = 0x80;
    smt::verify_non_membership(&root, &c, &st.siblings(&c)).unwrap();
}

#[test]
fn epoch_overflow_is_refused() {
    let st = Store::new();
    let n = nf(3);
    let mut path = vec![0u8; PATH_LEN];
    let (root, sig) = smt::genesis(KM, TREE).unwrap();
    assert_eq!(smt::insert_signed(KM, TREE, &root, u64::MAX, &sig, &n, &st.siblings(&n), &mut path).err(), Some(Error::TooLarge));
}
