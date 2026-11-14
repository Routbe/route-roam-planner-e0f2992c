//! Forward-secure host keys per epoch (Stap 7d): ratchet against an
//! independent reference, signed epoch links, epoch-bound credentials, the
//! one-way property against a compromised later key, and wiping.

use bls12_381::Scalar;
use rout_zk::blind;
use rout_zk::core_bbs::Msg;
use rout_zk::forward_secure::{self as fs, EpochKey, Link, MAX_ADVANCE, MAX_CREDENTIAL_MESSAGES, STATE_LEN};
use rout_zk::random::Seeded;
use rout_zk::Error;
use serde_json::Value;

const KID: &[u8] = b"host:00000000-0000-4000-8000-0000000000aa/key:1";
const SEED: [u8; 32] = [0x5a; 32];

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/forward_secure/ratchet.json")).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn state_of(k: &EpochKey) -> [u8; STATE_LEN] {
    let mut s = [0u8; STATE_LEN];
    k.export_state(&mut s).unwrap();
    s
}

/// Public keys PK_0..PK_n of one chain advanced one epoch at a time, with links.
fn chain(n: u64) -> (EpochKey, Vec<[u8; 96]>, Vec<Link>) {
    let mut k = EpochKey::from_seed(&SEED).unwrap();
    let mut pks = vec![k.public_key(KID).unwrap()];
    let mut links = vec![];
    for t in 1..=n {
        let l = k.advance(KID, t).unwrap();
        pks.push(l.public_key);
        links.push(l);
    }
    (k, pks, links)
}

#[test]
fn ratchet_matches_the_independent_hkdf_reference() {
    let f = fixture();
    let seed = h(&f["seed"]);
    let states: Vec<Vec<u8>> = f["states"].as_array().unwrap().iter().map(h).collect();
    let mut k = EpochKey::from_seed(&seed).unwrap();
    assert_eq!(state_of(&k).to_vec(), states[0]);
    for (t, expect) in states.iter().enumerate().skip(1) {
        k.advance(KID, t as u64).unwrap();
        assert_eq!(k.epoch(), t as u64);
        assert_eq!(&state_of(&k).to_vec(), expect, "epoch {t}");
    }
    // A jump ratchets through every intermediate epoch.
    let mut j = EpochKey::from_seed(&seed).unwrap();
    j.advance(KID, 1000).unwrap();
    assert_eq!(state_of(&j).to_vec(), h(&f["state_1000"]));
    // The raw step function is the same rule.
    let mut s = [0u8; 32];
    s.copy_from_slice(&states[3]);
    fs::ratchet(&mut s, 4);
    assert_eq!(s.to_vec(), states[4]);
}

#[test]
fn every_epoch_has_its_own_key_and_the_links_chain_from_the_anchor() {
    let (k, pks, links) = chain(4);
    for i in 0..pks.len() {
        for j in i + 1..pks.len() {
            assert_ne!(pks[i], pks[j]);
        }
    }
    assert_eq!(k.public_key(KID).unwrap(), pks[4]);
    for (i, l) in links.iter().enumerate() {
        assert_eq!((l.from, l.to), (i as u64, i as u64 + 1));
        fs::verify_link(&pks[i], KID, l.from, l.to, &l.public_key, &l.signature).unwrap();
    }
    // A skip of several epochs is one link signed by the old key.
    let mut s = EpochKey::from_seed(&SEED).unwrap();
    let l = s.advance(KID, 4).unwrap();
    assert_eq!(l.public_key, pks[4]);
    fs::verify_link(&pks[0], KID, 0, 4, &l.public_key, &l.signature).unwrap();
}

#[test]
fn tampered_or_misplaced_links_are_rejected() {
    let (_, pks, links) = chain(3);
    let l = links[1]; // 1 -> 2, signed by SK_1
    fs::verify_link(&pks[1], KID, 1, 2, &l.public_key, &l.signature).unwrap();
    assert_eq!(fs::verify_link(&pks[0], KID, 1, 2, &l.public_key, &l.signature), Err(Error::Rejected));
    assert_eq!(fs::verify_link(&pks[1], b"another host", 1, 2, &l.public_key, &l.signature), Err(Error::Rejected));
    assert_eq!(fs::verify_link(&pks[1], KID, 1, 3, &l.public_key, &l.signature), Err(Error::Rejected));
    assert_eq!(fs::verify_link(&pks[1], KID, 0, 2, &l.public_key, &l.signature), Err(Error::Rejected));
    assert_eq!(fs::verify_link(&pks[1], KID, 1, 2, &pks[3], &l.signature), Err(Error::Rejected));
    let mut sig = l.signature;
    sig[79] ^= 1;
    assert!(fs::verify_link(&pks[1], KID, 1, 2, &l.public_key, &sig).is_err());
    assert_eq!(fs::verify_link(&pks[1], KID, 2, 2, &l.public_key, &l.signature), Err(Error::Invalid));
    assert_eq!(fs::verify_link(&pks[1], KID, 1, 2, &pks[1], &l.signature), Err(Error::Rejected));
    // A public key that is not a valid G2 point never reaches a pairing.
    let mut bad = l.public_key;
    bad[95] ^= 0xff;
    assert!(fs::verify_link(&pks[1], KID, 1, 2, &bad, &l.signature).is_err());
    assert_eq!(fs::verify_link(&[0u8; 96], KID, 1, 2, &l.public_key, &l.signature), Err(Error::Invalid));
}

#[test]
fn a_compromised_later_key_yields_no_earlier_key_or_signature() {
    let (k, pks, _) = chain(3);
    let stolen = state_of(&k); // the attacker has SK_3 and everything derived from it
    let mut earlier = vec![];
    let mut e0 = EpochKey::from_seed(&SEED).unwrap();
    earlier.push(state_of(&e0));
    for t in 1..3 {
        e0.advance(KID, t).unwrap();
        earlier.push(state_of(&e0));
    }
    // Running the (only) step function forward from SK_3 with any epoch number never lands on SK_0..SK_2.
    for e in 0..64u64 {
        let mut s = stolen;
        fs::ratchet(&mut s, e);
        assert!(!earlier.contains(&s));
    }
    for e in 0..3u64 {
        // Reusing SK_3 as if it were an earlier state gives a different key.
        let fake = EpochKey::from_state(&stolen, e).unwrap();
        assert_ne!(fake.public_key(KID).unwrap(), pks[e as usize]);
        // A credential "for epoch e" signed with the stolen state fails under PK_e.
        let sig = fake.sign_credential(KID, &[], &[b"room 12"]).unwrap();
        assert_eq!(fs::verify_credential(&pks[e as usize], KID, e, &sig, &[b"room 12"], &[], &Scalar::zero()), Err(Error::Rejected));
    }
    // Nor can the attacker link a key of its own into an earlier epoch.
    let mut forged = EpochKey::from_state(&stolen, 1).unwrap();
    let l = forged.advance(KID, 2).unwrap();
    assert_eq!(fs::verify_link(&pks[1], KID, 1, 2, &l.public_key, &l.signature), Err(Error::Rejected));
    // What it does get is the current epoch and onwards (expected, and why advancing matters).
    let mut now = EpochKey::from_state(&stolen, 3).unwrap();
    assert_eq!(now.public_key(KID).unwrap(), pks[3]);
    let next = now.advance(KID, 4).unwrap();
    fs::verify_link(&pks[3], KID, 3, 4, &next.public_key, &next.signature).unwrap();
}

#[test]
fn credentials_verify_only_under_their_own_epoch_key() {
    let mut k = EpochKey::from_seed(&SEED).unwrap();
    k.advance(KID, 1).unwrap();
    let pk1 = k.public_key(KID).unwrap();
    let msgs: [&[u8]; 2] = [b"slot:2026-11-20T10:00Z", b"seats:1"];
    let sig1 = k.sign_credential(KID, &[], &msgs).unwrap();
    let z = Scalar::zero();
    fs::verify_credential(&pk1, KID, 1, &sig1, &msgs, &[], &z).unwrap();
    k.advance(KID, 2).unwrap();
    let pk2 = k.public_key(KID).unwrap();
    let sig2 = k.sign_credential(KID, &[], &msgs).unwrap();
    fs::verify_credential(&pk2, KID, 2, &sig2, &msgs, &[], &z).unwrap();
    // Signed with the expired epoch-1 key, presented for epoch 2.
    assert_eq!(fs::verify_credential(&pk2, KID, 2, &sig1, &msgs, &[], &z), Err(Error::Rejected));
    // The right key, but another epoch claimed.
    assert_eq!(fs::verify_credential(&pk1, KID, 2, &sig1, &msgs, &[], &z), Err(Error::Rejected));
    assert_eq!(fs::verify_credential(&pk2, KID, 1, &sig2, &msgs, &[], &z), Err(Error::Rejected));
    // A newer key's signature under an older epoch key.
    assert_eq!(fs::verify_credential(&pk1, KID, 1, &sig2, &msgs, &[], &z), Err(Error::Rejected));
    // Another host chain, an edited message.
    assert_eq!(fs::verify_credential(&pk2, b"another host", 2, &sig2, &msgs, &[], &z), Err(Error::Rejected));
    assert_eq!(fs::verify_credential(&pk2, KID, 2, &sig2, &[b"slot:2026-11-20T10:00Z", b"seats:9"], &[], &z), Err(Error::Rejected));
}

#[test]
fn blind_credentials_open_only_with_the_guest_blind() {
    let committed = [Msg::Hash(b"guest pseudonym"), Msg::Hash(b"guest secret")];
    let mut cwp = vec![0u8; blind::commitment_len(2)];
    let mut rng = Seeded { seed: b"rout-zk 7d blind credential test seed", dst: b"ROUT-7D-TEST" };
    let (n, pb) = blind::commit(&committed, &mut rng, &mut cwp).unwrap();
    let mut k = EpochKey::from_seed(&SEED).unwrap();
    k.advance(KID, 4).unwrap();
    let pk = k.public_key(KID).unwrap();
    let sig = k.sign_credential(KID, &cwp[..n], &[b"slot:7"]).unwrap();
    let bm: [&[u8]; 2] = [b"guest pseudonym", b"guest secret"];
    fs::verify_credential(&pk, KID, 4, &sig, &[b"slot:7"], &bm, &pb).unwrap();
    assert_eq!(fs::verify_credential(&pk, KID, 4, &sig, &[b"slot:7"], &bm, &Scalar::zero()), Err(Error::Rejected));
    assert_eq!(fs::verify_credential(&pk, KID, 4, &sig, &[b"slot:7"], &[], &pb), Err(Error::Rejected));
    assert_eq!(fs::verify_credential(&pk, KID, 3, &sig, &[b"slot:7"], &bm, &pb), Err(Error::Rejected));
    // A commitment whose proof does not check is refused before signing.
    let mut bad = cwp[..n].to_vec();
    bad[60] ^= 1;
    assert!(k.sign_credential(KID, &bad, &[b"slot:7"]).is_err());
}

#[test]
fn the_old_state_is_gone_after_a_transition_and_a_dropped_key_is_wiped() {
    let mut k = EpochKey::from_seed(&SEED).unwrap();
    let old = state_of(&k);
    k.advance(KID, 1).unwrap();
    let raw = unsafe { core::slice::from_raw_parts(&k as *const EpochKey as *const u8, core::mem::size_of::<EpochKey>()) };
    assert!(!raw.windows(STATE_LEN).any(|w| w == old), "SK_0 still inside the key after advancing");
    let skip = state_of(&k);
    k.advance(KID, 500).unwrap();
    let raw = unsafe { core::slice::from_raw_parts(&k as *const EpochKey as *const u8, core::mem::size_of::<EpochKey>()) };
    assert!(!raw.windows(STATE_LEN).any(|w| w == skip));

    // Drop wipes the state (the storage stays allocated inside ManuallyDrop).
    let mut slot = core::mem::ManuallyDrop::new(EpochKey::from_seed(&SEED).unwrap());
    let live = state_of(&slot);
    assert_ne!(live, [0u8; STATE_LEN]);
    let p = &*slot as *const EpochKey as *const u8;
    unsafe { core::mem::ManuallyDrop::drop(&mut slot) };
    let after = unsafe { core::slice::from_raw_parts(p, core::mem::size_of::<EpochKey>()) };
    assert!(!after.windows(STATE_LEN).any(|w| w == live), "dropped key still holds its state");
}

#[test]
fn limits_and_malformed_input() {
    assert!(EpochKey::from_seed(&[0u8; 32]).is_err());
    assert!(EpochKey::from_seed(&[1u8; 31]).is_err());
    assert!(EpochKey::from_state(&[1u8; 33], 0).is_err());
    let mut k = EpochKey::from_seed(&SEED).unwrap();
    assert_eq!(k.advance(KID, MAX_ADVANCE + 1), Err(Error::Invalid));
    assert_eq!(k.advance(&[0u8; 257], 1), Err(Error::Invalid));
    assert!(k.public_key(&[]).is_err());
    let many: Vec<&[u8]> = (0..=MAX_CREDENTIAL_MESSAGES).map(|_| &b"m"[..]).collect();
    assert_eq!(k.sign_credential(KID, &[], &many), Err(Error::TooLarge));
    k.sign_credential(KID, &[], &many[..MAX_CREDENTIAL_MESSAGES]).unwrap();
    // The last epoch can be reached but never passed.
    let mut end = EpochKey::from_state(&state_of(&k), u64::MAX - 1).unwrap();
    end.advance(KID, u64::MAX).unwrap();
    assert_eq!(end.advance(KID, u64::MAX), Err(Error::Invalid));
}
