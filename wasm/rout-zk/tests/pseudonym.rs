use rout_zk::pseudonym::{derive, hkdf_expand_32, hmac_sha256, matches, INFO};

#[test]
fn hmac_rfc4231_case_2() {
    let out = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
    assert_eq!(hex::encode(out), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

#[test]
fn hkdf_rfc5869_case_1_first_block() {
    let prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    assert_eq!(hex::encode(hkdf_expand_32(&prk, &info)), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
}

#[test]
fn same_guest_same_host_two_bookings_differ() {
    let seed = [7u8; 32];
    let a = derive(&seed, b"host-1", &[1u8; 32]).unwrap();
    let b = derive(&seed, b"host-1", &[2u8; 32]).unwrap();
    assert_ne!(a, b);
    assert!(matches(&seed, b"host-1", &[1u8; 32], &a).unwrap());
    assert!(!matches(&seed, b"host-1", &[2u8; 32], &a).unwrap());
    assert_eq!(INFO, b"rout.v1.booking.pseudonym");
}

#[test]
fn rejects_wrong_lengths() {
    assert!(derive(&[0u8; 31], b"h", &[0u8; 32]).is_err());
    assert!(derive(&[0u8; 32], b"h", &[0u8; 31]).is_err());
    assert!(derive(&[0u8; 32], b"", &[0u8; 32]).is_err());
}

/// Shared vector with src/lib/crypto-enclave/pseudonyms.test.ts (computed
/// independently with Python's hmac module).
#[test]
fn shared_vector() {
    let p = derive(&[7u8; 32], b"host-1", &[1u8; 32]).unwrap();
    assert_eq!(hex::encode(p), "0e80bd98bcb57b6e5c68f3f48ea94b5b1a9e1087520083bf1ee2f8855719140c");
}
