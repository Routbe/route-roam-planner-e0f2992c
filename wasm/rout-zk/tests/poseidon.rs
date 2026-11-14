//! Poseidon (Stap 7c) against the reference instance poseidonperm_x5_255_3
//! (tests/fixtures/poseidon/x5_255_3.json, see SOURCE.md).

use bls12_381::Scalar;
use rout_zk::poseidon::{hash2, permute, FULL_ROUNDS, PARTIAL_ROUNDS, TAG_FIXED_2, TAG_MERKLE_2, WIDTH};
use rout_zk::poseidon_constants::{MDS, ROUND_CONSTANTS};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/poseidon/x5_255_3.json")).unwrap()
}

fn scalar(hex_str: &str) -> Scalar {
    let mut be = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    assert_eq!(be.len(), 32);
    be.reverse();
    Option::from(Scalar::from_bytes(&be.try_into().unwrap())).expect("canonical")
}

#[test]
fn parameters_are_the_reference_instance() {
    let f = fixture();
    assert_eq!(f["prime"], "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    assert_eq!((f["t"].as_u64(), f["alpha"].as_u64()), (Some(WIDTH as u64), Some(5)));
    assert_eq!((f["R_F"].as_u64(), f["R_P"].as_u64()), (Some(FULL_ROUNDS as u64), Some(PARTIAL_ROUNDS as u64)));
    // The scalar field of the curve library is the same prime: -1 + 1 == 0.
    assert_eq!(scalar("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000") + Scalar::one(), Scalar::zero());
}

#[test]
fn round_constants_match_byte_for_byte() {
    let f = fixture();
    let rc = f["round_constants"].as_array().unwrap();
    assert_eq!(rc.len(), ROUND_CONSTANTS.len());
    assert_eq!(rc.len(), (FULL_ROUNDS + PARTIAL_ROUNDS) * WIDTH);
    for (i, c) in rc.iter().enumerate() {
        assert_eq!(ROUND_CONSTANTS[i], scalar(c.as_str().unwrap()), "round constant {i}");
    }
}

#[test]
fn mds_matches_byte_for_byte() {
    let f = fixture();
    for i in 0..WIDTH {
        for j in 0..WIDTH {
            assert_eq!(MDS[i][j], scalar(f["mds"][i][j].as_str().unwrap()), "MDS[{i}][{j}]");
        }
    }
}

#[test]
fn permutation_matches_the_published_vector() {
    for v in fixture()["vectors"].as_array().unwrap() {
        let mut s = [0, 1, 2].map(|i| scalar(v["input"][i].as_str().unwrap()));
        permute(&mut s);
        for i in 0..WIDTH {
            assert_eq!(s[i], scalar(v["output"][i].as_str().unwrap()), "output word {i}");
        }
    }
}

#[test]
fn hash2_is_word_one_of_the_permutation_and_tags_separate_domains() {
    let a = Scalar::from(7u64);
    let b = Scalar::from(11u64);
    let mut s = [TAG_MERKLE_2, a, b];
    permute(&mut s);
    assert_eq!(hash2(&TAG_MERKLE_2, &a, &b), s[1]);
    assert_ne!(hash2(&TAG_MERKLE_2, &a, &b), hash2(&TAG_FIXED_2, &a, &b));
    assert_ne!(hash2(&TAG_MERKLE_2, &a, &b), hash2(&TAG_MERKLE_2, &b, &a));
    assert_eq!(TAG_FIXED_2, Scalar::from(2u64) * Scalar::from(1u64 << 32) * Scalar::from(1u64 << 32));
}
