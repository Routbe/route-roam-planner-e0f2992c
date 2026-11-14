//! Stap 7b: Pedersen commitments and 64-bit Bulletproofs range proofs.

use bls12_381::{G1Affine, G1Projective, Scalar};
use rout_zk::bulletproofs::{prove, verify, BulletproofGens, RangeProof, PROOF_LEN};
use rout_zk::codec::scalar_from_be;
use rout_zk::pedersen::{generator, Commitment, Opening, PedersenGens, GENERATOR_DST};
use rout_zk::random::Seeded;
use rout_zk::Error;
use std::sync::OnceLock;

fn gens() -> &'static (PedersenGens, BulletproofGens) {
    static G: OnceLock<(PedersenGens, BulletproofGens)> = OnceLock::new();
    G.get_or_init(|| (PedersenGens::canonical(), BulletproofGens::canonical()))
}

fn rng(seed: &[u8]) -> Seeded<'_> {
    Seeded { seed, dst: b"ROUT_ZK_TEST_RANDOM_SCALARS_" }
}

fn prove_u64(v: u64, r: u64, ctx: &[u8]) -> (Commitment, RangeProof) {
    let (pg, bg) = gens();
    prove(pg, bg, &Scalar::from(v), &Scalar::from(r), ctx, &mut rng(&v.to_be_bytes())).unwrap()
}

#[test]
fn generators_are_distinct_valid_and_follow_the_dst() {
    let (pg, bg) = gens();
    assert_eq!(GENERATOR_DST, b"ROUT_ZK_V1_BLS12381G1_XMD:SHA-256_SSWU_RO_PEDERSEN_BULLETPROOFS_");
    let mut all = vec![pg.g, pg.h, bg.u];
    all.extend_from_slice(&bg.g);
    all.extend_from_slice(&bg.h);
    let enc: Vec<[u8; 48]> = all.iter().map(|p| G1Affine::from(p).to_compressed()).collect();
    for (i, a) in enc.iter().enumerate() {
        let p = G1Affine::from_compressed(a).unwrap();
        assert!(bool::from(p.is_on_curve() & p.is_torsion_free() & !p.is_identity()));
        for b in enc.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
    assert_eq!(all.len(), 3 + 128);
}

#[test]
fn valid_range_proofs_verify_across_the_whole_range() {
    let (pg, bg) = gens();
    for v in [0u64, 1, 2, 7, 1 << 32, (1 << 63) - 1, 1 << 63, u64::MAX - 1, u64::MAX] {
        let (c, p) = prove_u64(v, 0xabcdef ^ v, b"booking-ctx");
        assert_eq!(verify(pg, bg, &c, &p, b"booking-ctx"), Ok(()), "v = {v}");
        // Byte round trip of commitment and proof.
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), PROOF_LEN);
        assert_eq!(PROOF_LEN, 928);
        let p2 = RangeProof::from_bytes(&bytes).unwrap();
        let c2 = Commitment::from_bytes(&c.to_bytes()).unwrap();
        assert_eq!(verify(pg, bg, &c2, &p2, b"booking-ctx"), Ok(()));
        assert!(pg.opens(&c, &Opening::from_u64(v, Scalar::from(0xabcdef ^ v))));
    }
}

#[test]
fn prover_refuses_values_outside_the_range() {
    let (pg, bg) = gens();
    let r = Scalar::from(5u64);
    let two64 = Scalar::from(u64::MAX) + Scalar::one();
    let minus_one = -Scalar::one();
    let minus_big = -Scalar::from(1000u64);
    let huge = scalar_from_be(&[0x11u8; 32]).unwrap();
    for v in [two64, two64 + Scalar::one(), minus_one, minus_big, huge] {
        assert_eq!(prove(pg, bg, &v, &r, b"", &mut rng(b"x")).err(), Some(Error::Invalid));
    }
}

#[test]
fn verifier_rejects_wrong_commitment_context_and_tampering() {
    let (pg, bg) = gens();
    let (c, p) = prove_u64(42, 99, b"slot-1");
    // A different value, a different blinding, a different context.
    let (c43, _) = prove_u64(43, 99, b"slot-1");
    assert_eq!(verify(pg, bg, &c43, &p, b"slot-1"), Err(Error::Rejected));
    assert_eq!(verify(pg, bg, &pg.commit_u64(42, &Scalar::from(98u64)), &p, b"slot-1"), Err(Error::Rejected));
    assert_eq!(verify(pg, bg, &c, &p, b"slot-2"), Err(Error::Rejected));
    // Proofs of different statements do not transfer.
    let (_, p43) = prove_u64(43, 99, b"slot-1");
    assert_eq!(verify(pg, bg, &c, &p43, b"slot-1"), Err(Error::Rejected));

    // Every scalar field and point field, mutated, must fail (decode or verify).
    let good = p.to_bytes();
    let mut positions: Vec<usize> = (0..16).map(|i| i * 48 + 47).collect();
    positions.extend((0..5).map(|i| 16 * 48 + i * 32 + 31));
    for at in positions {
        let mut b = good;
        b[at] ^= 1;
        match RangeProof::from_bytes(&b) {
            Err(e) => assert_eq!(e, Error::Invalid),
            Ok(q) => assert_eq!(verify(pg, bg, &c, &q, b"slot-1"), Err(Error::Rejected), "byte {at}"),
        }
    }
    // Swapped scalars and swapped L/R are rejected.
    let mut q = p;
    core::mem::swap(&mut q.ipa_a, &mut q.ipa_b);
    assert_eq!(verify(pg, bg, &c, &q, b"slot-1"), Err(Error::Rejected));
    let mut q = p;
    core::mem::swap(&mut q.l, &mut q.r);
    assert_eq!(verify(pg, bg, &c, &q, b"slot-1"), Err(Error::Rejected));
    let mut q = p;
    q.t_hat += Scalar::one();
    assert_eq!(verify(pg, bg, &c, &q, b"slot-1"), Err(Error::Rejected));
}

#[test]
fn proof_decoding_is_strict() {
    let (_, p) = prove_u64(1, 2, b"");
    let good = p.to_bytes();
    assert_eq!(RangeProof::from_bytes(&good[..PROOF_LEN - 1]).err(), Some(Error::Invalid));
    let mut long = good.to_vec();
    long.push(0);
    assert_eq!(RangeProof::from_bytes(&long).err(), Some(Error::Invalid));
    // Identity point as A.
    let mut b = good;
    b[..48].copy_from_slice(&G1Affine::identity().to_compressed());
    assert_eq!(RangeProof::from_bytes(&b).err(), Some(Error::Invalid));
    // Non-canonical scalar (>= q) as t̂.
    let mut b = good;
    b[16 * 48 + 2 * 32..16 * 48 + 3 * 32].copy_from_slice(&[0xffu8; 32]);
    assert_eq!(RangeProof::from_bytes(&b).err(), Some(Error::Invalid));
}

#[test]
fn point_outside_the_subgroup_is_refused() {
    // x = 4 lies on y^2 = x^3 + 4 only off the r-torsion subgroup (the
    // cofactor of E(F_p) is not 1); search a small x that decompresses but
    // fails the subgroup check and make sure it never passes as a commitment.
    let mut found = false;
    for x in 1u8..=255 {
        let mut enc = [0u8; 48];
        enc[0] = 0x80; // compressed flag
        enc[47] = x;
        let p: Option<G1Affine> = G1Affine::from_compressed_unchecked(&enc).into();
        if let Some(p) = p {
            if bool::from(p.is_on_curve()) && !bool::from(p.is_torsion_free()) {
                assert_eq!(Commitment::from_bytes(&enc).err(), Some(Error::Invalid));
                let (_, proof) = prove_u64(1, 2, b"");
                let mut b = proof.to_bytes();
                b[48..96].copy_from_slice(&enc);
                assert_eq!(RangeProof::from_bytes(&b).err(), Some(Error::Invalid));
                found = true;
                break;
            }
        }
    }
    assert!(found);
}

#[test]
fn homomorphic_capacity_updates_keep_the_remainder_provable() {
    let (pg, bg) = gens();
    // Capacity 10, three bookings of 3, 2 and 4 seats.
    let cap = Opening::from_u64(10, Scalar::from(1111u64));
    let mut c_rem = pg.commit(&cap.value, &cap.blinding);
    let mut o_rem = Opening::new(cap.value, cap.blinding);
    for (i, (seats, r)) in [(3u64, 22u64), (2, 33), (4, 44)].into_iter().enumerate() {
        let b = Opening::from_u64(seats, Scalar::from(r));
        let c_i = pg.commit(&b.value, &b.blinding);
        // C_rem' = C_rem · C_i^{-1}
        c_rem = c_rem.sub(&c_i);
        o_rem = o_rem.sub(&b);
        assert!(pg.opens(&c_rem, &o_rem));
        let ctx = format!("slot-7/booking-{i}");
        let (c, p) = prove(pg, bg, &o_rem.value, &o_rem.blinding, ctx.as_bytes(), &mut rng(&[i as u8])).unwrap();
        assert!(c.ct_eq(&c_rem));
        assert_eq!(verify(pg, bg, &c_rem, &p, ctx.as_bytes()), Ok(()));
    }
    assert_eq!(o_rem.value_u64(), Some(1));
    // Adding back restores the commitment (cancellation).
    let back = c_rem.add(&pg.commit_u64(4, &Scalar::from(44u64)));
    assert!(pg.opens(&back, &Opening::from_u64(5, Scalar::from(1111u64 - 22 - 33))));

    // One more booking of 2 seats would overbook: C_rem < 0 cannot be proven.
    let over = Opening::from_u64(2, Scalar::from(55u64));
    let o_bad = o_rem.sub(&over);
    assert_eq!(o_bad.value_u64(), None);
    assert_eq!(prove(pg, bg, &o_bad.value, &o_bad.blinding, b"slot-7/booking-3", &mut rng(b"o")).err(), Some(Error::Invalid));
}

#[test]
fn manipulated_generators_are_refused() {
    let (pg, bg) = gens();
    let (g, h) = pg.to_bytes();
    assert!(PedersenGens::from_bytes(&g, &h).is_ok());

    let g_aff = G1Affine::from(pg.g);
    let h_aff = G1Affine::from(pg.h);
    let k = Scalar::from(0x5eed_u64);
    let cases: Vec<([u8; 48], [u8; 48])> = vec![
        (g, g),                                                      // h = g
        (h, g),                                                      // swapped
        (g, G1Affine::from(pg.g * k).to_compressed()),               // h = k·g (log known)
        (G1Affine::from(pg.h * k).to_compressed(), h),               // g = k·h
        (G1Affine::generator().to_compressed(), h),                  // standard base point as g
        (g, G1Affine::from(generator(b'h', 1)).to_compressed()),     // other index
        (g, G1Affine::from(-G1Projective::from(h_aff)).to_compressed()), // -h
        (G1Affine::identity().to_compressed(), h),                   // identity
    ];
    for (gb, hb) in cases {
        assert!(PedersenGens::from_bytes(&gb, &hb).is_err());
    }
    // A single flipped bit (off-curve or a different point) is refused too.
    for at in [0usize, 20, 47] {
        let mut hb = h;
        hb[at] ^= 0x01;
        assert!(PedersenGens::from_bytes(&g, &hb).is_err());
        let mut gb = g;
        gb[at] ^= 0x01;
        assert!(PedersenGens::from_bytes(&gb, &h).is_err());
    }

    // A prover who knows h = k·g can open one commitment to any value.
    // Proofs made under such a manipulated pair never verify under the
    // canonical generators.
    let bad_h = PedersenGens { g: pg.g, h: pg.g * k };
    let (c, p) = prove(&bad_h, bg, &Scalar::from(3u64), &Scalar::from(4u64), b"ctx", &mut rng(b"h")).unwrap();
    assert_eq!(verify(&bad_h, bg, &c, &p, b"ctx"), Ok(()));
    assert_eq!(verify(pg, bg, &c, &p, b"ctx"), Err(Error::Rejected));
    let bad_g = PedersenGens { g: G1Projective::from(G1Affine::generator()), h: pg.h };
    let (c, p) = prove(&bad_g, bg, &Scalar::from(3u64), &Scalar::from(4u64), b"ctx", &mut rng(b"g")).unwrap();
    assert_eq!(verify(pg, bg, &c, &p, b"ctx"), Err(Error::Rejected));
    let _ = g_aff;
}
