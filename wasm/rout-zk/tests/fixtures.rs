//! Byte-exact checks against the official BBS and Blind BBS fixtures
//! (BLS12-381-SHA-256). Every fixture file in tests/fixtures is exercised.

use bls12_381::{G1Affine, G1Projective, Scalar};
use rout_zk::blind::{self, Disclosure};
use rout_zk::codec::{scalar_from_be, scalar_to_be};
use rout_zk::core_bbs::{self, Msg};
use rout_zk::generators::{create_blind_generators, create_generators, p1, API_ID_BBS, API_ID_BLIND};
use rout_zk::random::Seeded;
use rout_zk::xmd::hash_to_scalar;
use serde_json::Value;
use std::path::PathBuf;
use std::vec::Vec;

fn load(rel: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(rel);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}
fn files(dir: &str) -> Vec<String> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir);
    let mut v: Vec<String> = std::fs::read_dir(p).unwrap().map(|e| format!("{dir}/{}", e.unwrap().file_name().to_str().unwrap())).collect();
    v.sort();
    v
}
fn valid(j: &Value) -> bool {
    j["result"]["valid"].as_bool().unwrap()
}

#[test]
fn generators_match() {
    let j = load("bbs/generators.json");
    assert_eq!(hexs(&p1().to_compressed()), j["P1"].as_str().unwrap());
    let msgs = j["MsgGenerators"].as_array().unwrap();
    let mut g = [G1Projective::identity(); 11];
    create_generators(11, API_ID_BBS, &mut g).unwrap();
    assert_eq!(hexs(&G1Affine::from(g[0]).to_compressed()), j["Q1"].as_str().unwrap());
    for (i, m) in msgs.iter().enumerate() {
        assert_eq!(hexs(&G1Affine::from(g[i + 1]).to_compressed()), m.as_str().unwrap());
    }
    let j = load("blind/generators.json");
    let mut g = [G1Projective::identity(); 11];
    create_generators(11, API_ID_BLIND, &mut g).unwrap();
    assert_eq!(hexs(&G1Affine::from(g[0]).to_compressed()), j["generators"]["Q1"].as_str().unwrap());
    for (i, m) in j["generators"]["MsgGenerators"].as_array().unwrap().iter().enumerate() {
        assert_eq!(hexs(&G1Affine::from(g[i + 1]).to_compressed()), m.as_str().unwrap());
    }
    let mut b = [G1Projective::identity(); 6];
    create_blind_generators(6, API_ID_BLIND, &mut b).unwrap();
    assert_eq!(hexs(&G1Affine::from(b[0]).to_compressed()), j["blindGenerators"]["Q2"].as_str().unwrap());
    for (i, m) in j["blindGenerators"]["MsgGenerators"].as_array().unwrap().iter().enumerate() {
        assert_eq!(hexs(&G1Affine::from(b[i + 1]).to_compressed()), m.as_str().unwrap());
    }
}

#[test]
fn hash_to_scalar_and_map_to_scalar() {
    let j = load("bbs/h2s.json");
    let s = hash_to_scalar(&hx(&j["message"]), &hx(&j["dst"])).unwrap();
    assert_eq!(hexs(&scalar_to_be(&s)), j["scalar"].as_str().unwrap());
    let j = load("bbs/MapMessageToScalarAsHash.json");
    for c in j["cases"].as_array().unwrap() {
        let m = hx(&c["message"]);
        let mut out = [Scalar::zero(); 1];
        core_bbs::messages_to_scalars(&[Msg::Hash(&m)], API_ID_BBS, &mut out).unwrap();
        assert_eq!(hexs(&scalar_to_be(&out[0])), c["scalar"].as_str().unwrap());
    }
}

#[test]
fn mocked_random_scalars() {
    let j = load("bbs/mockedRng.json");
    let (seed, dst) = (hx(&j["seed"]), hx(&j["dst"]));
    let n = j["count"].as_u64().unwrap() as usize;
    let mut out = vec![Scalar::zero(); n];
    use rout_zk::random::ScalarSource;
    Seeded { seed: &seed, dst: &dst }.fill(&mut out).unwrap();
    for (s, e) in out.iter().zip(j["mockedScalars"].as_array().unwrap()) {
        assert_eq!(hexs(&scalar_to_be(s)), e.as_str().unwrap());
    }
}

#[test]
fn keygen_and_sk_to_pk() {
    let j = load("bbs/keypair.json");
    let dst = hx(&j["keyDst"]);
    let sk = core_bbs::keygen(&hx(&j["keyMaterial"]), &hx(&j["keyInfo"]), Some(&dst)).unwrap();
    assert_eq!(hexs(&scalar_to_be(&sk)), j["keyPair"]["secretKey"].as_str().unwrap());
    assert_eq!(hexs(&core_bbs::sk_to_pk(&sk)), j["keyPair"]["publicKey"].as_str().unwrap());
}

#[test]
fn core_signatures() {
    for f in files("bbs/signature") {
        let j = load(&f);
        let pk = hx(&j["signerKeyPair"]["publicKey"]);
        let header = hx(&j["header"]);
        let msgs: Vec<Vec<u8>> = j["messages"].as_array().unwrap().iter().map(hx).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let sig = hx(&j["signature"]);
        let ok = core_bbs::verify(&pk, &sig, &header, &refs).is_ok();
        assert_eq!(ok, valid(&j), "{f}");
        if valid(&j) {
            let sk = core_bbs::secret_key_from_bytes(&hx(&j["signerKeyPair"]["secretKey"])).unwrap();
            let produced = core_bbs::sign(&sk, &pk, &header, &refs).unwrap();
            assert_eq!(hexs(&produced), hexs(&sig), "{f}");
        }
    }
}

#[test]
fn core_proofs() {
    let rng = load("bbs/mockedRng.json");
    let (seed, dst) = (hx(&rng["seed"]), hx(&rng["dst"]));
    let mut checked = 0;
    for f in files("bbs/proof") {
        let j = load(&f);
        let pk = hx(&j["signerPublicKey"]);
        let header = hx(&j["header"]);
        let ph = hx(&j["presentationHeader"]);
        let msgs: Vec<Vec<u8>> = j["messages"].as_array().unwrap().iter().map(hx).collect();
        let idx: Vec<usize> = j["disclosedIndexes"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as usize).collect();
        let disclosed: Vec<&[u8]> = idx.iter().map(|&i| msgs[i].as_slice()).collect();
        let proof = hx(&j["proof"]);
        let ok = core_bbs::proof_verify(&pk, &proof, &header, &ph, &disclosed, &idx).is_ok();
        assert_eq!(ok, valid(&j), "{f}");
        if valid(&j) {
            let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            let sig = hx(&j["signature"]);
            let mut out = [0u8; 4096];
            let n = core_bbs::proof_gen(&pk, &sig, &header, &ph, &refs, &idx, &mut Seeded { seed: &seed, dst: &dst }, &mut out).unwrap();
            assert_eq!(hexs(&out[..n]), hexs(&proof), "{f}");
            checked += 1;
        }
    }
    assert!(checked >= 3);
}

fn msgs_of(v: &Value) -> Vec<(bool, Vec<u8>)> {
    match v.as_array() {
        None => Vec::new(),
        Some(a) => a.iter().map(|m| (m[0].as_str().unwrap() == "RAW", hx(&m[1]))).collect(),
    }
}
fn as_msgs(v: &[(bool, Vec<u8>)]) -> Vec<Msg<'_>> {
    v.iter().map(|(raw, b)| if *raw { Msg::Raw(b) } else { Msg::Hash(b) }).collect()
}
fn blind_of(v: &Value) -> Scalar {
    if v.is_null() {
        Scalar::zero()
    } else {
        scalar_from_be(&hx(v)).unwrap()
    }
}
fn disclosures(v: &Value) -> Vec<Disclosure> {
    v.as_array().map(|a| a.iter().map(|d| match d.as_str().unwrap() {
        "DISCLOSE" => Disclosure::Disclose,
        "HIDE" => Disclosure::Hide,
        "COMMIT" => Disclosure::Commit,
        other => panic!("{other}"),
    }).collect()).unwrap_or_default()
}

#[test]
fn blind_commitments() {
    for f in files("blind/commit") {
        let j = load(&f);
        let m = msgs_of(&j["blindMessages"]);
        let p = &j["mockRngParameters"];
        let seed = p["SEED"].as_str().unwrap().as_bytes().to_vec();
        let dst = p["commit"]["DST"].as_str().unwrap().as_bytes().to_vec();
        let mut out = [0u8; 2048];
        let (n, pb) = blind::commit(&as_msgs(&m), &mut Seeded { seed: &seed, dst: &dst }, &mut out).unwrap();
        assert_eq!(hexs(&out[..n]), j["commitmentWithProof"].as_str().unwrap(), "{f}");
        assert_eq!(hexs(&scalar_to_be(&pb)), j["proverBlind"].as_str().unwrap(), "{f}");
        let mut g = [G1Projective::identity(); 20];
        create_blind_generators(m.len() + 1, API_ID_BLIND, &mut g).unwrap();
        blind::validate_commitment(&out[..n], &g[..m.len() + 1], API_ID_BLIND).unwrap();
        out[n - 1] ^= 1;
        assert!(blind::validate_commitment(&out[..n], &g[..m.len() + 1], API_ID_BLIND).is_err(), "{f} tampered");
    }
}

#[test]
fn blind_signatures() {
    for f in files("blind/signature") {
        let j = load(&f);
        assert!(valid(&j));
        let sk = core_bbs::secret_key_from_bytes(&hx(&j["signerKeyPair"]["secretKey"])).unwrap();
        let pk = hx(&j["signerKeyPair"]["publicKey"]);
        let cwp = if j["commitmentWithProof"].is_null() { Vec::new() } else { hx(&j["commitmentWithProof"]) };
        let header = hx(&j["header"]);
        let m = msgs_of(&j["messages"]);
        let b = msgs_of(&j["blindMessages"]);
        let sig = blind::blind_sign(&sk, &pk, &cwp, &header, &as_msgs(&m)).unwrap();
        assert_eq!(hexs(&sig), j["signature"].as_str().unwrap(), "{f}");
        let pb = blind_of(&j["proverBlind"]);
        blind::verify_blind_sign(&pk, &sig, &header, &as_msgs(&m), &as_msgs(&b), &pb).unwrap();
        let wrong = pb + Scalar::one();
        assert!(blind::verify_blind_sign(&pk, &sig, &header, &as_msgs(&m), &as_msgs(&b), &wrong).is_err(), "{f} wrong blind");
    }
}

#[test]
fn blind_proofs() {
    for f in files("blind/proof") {
        let j = load(&f);
        assert!(valid(&j));
        let s = load(&format!("blind/signature/{}", j["signatureFile"].as_str().unwrap()));
        let pk = hx(&j["signerPublicKey"]);
        let header = hx(&j["header"]);
        let ph = hx(&j["presentationHeader"]);
        let m = msgs_of(&s["messages"]);
        let b = msgs_of(&s["blindMessages"]);
        let pb = blind_of(&s["proverBlind"]);
        let sig = hx(&s["signature"]);
        let md = disclosures(&j["messageDisclosures"]);
        let bd = disclosures(&j["blindMessageDisclosures"]);
        let p = &j["mockRngParameters"];
        let seed = p["SEED"].as_str().unwrap().as_bytes().to_vec();
        let dst = p["proof"]["DST"].as_str().unwrap().as_bytes().to_vec();
        let mut out = [0u8; 8192];
        let n = blind::blind_proof_gen(&pk, &sig, &header, &ph, &as_msgs(&m), &as_msgs(&b), &md, &bd, &pb, &mut Seeded { seed: &seed, dst: &dst }, &mut out, None).unwrap();
        assert_eq!(hexs(&out[..n]), j["proof"].as_str().unwrap(), "{f}");

        let all_d: Vec<Disclosure> = md.iter().chain(bd.iter()).copied().collect();
        let all_m: Vec<Msg<'_>> = as_msgs(&m).into_iter().chain(as_msgs(&b)).collect();
        let disclosed: Vec<Msg<'_>> = all_m.iter().zip(&all_d).filter(|(_, d)| **d == Disclosure::Disclose).map(|(x, _)| *x).collect();
        let l = j["L"].as_u64().unwrap() as usize;
        blind::blind_proof_verify(&pk, &out[..n], &header, &ph, l, &disclosed, &all_d).unwrap();
        let mut bad = out[..n].to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(blind::blind_proof_verify(&pk, &bad, &header, &ph, l, &disclosed, &all_d).is_err(), "{f} tampered");
        assert!(blind::blind_proof_verify(&pk, &out[..n], &header, b"other", l, &disclosed, &all_d).is_err(), "{f} ph");
    }
}

#[test]
fn rejects_points_outside_the_subgroup() {
    // Identity and a non-subgroup encoding must be refused before any pairing.
    let mut id = [0u8; 48];
    id[0] = 0xc0;
    assert!(rout_zk::codec::g1_from_bytes(&id).is_err());
    let mut id2 = [0u8; 96];
    id2[0] = 0xc0;
    assert!(rout_zk::codec::pubkey_from_bytes(&id2).is_err());
    // x = 4 lies on E1 but outside the prime-order subgroup on BLS12-381.
    for x in 1u8..=16 {
        let mut b = [0u8; 48];
        b[0] = 0x80;
        b[47] = x;
        if let Some(p) = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&b)) {
            if bool::from(p.is_on_curve()) && !bool::from(p.is_torsion_free()) {
                assert!(rout_zk::codec::g1_from_bytes(&b).is_err());
                return;
            }
        }
    }
    panic!("no off-subgroup test point found");
}
