//! Runs the shared provider corpus against the Rust core. The TypeScript conformance suite reads
//! the same file, so both backends are held to identical outcomes on every vector.

use std::collections::BTreeSet;

use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use kokuin_crypto::{Algorithm, CryptoError, hash_blake3, sign_ed25519, verify};
use serde_json::Value;
use sha2::{Digest, Sha512};

const CORPUS: &str = include_str!("../../../packages/crypto-conformance/vectors/corpus.json");

struct VerifyCase {
    name: String,
    algorithm: Algorithm,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    valid: bool,
    weakened_by: Vec<String>,
}

fn corpus() -> Value {
    serde_json::from_str(CORPUS).expect("corpus is valid JSON")
}

fn entries<'a>(corpus: &'a Value, key: &str) -> &'a Vec<Value> {
    corpus[key]
        .as_array()
        .unwrap_or_else(|| panic!("corpus.{key} is an array"))
}

fn text<'a>(entry: &'a Value, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string in {entry}"))
}

fn bytes(entry: &Value, key: &str) -> Vec<u8> {
    hex::decode(text(entry, key)).unwrap_or_else(|_| panic!("{key} is hex in {entry}"))
}

fn verify_cases() -> Vec<VerifyCase> {
    let corpus = corpus();
    entries(&corpus, "verify")
        .iter()
        .map(|entry| VerifyCase {
            name: text(entry, "name").to_owned(),
            algorithm: match text(entry, "alg") {
                "EdDSA" => Algorithm::Ed25519,
                "ES256" => Algorithm::Es256,
                other => panic!("unknown algorithm {other}"),
            },
            public_key: bytes(entry, "publicKey"),
            message: bytes(entry, "message"),
            signature: bytes(entry, "signature"),
            valid: entry["valid"].as_bool().expect("valid is a boolean"),
            weakened_by: entry["weakenedBy"]["rust"]
                .as_array()
                .map(|names| {
                    names
                        .iter()
                        .map(|name| name.as_str().expect("weakening name").to_owned())
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

#[test]
fn signs_every_corpus_vector() {
    let corpus = corpus();
    let cases = entries(&corpus, "ed25519Sign");
    assert!(!cases.is_empty());
    for entry in cases {
        let signature = sign_ed25519(&bytes(entry, "seed"), &bytes(entry, "message"))
            .unwrap_or_else(|error| panic!("{}: {error:?}", text(entry, "name")));
        assert_eq!(
            signature.as_slice(),
            bytes(entry, "signature"),
            "{}",
            text(entry, "name")
        );
    }
    for entry in entries(&corpus, "ed25519InvalidSeeds") {
        assert_eq!(
            sign_ed25519(&bytes(entry, "seed"), &[]),
            Err(CryptoError::InvalidSeed),
            "{}",
            text(entry, "name")
        );
    }
}

#[test]
fn verifies_every_corpus_vector() {
    let cases = verify_cases();
    assert!(!cases.is_empty());
    let mismatches: Vec<&str> = cases
        .iter()
        .filter(|case| {
            verify(
                case.algorithm,
                &case.signature,
                &case.message,
                &case.public_key,
            ) != case.valid
        })
        .map(|case| case.name.as_str())
        .collect();
    assert!(
        mismatches.is_empty(),
        "disagrees with corpus: {mismatches:?}"
    );
}

#[test]
fn hashes_every_corpus_vector() {
    let corpus = corpus();
    for entry in entries(&corpus, "blake3") {
        let length = entry["length"].as_u64().expect("length") as usize;
        let output = hash_blake3(&bytes(entry, "input"), length)
            .unwrap_or_else(|error| panic!("{}: {error:?}", text(entry, "name")));
        let prefix = bytes(entry, "outputPrefix");
        assert_eq!(output.len(), length, "{}", text(entry, "name"));
        assert_eq!(output[..prefix.len()], prefix, "{}", text(entry, "name"));
    }
    for length in entries(&corpus, "blake3InvalidLengths") {
        let length = length.as_u64().expect("length") as usize;
        assert_eq!(
            hash_blake3(&[], length),
            Err(CryptoError::InvalidOutputLength),
            "length {length}"
        );
    }
}

// Deliberately weakened checks. Each corpus rejection names the ones that accept it, which proves
// the vector exercises the guard it claims rather than failing for some unrelated reason.

type Weakened = fn(&[u8], &[u8], &[u8]) -> bool;

/// The Ed25519 path without the strict point guard: dalek `verify_strict` alone.
fn ed25519_without_subgroup_guard(signature: &[u8], message: &[u8], key: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (<[u8; 32]>::try_from(key), Signature::try_from(signature))
    else {
        return false;
    };
    VerifyingKey::from_bytes(&key).is_ok_and(|key| key.verify_strict(message, &signature).is_ok())
}

/// Cofactored verification, 8(SB - R - kA) = 0, with lenient point decoding and no subgroup or
/// small-order checks. Only S must be canonical.
fn ed25519_cofactored(signature: &[u8], message: &[u8], key: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (<[u8; 32]>::try_from(key), <[u8; 64]>::try_from(signature))
    else {
        return false;
    };
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("R");
    let (Some(a), Some(r)) = (
        CompressedEdwardsY(key).decompress(),
        CompressedEdwardsY(r_bytes).decompress(),
    ) else {
        return false;
    };
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        signature[32..].try_into().expect("S"),
    )) else {
        return false;
    };
    let digest: [u8; 64] = Sha512::new()
        .chain_update(r_bytes)
        .chain_update(key)
        .chain_update(message)
        .finalize()
        .into();
    let k = Scalar::from_bytes_mod_order_wide(&digest);
    (EdwardsPoint::mul_base(&s) - r - a * k)
        .mul_by_cofactor()
        .is_identity()
}

/// The strict path, after reducing S mod L instead of rejecting S >= L.
fn ed25519_reducing_s(signature: &[u8], message: &[u8], key: &[u8]) -> bool {
    let Ok(mut signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let s: [u8; 32] = signature[32..].try_into().expect("S");
    signature[32..].copy_from_slice(&Scalar::from_bytes_mod_order(s).to_bytes());
    verify(Algorithm::Ed25519, &signature, message, key)
}

/// The ES256 path without the low-S guard.
fn es256_accepting_high_s(signature: &[u8], message: &[u8], key: &[u8]) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let (Ok(signature), Ok(key)) = (
        Signature::from_slice(signature),
        VerifyingKey::from_sec1_bytes(key),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Big-endian `value mod n`. One subtraction suffices because 2n > 2^256.
fn reduce_p256(value: &mut [u8]) {
    if *value < P256_ORDER[..] {
        return;
    }
    let mut borrow = 0u16;
    for (byte, order) in value.iter_mut().zip(P256_ORDER).rev() {
        let difference = 0x100 + u16::from(*byte) - u16::from(order) - borrow;
        *byte = difference as u8;
        borrow = u16::from(difference < 0x100);
    }
}

/// The strict ES256 path, after reducing r and s mod n instead of rejecting them.
fn es256_reducing_scalars(signature: &[u8], message: &[u8], key: &[u8]) -> bool {
    let Ok(mut signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    reduce_p256(&mut signature[..32]);
    reduce_p256(&mut signature[32..]);
    verify(Algorithm::Es256, &signature, message, key)
}

fn weakenings() -> Vec<(&'static str, Algorithm, Weakened)> {
    vec![
        (
            "subgroup",
            Algorithm::Ed25519,
            ed25519_without_subgroup_guard,
        ),
        ("cofactored", Algorithm::Ed25519, ed25519_cofactored),
        ("s-range", Algorithm::Ed25519, ed25519_reducing_s),
        ("low-s", Algorithm::Es256, es256_accepting_high_s),
        ("scalar-range", Algorithm::Es256, es256_reducing_scalars),
    ]
}

#[test]
fn every_rust_weakening_named_by_the_corpus_is_implemented() {
    let named: BTreeSet<String> = verify_cases()
        .into_iter()
        .flat_map(|case| case.weakened_by)
        .collect();
    let implemented: BTreeSet<String> = weakenings()
        .into_iter()
        .map(|(name, _, _)| name.to_owned())
        .collect();
    assert_eq!(named, implemented);
}

#[test]
fn each_weakening_flips_exactly_the_vectors_that_name_it() {
    let cases = verify_cases();
    for (name, algorithm, weakened) in weakenings() {
        let flipped: Vec<&str> = cases
            .iter()
            .filter(|case| {
                let accepted = if std::mem::discriminant(&case.algorithm)
                    == std::mem::discriminant(&algorithm)
                {
                    weakened(&case.signature, &case.message, &case.public_key)
                } else {
                    verify(
                        case.algorithm,
                        &case.signature,
                        &case.message,
                        &case.public_key,
                    )
                };
                accepted != case.valid
            })
            .map(|case| case.name.as_str())
            .collect();
        let expected: Vec<&str> = cases
            .iter()
            .filter(|case| case.weakened_by.iter().any(|entry| entry == name))
            .map(|case| case.name.as_str())
            .collect();
        assert!(!expected.is_empty(), "{name} certifies no vector");
        assert_eq!(flipped, expected, "weakening {name}");
        // Every flip is a rejected vector being accepted, never a valid one being lost.
        assert!(
            cases
                .iter()
                .filter(|case| flipped.contains(&case.name.as_str()))
                .all(|case| !case.valid),
            "weakening {name} rejected a valid vector"
        );
    }
}
