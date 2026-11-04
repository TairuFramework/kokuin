//! Runs the pinned upstream vectors (Wycheproof, SUPERCOP/RFC 8032, official blake3) against the
//! Rust core. `@kokuin/crypto-conformance` runs the same file against the TypeScript providers.
//! Expected outcomes are the upstream verdicts plus the documented verification policy; see
//! scripts/import-crypto-vectors.mjs.

use kokuin_crypto::{Algorithm, hash_blake3, sign_ed25519, verify};
use serde_json::Value;

const EXTERNAL: &str = include_str!("../../../packages/crypto-conformance/vectors/external.json");

fn vectors() -> Value {
    serde_json::from_str(EXTERNAL).expect("external vectors are valid JSON")
}

fn entries<'a>(vectors: &'a Value, key: &str) -> &'a Vec<Value> {
    vectors[key]
        .as_array()
        .unwrap_or_else(|| panic!("external.{key} is an array"))
}

fn text<'a>(entry: &'a Value, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string in {entry}"))
}

fn bytes(entry: &Value, key: &str) -> Vec<u8> {
    hex::decode(text(entry, key)).unwrap_or_else(|_| panic!("{key} is hex in {entry}"))
}

fn label(entry: &Value) -> String {
    format!("{}/{}", text(entry, "source"), text(entry, "id"))
}

#[test]
fn signs_every_external_vector() {
    let vectors = vectors();
    let cases = entries(&vectors, "ed25519Sign");
    assert!(cases.len() > 3);
    let wrong: Vec<String> = cases
        .iter()
        .filter(|entry| {
            sign_ed25519(&bytes(entry, "seed"), &bytes(entry, "message"))
                .map(|signature| signature.as_slice() != bytes(entry, "signature"))
                .unwrap_or(true)
        })
        .map(label)
        .collect();
    assert!(wrong.is_empty(), "signing disagrees: {wrong:?}");
}

#[test]
fn verifies_every_external_vector() {
    let vectors = vectors();
    let cases = entries(&vectors, "verify");
    assert!(!cases.is_empty());
    let wrong: Vec<String> = cases
        .iter()
        .filter(|entry| {
            let algorithm = match text(entry, "alg") {
                "EdDSA" => Algorithm::Ed25519,
                "ES256" => Algorithm::Es256,
                other => panic!("unknown algorithm {other}"),
            };
            let expected = entry["valid"].as_bool().expect("valid is a boolean");
            verify(
                algorithm,
                &bytes(entry, "signature"),
                &bytes(entry, "message"),
                &bytes(entry, "publicKey"),
            ) != expected
        })
        .map(label)
        .collect();
    assert!(wrong.is_empty(), "verification disagrees: {wrong:?}");
}

#[test]
fn hashes_every_external_vector() {
    let vectors = vectors();
    let cases = entries(&vectors, "blake3");
    assert!(!cases.is_empty());
    for entry in cases {
        let length = entry["inputLength"].as_u64().expect("inputLength") as usize;
        let input: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        let expected = bytes(entry, "hash");
        for output_len in [32, 131] {
            let output = hash_blake3(&input, output_len).expect("valid length");
            assert_eq!(
                output,
                expected[..output_len],
                "{}/{output_len}",
                label(entry)
            );
        }
    }
}
