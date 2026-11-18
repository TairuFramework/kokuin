//! Golden vector parity with `@kokuin/token`.
//!
//! The vector file is the one `packages/token/test/golden.test.ts` checks. Every case is checked on
//! its own, and a failing run lists the failing cases by name.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::SigningKey;
use kokuin_token::{
    DIDResolver, SignError, SignatureAlgorithm, TokenError, TokenSigner, VerifyOptions, did_key,
    normalize_did, peer4, sign_token, stringify_token, verify_token,
};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use serde_json::{Map, Value, json};

const TOKENS: &str = include_str!("../../../packages/token/test/golden/tokens.json");

struct Case {
    name: String,
    input: Value,
    expected: Value,
}

fn load() -> Vec<Case> {
    let file: Value = serde_json::from_str(TOKENS).expect("golden file is JSON");
    assert_eq!(file["version"], json!(1), "golden format version");
    let cases: Vec<Case> = file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["name"].as_str().expect("name").to_owned(),
            input: case["input"].clone(),
            expected: case["expected"].clone(),
        })
        .collect();
    let names: HashSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), cases.len(), "duplicate case names");
    cases
}

fn seed(hex_text: &Value) -> [u8; 32] {
    let bytes = hex::decode(hex_text.as_str().expect("hex seed")).expect("hex");
    bytes.try_into().expect("32-byte seed")
}

fn rejection(error: &TokenError) -> Value {
    json!({ "error": error.name(), "message": error.to_string() })
}

/// An Ed25519 `did:key` signer over a fixed seed, signing through kokuin-crypto.
struct SeedSigner {
    id: String,
    seed: [u8; 32],
}

impl SeedSigner {
    fn new(seed: [u8; 32]) -> Self {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Self {
            id: did_key::encode(SignatureAlgorithm::EdDSA, &public_key),
            seed,
        }
    }
}

impl TokenSigner for SeedSigner {
    fn id(&self) -> &str {
        &self.id
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EdDSA
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        kokuin_crypto::sign_ed25519(&self.seed, message)
            .map(Vec::from)
            .map_err(|error| SignError(format!("{error:?}")))
    }
}

/// The resolver a case describes: a fixed map from short form to document.
struct MapResolver(HashMap<String, Value>);

impl DIDResolver for MapResolver {
    fn resolve(&self, did: &str) -> Result<Option<Value>, String> {
        Ok(self.0.get(did).cloned())
    }
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().expect("object").clone()
}

fn compact_token(input: &Value) -> Result<Value, String> {
    let signer = SeedSigner::new(seed(&input["seed"]));
    let signed = sign_token(&signer, object(&input["header"]), object(&input["payload"]))
        .map_err(|error| error.to_string())?;
    Ok(Value::String(stringify_token(&signed)))
}

fn verify(input: &Value, with_header: bool) -> Value {
    let resolver = input
        .get("resolver")
        .map(|docs| MapResolver(object(docs).into_iter().collect()));
    let options = VerifyOptions {
        resolver: resolver
            .as_ref()
            .map(|resolver| resolver as &dyn DIDResolver),
        ..VerifyOptions::default()
    };
    match verify_token(input["token"].as_str().expect("token"), &options) {
        Ok(verified) => {
            let mut out = json!({
                "verified": true,
                "publicKey": hex::encode(&verified.public_key),
                "payload": Value::Object(verified.payload),
            });
            if with_header {
                out["header"] = Value::Object(verified.header);
            }
            out
        }
        Err(error) => rejection(&error),
    }
}

fn did_key_case(input: &Value) -> Result<Value, String> {
    let (algorithm, public_key) = match input["algorithm"].as_str() {
        Some("EdDSA") => (
            SignatureAlgorithm::EdDSA,
            SigningKey::from_bytes(&seed(&input["seed"]))
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
        Some("ES256") => {
            let secret = SecretKey::from_slice(&seed(&input["scalar"])).expect("scalar");
            (
                SignatureAlgorithm::ES256,
                secret.public_key().to_sec1_point(true).as_bytes().to_vec(),
            )
        }
        other => return Err(format!("unknown algorithm {other:?}")),
    };
    let did = did_key::encode(algorithm, &public_key);
    let (decoded_algorithm, decoded_key) = did_key::decode(&did).map_err(|e| e.to_string())?;
    if decoded_key != public_key || decoded_algorithm != algorithm {
        return Err("did:key does not round-trip".into());
    }
    Ok(json!({
        "did": did,
        "algorithm": decoded_algorithm.as_str(),
        "publicKey": hex::encode(decoded_key),
    }))
}

fn decode_peer4(input: &Value) -> Value {
    let long_form = input["longForm"].as_str().expect("longForm");
    let max_doc_size = input["maxDocSize"].as_u64().map(|size| size as usize);
    match peer4::decode(long_form, max_doc_size) {
        Ok(decoded) => {
            json!({ "shortForm": decoded.short_form, "doc": decoded.doc.as_value() })
        }
        Err(error) => rejection(&error),
    }
}

fn run(case: &Case) -> Result<Value, String> {
    let input = &case.input;
    let name = case.name.as_str();
    if name.ends_with(": compact token") {
        return compact_token(input);
    }
    if name.ends_with(": did:key") {
        return did_key_case(input);
    }
    if name.starts_with("Ed25519 seed ") {
        return Ok(verify(input, false));
    }
    match name {
        "did:peer:4: fixed document" => {
            let encoded = peer4::encode(&input["doc"]).map_err(|e| e.to_string())?;
            Ok(json!({ "longForm": encoded.long_form, "shortForm": encoded.short_form }))
        }
        "did:peer:4: long-form decode" => {
            let decoded = decode_peer4(input);
            // The document re-encodes to the same identifier.
            let encoded = peer4::encode(&decoded["doc"]).map_err(|e| e.to_string())?;
            if encoded.long_form != input["longForm"] {
                return Err("decoded document does not re-encode to its long form".into());
            }
            Ok(decoded)
        }
        "did:peer:4: short form of either form" => {
            let long_form = input["longForm"].as_str().expect("longForm");
            let short_form = input["shortForm"].as_str().expect("shortForm");
            let short = |did| peer4::short_form(did).map_err(|e: TokenError| e.to_string());
            Ok(json!({
                "fromLong": short(long_form)?,
                "fromShort": short(short_form)?,
                "normalizedLong": normalize_did(long_form),
                "normalizedShort": normalize_did(short_form),
            }))
        }
        _ if input.get("token").is_some() => Ok(verify(input, true)),
        _ if input.get("longForm").is_some() => Ok(decode_peer4(input)),
        _ => Err("no runner for this case".into()),
    }
}

#[test]
fn golden_tokens() {
    let cases = load();
    assert_eq!(cases.len(), 28, "case count");
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| match run(case) {
            Ok(actual) if actual == case.expected => None,
            Ok(actual) => Some(format!(
                "{}: expected {}, got {actual}",
                case.name, case.expected
            )),
            Err(why) => Some(format!("{}: {why}", case.name)),
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} golden cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
