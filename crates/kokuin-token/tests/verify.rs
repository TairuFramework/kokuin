//! Verification paths the golden vectors do not cover: injected methods, the document cache, time
//! and audience claims, and header rejections. Expected messages are the TS ones.

use ed25519_dalek::SigningKey;
use kokuin_token::{
    DIDCache, DIDMethodResolver, InMemoryDIDCache, MethodError, ResolveIssuerHeader,
    ResolvedSigningKey, SignError, SignatureAlgorithm, TokenError, TokenSigner, VerifyOptions,
    did_key, peer4, sign_token, stringify_token, verify_token,
};
use serde_json::{Map, Value, json};
use sozai_codec::base64url;

struct Signer {
    id: String,
    seed: [u8; 32],
    kid: Option<String>,
}

fn public_key(seed: [u8; 32]) -> Vec<u8> {
    SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

impl Signer {
    fn did_key(seed: [u8; 32]) -> Self {
        Self {
            id: did_key::encode(SignatureAlgorithm::EdDSA, &public_key(seed)).unwrap(),
            seed,
            kid: None,
        }
    }

    fn with_id(seed: [u8; 32], id: &str) -> Self {
        Self {
            id: id.to_owned(),
            seed,
            kid: None,
        }
    }
}

impl TokenSigner for Signer {
    fn id(&self) -> &str {
        &self.id
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EdDSA
    }
    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        kokuin_crypto::sign_ed25519(&self.seed, message)
            .map(Vec::from)
            .map_err(|error| SignError(format!("{error:?}")))
    }
}

fn token(signer: &Signer, payload: Value) -> String {
    let payload = payload.as_object().cloned().unwrap_or_default();
    stringify_token(&sign_token(signer, Map::new(), payload).unwrap()).unwrap()
}

fn error(token: &str, options: &VerifyOptions<'_>) -> TokenError {
    verify_token(token, options).unwrap_err()
}

/// A method answering with one fixed current key and, optionally, one historic key.
struct FixedMethod {
    current: Vec<u8>,
    historic: Option<Vec<u8>>,
    failure: Option<MethodError>,
}

impl DIDMethodResolver for FixedMethod {
    fn method(&self) -> &str {
        "test"
    }

    fn resolve(
        &self,
        _did: &str,
        _header: &ResolveIssuerHeader,
    ) -> Result<ResolvedSigningKey, MethodError> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        Ok(ResolvedSigningKey {
            alg: SignatureAlgorithm::EdDSA,
            public_key: self.current.clone(),
        })
    }

    fn resolve_historic(
        &self,
        _did: &str,
        _header: &ResolveIssuerHeader,
    ) -> Option<Result<ResolvedSigningKey, MethodError>> {
        self.historic.clone().map(|public_key| {
            Ok(ResolvedSigningKey {
                alg: SignatureAlgorithm::EdDSA,
                public_key,
            })
        })
    }
}

#[test]
fn injected_method_current_and_historic_keys() {
    let (old, new) = ([7; 32], [8; 32]);
    let method = FixedMethod {
        current: public_key(new),
        historic: Some(public_key(old)),
        failure: None,
    };
    let methods: [&dyn DIDMethodResolver; 1] = [&method];
    let signed_by_old = token(&Signer::with_id(old, "did:test:a"), json!({}));
    let current = VerifyOptions {
        methods: &methods,
        ..VerifyOptions::default()
    };
    assert_eq!(
        error(&signed_by_old, &current),
        TokenError::InvalidSignature
    );
    let historic = VerifyOptions {
        historic: true,
        ..current
    };
    assert_eq!(
        verify_token(&signed_by_old, &historic).unwrap().public_key,
        public_key(old)
    );

    // No `resolve_historic`: the historic question fails closed instead of asking `resolve`.
    let current_only = FixedMethod {
        current: public_key(old),
        historic: None,
        failure: None,
    };
    let methods: [&dyn DIDMethodResolver; 1] = [&current_only];
    let options = VerifyOptions {
        methods: &methods,
        historic: true,
        ..VerifyOptions::default()
    };
    let refused = error(&signed_by_old, &options);
    assert_eq!(refused.name(), "UnresolvableIssuerError");
    assert_eq!(
        refused.to_string(),
        "DID method test cannot resolve historic keys: did:test:a"
    );
    // Without a registry, the method is unknown.
    assert_eq!(
        error(&signed_by_old, &VerifyOptions::default()),
        TokenError::UnresolvableIssuer("Unknown DID: did:test:a".into())
    );
}

#[test]
fn injected_method_errors_keep_their_category() {
    let signed = token(&Signer::with_id([7; 32], "did:test:a"), json!({}));
    for (failure, name) in [
        (
            MethodError::IssuerKeyNotFound("no such key".into()),
            "IssuerKeyNotFoundError",
        ),
        (
            MethodError::Unresolvable("log unavailable".into()),
            "UnresolvableIssuerError",
        ),
    ] {
        let method = FixedMethod {
            current: Vec::new(),
            historic: None,
            failure: Some(failure),
        };
        let methods: [&dyn DIDMethodResolver; 1] = [&method];
        let options = VerifyOptions {
            methods: &methods,
            ..VerifyOptions::default()
        };
        assert_eq!(error(&signed, &options).name(), name);
    }
}

fn peer4_identity(seed: [u8; 32]) -> (Value, peer4::Peer4) {
    let mut key = vec![0xed, 0x01];
    key.extend(public_key(seed));
    let doc = json!({
        "verificationMethod": [{
            "id": "#key-0",
            "type": "Multikey",
            "publicKeyMultibase": kokuin_token::multibase::encode(&key).unwrap(),
        }],
        "authentication": ["#key-0"],
    });
    let forms = peer4::encode(&doc).unwrap();
    (doc, forms)
}

#[test]
fn cache_learns_long_form_documents_only_after_verification() {
    let seed = [9; 32];
    let (doc, forms) = peer4_identity(seed);
    let cache = InMemoryDIDCache::default();
    let options = VerifyOptions {
        cache: Some(&cache),
        ..VerifyOptions::default()
    };
    // A long-form token signed by another key teaches the cache nothing.
    let forged = token(&Signer::with_id([1; 32], &forms.long_form), json!({}));
    assert_eq!(error(&forged, &options), TokenError::InvalidSignature);
    assert!(cache.get(&forms.short_form).is_none());

    let long = token(&Signer::with_id(seed, &forms.long_form), json!({}));
    verify_token(&long, &options).unwrap();
    assert_eq!(cache.get(&forms.short_form), Some(doc));
    // The short form now resolves through the cache alone.
    let short = token(&Signer::with_id(seed, &forms.short_form), json!({}));
    assert_eq!(
        verify_token(&short, &options).unwrap().public_key,
        public_key(seed)
    );
}

#[test]
fn time_and_audience_claims() {
    let signer = Signer::did_key([3; 32]);
    let signed = token(
        &signer,
        json!({ "exp": 100, "nbf": 50, "aud": "did:example:a" }),
    );
    let at = |time: f64| VerifyOptions {
        at_time: Some(time),
        ..VerifyOptions::default()
    };
    assert!(verify_token(&signed, &at(75.0)).is_ok());
    assert_eq!(error(&signed, &at(101.0)).to_string(), "Token expired");
    assert_eq!(error(&signed, &at(49.0)).to_string(), "Token not yet valid");
    let tolerant = VerifyOptions {
        clock_tolerance: 2.0,
        ..at(101.0)
    };
    assert!(verify_token(&signed, &tolerant).is_ok());

    let other: [&str; 1] = ["did:example:b"];
    let options = VerifyOptions {
        audience: Some(&other),
        ..at(75.0)
    };
    assert_eq!(
        error(&signed, &options).to_string(),
        "Invalid token: audience \"did:example:a\" not accepted"
    );
    let unaddressed = token(&signer, json!({}));
    assert_eq!(
        error(&unaddressed, &options).to_string(),
        "Invalid token: audience missing not accepted"
    );
}

fn segment(value: Value) -> String {
    base64url::encode(value.to_string().as_bytes())
}

#[test]
fn header_and_format_rejections() {
    let message = |token: &str| error(token, &VerifyOptions::default()).to_string();
    let payload = segment(json!({ "iss": "did:key:z" }));
    assert_eq!(
        message("a.b"),
        "Invalid token format: expected 3 parts separated by dots"
    );
    assert_eq!(
        message(&format!(
            "{}.{payload}.",
            segment(json!({ "alg": "EdDSA" }))
        )),
        "Invalid token header type"
    );
    assert_eq!(
        message(&format!(
            "{}.{payload}.",
            segment(json!({ "typ": "JWT", "alg": "none" }))
        )),
        "Invalid token: unsigned tokens rejected, pass allowUnsigned to accept"
    );
    assert_eq!(
        message(&format!(
            "{}.{payload}.",
            segment(json!({ "typ": "JWT", "alg": "HS256" }))
        )),
        "Unsupported signature algorithm"
    );
    assert_eq!(message("!!.x.y"), "Invalid base64url encoding");
    let invalid_utf8 = base64url::encode(&[0xff]);
    assert_eq!(
        error(&format!("{invalid_utf8}.x.y"), &VerifyOptions::default()).name(),
        "TypeError"
    );
    let signer = Signer::did_key([4; 32]);
    let mismatched = sign_token(
        &signer,
        Map::new(),
        json!({ "iss": "did:key:other" })
            .as_object()
            .cloned()
            .unwrap(),
    );
    assert_eq!(
        mismatched.unwrap_err().to_string(),
        "Invalid payload: issuer does not match signer"
    );
}

/// A cache that answers every short form with one fixed document, as a corrupted or hostile
/// store would.
struct LyingCache(Value);

impl DIDCache for LyingCache {
    fn get(&self, _short_form: &str) -> Option<Value> {
        Some(self.0.clone())
    }

    fn set(&self, _short_form: &str, _doc: &Value) -> Result<(), TokenError> {
        Ok(())
    }
}

#[test]
fn cache_answer_is_checked_against_the_short_form() {
    let (_, forms) = peer4_identity([9; 32]);
    // The cached document names the attacker's key, and the token is signed with it.
    let attacker = [10; 32];
    let (attacker_doc, _) = peer4_identity(attacker);
    let cache = LyingCache(attacker_doc);
    let options = VerifyOptions {
        cache: Some(&cache),
        ..VerifyOptions::default()
    };
    let forged = token(&Signer::with_id(attacker, &forms.short_form), json!({}));
    assert_eq!(
        error(&forged, &options),
        TokenError::UnresolvableIssuer("DIDResolver: short form/doc hash mismatch".into())
    );
}

#[test]
fn non_object_segments_are_errors() {
    let payload = segment(json!({ "iss": "did:key:z" }));
    // TS reads `.typ` of a null header and throws a TypeError.
    let null_header = error(
        &format!("{}.{payload}.", segment(Value::Null)),
        &VerifyOptions::default(),
    );
    assert_eq!(null_header.name(), "TypeError");
    assert_eq!(
        null_header.to_string(),
        "Cannot read properties of null (reading 'typ')"
    );
    // Any other non-object header has no `typ`.
    assert_eq!(
        error(
            &format!("{}.{payload}.", segment(json!([]))),
            &VerifyOptions::default()
        )
        .to_string(),
        "Invalid token header type"
    );
    // A non-object payload fails the payload schema.
    let header = segment(json!({ "typ": "JWT", "alg": "EdDSA" }));
    let array_payload = error(
        &format!("{header}.{}.AA", segment(json!([1]))),
        &VerifyOptions::default(),
    );
    assert_eq!(array_payload.name(), "AggregateError");
    assert_eq!(
        array_payload.to_string(),
        "Validation failed for schema object (/ type)"
    );
    // Decoding without verification refuses rather than inventing an empty object.
    for token in [
        format!("{}.{payload}.AA", segment(json!("text"))),
        format!("{header}.{}.AA", segment(Value::Null)),
    ] {
        assert!(
            kokuin_token::decode_signed_token(&token).is_err(),
            "{token}"
        );
    }
    let decoded = kokuin_token::decode_signed_token(&format!("{header}.{payload}.AA")).unwrap();
    assert_eq!(decoded.payload["iss"], json!("did:key:z"));
}

/// A resolver whose document is a parsed value nested far past the JSON depth bound, built
/// without recursion, as a resolver that lifted serde's recursion limit could return.
struct DeepResolver(usize);

impl kokuin_token::DIDResolver for DeepResolver {
    fn resolve(&self, _did: &str) -> Result<Option<Value>, String> {
        let mut deep = Value::Array(Vec::new());
        for _ in 0..self.0 {
            deep = Value::Array(vec![deep]);
        }
        let mut doc = json!({
            "verificationMethod": [{ "id": "#key-0", "type": "Multikey", "publicKeyMultibase": "z" }],
            "authentication": ["#key-0"],
        });
        doc["x"] = deep;
        Ok(Some(doc))
    }
}

#[test]
fn deep_resolver_document_is_unresolvable_on_a_small_stack() {
    let seed = [9; 32];
    let (_, forms) = peer4_identity(seed);
    let signed = token(&Signer::with_id(seed, &forms.short_form), json!({}));
    // 512 KiB, the iOS secondary thread stack. Canonicalizing, cloning or dropping this document
    // recursively would abort the process.
    let result = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || {
            let resolver = DeepResolver(200_000);
            let options = VerifyOptions {
                resolver: Some(&resolver),
                ..VerifyOptions::default()
            };
            verify_token(&signed, &options).map(|_| ())
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(
        result,
        Err(TokenError::UnresolvableIssuer(
            "JSON exceeds maximum nesting depth of 128".into()
        ))
    );
    // The bound is the parse bound: a cache refuses such a document too.
    let cache = InMemoryDIDCache::default();
    let shallow = kokuin_token::DIDResolver::resolve(&DeepResolver(200), "")
        .unwrap()
        .unwrap();
    assert_eq!(
        cache
            .set(&forms.short_form, &shallow)
            .unwrap_err()
            .to_string(),
        "JSON exceeds maximum nesting depth of 128"
    );
}
