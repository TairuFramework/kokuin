//! Compact (JWS) tokens: signing, serialization and verification, as `token.ts` and `utils.ts`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use sozai_codec::base64url;

use crate::cache::DIDCache;
use crate::json::{b64u_from_json, b64u_to_json, from_b64u};
use crate::method::{DIDMethodResolver, ResolveIssuerHeader};
use crate::resolve::{DIDResolver, ResolveIssuerParams, resolve_issuer};
use crate::schema::validate_signed_payload;
use crate::{SignatureAlgorithm, TokenError};

const FORMAT_ERROR: &str = "Invalid token format: expected 3 parts separated by dots";

/// A token signer failed. The message is the signer's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignError(pub String);

/// An identity that signs tokens (TS `SigningIdentity`).
pub trait TokenSigner {
    /// The issuer DID written to `iss`.
    fn id(&self) -> &str;

    /// The algorithm written to the header's `alg`.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The `kid` written to the header, if any (a did:peer:4 identity names its key fragment).
    fn kid(&self) -> Option<&str> {
        None
    }

    /// Sign the token's signing input bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// A signed token: the decoded header and payload, and the exact signing input.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedToken {
    /// `<header>.<payload>` as base64url segments: the bytes the signature covers.
    pub data: String,
    /// The header.
    pub header: Map<String, Value>,
    /// The payload.
    pub payload: Map<String, Value>,
    /// The base64url signature.
    pub signature: String,
}

/// A token whose signature verified.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedToken {
    /// The signed segments exactly as received.
    pub data: String,
    /// The header, decoded from the received bytes.
    pub header: Map<String, Value>,
    /// The payload, decoded from the received bytes.
    pub payload: Map<String, Value>,
    /// The base64url signature.
    pub signature: String,
    /// The issuer key the signature verified against.
    pub public_key: Vec<u8>,
    /// That key's algorithm.
    pub alg: SignatureAlgorithm,
}

/// Sign a header and payload (TS `SigningIdentity.signToken`).
///
/// The header gets `typ: "JWT"`, the signer's `alg`, and its `kid` when it has one; the payload
/// gets `iss` set to the signer's id. Both are serialized canonically.
pub fn sign_token(
    signer: &dyn TokenSigner,
    header: Map<String, Value>,
    payload: Map<String, Value>,
) -> Result<SignedToken, TokenError> {
    let id = signer.id();
    if let Some(iss) = payload.get("iss")
        && !iss.is_null()
        && iss.as_str() != Some(id)
    {
        return Err(TokenError::invalid(
            "Invalid payload: issuer does not match signer",
        ));
    }
    let mut header = header;
    header.insert("typ".into(), "JWT".into());
    header.insert("alg".into(), signer.algorithm().as_str().into());
    if let Some(kid) = signer.kid() {
        header.insert("kid".into(), kid.into());
    }
    let mut payload = payload;
    payload.insert("iss".into(), id.into());
    let header_value = Value::Object(header);
    let payload_value = Value::Object(payload);
    let data = format!(
        "{}.{}",
        b64u_from_json(&header_value)?,
        b64u_from_json(&payload_value)?
    );
    let signature = signer
        .sign(data.as_bytes())
        .map_err(|SignError(message)| TokenError::Invalid(message))?;
    let (Value::Object(header), Value::Object(payload)) = (header_value, payload_value) else {
        unreachable!("built as objects above");
    };
    Ok(SignedToken {
        data,
        header,
        payload,
        signature: base64url::encode(&signature),
    })
}

/// The compact form of a signed token: its canonical header and payload and its signature
/// (`stringifyToken`).
pub fn stringify_token(token: &SignedToken) -> String {
    let header = b64u_from_json(&Value::Object(token.header.clone())).unwrap_or_default();
    let payload = b64u_from_json(&Value::Object(token.payload.clone())).unwrap_or_default();
    format!("{header}.{payload}.{}", token.signature)
}

fn into_object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(object) => object,
        _ => Map::new(),
    }
}

/// Parse a compact token without verifying it; `data` keeps the received segments
/// (`decodeSignedToken`).
///
/// TS returns whatever JSON the segments hold; a segment that is not an object decodes here to an
/// empty map. Nothing is validated, so never authorize on the result.
pub fn decode_signed_token(token: &str) -> Result<SignedToken, TokenError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenError::invalid(FORMAT_ERROR));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(TokenError::invalid(FORMAT_ERROR));
    }
    Ok(SignedToken {
        data: format!("{header}.{payload}"),
        header: into_object(b64u_to_json(header)?),
        payload: into_object(b64u_to_json(payload)?),
        signature: signature.to_owned(),
    })
}

/// What [`verify_token`] checks against. The default resolves `did:key` and long-form
/// `did:peer:4` issuers only, and checks time claims against the system clock.
#[derive(Clone, Copy, Default)]
pub struct VerifyOptions<'a> {
    /// Resolves did:peer:4 short forms.
    pub resolver: Option<&'a dyn DIDResolver>,
    /// Read before the resolver, written after the signature verifies.
    pub cache: Option<&'a dyn DIDCache>,
    /// DID methods resolved by injection (`did:kokuin:`).
    pub methods: &'a [&'a dyn DIDMethodResolver],
    /// Accepted audiences. When set, a token whose `aud` is not among them is rejected; an empty
    /// list accepts none.
    pub audience: Option<&'a [&'a str]>,
    /// Verify against a key the issuer has rotated away, as well as its current ones. Only for a
    /// past-issued artefact, never to authenticate a live signer.
    pub historic: bool,
    /// The time to check `exp` and `nbf` against, in unix seconds. Defaults to now.
    pub at_time: Option<f64>,
    /// Clock skew tolerance in seconds.
    pub clock_tolerance: f64,
}

/// A cache-first view of the resolver, as `verifySignedPayload` builds it.
struct CachedResolver<'a> {
    cache: &'a dyn DIDCache,
    resolver: Option<&'a dyn DIDResolver>,
}

impl DIDResolver for CachedResolver<'_> {
    fn resolve(&self, did: &str) -> Result<Option<Value>, String> {
        if let Some(doc) = self.cache.get(did) {
            return Ok(Some(doc));
        }
        match self.resolver {
            Some(resolver) => resolver.resolve(did),
            None => Ok(None),
        }
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as f64)
        .unwrap_or(0.0)
}

fn assert_time_claims_valid(
    payload: &Map<String, Value>,
    options: &VerifyOptions<'_>,
) -> Result<(), TokenError> {
    let time = options.at_time.unwrap_or_else(now);
    let tolerance = options.clock_tolerance;
    if let Some(exp) = payload.get("exp").and_then(Value::as_f64)
        && exp + tolerance < time
    {
        return Err(TokenError::invalid("Token expired"));
    }
    if let Some(nbf) = payload.get("nbf").and_then(Value::as_f64)
        && nbf - tolerance > time
    {
        return Err(TokenError::invalid("Token not yet valid"));
    }
    Ok(())
}

fn assert_audience_valid(
    payload: &Map<String, Value>,
    audience: Option<&[&str]>,
) -> Result<(), TokenError> {
    let Some(allowed) = audience else {
        return Ok(());
    };
    match payload.get("aud").and_then(Value::as_str) {
        Some(aud) if allowed.contains(&aud) => Ok(()),
        Some(aud) => Err(TokenError::invalid(format!(
            "Invalid token: audience \"{aud}\" not accepted"
        ))),
        None => Err(TokenError::invalid(
            "Invalid token: audience missing not accepted",
        )),
    }
}

/// Verify a compact token (`verifyToken` on a string).
///
/// The signature is checked over the received `<header>.<payload>` bytes, never a
/// re-serialization: a token whose payload was re-encoded fails even when its JSON value is
/// unchanged, and one signed over non-canonical JSON verifies as signed. Unsigned (`alg: none`)
/// tokens are always rejected; this port has no `allowUnsigned`.
pub fn verify_token(token: &str, options: &VerifyOptions<'_>) -> Result<VerifiedToken, TokenError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [encoded_header, encoded_payload, signature] = parts[..] else {
        return Err(TokenError::invalid(FORMAT_ERROR));
    };

    let header = b64u_to_json(encoded_header)?;
    if header.get("typ").and_then(Value::as_str) != Some("JWT") {
        return Err(TokenError::invalid("Invalid token header type"));
    }
    let alg = header.get("alg").and_then(Value::as_str);
    if alg == Some("none") {
        return Err(TokenError::invalid(if options.audience.is_some() {
            "Invalid token: audience validation requires a signed token"
        } else {
            "Invalid token: unsigned tokens rejected, pass allowUnsigned to accept"
        }));
    }
    // The header's `alg` only gates which algorithms are accepted at all: the signature is
    // checked with the algorithm the issuer's key resolves to, as in TS.
    if alg.and_then(SignatureAlgorithm::parse).is_none() {
        return Err(TokenError::invalid("Unsupported signature algorithm"));
    }

    let payload = b64u_to_json(encoded_payload)?;
    let signature_bytes = from_b64u(signature)?;
    let data = format!("{encoded_header}.{encoded_payload}");

    let object = validate_signed_payload(&payload)?;
    let iss = object["iss"].as_str().unwrap_or_default();
    let issuer_header = ResolveIssuerHeader {
        kid: header.get("kid").filter(|kid| !kid.is_null()).cloned(),
    };
    let cached = options.cache.map(|cache| CachedResolver {
        cache,
        resolver: options.resolver,
    });
    let resolver = match &cached {
        Some(cached) => Some(cached as &dyn DIDResolver),
        None => options.resolver,
    };
    let resolved = resolve_issuer(
        iss,
        &issuer_header,
        &ResolveIssuerParams {
            resolver,
            methods: options.methods,
            historic: options.historic,
        },
    )?;
    if !kokuin_crypto::verify(
        resolved.alg.into(),
        &signature_bytes,
        data.as_bytes(),
        &resolved.public_key,
    ) {
        return Err(TokenError::InvalidSignature);
    }
    if let (Some(cache), Some((short_form, doc))) = (options.cache, &resolved.peer4_doc) {
        cache.set(short_form, doc.as_value())?;
    }

    let payload = into_object(payload);
    assert_time_claims_valid(&payload, options)?;
    assert_audience_valid(&payload, options.audience)?;
    Ok(VerifiedToken {
        data,
        header: into_object(header),
        payload,
        signature: signature.to_owned(),
        public_key: resolved.public_key,
        alg: resolved.alg,
    })
}
