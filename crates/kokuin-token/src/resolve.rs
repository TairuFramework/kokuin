//! Issuer resolution, as `resolveIssuerWithDoc` in `packages/token/src/did.ts`.

use serde_json::Value;

use crate::method::{DIDMethodResolver, MethodError, ResolveIssuerHeader, find_method_resolver};
use crate::multibase::{self, js_length};
use crate::peer4::{self, DEFAULT_MAX_DOC_SIZE, DIDDoc};
use crate::{SignatureAlgorithm, TokenError, did_key};

/// Resolves a did:peer:4 short form to its document (TS `DIDResolver`).
///
/// `Ok(None)` means unknown. An error is treated exactly like `None`: a network-backed resolver
/// that fails must be indistinguishable from one that knows nothing, so the issuer is
/// unresolvable either way.
pub trait DIDResolver {
    /// The document for a short form, if known.
    fn resolve(&self, did: &str) -> Result<Option<Value>, String>;
}

/// The issuer key resolution found.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedIssuer {
    /// The key's algorithm.
    pub alg: SignatureAlgorithm,
    /// The raw public key.
    pub public_key: Vec<u8>,
    /// The did:peer:4 short form and document, when the issuer was a long form or the resolver
    /// supplied one. Write it to a cache only after the signature verifies.
    pub peer4_doc: Option<(String, DIDDoc)>,
}

/// What [`resolve_issuer`] resolves against.
#[derive(Clone, Copy, Default)]
pub struct ResolveIssuerParams<'a> {
    /// Resolves did:peer:4 short forms.
    pub resolver: Option<&'a dyn DIDResolver>,
    /// DID methods resolved by injection (`did:kokuin:`).
    pub methods: &'a [&'a dyn DIDMethodResolver],
    /// Ask a method for a key the issuer signed with in the past, not one it holds now. Reaches
    /// only the method registry: `did:key` and `did:peer:4` have no past key set.
    pub historic: bool,
}

fn from_method(error: MethodError) -> TokenError {
    match error {
        MethodError::IssuerKeyNotFound(message) => TokenError::IssuerKeyNotFound(message),
        MethodError::Unresolvable(message) => TokenError::UnresolvableIssuer(message),
    }
}

/// Resolve a token issuer (did:key, did:peer:4 or an injected method) to its algorithm and public
/// key (`resolveIssuerWithDoc`).
pub fn resolve_issuer(
    iss: &str,
    header: &ResolveIssuerHeader,
    params: &ResolveIssuerParams<'_>,
) -> Result<ResolvedIssuer, TokenError> {
    if let Some(method) = find_method_resolver(params.methods, iss) {
        let resolved = if params.historic {
            method.resolve_historic(iss, header).ok_or_else(|| {
                TokenError::UnresolvableIssuer(format!(
                    "DID method {} cannot resolve historic keys: {iss}",
                    method.method()
                ))
            })?
        } else {
            method.resolve(iss, header)
        }
        .map_err(from_method)?;
        return Ok(ResolvedIssuer {
            alg: resolved.alg,
            public_key: resolved.public_key,
            peer4_doc: None,
        });
    }

    if peer4::is_peer4(iss) {
        let short_form = peer4::short_form(iss)?;
        if iss != short_form {
            let doc = peer4::decode(iss, None)?.doc;
            let (alg, public_key) = resolve_kid_or_auth(&doc, header.kid.as_ref())?;
            return Ok(ResolvedIssuer {
                alg,
                public_key,
                peer4_doc: Some((short_form, doc)),
            });
        }
        let unknown = || TokenError::UnresolvableIssuer(format!("Unknown DID: {short_form}"));
        let Some(resolver) = params.resolver else {
            return Err(unknown());
        };
        let doc = match resolver.resolve(&short_form) {
            Ok(Some(doc)) if !doc.is_null() => doc,
            _ => return Err(unknown()),
        };
        // An unusable answer (oversized, or not hashing to the DID asked for) is unresolvable.
        peer4::assert_doc_within_max_size(&doc, DEFAULT_MAX_DOC_SIZE)
            .map_err(|error| TokenError::UnresolvableIssuer(error.to_string()))?;
        // As in TS, a document the encoder refuses (schema, base58 length) fails as itself.
        if peer4::encode(&doc)?.short_form != short_form {
            return Err(TokenError::UnresolvableIssuer(
                "DIDResolver: short form/doc hash mismatch".into(),
            ));
        }
        let doc = DIDDoc::new(doc)?;
        let (alg, public_key) = resolve_kid_or_auth(&doc, header.kid.as_ref())?;
        return Ok(ResolvedIssuer {
            alg,
            public_key,
            peer4_doc: Some((short_form, doc)),
        });
    }

    if !did_key::has_prefix(iss) {
        return Err(TokenError::UnresolvableIssuer(format!(
            "Unknown DID: {iss}"
        )));
    }
    let (alg, public_key) = did_key::decode(iss)?;
    Ok(ResolvedIssuer {
        alg,
        public_key,
        peer4_doc: None,
    })
}

/// JavaScript's `String(value)` for the JSON values a header can carry.
fn js_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number
            .as_f64()
            .and_then(|number| sozai_codec::canonical::format_number(number).ok())
            .unwrap_or_else(|| number.to_string()),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "null".into(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn resolve_kid_or_auth(
    doc: &DIDDoc,
    kid: Option<&Value>,
) -> Result<(SignatureAlgorithm, Vec<u8>), TokenError> {
    let Some(kid) = kid else {
        let Some(first) = doc.authentication().next() else {
            return Err(TokenError::invalid(
                "resolveIssuer: did:peer:4 token missing kid and doc has no authentication entries",
            ));
        };
        return resolve_kid_from_doc(doc, &Value::String(first.to_owned()));
    };
    // A kid must name a method the subject authorized for `authentication`, else a key listed only
    // under `assertionMethod` could sign tokens. An absent kid is reported as such first.
    if doc.verification_method(kid).is_none() {
        return Err(TokenError::invalid(format!(
            "KidNotFound: {}",
            js_string(kid)
        )));
    }
    let authorized = doc.has_authentication()
        && doc
            .authentication()
            .any(|fragment| Some(fragment) == kid.as_str());
    if !authorized {
        return Err(TokenError::invalid(format!(
            "resolveIssuer: kid {} is not an authentication method",
            js_string(kid)
        )));
    }
    resolve_kid_from_doc(doc, kid)
}

fn resolve_kid_from_doc(
    doc: &DIDDoc,
    kid: &Value,
) -> Result<(SignatureAlgorithm, Vec<u8>), TokenError> {
    let Some(key) = doc.verification_method(kid) else {
        return Err(TokenError::invalid(format!(
            "KidNotFound: {}",
            js_string(kid)
        )));
    };
    if js_length(key) > did_key::MAX_DID_KEY_ENCODED {
        return Err(TokenError::invalid(
            "Invalid verification method: key too large",
        ));
    }
    // Unlike did:key, the key length is not checked here: a wrong-length key fails verification.
    did_key::algorithm_and_public_key(&multibase::decode(key)?)
        .ok_or_else(|| TokenError::invalid("Unsupported verification method codec"))
}

/// Fold a DID to its canonical form for equality: a did:peer:4 becomes its short form; any other
/// DID is returned unchanged (`normalizeDID`).
pub fn normalize_did(did: &str) -> String {
    peer4::short_form(did).unwrap_or_else(|_| did.to_owned())
}
