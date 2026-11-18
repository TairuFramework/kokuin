//! Root-chain event verification, as the verifying half of `packages/controller/src/events.ts`.
//!
//! Events are read as the JSON values they arrived as: a field may hold any JSON type, and each
//! check is the TS one applied to that value.

use serde_json::Value;
use sozai_codec::base64url;

use crate::canonical::{canonical_text, digest_of, digest_of_str};
use crate::js::{is_safe_integer, prop, prop_is, strict_eq_number, to_number};
use crate::keys::{KeyAlgorithm, try_decode_key};

/// The did:kokuin method prefix (`DID_PREFIX`).
pub const DID_PREFIX: &str = "did:kokuin:";

/// How a deny entry names a key rather than a DID (`KEY_TARGET_PREFIX`).
pub const KEY_TARGET_PREFIX: &str = "#";

/// The deny-set spelling of `key` (`keyTarget`).
pub fn key_target(key: &str) -> String {
    format!("{KEY_TARGET_PREFIX}{key}")
}

/// The key a deny entry names, or `None` when it names a DID (`keyFromTarget`).
pub fn key_from_target(target: &str) -> Option<&str> {
    target.strip_prefix(KEY_TARGET_PREFIX)
}

/// The DID an inception body hashes to (`didFromInception`).
pub fn did_from_inception(event: &Value) -> String {
    format!("{DID_PREFIX}{}", digest_of(event))
}

/// A published key list: an array of strings (`isKeyList`).
pub(crate) fn key_list(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

/// A management member as a snapshot carries it (`MemberEntry`).
#[derive(Clone, Debug, PartialEq)]
pub struct MemberEntry {
    /// The DID the member acts as.
    pub did: String,
    /// The pinned Ed25519 key, encoded as a key in `k` is.
    pub key: String,
    /// The digest of the add that admitted it: its incarnation.
    pub add: String,
    /// Lease end, unix seconds.
    pub lease: f64,
}

/// The shape of one snapshot member (`isMemberEntry`).
pub(crate) fn member_entry(value: &Value) -> Option<MemberEntry> {
    let entry = value.as_object()?;
    let lease = entry.get("lease");
    if !is_safe_integer(lease) || lease.and_then(Value::as_f64)? < 0.0 {
        return None;
    }
    Some(MemberEntry {
        did: entry.get("did")?.as_str()?.to_owned(),
        key: entry.get("key")?.as_str()?.to_owned(),
        add: entry.get("add")?.as_str()?.to_owned(),
        lease: lease?.as_f64()?,
    })
}

/// `threshold === keys.length` (`isEnforcedThreshold`).
fn is_enforced_threshold(threshold: Option<&Value>, keys: &[String]) -> bool {
    strict_eq_number(threshold, keys.len() as f64)
}

/// A non-empty list of X25519-tagged keys (`verifyAgreementKeys`).
fn verify_agreement_keys(ka: Option<&Value>) -> bool {
    match key_list(ka) {
        Some(keys) if !keys.is_empty() => keys
            .iter()
            .all(|key| matches!(try_decode_key(key), Some((KeyAlgorithm::X25519, _)))),
        _ => false,
    }
}

/// Unpadded base64url, as `base64urlnopad.decode`: padding is refused, not ignored.
fn decode_signature(sig: &Value) -> Option<Vec<u8>> {
    let text = sig.as_str()?;
    if text.contains('=') {
        return None;
    }
    base64url::decode(text).ok()
}

/// Whether `sigs` verify n-of-n over `event`'s canonical bytes under `keys` (`verifySignatures`).
/// Malformed signatures, keys and non-canonical bodies yield false.
pub(crate) fn verify_signatures(event: &Value, sigs: &[Value], keys: &[String]) -> bool {
    if sigs.len() != keys.len() || sigs.is_empty() {
        return false;
    }
    let Some(text) = canonical_text(event) else {
        return false;
    };
    let mut items = Vec::with_capacity(sigs.len());
    for (sig, key) in sigs.iter().zip(keys) {
        let Some((KeyAlgorithm::EdDSA, public_key)) = try_decode_key(key) else {
            return false;
        };
        let Some(signature) = decode_signature(sig) else {
            return false;
        };
        items.push((signature, public_key));
    }
    items.iter().all(|(signature, public_key)| {
        kokuin_crypto::verify(
            kokuin_crypto::Algorithm::Ed25519,
            signature,
            text.as_bytes(),
            public_key,
        )
    })
}

/// `event.r === undefined` and the rest of `isPublishedRotate`.
fn is_published_rotate(event: &Value) -> Option<(Vec<String>, Vec<String>)> {
    let k = key_list(prop(event, "k"))?;
    let n = key_list(prop(event, "n"))?;
    let seal_ok = match prop(event, "a") {
        None | Some(Value::Null) | Some(Value::String(_)) => true,
        Some(_) => false,
    };
    (is_enforced_threshold(prop(event, "kt"), &k)
        && is_enforced_threshold(prop(event, "nt"), &n)
        && seal_ok
        && prop(event, "r").is_none())
    .then_some((k, n))
}

/// Whether an inception is well formed, hashes to `did` and is signed by its keys
/// (`verifyInception`).
pub(crate) fn verify_inception(event: &Value, sigs: &[Value], did: &str) -> bool {
    if !prop_is(event, "t", "icp") || prop(event, "i").is_some() {
        return false;
    }
    let (Some(k), Some(n), Some(Value::String(_))) = (
        key_list(prop(event, "k")),
        key_list(prop(event, "n")),
        prop(event, "r"),
    ) else {
        return false;
    };
    if !is_enforced_threshold(prop(event, "kt"), &k)
        || !is_enforced_threshold(prop(event, "nt"), &n)
    {
        return false;
    }
    if did_from_inception(event) != did {
        return false;
    }
    if !verify_agreement_keys(prop(event, "ka")) {
        return false;
    }
    verify_signatures(event, sigs, &k)
}

/// Whether a rotate chains to `prior_digest`, reveals what `prior_next` committed and is signed by
/// the revealed keys (`verifyRotate`).
pub(crate) fn verify_rotate(
    event: &Value,
    sigs: &[Value],
    prior_digest: &str,
    prior_next: &[String],
) -> bool {
    if !prop_is(event, "t", "rot") || !prop_is(event, "p", prior_digest) {
        return false;
    }
    let Some((k, _)) = is_published_rotate(event) else {
        return false;
    };
    if k.len() != prior_next.len() {
        return false;
    }
    if k.iter()
        .zip(prior_next)
        .any(|(key, commitment)| digest_of_str(key) != *commitment)
    {
        return false;
    }
    if !verify_agreement_keys(prop(event, "ka")) {
        return false;
    }
    verify_signatures(event, sigs, &k)
}

fn is_nullish(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

/// Whether a reset chains to the inception and is signed by the recovery key it reveals
/// (`verifyReset`).
pub(crate) fn verify_reset(
    event: &Value,
    sigs: &[Value],
    recovery_key: Option<&Value>,
    inception: &Value,
) -> bool {
    if !prop_is(event, "t", "rot")
        || !prop_is(event, "p", &digest_of(inception))
        || !strict_eq_number(prop(event, "s"), 0.0)
        || to_number(prop(event, "g")) < 1.0
    {
        return false;
    }
    if is_published_rotate(event).is_none() {
        return false;
    }
    if prop(event, "a").is_some() {
        return false;
    }
    let m = prop(event, "m");
    let d = prop(event, "d");
    let empty_deny = key_list(d).is_some_and(|deny| deny.is_empty());
    if prop(event, "u").is_some() && (is_nullish(m) || is_nullish(d)) {
        return false;
    }
    if if is_nullish(m) {
        !empty_deny
    } else {
        is_nullish(d)
    } {
        return false;
    }
    if m.and_then(Value::as_array).is_some_and(Vec::is_empty) && empty_deny {
        return false;
    }
    if sigs.len() != 1 {
        return false;
    }
    if !verify_agreement_keys(prop(event, "ka")) {
        return false;
    }
    let Some(revealed) = recovery_key.and_then(Value::as_str) else {
        return false;
    };
    if prop(inception, "r").and_then(Value::as_str) != Some(digest_of_str(revealed).as_str()) {
        return false;
    }
    verify_signatures(event, sigs, &[revealed.to_owned()])
}
