//! `did:peer:4`, as `packages/token/src/peer4.ts`: a DID whose document is embedded in its long
//! form and fixed by the hash its short form carries.

use serde_json::Value;

use crate::TokenError;
use crate::json::{canonical, check_value_depth, parse, to_utf8};
use crate::multibase::{self, js_length, multihash_sha256, verify_multihash};
use crate::schema::validate_did_doc;

const PREFIX: &str = "did:peer:4";
const JSON_MULTICODEC: [u8; 2] = [0x80, 0x04];

/// The default bound on a document's canonical byte size: 4 KiB.
pub const DEFAULT_MAX_DOC_SIZE: usize = 4 * 1024;
/// Undercounts the smallest legal verification method entry (44 bytes), so the O(1) entry-count
/// guard never rejects a document the byte measure would accept.
const MIN_VERIFICATION_METHOD_BYTES: usize = 40;
/// base58 expands bytes to characters by log(256) / log(58).
const BASE58_EXPANSION: f64 = 1.3658;
/// A SHA-256 multihash is 47 base58 characters plus the multibase `z`.
const MAX_HASH_ENCODED: usize = 64;

/// A DID document that passed the did:peer:4 document schema. It keeps the JSON value as given,
/// additional properties included.
#[derive(Clone, Debug, PartialEq)]
pub struct DIDDoc(Value);

impl DIDDoc {
    /// Validate a JSON value against the document schema.
    pub fn new(value: Value) -> Result<Self, TokenError> {
        if validate_did_doc(&value) {
            Ok(Self(value))
        } else {
            Err(TokenError::invalid(
                "did:peer:4 doc failed schema validation",
            ))
        }
    }

    /// The document as JSON.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// The document as JSON, by value.
    pub fn into_value(self) -> Value {
        self.0
    }

    fn strings(&self, key: &str) -> impl Iterator<Item = &str> {
        self.0[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
    }

    /// The `authentication` fragments, in order.
    pub fn authentication(&self) -> impl Iterator<Item = &str> {
        self.strings("authentication")
    }

    /// Whether the document has an `authentication` list at all.
    pub(crate) fn has_authentication(&self) -> bool {
        self.0.get("authentication").is_some()
    }

    /// The `keyAgreement` fragments, in order.
    pub fn key_agreement(&self) -> impl Iterator<Item = &str> {
        self.strings("keyAgreement")
    }

    /// The `publicKeyMultibase` of the first verification method whose `id` equals `id`.
    pub fn verification_method(&self, id: &Value) -> Option<&str> {
        self.0["verificationMethod"]
            .as_array()?
            .iter()
            .find(|method| &method["id"] == id)
            .and_then(|method| method["publicKeyMultibase"].as_str())
    }
}

/// A did:peer:4 identifier in both forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer4 {
    /// The self-contained form, with the document embedded.
    pub long_form: String,
    /// The hash-only form.
    pub short_form: String,
}

/// A decoded long form.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedPeer4 {
    /// The long form decoded.
    pub long_form: String,
    /// Its short form.
    pub short_form: String,
    /// The embedded document.
    pub doc: DIDDoc,
}

/// Whether a string is a did:peer:4 identifier, in either form (`isPeer4`).
pub fn is_peer4(value: &str) -> bool {
    value
        .strip_prefix(PREFIX)
        .is_some_and(|rest| rest.starts_with('z'))
}

fn separator(did: &str) -> Option<usize> {
    did[PREFIX.len()..]
        .find(':')
        .map(|index| index + PREFIX.len())
}

/// The short form of a did:peer:4 identifier, given either form (`getPeer4ShortForm`).
pub fn short_form(did: &str) -> Result<String, TokenError> {
    if !is_peer4(did) {
        return Err(TokenError::invalid("Invalid did:peer:4 identifier"));
    }
    Ok(match separator(did) {
        Some(index) => did[..index].to_owned(),
        None => did.to_owned(),
    })
}

/// Refuse a document whose canonical serialization exceeds `max_size` bytes
/// (`assertDocWithinMaxSize`). The O(1) entry-count check runs first, so a huge
/// `verificationMethod` list is refused before it is measured.
pub fn assert_doc_within_max_size(doc: &Value, max_size: usize) -> Result<(), TokenError> {
    let max_entries = max_size.div_ceil(MIN_VERIFICATION_METHOD_BYTES);
    if let Some(methods) = doc.get("verificationMethod").and_then(Value::as_array)
        && methods.len() > max_entries
    {
        return Err(TokenError::invalid(format!(
            "did:peer:4 resolver doc has too many verification methods: {} > {max_entries}",
            methods.len()
        )));
    }
    // Not in TS, whose documents all come from `JSON.parse`: a caller-built value can nest past
    // the parse bound, and canonicalization recurses once per level.
    check_value_depth(doc)?;
    let size = canonical(doc)?.len();
    if size > max_size {
        return Err(TokenError::invalid(format!(
            "did:peer:4 resolver doc too large: {size} > {max_size}"
        )));
    }
    Ok(())
}

/// Decode a long form into its document, checking the embedded hash (`decodePeer4`).
///
/// `max_doc_size` bounds the document's byte size; `None` is [`DEFAULT_MAX_DOC_SIZE`]. TS keeps an
/// LRU of successful decodes; it only skips repeated work and changes no result, so this
/// stateless port omits it.
pub fn decode(long_form: &str, max_doc_size: Option<usize>) -> Result<DecodedPeer4, TokenError> {
    if !is_peer4(long_form) {
        return Err(TokenError::invalid("Invalid did:peer:4 identifier"));
    }
    let Some(index) = separator(long_form) else {
        return Err(TokenError::invalid(
            "Expected did:peer:4 long form, got short form",
        ));
    };
    let hash_encoded = &long_form[PREFIX.len()..index];
    let encoded_doc = &long_form[index + 1..];

    // Both segments feed an O(n^2) base58 decode, so bound them before decoding.
    if js_length(hash_encoded) > MAX_HASH_ENCODED {
        return Err(TokenError::invalid("did:peer:4 hash too large"));
    }
    let max_size = max_doc_size.unwrap_or(DEFAULT_MAX_DOC_SIZE);
    let max_encoded = (((max_size.saturating_add(JSON_MULTICODEC.len()) as f64) * BASE58_EXPANSION)
        .ceil() as usize)
        .saturating_add(8);
    let encoded_length = js_length(encoded_doc);
    if encoded_length > max_encoded {
        return Err(TokenError::invalid(format!(
            "did:peer:4 encoded doc too large: {encoded_length} > {max_encoded}"
        )));
    }

    let hash = multibase::decode(hash_encoded)?;
    if !verify_multihash(&hash, encoded_doc.as_bytes()) {
        return Err(TokenError::invalid("did:peer:4 hash mismatch"));
    }
    let tagged = multibase::decode(encoded_doc)?;
    let Some(doc_bytes) = tagged.strip_prefix(&JSON_MULTICODEC) else {
        return Err(TokenError::invalid(
            "did:peer:4 doc missing JSON multicodec prefix",
        ));
    };
    if doc_bytes.len() > max_size {
        return Err(TokenError::invalid(format!(
            "did:peer:4 doc too large: {} > {max_size}",
            doc_bytes.len()
        )));
    }
    let doc = parse(&to_utf8(doc_bytes.to_vec())?)?;
    let doc = DIDDoc::new(doc)?;
    Ok(DecodedPeer4 {
        long_form: long_form.to_owned(),
        short_form: format!("{PREFIX}{hash_encoded}"),
        doc,
    })
}

/// Encode a DID document as a did:peer:4 identifier (`encodePeer4`).
///
/// As in TS, a document whose tagged canonical bytes exceed 2048 cannot be base58 encoded and
/// fails with `invalid length`, although decoding accepts up to [`DEFAULT_MAX_DOC_SIZE`].
pub fn encode(doc: &Value) -> Result<Peer4, TokenError> {
    // Before the clone and canonicalization below, both of which recurse once per level.
    check_value_depth(doc)?;
    let doc = DIDDoc::new(doc.clone())?;
    let mut tagged = JSON_MULTICODEC.to_vec();
    tagged.extend_from_slice(canonical(doc.as_value())?.as_bytes());
    let encoded_doc = multibase::encode(&tagged)?;
    let hash = multibase::encode(&multihash_sha256(encoded_doc.as_bytes()))?;
    let short_form = format!("{PREFIX}{hash}");
    Ok(Peer4 {
        long_form: format!("{short_form}:{encoded_doc}"),
        short_form,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn doc() -> Value {
        json!({
            "verificationMethod": [{ "id": "#key-0", "type": "Multikey", "publicKeyMultibase": "z" }],
            "authentication": ["#key-0"],
        })
    }

    #[test]
    fn round_trips_and_forms() {
        let encoded = encode(&doc()).unwrap();
        let decoded = decode(&encoded.long_form, None).unwrap();
        assert_eq!(decoded.short_form, encoded.short_form);
        assert_eq!(decoded.doc.as_value(), &doc());
        assert_eq!(short_form(&encoded.long_form).unwrap(), encoded.short_form);
        assert_eq!(short_form(&encoded.short_form).unwrap(), encoded.short_form);
        assert!(!is_peer4("did:peer:4"));
        assert!(!is_peer4("did:peer:2z"));
        assert_eq!(
            short_form("did:key:z").unwrap_err().to_string(),
            "Invalid did:peer:4 identifier"
        );
    }

    #[test]
    fn rejects_bad_segments() {
        let encoded = encode(&doc()).unwrap();
        let error = |did: &str| decode(did, None).unwrap_err().to_string();
        let long_hash = format!("did:peer:4z{}:zabc", "2".repeat(64));
        assert_eq!(error(&long_hash), "did:peer:4 hash too large");
        // A doc segment that hashes right but lacks the JSON multicodec.
        let untagged = multibase::encode(b"{}").unwrap();
        let hash = multibase::encode(&multihash_sha256(untagged.as_bytes())).unwrap();
        assert_eq!(
            error(&format!("did:peer:4{hash}:{untagged}")),
            "did:peer:4 doc missing JSON multicodec prefix"
        );
        // A tagged doc that hashes right but fails the schema.
        let mut tagged = JSON_MULTICODEC.to_vec();
        tagged.extend_from_slice(b"{}");
        let bad = multibase::encode(&tagged).unwrap();
        let hash = multibase::encode(&multihash_sha256(bad.as_bytes())).unwrap();
        assert_eq!(
            error(&format!("did:peer:4{hash}:{bad}")),
            "did:peer:4 doc failed schema validation"
        );
        assert!(decode(&encoded.long_form, Some(0)).is_err());
    }

    /// Base58 without the 2048-byte encode limit, to build long forms TS could not produce but an
    /// attacker can: decoding accepts up to 4096 characters.
    fn base58_unbounded(bytes: &[u8]) -> String {
        let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
        let mut digits: Vec<u32> = Vec::new();
        for &byte in &bytes[zeros..] {
            let mut carry = u32::from(byte);
            for digit in digits.iter_mut() {
                carry += *digit << 8;
                *digit = carry % 58;
                carry /= 58;
            }
            while carry > 0 {
                digits.push(carry % 58);
                carry /= 58;
            }
        }
        let mut out = "1".repeat(zeros);
        out.extend(
            digits
                .iter()
                .rev()
                .map(|&d| char::from(alphabet[d as usize])),
        );
        out
    }

    #[test]
    fn deep_embedded_doc_is_refused_on_a_small_stack() {
        // A hash-correct long form nesting 1450 levels: just under the 4096-character decode limit.
        let depth = 1450;
        let json = format!(
            r##"{{"verificationMethod":[{{"id":"#k","type":"Multikey","publicKeyMultibase":"z"}}],"x":{}{}}}"##,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let mut tagged = JSON_MULTICODEC.to_vec();
        tagged.extend_from_slice(json.as_bytes());
        let encoded_doc = format!("z{}", base58_unbounded(&tagged));
        assert!(encoded_doc.len() <= 4097, "fits the decode limit");
        let hash = multibase::encode(&multihash_sha256(encoded_doc.as_bytes())).unwrap();
        let long_form = format!("did:peer:4{hash}:{encoded_doc}");
        // 512 KiB, the iOS secondary thread stack: unbounded recursion here aborts the process.
        let result = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || decode(&long_form, None).map(|_| ()))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(
            result,
            Err(TokenError::invalid(
                "JSON exceeds maximum nesting depth of 128"
            ))
        );
    }

    #[test]
    fn encode_refuses_what_base58_cannot_hold() {
        let mut big = doc();
        big["pad"] = json!("x".repeat(2100));
        assert_eq!(encode(&big).unwrap_err().to_string(), "invalid length");
    }

    #[test]
    fn size_guard_counts_entries_first() {
        let methods: Vec<Value> = (0..104)
            .map(|_| json!({ "id": "#k", "type": "Multikey", "publicKeyMultibase": "z" }))
            .collect();
        let crowded = json!({ "verificationMethod": methods });
        assert_eq!(
            assert_doc_within_max_size(&crowded, DEFAULT_MAX_DOC_SIZE)
                .unwrap_err()
                .to_string(),
            "did:peer:4 resolver doc has too many verification methods: 104 > 103"
        );
        assert!(assert_doc_within_max_size(&doc(), DEFAULT_MAX_DOC_SIZE).is_ok());
    }
}
