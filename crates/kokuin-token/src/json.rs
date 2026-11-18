//! JSON text decoding as `@sozai/codec` `b64uToJSON` and `JSON.parse` do it.

use serde_json::Value;
use sozai_codec::{base64url, json};

use sozai_codec::json::MAX_DEPTH;
pub(crate) use sozai_codec::json::dismantle;

use crate::TokenError;

fn depth_error() -> TokenError {
    TokenError::invalid(json::JSONError::MaximumDepth(MAX_DEPTH).to_string())
}

/// Bound caller-provided JSON before recursive clone, canonicalization or drop.
pub(crate) fn check_value_depth(value: &Value) -> Result<(), TokenError> {
    if json::check_value_depth(value, MAX_DEPTH) {
        Ok(())
    } else {
        Err(depth_error())
    }
}

/// Decode UTF-8 strictly, as `toUTF` does. A leading BOM is kept, not stripped.
pub(crate) fn to_utf8(bytes: Vec<u8>) -> Result<String, TokenError> {
    String::from_utf8(bytes).map_err(|_| TokenError::InvalidUTF8)
}

/// `@sozai/json` `parse` with its default options: a nesting check, then `JSON.parse`. Every JSON
/// text this crate reads goes through here, and all of it is untrusted.
///
/// The scan bounds nesting at 128 before any recursion, so serde's own limit (which stops at 127,
/// one short of TS) is lifted only for text already known to be within the bound.
///
/// Diverges from JavaScript on one input class: a string escape encoding a lone UTF-16
/// surrogate (`"\ud800"`) fails here, since no Rust string can hold it.
pub(crate) fn parse(text: &str) -> Result<Value, TokenError> {
    json::parse(text).map_err(|error| match error {
        json::JSONError::MaximumDepth(_) => depth_error(),
        json::JSONError::InvalidJSON(message) => TokenError::InvalidJSON(message),
    })
}

/// Strict base64url, as `fromB64U`.
pub(crate) fn from_b64u(text: &str) -> Result<Vec<u8>, TokenError> {
    base64url::decode(text).map_err(|_| TokenError::invalid("Invalid base64url encoding"))
}

/// `b64uToJSON`: strict base64url, strict UTF-8, then `@sozai/json` `parse`.
pub(crate) fn b64u_to_json(text: &str) -> Result<Value, TokenError> {
    parse(&to_utf8(from_b64u(text)?)?)
}

/// `b64uFromJSON` with canonicalization, the only mode the token functions use.
pub(crate) fn b64u_from_json(value: &Value) -> Result<String, TokenError> {
    Ok(base64url::encode(canonical(value)?.as_bytes()))
}

/// `canonicalStringify`.
pub(crate) fn canonical(value: &Value) -> Result<String, TokenError> {
    sozai_codec::canonical::stringify(value).map_err(|error| TokenError::Invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_depth_counts_as_the_text_scan_does() {
        let nest = |depth: usize| {
            let mut value = Value::Array(Vec::new());
            for _ in 1..depth {
                value = serde_json::json!({ "a": [1, value] });
            }
            value
        };
        // Each wrap adds an object and an array: 1 + 2 * 63 = 127, 1 + 2 * 64 = 129.
        let within = nest(64);
        assert_eq!(check_value_depth(&within), Ok(()));
        assert_eq!(
            check_value_depth(&within).is_ok(),
            json::check_depth(&within.to_string(), MAX_DEPTH).is_ok()
        );
        let over = nest(65);
        assert_eq!(check_value_depth(&over), Err(depth_error()));
        assert_eq!(
            json::check_depth(&over.to_string(), MAX_DEPTH),
            Err(json::JSONError::MaximumDepth(MAX_DEPTH))
        );
        let mut exact = Value::Array(Vec::new());
        for _ in 1..128 {
            exact = Value::Array(vec![exact]);
        }
        assert_eq!(check_value_depth(&exact), Ok(()));
        assert!(check_value_depth(&Value::Array(vec![exact])).is_err());
        assert_eq!(check_value_depth(&serde_json::json!("scalar")), Ok(()));
    }

    #[test]
    fn depth_limit_matches_sozai_json() {
        let at_limit = format!("{}{}", "[".repeat(128), "]".repeat(128));
        assert!(parse(&at_limit).is_ok());
        let over = format!("{}{}", "[".repeat(129), "]".repeat(129));
        assert_eq!(
            parse(&over),
            Err(TokenError::invalid(
                "JSON exceeds maximum nesting depth of 128"
            ))
        );
        // Brackets inside strings, escaped quotes included, do not count.
        let quoted = format!("[\"\\\"{}\"]", "[".repeat(200));
        assert!(parse(&quoted).is_ok());
    }

    #[test]
    fn duplicate_keys_keep_the_last_value() {
        assert_eq!(
            parse(r#"{"a":1,"a":2}"#).unwrap(),
            serde_json::json!({ "a": 2 })
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_trailing_text() {
        assert_eq!(to_utf8(vec![0xff]), Err(TokenError::InvalidUTF8));
        assert!(matches!(parse("{} x"), Err(TokenError::InvalidJSON(_))));
    }
}
