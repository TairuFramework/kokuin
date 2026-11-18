//! JSON text decoding as `@sozai/codec` `b64uToJSON` and `JSON.parse` do it.

use serde_core::Deserialize;
use serde_json::Value;
use sozai_codec::base64url;

use crate::TokenError;

/// `@sozai/json` `parse` rejects deeper nesting than this before parsing.
const MAX_DEPTH: usize = 128;

/// Decode UTF-8 strictly, as `toUTF` does. A leading BOM is kept, not stripped.
pub(crate) fn to_utf8(bytes: Vec<u8>) -> Result<String, TokenError> {
    String::from_utf8(bytes).map_err(|_| TokenError::InvalidUTF8)
}

/// `JSON.parse`: no nesting limit beyond what the caller bounds.
///
/// Diverges from JavaScript on one input class: a string escape encoding a lone UTF-16
/// surrogate (`"\ud800"`) fails here, since no Rust string can hold it.
pub(crate) fn parse_unbounded(text: &str) -> Result<Value, TokenError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    let value = Value::deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value))
        .map_err(|error| TokenError::InvalidJSON(error.to_string()))?;
    Ok(value)
}

/// `@sozai/json` `parse` with its default options: a nesting check, then `JSON.parse`.
pub(crate) fn parse(text: &str) -> Result<Value, TokenError> {
    check_depth(text)?;
    parse_unbounded(text)
}

/// The same scan as `checkDepth` in `@sozai/json`: brackets outside strings, counted before the
/// text is parsed, so an over-deep document is refused even when it is not valid JSON.
fn check_depth(text: &str) -> Result<(), TokenError> {
    let mut depth: i64 = 0;
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            match byte {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH as i64 {
                    return Err(TokenError::invalid(format!(
                        "JSON exceeds maximum nesting depth of {MAX_DEPTH}"
                    )));
                }
            }
            b'}' | b']' => depth -= 1,
            _ => {}
        }
    }
    Ok(())
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
