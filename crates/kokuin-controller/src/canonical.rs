//! Canonical bytes and digests, as `packages/controller/src/canonical.ts`.

use kokuin_token::multibase;
use serde_json::Value;
use sozai_codec::canonical;

/// Deepest nesting the canonicalizer encodes; the top-level value is depth 1 (`MAX_CANONICAL_DEPTH`).
pub const MAX_CANONICAL_DEPTH: usize = 64;

/// Whether the canonical encoder accepts `value` (`isCanonicalizable`).
///
/// A `serde_json::Value` holds no non-finite number and no non-plain object, so only the depth
/// bound remains. Walked with an explicit stack: input can nest far deeper than the native stack.
pub fn is_canonicalizable(value: &Value) -> bool {
    let mut stack = vec![(value, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_CANONICAL_DEPTH {
            return false;
        }
        match value {
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(map) => stack.extend(map.values().map(|item| (item, depth + 1))),
            _ => {}
        }
    }
    true
}

/// RFC 8785 canonical text, or `None` for a value [`is_canonicalizable`] refuses (`canonicalBytes`).
pub fn canonical_text(value: &Value) -> Option<String> {
    if !is_canonicalizable(value) {
        return None;
    }
    canonical::stringify(value).ok()
}

/// Self-addressing digest: multibase(multihash(canonical bytes)) (`digestOf`).
///
/// Every caller has checked the value is canonicalizable, where TS would throw otherwise; a value
/// that is not digests to the empty string, which names no event and no key.
pub fn digest_of(value: &Value) -> String {
    canonical_text(value)
        .and_then(|text| multibase::encode(&multibase::multihash_sha256(text.as_bytes())).ok())
        .unwrap_or_default()
}

/// [`digest_of`] a JSON string, as `digestOf(key)` reads an encoded key.
pub fn digest_of_str(text: &str) -> String {
    digest_of(&Value::String(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn nest(depth: usize) -> Value {
        (1..depth).fold(json!(0), |inner, _| json!([inner]))
    }

    #[test]
    fn depth_bound_matches_typescript() {
        assert!(is_canonicalizable(&nest(64)));
        assert!(!is_canonicalizable(&nest(65)));
    }
}
