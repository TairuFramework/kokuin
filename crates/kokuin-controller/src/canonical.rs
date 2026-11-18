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

/// Self-addressing digest: multibase(multihash(canonical bytes)), or `None` for a value
/// [`is_canonicalizable`] refuses (`digestOf`, which throws there).
pub fn try_digest_of(value: &Value) -> Option<String> {
    canonical_text(value)
        .and_then(|text| multibase::encode(&multibase::multihash_sha256(text.as_bytes())).ok())
}

/// [`try_digest_of`] for a value the caller has already checked is canonicalizable.
///
/// Every call site checks first, where TS would throw otherwise. Should one ever reach it with a
/// value that is not, it digests to the empty string, which names no event and no key.
pub(crate) fn digest_of(value: &Value) -> String {
    let digest = try_digest_of(value);
    debug_assert!(
        digest.is_some(),
        "digest_of called on an uncanonicalizable value"
    );
    digest.unwrap_or_default()
}

/// Shared JSON input bound; retained as part of the controller's public API.
pub use sozai_codec::json::MAX_DEPTH as MAX_INPUT_DEPTH;
pub(crate) use sozai_codec::json::dismantle;

/// Bound caller-provided JSON before any recursive processing.
pub(crate) fn within_input_depth(value: &Value) -> bool {
    sozai_codec::json::check_value_depth(value, MAX_INPUT_DEPTH)
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
        // Not `json!([inner])`: it serializes the interpolated value, recursively.
        (1..depth).fold(json!(0), |inner, _| Value::Array(vec![inner]))
    }

    #[test]
    fn depth_bound_matches_typescript() {
        assert!(is_canonicalizable(&nest(64)));
        assert!(!is_canonicalizable(&nest(65)));
    }

    #[test]
    fn input_depth_counts_containers_and_dismantles_deep_values() {
        // `nest(n)` is n - 1 arrays around a number.
        assert!(within_input_depth(&nest(MAX_INPUT_DEPTH + 1)));
        assert!(!within_input_depth(&nest(MAX_INPUT_DEPTH + 2)));
        let deep = nest(200_000);
        assert!(!within_input_depth(&deep));
        dismantle(deep);
    }
}
