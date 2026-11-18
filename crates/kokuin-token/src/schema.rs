//! The two JSON schemas verification applies: `signedPayloadSchema` (`schemas.ts`) and
//! `didDocSchema` (`peer4.ts`).

use serde_json::{Map, Value};

use crate::TokenError;

fn is_string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

/// Validate a signed token payload, failing as `assertType(validateSignedPayload, payload)`.
///
/// The message names the first issue the way `@sozai/schema` reports Ajv's first error: the root
/// type, then the `required` keyword, then each property in schema order.
pub(crate) fn validate_signed_payload(payload: &Value) -> Result<&Map<String, Value>, TokenError> {
    let fail = |path: &str, keyword: &str| {
        TokenError::Validation(format!(
            "Validation failed for schema object ({path} {keyword})"
        ))
    };
    let Some(object) = payload.as_object() else {
        return Err(fail("/", "type"));
    };
    if !object.contains_key("iss") {
        return Err(fail("/", "required"));
    }
    for (key, check) in [
        ("iss", Value::is_string as fn(&Value) -> bool),
        ("sub", Value::is_string),
        ("aud", Value::is_string),
        ("cap", |value: &Value| {
            value.is_string() || is_string_array(value)
        }),
        ("exp", Value::is_number),
        ("nbf", Value::is_number),
        ("iat", Value::is_number),
    ] {
        if let Some(value) = object.get(key)
            && !check(value)
        {
            // `cap` is an `anyOf`: Ajv reports its first branch's `type` error before `anyOf`.
            return Err(fail(&format!("/{key}"), "type"));
        }
    }
    Ok(object)
}

fn is_verification_method(value: &Value) -> bool {
    value.as_object().is_some_and(|method| {
        ["id", "type", "publicKeyMultibase"]
            .iter()
            .all(|key| method.get(*key).is_some_and(Value::is_string))
    })
}

/// Whether a value conforms to the DID document schema used inside did:peer:4
/// (`validateDIDDoc`).
pub fn validate_did_doc(value: &Value) -> bool {
    let Some(doc) = value.as_object() else {
        return false;
    };
    let context_ok = doc
        .get("@context")
        .is_none_or(|context| context.is_string() || is_string_array(context));
    let methods_ok = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| !methods.is_empty() && methods.iter().all(is_verification_method));
    let relationships_ok = ["authentication", "keyAgreement", "assertionMethod"]
        .iter()
        .all(|key| doc.get(*key).is_none_or(is_string_array));
    context_ok && methods_ok && relationships_ok
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn message(payload: Value) -> String {
        validate_signed_payload(&payload).unwrap_err().to_string()
    }

    #[test]
    fn signed_payload_first_issue() {
        assert_eq!(
            message(json!([])),
            "Validation failed for schema object (/ type)"
        );
        assert_eq!(
            message(json!({ "sub": 1 })),
            "Validation failed for schema object (/ required)"
        );
        assert_eq!(
            message(json!({ "iss": "a", "cap": [1] })),
            "Validation failed for schema object (/cap type)"
        );
        assert_eq!(
            message(json!({ "iss": "a", "exp": "1" })),
            "Validation failed for schema object (/exp type)"
        );
        assert!(validate_signed_payload(&json!({ "iss": "a", "cap": ["x"], "exp": 1.5 })).is_ok());
    }

    #[test]
    fn did_doc_schema() {
        let method = json!({ "id": "#a", "type": "Multikey", "publicKeyMultibase": "z" });
        assert!(validate_did_doc(&json!({ "verificationMethod": [method] })));
        assert!(!validate_did_doc(&json!({ "verificationMethod": [] })));
        assert!(!validate_did_doc(
            &json!({ "verificationMethod": [method], "authentication": null })
        ));
        assert!(!validate_did_doc(
            &json!({ "verificationMethod": [method], "@context": [1] })
        ));
        assert!(validate_did_doc(
            &json!({ "verificationMethod": [method], "@context": "x", "extra": {} })
        ));
    }
}
