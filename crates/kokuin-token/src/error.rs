//! The error every fallible function in this crate returns.

use std::fmt;

/// A token, DID or document failure.
///
/// The variants follow the error classes `@kokuin/token` throws, so a caller (and the golden
/// tests) can match the TS category by [`TokenError::name`] and the TS text by [`fmt::Display`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// The signature does not verify against the issuer's key: `Error('Invalid signature')`.
    InvalidSignature,
    /// No method, resolver or registry entry turned the issuer into a usable key
    /// (`UnresolvableIssuerError`). Nothing was learned either way: a caller must fail closed and
    /// never read it as "checked and fine".
    UnresolvableIssuer(String),
    /// A DID method resolved the issuer, and the token named a key it does not have
    /// (`IssuerKeyNotFoundError`). Positive evidence that the token is bad.
    IssuerKeyNotFound(String),
    /// Bytes that are not UTF-8 where text is expected (a `TypeError` from `toUTF`).
    InvalidUTF8,
    /// A value of the wrong JSON type where TS dereferences it (a `TypeError`), such as a `null`
    /// header.
    InvalidType(String),
    /// Text that is not JSON (a `SyntaxError` from `JSON.parse`). The message is serde_json's,
    /// not the JavaScript engine's.
    InvalidJSON(String),
    /// A payload that fails the signed payload schema (`ValidationError`, an `AggregateError`).
    Validation(String),
    /// Any other failure: a plain `Error` carrying the TS message.
    Invalid(String),
}

impl TokenError {
    /// The JavaScript error name `@kokuin/token` reports for this failure.
    pub fn name(&self) -> &'static str {
        match self {
            Self::InvalidSignature | Self::Invalid(_) => "Error",
            Self::UnresolvableIssuer(_) => "UnresolvableIssuerError",
            Self::IssuerKeyNotFound(_) => "IssuerKeyNotFoundError",
            Self::InvalidUTF8 | Self::InvalidType(_) => "TypeError",
            Self::InvalidJSON(_) => "SyntaxError",
            Self::Validation(_) => "AggregateError",
        }
    }

    /// Whether the issuer could not be resolved (see [`TokenError::UnresolvableIssuer`]).
    pub fn is_unresolvable_issuer(&self) -> bool {
        matches!(self, Self::UnresolvableIssuer(_))
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("Invalid signature"),
            Self::InvalidUTF8 => f.write_str("The encoded data was not valid for encoding utf-8"),
            Self::UnresolvableIssuer(message)
            | Self::IssuerKeyNotFound(message)
            | Self::InvalidType(message)
            | Self::InvalidJSON(message)
            | Self::Validation(message)
            | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TokenError {}
