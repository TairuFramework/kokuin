#![forbid(unsafe_code)]
//! A Rust port of `@kokuin/token`: compact (JWS) tokens signed with Ed25519 or ES256, and issuer
//! resolution for `did:key`, `did:peer:4` and injected DID methods ([`DIDMethodResolver`], which
//! `did:kokuin:` implements in the controller crate).
//!
//! It matches the TS package byte for byte on the golden vectors in
//! `packages/token/test/golden/tokens.json`.

mod cache;
pub mod did_key;
mod error;
mod json;
mod method;
pub mod multibase;
pub mod peer4;
mod resolve;
mod schema;
mod token;

pub use cache::{DEFAULT_MAX_ENTRIES, DIDCache, InMemoryDIDCache};
pub use error::TokenError;
pub use method::{
    AgreementAlgorithm, DIDMethodResolver, MemberQuery, MethodError, ResolveIssuerHeader,
    ResolvedAgreementKey, ResolvedHistoricMember, ResolvedMember, ResolvedSigningKey,
    find_method_resolver,
};
pub use resolve::{
    DIDResolver, ResolveIssuerParams, ResolvedIssuer, normalize_did, resolve_issuer,
};
pub use schema::validate_did_doc;
pub use token::{
    SignError, SignedToken, TokenSigner, VerifiedToken, VerifyOptions, decode_signed_token,
    sign_token, stringify_token, verify_token,
};

/// A token signature algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// Ed25519.
    EdDSA,
    /// ECDSA over P-256 with SHA-256.
    ES256,
}

impl SignatureAlgorithm {
    /// The JOSE name: `EdDSA` or `ES256`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::ES256 => "ES256",
        }
    }

    /// The algorithm a JOSE name denotes, if supported.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "EdDSA" => Some(Self::EdDSA),
            "ES256" => Some(Self::ES256),
            _ => None,
        }
    }
}

impl From<SignatureAlgorithm> for kokuin_crypto::Algorithm {
    fn from(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::EdDSA => Self::Ed25519,
            SignatureAlgorithm::ES256 => Self::Es256,
        }
    }
}
