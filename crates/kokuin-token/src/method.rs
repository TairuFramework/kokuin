//! Injected DID method resolution, as `packages/token/src/method.ts`.
//!
//! Methods whose document is a projection of an event log (`did:kokuin:`) cannot be resolved from
//! the identifier alone, and the controller crate depends on this one for signing. Injecting the
//! resolver keeps the dependency one-way.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::SignatureAlgorithm;

/// The header fields issuer resolution reads. `kid` is kept as the JSON value the header carried:
/// TS compares it with `===`, so a non-string `kid` never matches a fragment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolveIssuerHeader {
    /// The header's `kid`, absent when missing or `null`.
    pub kid: Option<Value>,
}

/// The signing key a DID method resolved for an issuer and header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSigningKey {
    /// The key's algorithm.
    pub alg: SignatureAlgorithm,
    /// The raw public key.
    pub public_key: Vec<u8>,
}

/// The member of a subject's management tier being asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberQuery {
    /// The member's DID.
    pub did: String,
    /// The digest of the event that added it.
    pub add: String,
    /// Its generation.
    pub generation: u64,
}

/// The key a subject's log pins for a member, and when that membership lapses (unix seconds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMember {
    /// The member's signing key.
    pub key: ResolvedSigningKey,
    /// When the membership lapses, in unix seconds.
    pub lease: u64,
}

/// Historic incarnation evidence, marked removed unless the incarnation is effective in the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHistoricMember {
    /// The member and its lease.
    pub member: ResolvedMember,
    /// False only for an incarnation present and effective in the head.
    pub removed: bool,
}

/// A key agreement algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgreementAlgorithm {
    /// X25519.
    X25519,
}

/// A key agreement key a DID method resolved for a recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAgreementKey {
    /// The key's algorithm.
    pub alg: AgreementAlgorithm,
    /// The raw public key.
    pub public_key: Vec<u8>,
}

/// Why a DID method could not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodError {
    /// The method resolved the DID, and it has no such key (`IssuerKeyNotFoundError`). Passed
    /// through as positive evidence that the token is bad.
    IssuerKeyNotFound(String),
    /// Anything else: verification re-types it as an unresolvable issuer, message kept.
    Unresolvable(String),
}

/// A DID method resolution can route `iss` through without linking its implementation
/// (TS `DIDMethodResolver`).
///
/// Optional members return `None` when the method does not implement them; each documents what
/// that absence means. Resolution is synchronous: implementations read local state.
pub trait DIDMethodResolver {
    /// The method segment, without `did:` and without the trailing colon, e.g. `kokuin`.
    fn method(&self) -> &str;

    /// The key this subject signs with **now**: its head keys, nothing rotated away.
    fn resolve(
        &self,
        did: &str,
        header: &ResolveIssuerHeader,
    ) -> Result<ResolvedSigningKey, MethodError>;

    /// The key this subject signed with **at some point in the past**, for verifying an artefact
    /// it has already issued, never for authenticating a live signer. Absence fails closed: a
    /// historic resolution refuses rather than asking [`DIDMethodResolver::resolve`].
    fn resolve_historic(
        &self,
        _did: &str,
        _header: &ResolveIssuerHeader,
    ) -> Option<Result<ResolvedSigningKey, MethodError>> {
        None
    }

    /// The recipient's key agreement keys, in the method's order. Absent for a method with no
    /// key agreement.
    fn resolve_agreement_key(
        &self,
        _did: &str,
    ) -> Option<Result<Vec<ResolvedAgreementKey>, MethodError>> {
        None
    }

    /// What this subject has revoked, answered for now. Match entries, never enumerate them.
    /// Absence **disables enforcement** for every subject of this method, so a method that can
    /// revoke must implement it, wrappers included.
    fn resolve_deny_set(&self, _did: &str) -> Option<Result<BTreeSet<String>, MethodError>> {
        None
    }

    /// The key and lease the subject's log holds for one member, answered for now. Absence fails
    /// closed: every member-issued grant is refused.
    fn resolve_member(
        &self,
        _subject: &str,
        _member: &MemberQuery,
    ) -> Option<Result<ResolvedMember, MethodError>> {
        None
    }

    /// Incarnation and generation evidence for a member, never signing time. Absence fails
    /// closed.
    fn resolve_member_historic(
        &self,
        _subject: &str,
        _member: &MemberQuery,
    ) -> Option<Result<ResolvedHistoricMember, MethodError>> {
        None
    }
}

/// The method registered for a DID's method segment (`findMethodResolver`). A malformed DID
/// yields `None`.
pub fn find_method_resolver<'a>(
    registry: &[&'a dyn DIDMethodResolver],
    did: &str,
) -> Option<&'a dyn DIDMethodResolver> {
    let mut parts = did.split(':');
    let (Some("did"), Some(method), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    registry
        .iter()
        .copied()
        .find(|resolver| resolver.method() == method)
}
