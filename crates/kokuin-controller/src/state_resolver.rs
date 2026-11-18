//! Answers out of a folded view, as `packages/controller/src/state-resolver.ts`.

use std::collections::BTreeSet;

use kokuin_token::{
    AgreementAlgorithm, MemberQuery, ResolveIssuerHeader, ResolvedAgreementKey,
    ResolvedHistoricMember, ResolvedMember, ResolvedSigningKey, SignatureAlgorithm, normalize_did,
};
use serde_json::Value;

use crate::ControllerError;
use crate::events::key_target;
use crate::fold::{KeyState, MemberState};
use crate::js::number_string;
use crate::keys::{KeyAlgorithm, decode_key};
use crate::members::denial_targets_member;

/// The method segment of `did:kokuin:` (`DID_METHOD`).
pub const DID_METHOD: &str = "kokuin";
/// What every answer fails with while the epoch is saturated, before `: <did>`
/// (`EPOCH_SATURATED`).
pub const EPOCH_SATURATED: &str = "controller epoch is saturated";
/// What `resolveMember` refuses a member with that is not live (`MEMBER_NOT_EFFECTIVE`).
pub const MEMBER_NOT_EFFECTIVE: &str = "not an effective management member";
/// Historic membership refusals (`MEMBER_NOT_HISTORIC`).
pub const MEMBER_NOT_HISTORIC: &str = "not a historic management member";
/// What a token signed by a revoked key is refused with, before `: #<key>` (`KEY_REVOKED`).
pub const KEY_REVOKED: &str = "kid names a key the controller has revoked";

/// A folded log as every answer reads it (`FoldedView`): `states` for the historic key scan,
/// `head` for every live answer.
#[derive(Clone, Debug, PartialEq)]
pub struct FoldedView {
    /// One state per chain event.
    pub states: Vec<KeyState>,
    /// The last chain state merged with the current epoch.
    pub head: KeyState,
}

/// The `kid` fragment's body, or `None` when the header names no key (`keyFromKid`).
fn key_from_kid(did: &str, kid: Option<&Value>) -> Result<Option<String>, ControllerError> {
    match kid {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(kid)) => match kid.strip_prefix('#') {
            Some(key) => Ok(Some(key.to_owned())),
            None => Err(ControllerError::key_not_found(format!(
                "Controller {did} kid is not a key fragment: {kid}"
            ))),
        },
        // `kid.startsWith` on a non-string.
        Some(_) => Err(ControllerError::TypeError(
            "kid.startsWith is not a function".into(),
        )),
    }
}

fn first_key(did: &str, head: &KeyState) -> Result<String, ControllerError> {
    head.keys.first().cloned().ok_or_else(|| {
        ControllerError::key_not_found(format!("Controller {did} has no signing key"))
    })
}

/// The key `kid` names out of the head's key set alone (`headSigningKey`).
fn head_signing_key(
    did: &str,
    head: &KeyState,
    kid: Option<&Value>,
) -> Result<String, ControllerError> {
    let Some(key) = key_from_kid(did, kid)? else {
        return first_key(did, head);
    };
    if !head.keys.contains(&key) {
        return Err(ControllerError::key_not_found(format!(
            "Controller {did} kid names a key that is not current: #{key}"
        )));
    }
    Ok(key)
}

/// The key `kid` names out of every position of the current generation (`historicSigningKey`).
fn historic_signing_key(
    did: &str,
    view: &FoldedView,
    kid: Option<&Value>,
) -> Result<String, ControllerError> {
    let Some(key) = key_from_kid(did, kid)? else {
        return first_key(did, &view.head);
    };
    for state in view.states.iter().rev() {
        if state.generation != view.head.generation {
            break;
        }
        if state.keys.contains(&key) {
            return Ok(key);
        }
    }
    Err(ControllerError::key_not_found(format!(
        "Controller {did} kid names a key outside the current generation: #{key}"
    )))
}

/// The signing key `header` names; a revoked key answers neither question (`signingKeyFrom`).
pub fn signing_key_from(
    did: &str,
    view: &FoldedView,
    header: &ResolveIssuerHeader,
    historic: bool,
) -> Result<ResolvedSigningKey, ControllerError> {
    let head = &view.head;
    if head.keys.is_empty() {
        return Err(ControllerError::plain(format!(
            "Controller {did} has no signing key"
        )));
    }
    let kid = header.kid.as_ref();
    let selected = if historic {
        historic_signing_key(did, view, kid)?
    } else {
        head_signing_key(did, head, kid)?
    };
    let target = key_target(&selected);
    if head.deny.contains(&target) {
        return Err(ControllerError::key_not_found(format!(
            "Controller {did} {KEY_REVOKED}: {target}"
        )));
    }
    match decode_key(&selected).map_err(ControllerError::plain)? {
        (KeyAlgorithm::EdDSA, public_key) => Ok(ResolvedSigningKey {
            alg: SignatureAlgorithm::EdDSA,
            public_key,
        }),
        (alg, _) => Err(ControllerError::plain(format!(
            "Controller {did} signing key is not a signature algorithm: {}",
            alg.as_str()
        ))),
    }
}

/// The head's key agreement set, minus anything it has revoked (`agreementKeysFrom`).
pub fn agreement_keys_from(
    did: &str,
    head: &KeyState,
) -> Result<Vec<ResolvedAgreementKey>, ControllerError> {
    let mut keys = Vec::new();
    for value in &head.agreement {
        if head.deny.contains(&key_target(value)) {
            continue;
        }
        match decode_key(value).map_err(ControllerError::plain)? {
            (KeyAlgorithm::X25519, public_key) => keys.push(ResolvedAgreementKey {
                alg: AgreementAlgorithm::X25519,
                public_key,
            }),
            (alg, _) => {
                return Err(ControllerError::plain(format!(
                    "Controller {did} publishes an unsupported agreement key: {}",
                    alg.as_str()
                )));
            }
        }
    }
    Ok(keys)
}

/// The deny set a capability check reads: every raw entry and its canonical DID form
/// (`resolveDenySet`).
pub fn deny_set_from(head: &KeyState) -> BTreeSet<String> {
    let mut denied = BTreeSet::new();
    for entry in head.deny.iter() {
        denied.insert(entry.clone());
        denied.insert(normalize_did(entry));
    }
    denied
}

fn lease_seconds(lease: f64) -> u64 {
    // A lease is a non-negative safe integer on every path that admits a member.
    lease.max(0.0) as u64
}

fn ed25519_member(
    member: &MemberState,
    refuse: impl Fn(String) -> ControllerError,
) -> Result<ResolvedMember, ControllerError> {
    match decode_key(&member.entry.key).map_err(ControllerError::plain)? {
        (KeyAlgorithm::EdDSA, public_key) => Ok(ResolvedMember {
            key: ResolvedSigningKey {
                alg: SignatureAlgorithm::EdDSA,
                public_key,
            },
            lease: lease_seconds(member.entry.lease),
        }),
        (alg, _) => Err(refuse(format!(
            "pinned key is not Ed25519: {}",
            alg.as_str()
        ))),
    }
}

/// The key and lease the head pins for one live member of its generation (`memberFrom`).
pub fn member_from(
    did: &str,
    head: &KeyState,
    query: &MemberQuery,
) -> Result<ResolvedMember, ControllerError> {
    let refuse = |why: String| {
        ControllerError::key_not_found(format!(
            "Controller {did} {} is {MEMBER_NOT_EFFECTIVE}: {why}",
            query.did
        ))
    };
    let generation = query.generation as f64;
    if generation != head.generation {
        return Err(refuse(format!(
            "generation {} is not the current {}",
            number_string(generation),
            number_string(head.generation)
        )));
    }
    let Some(member) = head.members.get(&query.add) else {
        return Err(refuse(format!("no member was added by {}", query.add)));
    };
    if !member.effective {
        return Err(refuse(
            if member.removed { "removed" } else { "denied" }.into(),
        ));
    }
    if normalize_did(&member.entry.did) != normalize_did(&query.did) {
        return Err(refuse(format!("incarnation {} is another DID", query.add)));
    }
    ed25519_member(member, refuse)
}

/// Incarnation evidence within the current generation, never proof of signing time
/// (`historicMemberFrom`).
pub fn historic_member_from(
    did: &str,
    view: &FoldedView,
    query: &MemberQuery,
) -> Result<ResolvedHistoricMember, ControllerError> {
    let refuse = || {
        ControllerError::key_not_found(format!(
            "Controller {did} {} is {MEMBER_NOT_HISTORIC}",
            query.did
        ))
    };
    let generation = query.generation as f64;
    if generation != view.head.generation {
        return Err(refuse());
    }
    let current = view.head.members.get(&query.add);
    if current.is_some_and(|member| !member.removed && !member.effective) {
        return Err(refuse());
    }
    let historic = view.states.iter().rev().find(|state| {
        state.generation == generation
            && (state.members.contains_key(&query.add) || state.tombstones.contains_key(&query.add))
    });
    let tombstone = view
        .head
        .tombstones
        .get(&query.add)
        .or_else(|| historic.and_then(|state| state.tombstones.get(&query.add)));
    let member = match (current, tombstone) {
        (Some(current), _) => current.clone(),
        (None, Some(entry)) => MemberState {
            entry: entry.clone(),
            removed: true,
            effective: false,
        },
        (None, None) => match historic.and_then(|state| state.members.get(&query.add)) {
            Some(member) => member.clone(),
            None => return Err(refuse()),
        },
    };
    if !member.removed
        && view
            .head
            .deny
            .iter()
            .any(|entry| denial_targets_member(entry, &member.entry))
    {
        return Err(refuse());
    }
    if !member.removed && !member.effective {
        return Err(refuse());
    }
    if normalize_did(&member.entry.did) != normalize_did(&query.did) {
        return Err(refuse());
    }
    let resolved = ed25519_member(&member, |_| refuse()).map_err(|_| refuse())?;
    Ok(ResolvedHistoricMember {
        member: resolved,
        removed: !current.is_some_and(|member| member.effective),
    })
}
