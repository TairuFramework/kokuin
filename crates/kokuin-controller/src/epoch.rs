//! Epoch events and the epoch merge, as `packages/controller/src/epoch-events.ts` (the verifying
//! half) and `packages/controller/src/epoch.ts`.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;
use sozai_codec::compare_utf16;

use crate::canonical::{canonical_text, digest_of};
use crate::events::{MemberEntry, key_from_target, verify_signatures};
use crate::fold::{KeyState, MemberState};
use crate::js::{is_safe_integer, prop, strict_eq_number};
use crate::limits::{
    MAX_EPOCH_EVENTS, MAX_EVENT_BYTES, MAX_EVENT_PARENTS, MAX_EVENT_SIGNATURES,
    MAX_FAILED_SIGNATURES,
};
use crate::log::snapshot_entries;
use crate::members::{RootKeySet, denial_targets_member, is_root_key, member_carries_key};
use crate::ordered::{OrderedMap, OrderedSet};

/// A member-signed add (`ADD_NOT_ROOT`).
pub const ADD_NOT_ROOT: &str = "only root may add a member";
/// An add pinning a root key (`ADD_KEY_IS_ROOT`).
pub const ADD_KEY_IS_ROOT: &str = "member key is a root key";
/// An add whose DID does not carry exactly its pin (`ADD_DID_MISMATCH`).
pub const ADD_DID_MISMATCH: &str = "member DID does not carry its key";
/// An add a denial in its causal past targets (`ADD_KEY_DENIED`).
pub const ADD_KEY_DENIED: &str = "member is denied in the causal state";
/// An add of a key an effective member already pins (`ADD_KEY_ALREADY_MEMBER`).
pub const ADD_KEY_ALREADY_MEMBER: &str = "member key is already an effective member";
/// A member renewing itself (`SELF_RENEW`).
pub const SELF_RENEW: &str = "a member may not renew itself";
/// A member removing itself (`SELF_REMOVE`).
pub const SELF_REMOVE: &str = "a member may not remove itself";
/// A renew or remove naming an unknown add (`UNKNOWN_MEMBER`).
pub const UNKNOWN_MEMBER: &str = "target is not a member of the causal state";
/// A member revoke targeting a member (`MEMBER_REVOKES_MEMBER`).
pub const MEMBER_REVOKES_MEMBER: &str = "a member may not revoke a member";
/// A revoke denying a published root key (`REVOKE_NAMES_ROOT_KEY`).
pub const REVOKE_NAMES_ROOT_KEY: &str = "revoke targets a key the chain publishes";
/// A presentation whose failing signatures pass the limit (`TOO_MANY_FAILED_SIGNATURES`).
pub const TOO_MANY_FAILED_SIGNATURES: &str =
    "controller log exceeds request limits: too many signatures fail to verify";
/// A fold-loop index off the state list: a broken invariant (`INTERNAL_FOLD_INVARIANT`).
pub const INTERNAL_FOLD_INVARIANT: &str = "internal fold invariant: missing event or prior state";

/// Epoch limits. Lowering `max_epoch_events` is test-only in TS (`EpochLimits`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochLimits {
    /// Applied events past which the epoch is saturated.
    pub max_epoch_events: usize,
}

impl Default for EpochLimits {
    fn default() -> Self {
        Self {
            max_epoch_events: MAX_EPOCH_EVENTS,
        }
    }
}

/// [`fold_epoch_detailed`]'s answer (`FoldEpochDetail`).
#[derive(Clone, Debug, PartialEq)]
pub struct EpochDetail {
    /// The anchor merged with the epoch.
    pub head: KeyState,
    /// Applied digests, parents first, ties by ascending digest.
    pub applied: Vec<String>,
    /// Well-formed events whose parents never all applied.
    pub pending: usize,
    /// Refusals, counted by distinct event.
    pub rejected: usize,
    /// Why each refused or pending event did not apply, by digest.
    pub reasons: BTreeMap<String, String>,
    /// The copy that verified, for each applied digest.
    pub authentic: HashMap<String, Value>,
}

fn is_string_list(value: Option<&Value>, max: usize) -> Option<&Vec<Value>> {
    value
        .and_then(Value::as_array)
        .filter(|items| items.len() <= max && items.iter().all(Value::is_string))
}

fn is_seconds(value: Option<&Value>) -> bool {
    is_safe_integer(value) && value.and_then(Value::as_f64).is_some_and(|n| n >= 0.0)
}

fn is_string(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(_)))
}

fn has_type_fields(event: &Value) -> bool {
    let field = |key| prop(event, key);
    match field("t").and_then(Value::as_str) {
        Some("add") => {
            is_string(field("did")) && is_string(field("key")) && is_seconds(field("lease"))
        }
        Some("ren") => is_string(field("add")) && is_seconds(field("lease")),
        Some("rmv") => is_string(field("add")),
        Some("rev") => is_string(field("x")),
        _ => false,
    }
}

/// Whether `value` has the shape of a signed epoch event (`isEpochEventShape`).
pub fn is_epoch_event_shape(value: &Value) -> bool {
    let (Some(Value::Object(_)), Some(event @ Value::Object(_))) =
        (Some(value), prop(value, "event"))
    else {
        return false;
    };
    match is_string_list(prop(value, "sigs"), MAX_EVENT_SIGNATURES) {
        Some(sigs) if !sigs.is_empty() => {}
        _ => return false,
    }
    if prop(value, "recoveryKey").is_some() {
        return false;
    }
    if !strict_eq_number(prop(event, "v"), 1.0)
        || !matches!(
            prop(event, "t").and_then(Value::as_str),
            Some("add" | "ren" | "rmv" | "rev")
        )
        || !is_string(prop(event, "i"))
        || !is_seconds(prop(event, "g"))
        || !is_string(prop(event, "e"))
        || prop(event, "crit") != Some(&Value::Bool(true))
        || !matches!(prop(event, "by"), None | Some(Value::String(_)))
    {
        return false;
    }
    let Some(parents) = is_string_list(prop(event, "p"), MAX_EVENT_PARENTS) else {
        return false;
    };
    let distinct: HashSet<&str> = parents.iter().filter_map(Value::as_str).collect();
    if parents.is_empty() || distinct.len() != parents.len() {
        return false;
    }
    if !has_type_fields(event) {
        return false;
    }
    canonical_text(event).is_some_and(|text| text.len() <= MAX_EVENT_BYTES)
}

/// Who an epoch signature is checked against (`EpochSignatureSigner`).
enum EpochSigner<'a> {
    Root(&'a [String]),
    Member(&'a str),
}

/// Whether `signed` verifies under `signer`, the kind agreeing with `by` (`verifyEpochSignature`).
fn verify_epoch_signature(signed: &Value, signer: &EpochSigner<'_>) -> bool {
    let (Some(event @ Value::Object(_)), Some(Value::Array(sigs))) =
        (prop(signed, "event"), prop(signed, "sigs"))
    else {
        return false;
    };
    if sigs.len() > MAX_EVENT_SIGNATURES {
        return false;
    }
    match signer {
        EpochSigner::Root(keys) => {
            prop(event, "by").is_none() && verify_signatures(event, sigs, keys)
        }
        EpochSigner::Member(key) => {
            sigs.len() == 1
                && is_string(prop(event, "by"))
                && verify_signatures(event, sigs, &[(*key).to_owned()])
        }
    }
}

/// What one epoch accumulates: a join-semilattice (`EpochState`).
#[derive(Clone, Default)]
struct EpochState {
    added: OrderedMap<MemberEntry>,
    removed: OrderedSet,
    leases: HashMap<String, f64>,
    deny: OrderedSet,
}

impl EpochState {
    /// `self` becomes the join of itself and `other` (`joinInto`).
    fn join(&mut self, other: &EpochState) {
        for (add, entry) in other.added.iter() {
            self.added.insert(add.clone(), entry.clone());
        }
        for add in other.removed.iter() {
            self.removed.insert(add.clone());
        }
        for (add, &lease) in &other.leases {
            let current = self.leases.get(add);
            if current.is_none_or(|&current| lease > current) {
                self.leases.insert(add.clone(), lease);
            }
        }
        for entry in other.deny.iter() {
            self.deny.insert(entry.clone());
        }
    }

    fn of_anchor(anchor: &KeyState) -> Self {
        let mut state = Self::default();
        for member in anchor.members.values() {
            state
                .added
                .insert(member.entry.add.clone(), member.entry.clone());
            if member.removed {
                state.removed.insert(member.entry.add.clone());
            }
        }
        for entry in anchor.deny.iter() {
            state.deny.insert(entry.clone());
        }
        state
    }

    fn is_effective(&self, member: &MemberEntry) -> bool {
        !self.removed.contains(&member.add) && !is_denied(&self.deny, member)
    }
}

fn is_denied(deny: &OrderedSet, member: &MemberEntry) -> bool {
    deny.iter()
        .any(|entry| denial_targets_member(entry, member))
}

struct Candidate {
    digest: String,
    event: Value,
    copies: Vec<Value>,
    trusted: Option<Value>,
    authentic: Option<Value>,
}

/// Among the copies that verify, the one whose signature list sorts first (`canonicalCopy`).
fn canonical_copy(
    copies: &[Value],
    verifies: impl Fn(&Value) -> bool,
    failed: &mut usize,
) -> Option<Value> {
    let mut distinct: HashMap<String, &Value> = HashMap::new();
    for copy in copies {
        let key =
            serde_json::to_string(prop(copy, "sigs").unwrap_or(&Value::Null)).unwrap_or_default();
        distinct.entry(key).or_insert(copy);
    }
    let mut keys: Vec<&String> = distinct.keys().collect();
    keys.sort_by(|a, b| compare_utf16(a, b));
    for key in keys {
        let copy = distinct[key];
        if verifies(copy) {
            return Some(copy.clone());
        }
        *failed += prop(copy, "sigs")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if *failed > MAX_FAILED_SIGNATURES {
            return None;
        }
    }
    None
}

fn str_field<'a>(event: &'a Value, key: &str) -> &'a str {
    prop(event, key).and_then(Value::as_str).unwrap_or_default()
}

fn num_field(event: &Value, key: &str) -> f64 {
    prop(event, key).and_then(Value::as_f64).unwrap_or_default()
}

/// Judge `candidate` against the state its parents established: its own effect, or the reason it
/// is refused (`evaluate`).
fn evaluate(
    candidate: &mut Candidate,
    causal: &EpochState,
    anchor: &KeyState,
    roots: &RootKeySet,
    failed: &mut usize,
) -> Result<EpochState, &'static str> {
    let event = &candidate.event;
    let mut authenticate = |signer: EpochSigner<'_>| {
        candidate.trusted.clone().or_else(|| {
            canonical_copy(
                &candidate.copies,
                |copy| verify_epoch_signature(copy, &signer),
                failed,
            )
        })
    };
    let signer: Option<MemberEntry> = match prop(event, "by").and_then(Value::as_str) {
        None => {
            candidate.authentic = authenticate(EpochSigner::Root(&anchor.keys));
            if candidate.authentic.is_none() {
                return Err("invalid root signature");
            }
            None
        }
        Some(by) => {
            let Some(member) = causal.added.get(by) else {
                return Err("signer is not a member of the causal state");
            };
            if causal.removed.contains(by) {
                return Err("signer was removed in the causal state");
            }
            if is_denied(&causal.deny, member) {
                return Err("signer is denied in the causal state");
            }
            candidate.authentic = authenticate(EpochSigner::Member(&member.key));
            if candidate.authentic.is_none() {
                return Err("invalid member signature");
            }
            Some(member.clone())
        }
    };

    let event = &candidate.event;
    let mut effect = EpochState::default();
    match str_field(event, "t") {
        "rev" => {
            let target = str_field(event, "x");
            if signer.is_some()
                && causal
                    .added
                    .values()
                    .any(|member| denial_targets_member(target, member))
            {
                return Err(MEMBER_REVOKES_MEMBER);
            }
            if key_from_target(target).is_some_and(|key| {
                anchor.keys.iter().any(|k| k == key) || anchor.agreement.iter().any(|k| k == key)
            }) {
                return Err(REVOKE_NAMES_ROOT_KEY);
            }
            effect.deny.insert(target);
            Ok(effect)
        }
        "add" => {
            if signer.is_some() {
                return Err(ADD_NOT_ROOT);
            }
            let entry = MemberEntry {
                did: str_field(event, "did").to_owned(),
                key: str_field(event, "key").to_owned(),
                add: candidate.digest.clone(),
                lease: num_field(event, "lease"),
            };
            if !member_carries_key(&entry.did, &entry.key) {
                return Err(ADD_DID_MISMATCH);
            }
            if is_root_key(&entry.key, roots) {
                return Err(ADD_KEY_IS_ROOT);
            }
            if is_denied(&causal.deny, &entry) {
                return Err(ADD_KEY_DENIED);
            }
            if causal
                .added
                .values()
                .any(|member| member.key == entry.key && causal.is_effective(member))
            {
                return Err(ADD_KEY_ALREADY_MEMBER);
            }
            effect.added.insert(candidate.digest.clone(), entry);
            Ok(effect)
        }
        t @ ("ren" | "rmv") => {
            let add = str_field(event, "add");
            let Some(target) = causal.added.get(add) else {
                return Err(UNKNOWN_MEMBER);
            };
            if signer.is_some_and(|signer| signer.key == target.key) {
                return Err(if t == "ren" { SELF_RENEW } else { SELF_REMOVE });
            }
            if t == "ren" {
                effect
                    .leases
                    .insert(add.to_owned(), num_field(event, "lease"));
            } else {
                effect.removed.insert(add);
            }
            Ok(effect)
        }
        _ => Err("unknown epoch event type"),
    }
}

/// Merge the current epoch into the chain's last state (`foldEpochDetailed`). Invalid entries are
/// counted and dropped; the one refusal is the failed-signature request limit.
pub fn fold_epoch_detailed(
    did: &str,
    chain_states: &[KeyState],
    events: &[Value],
    trusted: Option<&[Value]>,
    limits: EpochLimits,
) -> Result<EpochDetail, String> {
    let Some(anchor) = chain_states.last() else {
        return Err(INTERNAL_FOLD_INVARIANT.into());
    };
    let events = snapshot_entries(events);
    let mut reasons: BTreeMap<String, String> = BTreeMap::new();
    let mut rejected = 0usize;

    let chain_digests: HashSet<&str> = chain_states.iter().map(|s| s.digest.as_str()).collect();
    let mut root_keys = HashSet::new();
    let mut commitments = HashSet::new();
    for state in chain_states
        .iter()
        .filter(|state| state.generation == anchor.generation)
    {
        root_keys.extend(state.keys.iter().chain(&state.agreement).cloned());
        commitments.extend(state.next.iter().cloned());
    }
    let roots = RootKeySet {
        keys: root_keys,
        commitments,
        recovery: anchor.recovery.clone(),
    };

    let refusal = |event: &Value| -> Option<&'static str> {
        if prop(event, "i").and_then(Value::as_str) != Some(did) {
            return Some("event names a different controller");
        }
        if !strict_eq_number(prop(event, "g"), anchor.generation) {
            return Some("event names a different generation");
        }
        None
    };

    // 1. Triage: memory first, then the presentation.
    let mut candidates: OrderedMap<Candidate> = OrderedMap::new();
    let mut other_epochs: HashSet<String> = HashSet::new();
    let mut counted: HashSet<String> = HashSet::new();
    for entry in snapshot_entries(trusted.unwrap_or_default()) {
        if !is_epoch_event_shape(&entry) {
            continue;
        }
        let event = prop(&entry, "event").cloned().unwrap_or(Value::Null);
        if str_field(&event, "e") != anchor.epoch || refusal(&event).is_some() {
            continue;
        }
        let digest = digest_of(&event);
        if !candidates.contains_key(&digest) {
            candidates.insert(
                digest.clone(),
                Candidate {
                    digest,
                    event,
                    copies: vec![entry.clone()],
                    trusted: Some(entry),
                    authentic: None,
                },
            );
        }
    }
    for entry in events {
        if !is_epoch_event_shape(&entry) {
            rejected += 1;
            continue;
        }
        let event = prop(&entry, "event").cloned().unwrap_or(Value::Null);
        let digest = digest_of(&event);
        if str_field(&event, "e") != anchor.epoch {
            other_epochs.insert(digest);
            continue;
        }
        if let Some(reason) = refusal(&event) {
            reasons.insert(digest.clone(), reason.into());
            if counted.insert(digest) {
                rejected += 1;
            }
            continue;
        }
        match candidates.get_mut(&digest) {
            None => candidates.insert(
                digest.clone(),
                Candidate {
                    digest,
                    event,
                    copies: vec![entry],
                    trusted: None,
                    authentic: None,
                },
            ),
            Some(existing) => {
                if existing.trusted.is_none() {
                    existing.copies.push(entry);
                }
            }
        }
    }

    let parents_of = |candidate: &Candidate| -> Vec<String> {
        prop(&candidate.event, "p")
            .and_then(Value::as_array)
            .map(|parents| {
                parents
                    .iter()
                    .filter_map(|parent| parent.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };

    // Parents: a cross-epoch parent refuses the child, judged before any edge is registered.
    let cross_epoch: Vec<String> = candidates
        .values()
        .filter(|candidate| {
            parents_of(candidate).iter().any(|parent| {
                *parent != anchor.epoch
                    && !candidates.contains_key(parent)
                    && (other_epochs.contains(parent) || chain_digests.contains(parent.as_str()))
            })
        })
        .map(|candidate| candidate.digest.clone())
        .collect();
    let mut live: OrderedMap<Candidate> = OrderedMap::new();
    let cross: HashSet<&String> = cross_epoch.iter().collect();
    for (digest, candidate) in candidates.into_entries() {
        if cross.contains(&digest) {
            reasons.insert(digest, "event lists a parent outside its epoch".into());
            rejected += 1;
        } else {
            live.insert(digest, candidate);
        }
    }
    let mut candidates = live;

    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut waiting: HashMap<String, usize> = HashMap::new();
    let mut ready: Vec<String> = Vec::new();
    for candidate in candidates.values() {
        let mut waits = 0;
        for parent in parents_of(candidate) {
            if parent == anchor.epoch {
                continue;
            }
            waits += 1;
            if candidates.contains_key(&parent) {
                children
                    .entry(parent)
                    .or_default()
                    .push(candidate.digest.clone());
            }
        }
        waiting.insert(candidate.digest.clone(), waits);
        if waits == 0 {
            insert_sorted(&mut ready, candidate.digest.clone());
        }
    }

    // Kahn's algorithm, smallest ready digest first.
    let anchor_after = EpochState::of_anchor(anchor);
    let mut after: HashMap<String, EpochState> = HashMap::new();
    let mut unread: HashMap<String, usize> = HashMap::new();
    let mut applied: Vec<String> = Vec::new();
    let mut authentic: HashMap<String, Value> = HashMap::new();
    let mut union = anchor_after.clone();
    let mut failed = 0usize;
    let mut evaluated = 0usize;

    while !ready.is_empty() {
        let digest = ready.remove(0);
        let Some(candidate) = candidates.get_mut(&digest) else {
            return Err(INTERNAL_FOLD_INVARIANT.into());
        };
        evaluated += 1;

        let mut causal = EpochState::default();
        let mut seen_anchor = false;
        for parent in parents_of(candidate) {
            if parent == anchor.epoch {
                if !seen_anchor {
                    causal.join(&anchor_after);
                }
                seen_anchor = true;
                continue;
            }
            if let Some(parent_after) = after.get(&parent) {
                causal.join(parent_after);
            }
            let left = unread.get(&parent).copied().unwrap_or(1).saturating_sub(1);
            if left == 0 {
                unread.remove(&parent);
                after.remove(&parent);
            } else {
                unread.insert(parent, left);
            }
        }

        let outcome = evaluate(candidate, &causal, anchor, &roots, &mut failed);
        if failed > MAX_FAILED_SIGNATURES {
            return Err(TOO_MANY_FAILED_SIGNATURES.into());
        }
        let effect = match outcome {
            Err(reason) => {
                rejected += 1;
                reasons.insert(digest, reason.into());
                continue;
            }
            Ok(effect) => effect,
        };
        applied.push(digest.clone());
        if let Some(copy) = candidate.authentic.clone() {
            authentic.insert(digest.clone(), copy);
        }
        union.join(&effect);
        if let Some(kids) = children.get(&digest).filter(|kids| !kids.is_empty()) {
            causal.join(&effect);
            after.insert(digest.clone(), causal);
            unread.insert(digest.clone(), kids.len());
            for kid in kids {
                let left = waiting.get(kid).copied().unwrap_or(0);
                waiting.insert(kid.clone(), left.saturating_sub(1));
                if left == 1 {
                    insert_sorted(&mut ready, kid.clone());
                }
            }
        }
    }

    let pending = candidates.len() - evaluated;
    let applied_set: HashSet<&String> = applied.iter().collect();
    for (digest, _) in candidates.iter() {
        if !applied_set.contains(digest) && !reasons.contains_key(digest) {
            reasons.insert(
                digest.clone(),
                "a parent is missing or was not applied".into(),
            );
        }
    }

    let mut members = OrderedMap::new();
    for (add, entry) in union.added.iter() {
        let lease = entry
            .lease
            .max(union.leases.get(add).copied().unwrap_or(0.0));
        let removed = union.removed.contains(add);
        let effective = !removed && !is_denied(&union.deny, entry);
        members.insert(
            add.clone(),
            MemberState {
                entry: MemberEntry {
                    lease,
                    ..entry.clone()
                },
                removed,
                effective,
            },
        );
    }
    let saturated = applied.len() > limits.max_epoch_events;
    Ok(EpochDetail {
        head: KeyState {
            deny: union.deny,
            members,
            saturated,
            ..anchor.clone()
        },
        applied,
        pending,
        rejected,
        reasons,
        authentic,
    })
}

/// Insert `digest` into `sorted`, keeping ascending order (`insertSorted`).
fn insert_sorted(sorted: &mut Vec<String>, digest: String) {
    let at = sorted.partition_point(|item| compare_utf16(item, &digest).is_lt());
    sorted.insert(at, digest);
}
