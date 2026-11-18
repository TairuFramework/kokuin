//! The root-chain fold, as `packages/controller/src/fold.ts`.

use std::collections::HashSet;

use serde_json::Value;

use crate::canonical::{digest_of, is_canonicalizable};
use crate::epoch::{EpochLimits, fold_epoch_detailed};
use crate::events::{
    MemberEntry, key_from_target, key_list, key_target, verify_inception, verify_reset,
    verify_rotate,
};
use crate::js::{is_safe_integer, js_string, prop, prop_is, strict_eq_number, to_number};
use crate::limits::MAX_LOG_EVENTS;
use crate::log::{ControllerLog, LOG_TOO_LARGE, MALFORMED_LOG, snapshot_entries};
use crate::members::{
    ROTATE_NEEDS_SNAPSHOT, RootKeySet, WireSnapshot, denial_targets_member, validate_snapshot,
};
use crate::ordered::{OrderedMap, OrderedSet};

/// A reset opens a generation with no removed incarnations (`RESET_HAS_TOMBSTONES`).
pub const RESET_HAS_TOMBSTONES: &str = "reset must not carry removed incarnations";
/// What a log padded past [`MAX_SKIPPED_SLACK`] fails with (`TOO_MANY_UNKNOWN_EVENTS`).
pub const TOO_MANY_UNKNOWN_EVENTS: &str = "too many unknown events";
/// Unknown events a log may carry beyond the number it understands (`MAX_SKIPPED_SLACK`).
pub const MAX_SKIPPED_SLACK: usize = 8;
/// What a log entry that is not a signed event at all fails with.
const MALFORMED_EVENT: &str = "malformed event";

/// One management member as a state holds it (`MemberState`).
#[derive(Clone, Debug, PartialEq)]
pub struct MemberState {
    /// The snapshot or add entry.
    pub entry: MemberEntry,
    /// Whether a removal has ended it.
    pub removed: bool,
    /// Present, not removed and not denied: whether it may act.
    pub effective: bool,
}

/// The key state at one position of a controller log (`KeyState`).
///
/// `generation`, `seq`, `key_generation` and `key_seq` are TS `gen`, `seq`, `keyGen` and `keySeq`,
/// held as the doubles TS holds.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyState {
    /// The controller DID.
    pub did: String,
    /// The generation, incremented only by a reset.
    pub generation: f64,
    /// The sequence within the generation.
    pub seq: f64,
    /// Generation in which the current `keys` were established.
    pub key_generation: f64,
    /// Derivation index of the current `keys`.
    pub key_seq: f64,
    /// Authority public keys.
    pub keys: Vec<String>,
    /// Key agreement public keys.
    pub agreement: Vec<String>,
    /// Pre-rotation commitments.
    pub next: Vec<String>,
    /// The inception's recovery commitment.
    pub recovery: String,
    /// Denied holders (`did:…`) and signers (`#<key>`).
    pub deny: OrderedSet,
    /// The management set, by add digest.
    pub members: OrderedMap<MemberState>,
    /// Removed incarnations a snapshot carried, by add digest.
    pub tombstones: OrderedMap<MemberEntry>,
    /// Digest of the chain event that opened this state's epoch.
    pub epoch: String,
    /// Whether the epoch holds more events than a verifier evaluates.
    pub saturated: bool,
    /// Digest of the event that produced this state.
    pub digest: String,
}

/// Why a log did not fold: the reason and the chain index, `-1` for a request limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldFailure {
    /// The TS reason string.
    pub reason: String,
    /// The failing chain event, or `-1` when no one event is at fault.
    pub index: i64,
}

impl FoldFailure {
    pub(crate) fn new(reason: impl Into<String>, index: i64) -> Self {
        Self {
            reason: reason.into(),
            index,
        }
    }
}

/// A folded log (`FoldResult` with `ok: true`).
#[derive(Clone, Debug, PartialEq)]
pub struct Folded {
    /// One state per chain event.
    pub states: Vec<KeyState>,
    /// The last chain state merged with the current epoch.
    pub head: KeyState,
    /// Digests of the epoch events that applied, parents first.
    pub applied: Vec<String>,
    /// Well-formed epoch events still waiting on a parent.
    pub pending: usize,
    /// Epoch events refused.
    pub rejected: usize,
}

/// What [`fold_log`] answers (`FoldResult`).
pub type FoldOutcome = Result<Folded, FoldFailure>;

/// Whether a log entry has the envelope shape everything downstream reads (`isSignedEventShape`).
fn is_signed_event_shape(value: &Value) -> bool {
    let Some(event) = prop(value, "event") else {
        return false;
    };
    if !matches!(event, Value::Object(_) | Value::Array(_)) {
        return false;
    }
    match prop(value, "sigs") {
        Some(Value::Array(sigs)) if sigs.iter().all(Value::is_string) => {}
        _ => return false,
    }
    if !matches!(prop(value, "recoveryKey"), None | Some(Value::String(_))) {
        return false;
    }
    is_canonicalizable(event)
}

fn sigs_of(signed: &Value) -> &[Value] {
    prop(signed, "sigs")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn nullish(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

enum Step {
    State(KeyState),
    Skipped(KeyState),
}

/// Validate one chain event against the state so far and produce the next state (`stepEvent`).
fn step_event(
    did: &str,
    inception: &Value,
    signed: &Value,
    prior: &KeyState,
    chain: &[KeyState],
) -> Result<Step, String> {
    if !is_signed_event_shape(signed) {
        return Err(MALFORMED_EVENT.into());
    }
    let Some(event) = prop(signed, "event") else {
        return Err(MALFORMED_EVENT.into());
    };
    let sigs = sigs_of(signed);

    if !prop_is(event, "i", did) {
        return Err("event names a different controller".into());
    }

    if prop_is(event, "t", "rot") {
        return rotate(did, inception, signed, event, sigs, prior, chain).map(Step::State);
    }

    if !prop_is(event, "p", &prior.digest) {
        return Err("event does not chain to the previous digest".into());
    }
    let crit = prop(event, "crit");
    if crit != Some(&Value::Bool(false)) {
        let t = js_string(prop(event, "t"));
        return Err(if crate::js::truthy(crit) {
            format!("unknown critical event type: {t}")
        } else {
            format!("unknown event type with no criticality flag: {t}")
        });
    }
    if !strict_eq_number(prop(event, "g"), prior.generation)
        || !strict_eq_number(prop(event, "s"), prior.seq + 1.0)
    {
        return Err("sequence gap".into());
    }
    Ok(Step::Skipped(prior.clone()))
}

/// The `rot` branch of `stepEvent`: a rotate or a reset.
fn rotate(
    did: &str,
    inception: &Value,
    signed: &Value,
    event: &Value,
    sigs: &[Value],
    prior: &KeyState,
    chain: &[KeyState],
) -> Result<KeyState, String> {
    let g = prop(event, "g");
    let is_reset = to_number(g) > prior.generation;

    if is_reset {
        if !is_safe_integer(g) || g.and_then(Value::as_f64).is_none_or(|g| g < 1.0) {
            return Err("invalid reset".into());
        }
        if prop(event, "u").is_some() {
            return Err(RESET_HAS_TOMBSTONES.into());
        }
        if !strict_eq_number(prop(event, "s"), 0.0) {
            return Err("reset must restart the sequence".into());
        }
        if !verify_reset(event, sigs, prop(signed, "recoveryKey"), inception) {
            return Err("invalid reset".into());
        }
    } else {
        if !prop_is(event, "p", &prior.digest) {
            return Err("event does not chain to the previous digest".into());
        }
        if !strict_eq_number(g, prior.generation)
            || !strict_eq_number(prop(event, "s"), prior.seq + 1.0)
        {
            return Err("sequence gap".into());
        }
        if !verify_rotate(event, sigs, &prior.digest, &prior.next) {
            return Err("invalid rotate".into());
        }
    }

    // Verified above: a rotate's `k`, `ka` and `n` are key lists, its `g` and `s` numbers.
    let keys = key_list(prop(event, "k")).unwrap_or_default();
    let agreement = key_list(prop(event, "ka")).unwrap_or_default();
    let next = key_list(prop(event, "n")).unwrap_or_default();
    let m = prop(event, "m");
    let d = prop(event, "d");
    if !is_reset && (nullish(m) || nullish(d)) {
        return Err(ROTATE_NEEDS_SNAPSHOT.into());
    }
    let u = prop(event, "u");
    if u.is_some() && (nullish(m) || nullish(d)) {
        return Err(ROTATE_NEEDS_SNAPSHOT.into());
    }
    let empty_list = Value::Array(Vec::new());
    let wire = if nullish(m) {
        WireSnapshot {
            members: Some(&empty_list),
            removed: None,
            deny: Some(&empty_list),
        }
    } else {
        WireSnapshot {
            members: m,
            removed: u,
            deny: if nullish(d) { Some(&empty_list) } else { d },
        }
    };

    let mut generation_keys: HashSet<String> = keys.iter().chain(&agreement).cloned().collect();
    let mut commitments: HashSet<String> = next.iter().cloned().collect();
    if !is_reset {
        for state in chain
            .iter()
            .filter(|state| state.generation == prior.generation)
        {
            generation_keys.extend(state.keys.iter().chain(&state.agreement).cloned());
            commitments.extend(state.next.iter().cloned());
        }
    }
    let tombstones: HashSet<String> = if is_reset {
        HashSet::new()
    } else {
        prior
            .deny
            .iter()
            .filter(|entry| key_from_target(entry).is_some_and(|key| generation_keys.contains(key)))
            .cloned()
            .collect()
    };
    let root = RootKeySet {
        keys: generation_keys,
        commitments,
        recovery: prior.recovery.clone(),
    };
    let snapshot = validate_snapshot(&wire, &root, &tombstones).map_err(str::to_owned)?;

    let deny: OrderedSet = snapshot.deny.iter().cloned().collect();
    if let Some(key) = keys
        .iter()
        .chain(&agreement)
        .find(|key| deny.contains(&key_target(key)))
    {
        return Err(format!("rotate establishes a denied key: {key}"));
    }

    let mut members = OrderedMap::new();
    for entry in snapshot.members {
        let denied = snapshot
            .deny
            .iter()
            .any(|denial| denial_targets_member(denial, &entry));
        members.insert(
            entry.add.clone(),
            MemberState {
                entry,
                removed: false,
                effective: !denied,
            },
        );
    }
    let mut member_tombstones = OrderedMap::new();
    for entry in snapshot.removed {
        member_tombstones.insert(entry.add.clone(), entry);
    }

    let generation = g.and_then(Value::as_f64).unwrap_or(f64::NAN);
    let seq = prop(event, "s").and_then(Value::as_f64).unwrap_or(f64::NAN);
    let digest = digest_of(event);
    Ok(KeyState {
        did: did.to_owned(),
        generation,
        seq,
        key_generation: generation,
        key_seq: if is_reset { 0.0 } else { prior.key_seq + 1.0 },
        keys,
        agreement,
        next,
        recovery: prior.recovery.clone(),
        deny,
        members,
        tombstones: member_tombstones,
        epoch: digest.clone(),
        saturated: false,
        digest,
    })
}

/// Validate the inception and seed the state list (`initFold`).
fn init_fold(did: &str, events: &[Value]) -> Result<KeyState, FoldFailure> {
    let Some(first) = events.first() else {
        return Err(FoldFailure::new("empty log", 0));
    };
    if !is_signed_event_shape(first) {
        return Err(FoldFailure::new(MALFORMED_EVENT, 0));
    }
    let event = prop(first, "event").unwrap_or(&Value::Null);
    if !prop_is(event, "t", "icp") {
        return Err(FoldFailure::new("first event must be an inception", 0));
    }
    if !verify_inception(event, sigs_of(first), did) {
        return Err(FoldFailure::new("invalid inception", 0));
    }
    // `verify_inception` admits only `g === 0` and `s === 0`, so both are numbers here.
    let (Some(generation), Some(seq)) = (
        prop(event, "g").and_then(Value::as_f64),
        prop(event, "s").and_then(Value::as_f64),
    ) else {
        return Err(FoldFailure::new("invalid inception", 0));
    };
    let digest = digest_of(event);
    Ok(KeyState {
        did: did.to_owned(),
        generation,
        seq,
        key_generation: generation,
        key_seq: 0.0,
        keys: key_list(prop(event, "k")).unwrap_or_default(),
        agreement: key_list(prop(event, "ka")).unwrap_or_default(),
        next: key_list(prop(event, "n")).unwrap_or_default(),
        recovery: prop(event, "r")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        deny: OrderedSet::new(),
        members: OrderedMap::new(),
        tombstones: OrderedMap::new(),
        epoch: digest.clone(),
        saturated: false,
        digest,
    })
}

/// The chain alone: one state per event, or the first event that does not fold (`foldChain`).
/// `events` must already be snapshotted.
pub(crate) fn fold_chain(did: &str, events: &[Value]) -> Result<Vec<KeyState>, FoldFailure> {
    let first = init_fold(did, events)?;
    let inception = prop(&events[0], "event").cloned().unwrap_or(Value::Null);
    let mut states = vec![first];
    let mut understood = 1usize;
    let mut skipped = 0usize;
    for (i, signed) in events.iter().enumerate().skip(1) {
        let prior = &states[i - 1];
        match step_event(did, &inception, signed, prior, &states) {
            Err(reason) => return Err(FoldFailure::new(reason, i as i64)),
            Ok(Step::Skipped(state)) => {
                skipped += 1;
                if skipped > understood + MAX_SKIPPED_SLACK {
                    return Err(FoldFailure::new(TOO_MANY_UNKNOWN_EVENTS, i as i64));
                }
                states.push(state);
            }
            Ok(Step::State(state)) => {
                understood += 1;
                states.push(state);
            }
        }
    }
    Ok(states)
}

/// [`fold_chain`] over an unsnapshotted chain: the chain half of `foldLog` with no epoch events.
pub(crate) fn fold_chain_only(did: &str, chain: &[Value]) -> Result<Vec<KeyState>, FoldFailure> {
    fold_chain(did, &snapshot_entries(chain))
}

/// Fold a controller log into per-position key state and the head the current epoch makes of the
/// last one (`foldLog`). `input` is untrusted: anything that is not a log fails `malformed log`,
/// including a value nesting deeper than `MAX_INPUT_DEPTH` containers (see
/// [`ControllerLog::from_value`]). The caller still owns `input` and drops it: one too deep for the
/// default recursive drop is the caller's to take apart.
pub fn fold_log(did: &str, input: &Value) -> FoldOutcome {
    let Some(log) = ControllerLog::from_value(input) else {
        return Err(FoldFailure::new(MALFORMED_LOG, 0));
    };
    fold_controller_log(did, &log)
}

/// [`fold_log`] over a log already in hand, which must satisfy [`ControllerLog`]'s depth
/// precondition.
pub fn fold_controller_log(did: &str, log: &ControllerLog) -> FoldOutcome {
    if log.events.len() > MAX_LOG_EVENTS {
        return Err(FoldFailure::new(LOG_TOO_LARGE, -1));
    }
    let log = log.snapshot();
    let states = fold_chain(did, &log.chain)?;
    let detail = fold_epoch_detailed(did, &states, &log.events, None, EpochLimits::default())
        .map_err(|reason| FoldFailure::new(reason, -1))?;
    Ok(Folded {
        states,
        head: detail.head,
        applied: detail.applied,
        pending: detail.pending,
        rejected: detail.rejected,
    })
}

/// The state at `position`, when the fold succeeded (`keyStateAt`).
pub fn key_state_at(outcome: &FoldOutcome, position: usize) -> Option<&KeyState> {
    outcome.as_ref().ok()?.states.get(position)
}
