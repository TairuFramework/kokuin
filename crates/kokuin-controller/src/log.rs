//! The controller log and its held-fold helpers, as the parts of `packages/controller/src/log.ts`
//! and `log-snapshot.ts` resolution uses.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::canonical::{digest_of, is_canonicalizable};
use crate::epoch::{EpochLimits, fold_epoch_detailed};
use crate::fold::{FoldFailure, Folded, KeyState};
use crate::js::prop;

/// What a request carrying more epoch events than the limit fails with (`LOG_TOO_LARGE`).
pub const LOG_TOO_LARGE: &str = "controller log exceeds request limits";
/// What an input that is not a log at all fails with (`MALFORMED_LOG`).
pub const MALFORMED_LOG: &str = "malformed log";
/// What a resolver answers when the loaded log loses to the one seen (`LOG_NOT_AUTHORITATIVE`).
pub const LOG_NOT_AUTHORITATIVE: &str = "the loaded log does not supersede the one already seen";
/// What a resolver answers when the loaded log and the one seen are a fork (`LOG_FORKED`).
pub const LOG_FORKED: &str = "the loaded log and the one already seen are a fork";

/// A controller's log: the root chain and the current epoch's events (`ControllerLog`). Entries are
/// kept as the untrusted JSON they arrived as; the fold checks each one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ControllerLog {
    /// The root chain.
    pub chain: Vec<Value>,
    /// The epoch events.
    pub events: Vec<Value>,
}

impl ControllerLog {
    /// The log `value` is, if it has the two lists a log is made of (`isControllerLog`).
    pub fn from_value(value: &Value) -> Option<Self> {
        Some(Self {
            chain: prop(value, "chain")?.as_array()?.clone(),
            events: prop(value, "events")?.as_array()?.clone(),
        })
    }

    /// The log as JSON.
    pub fn to_value(&self) -> Value {
        json!({ "chain": self.chain, "events": self.events })
    }

    /// Own copies of the entries, reduced to the envelope the fold reads (`snapshotLog`).
    pub(crate) fn snapshot(&self) -> Self {
        Self {
            chain: snapshot_entries(&self.chain),
            events: snapshot_entries(&self.events),
        }
    }
}

/// One entry reduced to `event`, `sigs` and `recoveryKey`, dropping a body the canonicalizer
/// refuses (`snapshotEntries`). Non-object entries are kept as they are.
pub(crate) fn snapshot_entries(entries: &[Value]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| {
            if !matches!(entry, Value::Object(_) | Value::Array(_)) {
                return entry.clone();
            }
            let mut out = Map::new();
            if let Some(event) = prop(entry, "event").filter(|event| is_canonicalizable(event)) {
                out.insert("event".into(), event.clone());
            }
            if let Some(sigs) = prop(entry, "sigs") {
                out.insert("sigs".into(), sigs.clone());
            }
            if let Some(recovery_key) = prop(entry, "recoveryKey") {
                out.insert("recoveryKey".into(), recovery_key.clone());
            }
            Value::Object(out)
        })
        .collect()
}

/// Whether the snapshotted entries still describe `original` entry for entry (`unchangedEntries`).
pub(crate) fn unchanged_entries(owned: &[Value], original: &[Value]) -> bool {
    owned.len() == original.len()
        && owned.iter().zip(original).all(|(entry, candidate)| {
            if !matches!(entry, Value::Object(_) | Value::Array(_))
                || !matches!(candidate, Value::Object(_) | Value::Array(_))
            {
                return false;
            }
            let same_sigs = match (prop(entry, "sigs"), prop(candidate, "sigs")) {
                (Some(Value::Array(a)), Some(Value::Array(b))) => {
                    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.is_string() && a == b)
                }
                _ => false,
            };
            let candidate_event = prop(candidate, "event");
            prop(entry, "recoveryKey") == prop(candidate, "recoveryKey")
                && same_sigs
                && candidate_event.is_some_and(is_canonicalizable)
                && prop(entry, "event").map(digest_of) == candidate_event.map(digest_of)
        })
}

/// A fold of a held log, with the copy of each applied event whose signature verified
/// (`HeldFold`).
pub(crate) struct HeldFold {
    pub result: Folded,
    pub authentic: HashMap<String, Value>,
}

/// The chain's states merged with `events` as the current epoch (`withEpoch`).
pub(crate) fn with_epoch(
    did: &str,
    states: Vec<KeyState>,
    events: &[Value],
    limits: EpochLimits,
    trusted: Option<&[Value]>,
) -> Result<HeldFold, FoldFailure> {
    let detail = fold_epoch_detailed(did, &states, events, trusted, limits)
        .map_err(|reason| FoldFailure::new(reason, -1))?;
    Ok(HeldFold {
        result: Folded {
            states,
            head: detail.head,
            applied: detail.applied,
            pending: detail.pending,
            rejected: detail.rejected,
        },
        authentic: detail.authentic,
    })
}

/// One copy of each applied event, in the fold's order; a saturated epoch keeps the first
/// `MAX_EPOCH_EVENTS + 1` (`appliedCopies`).
pub(crate) fn applied_copies(held: &HeldFold, limits: EpochLimits) -> Vec<Value> {
    let keep = if held.result.head.saturated {
        held.result
            .applied
            .iter()
            .take(limits.max_epoch_events.saturating_add(1))
            .collect::<Vec<_>>()
    } else {
        held.result.applied.iter().collect()
    };
    keep.into_iter()
        .filter_map(|digest| held.authentic.get(digest))
        .map(|copy| {
            json!({
                "event": prop(copy, "event").cloned().unwrap_or(Value::Null),
                "sigs": prop(copy, "sigs").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}
