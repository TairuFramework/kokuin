//! Truncation protection, as `packages/controller/src/history.ts`: a log is folded against the one
//! this party already accepted, so a prefix that withholds a revoke is refused.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::canonical::{dismantle, within_input_depth};
use crate::epoch::EpochLimits;
use crate::fold::{FoldFailure, Folded, KeyState, fold_chain_only};
use crate::limits::MAX_LOG_EVENTS;
use crate::log::{
    ControllerLog, LOG_FORKED, LOG_NOT_AUTHORITATIVE, LOG_TOO_LARGE, MALFORMED_LOG, applied_copies,
    with_epoch,
};
use crate::supersede::{ResolveFailure, ResolveResult, resolve_branches};
use crate::{ControllerError, fold::fold_chain};

/// The update a [`LogStore::merge`] applies: the current log in, the log to keep out.
pub type LogUpdate<'a> =
    dyn FnMut(Option<&ControllerLog>) -> Result<ControllerLog, ControllerError> + 'a;

/// Where a consumer keeps the log it accepted for each DID (`LogStore`).
pub trait LogStore {
    /// The accepted log for `did`, if any.
    fn get(&self, did: &str) -> Option<ControllerLog>;

    /// Replace the log for `did` with what `update` makes of the current one, atomically per DID.
    /// When `update` fails, nothing is written and the failure propagates.
    fn merge(
        &self,
        did: &str,
        update: &mut LogUpdate<'_>,
    ) -> Result<ControllerLog, ControllerError>;
}

/// An in-memory [`LogStore`] (`createMemoryLogStore`). The lock serialises merges.
#[derive(Debug, Default)]
pub struct MemoryLogStore {
    logs: Mutex<HashMap<String, ControllerLog>>,
}

impl MemoryLogStore {
    /// Store `log` for `did` as accepted, unauthenticated: for seeding memory this party built
    /// itself. A log with an entry nesting deeper than `MAX_INPUT_DEPTH` containers is refused and
    /// taken apart without recursion (`false`), since the store clones, compares and drops what it
    /// holds recursively.
    #[must_use]
    pub fn put(&self, did: &str, log: ControllerLog) -> bool {
        if !log.chain.iter().chain(&log.events).all(within_input_depth) {
            log.chain.into_iter().chain(log.events).for_each(dismantle);
            return false;
        }
        self.lock().insert(did.to_owned(), log);
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ControllerLog>> {
        self.logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl LogStore for MemoryLogStore {
    fn get(&self, did: &str) -> Option<ControllerLog> {
        self.lock().get(did).cloned()
    }

    fn merge(
        &self,
        did: &str,
        update: &mut LogUpdate<'_>,
    ) -> Result<ControllerLog, ControllerError> {
        let mut logs = self.lock();
        let next = update(logs.get(did))?;
        if logs.get(did) != Some(&next) {
            logs.insert(did.to_owned(), next.clone());
        }
        Ok(next)
    }
}

/// What [`authoritative_log`] answers: the log to remember and the fold to answer from
/// (`AuthoritativeLog`).
#[derive(Clone, Debug, PartialEq)]
pub struct AuthoritativeLog {
    /// The settled chain and the current epoch's applied events.
    pub log: ControllerLog,
    /// The fold of the settled chain with the union of seen and loaded epoch events.
    pub result: Folded,
}

/// The stored log and its chain's head, or `None` when there is no usable memory (`recall`).
fn recall(did: &str, seen: Option<&ControllerLog>) -> Option<(ControllerLog, KeyState)> {
    let seen = seen?;
    if seen.chain.is_empty() {
        return None;
    }
    let states = fold_chain_only(did, &seen.chain).ok()?;
    let head = states.last()?.clone();
    Some((seen.clone(), head))
}

/// Fold `loaded` against the log already `seen` and say what to remember (`authoritativeLog`).
///
/// The loaded chain must extend the seen one or win against it under branch resolution; a chain
/// that loses is refused (`LOG_NOT_AUTHORITATIVE`), a fork too (`LOG_FORKED`). The epoch is the
/// union of what was seen and loaded; seen events are trusted, loaded ones checked.
///
/// `loaded` is untrusted and bounded as [`ControllerLog::from_value`] bounds it: one nesting deeper
/// than `MAX_INPUT_DEPTH` containers fails `malformed log`. The caller still owns and drops it.
/// `seen` is this party's own memory and must satisfy [`ControllerLog`]'s depth precondition.
pub fn authoritative_log(
    did: &str,
    loaded: &Value,
    seen: Option<&ControllerLog>,
    context: &str,
    limits: EpochLimits,
) -> Result<AuthoritativeLog, ControllerError> {
    let invalid = |failure: FoldFailure| {
        ControllerError::plain(format!(
            "{context}: invalid log for {did}: {} at event {}",
            failure.reason, failure.index
        ))
    };
    let Some(loaded) = ControllerLog::from_value(loaded) else {
        return Err(invalid(FoldFailure::new(MALFORMED_LOG, 0)));
    };
    if loaded.events.len() > MAX_LOG_EVENTS {
        return Err(invalid(FoldFailure::new(LOG_TOO_LARGE, -1)));
    }
    let loaded = loaded.snapshot();
    let seen = seen.map(ControllerLog::snapshot);
    let mut states = fold_chain(did, &loaded.chain).map_err(invalid)?;
    let Some(loaded_head) = states.last().map(|state| state.digest.clone()) else {
        return Err(invalid(FoldFailure::new("no state produced", 0)));
    };

    let mut chain = loaded.chain.clone();
    let memory = recall(did, seen.as_ref());
    if let Some((memory_log, memory_head)) = &memory
        && !states
            .iter()
            .any(|state| state.digest == memory_head.digest)
    {
        let winner = match resolve_branches(did, &[memory_log.chain.clone(), loaded.chain.clone()])
        {
            ResolveResult::Winner { winner, .. } => winner,
            ResolveResult::Failed { failure, .. } => {
                let reason = if failure == ResolveFailure::Duplicity {
                    LOG_FORKED
                } else {
                    LOG_NOT_AUTHORITATIVE
                };
                return Err(ControllerError::plain(format!("{reason}: {did}")));
            }
        };
        let winner_states = fold_chain_only(did, &winner).ok();
        let winner_head = winner_states
            .as_ref()
            .and_then(|states| states.last())
            .map(|state| state.digest.clone());
        let Some(winner_states) = winner_states.filter(|_| winner_head == Some(loaded_head)) else {
            return Err(ControllerError::plain(format!(
                "{LOG_NOT_AUTHORITATIVE}: {did}"
            )));
        };
        chain = winner;
        states = winner_states;
    }

    let trusted = memory.as_ref().map(|(log, _)| log.events.as_slice());
    let held = with_epoch(did, states, &loaded.events, limits, trusted).map_err(invalid)?;
    let events = applied_copies(&held, limits);
    Ok(AuthoritativeLog {
        log: ControllerLog { chain, events },
        result: held.result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_refuses_an_over_deep_log_without_recursion() {
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                let mut deep = Value::Null;
                for _ in 0..200_000 {
                    deep = Value::Array(vec![deep]);
                }
                let store = MemoryLogStore::default();
                let log = ControllerLog {
                    chain: Vec::new(),
                    events: vec![deep],
                };
                assert!(!store.put("did:kokuin:zX", log));
                assert_eq!(store.get("did:kokuin:zX"), None);
                assert!(store.put("did:kokuin:zX", ControllerLog::default()));
            })
            .expect("spawn")
            .join()
            .expect("no panic");
    }
}
