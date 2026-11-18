//! Root-chain device revocation indices, as `deviceRevokeIndices` in
//! `packages/controller/src/device-revoke.ts`. Building a revoke signs, so it stays in TS.

use kokuin_token::normalize_did;
use serde_json::Value;

use crate::fold::fold_chain_only;
use crate::js::{prop, prop_is};
use crate::log::snapshot_entries;
use crate::ordered::OrderedSet;

fn denies_subject(deny: &OrderedSet, subject: &str) -> bool {
    let canonical = normalize_did(subject);
    deny.iter().any(|entry| normalize_did(entry) == canonical)
}

/// Every same-generation rotate newly denying `subject`, in chain order, or nothing for an invalid
/// chain or one that is not root-only (`deviceRevokeIndices`).
pub fn device_revoke_indices(did: &str, chain: &[Value], subject: &str) -> Vec<usize> {
    let chain = snapshot_entries(chain);
    let Ok(states) = fold_chain_only(did, &chain) else {
        return Vec::new();
    };
    let root_only = chain.iter().enumerate().all(|(index, entry)| {
        let event = prop(entry, "event").unwrap_or(&Value::Null);
        prop_is(event, "t", if index == 0 { "icp" } else { "rot" })
    });
    if !root_only {
        return Vec::new();
    }
    (1..chain.len())
        .filter(|&index| {
            let (Some(state), Some(prior)) = (states.get(index), states.get(index - 1)) else {
                return false;
            };
            state.generation == prior.generation
                && denies_subject(&state.deny, subject)
                && !denies_subject(&prior.deny, subject)
        })
        .collect()
}
