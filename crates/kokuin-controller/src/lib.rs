#![forbid(unsafe_code)]
//! A Rust port of the `@kokuin/controller` fold: a `did:kokuin:` controller's event log folded
//! into its key state, and the [`DIDMethodResolver`](kokuin_token::DIDMethodResolver) that answers
//! for it.
//!
//! The root chain (inception, rotates, resets) fixes the keys and every settlement; the current
//! epoch's events (member adds, renewals, removals, revokes) merge into the chain's last state to
//! give the head. Resolution answers from the head, scans the chain's states for a rotated-away
//! key on historic resolution, refuses while the epoch is saturated, and with a [`LogStore`]
//! refuses a log that is behind the one already accepted.
//!
//! It matches the TS package on the golden vectors in
//! `packages/controller/test/golden/controller.json`. It verifies; it does not build or sign
//! events.

mod canonical;
mod device_revoke;
mod epoch;
mod error;
mod events;
mod fold;
mod history;
mod js;
mod keys;
mod limits;
mod log;
mod members;
mod ordered;
mod resolver;
mod state_resolver;
mod supersede;

pub use canonical::{MAX_CANONICAL_DEPTH, MAX_INPUT_DEPTH, is_canonicalizable, try_digest_of};
pub use device_revoke::device_revoke_indices;
pub use epoch::{
    ADD_DID_MISMATCH, ADD_KEY_ALREADY_MEMBER, ADD_KEY_DENIED, ADD_KEY_IS_ROOT, ADD_NOT_ROOT,
    EpochDetail, EpochLimits, MEMBER_REVOKES_MEMBER, REVOKE_NAMES_ROOT_KEY, SELF_REMOVE,
    SELF_RENEW, TOO_MANY_FAILED_SIGNATURES, UNKNOWN_MEMBER, fold_epoch_detailed,
    is_epoch_event_shape,
};
pub use error::ControllerError;
pub use events::{
    DID_PREFIX, KEY_TARGET_PREFIX, MemberEntry, did_from_inception, key_from_target, key_target,
};
pub use fold::{
    FoldFailure, FoldOutcome, Folded, KeyState, MAX_SKIPPED_SLACK, MemberState,
    RESET_HAS_TOMBSTONES, TOO_MANY_UNKNOWN_EVENTS, fold_controller_log, fold_log, key_state_at,
};
pub use history::{AuthoritativeLog, LogStore, LogUpdate, MemoryLogStore, authoritative_log};
pub use keys::{KeyAlgorithm, encode_key, try_decode_key};
pub use limits::{
    DEFAULT_LEASE_SECONDS, MAX_EPOCH_EVENTS, MAX_EVENT_BYTES, MAX_EVENT_PARENTS,
    MAX_EVENT_SIGNATURES, MAX_FAILED_SIGNATURES, MAX_LOG_EVENTS,
};
pub use log::{ControllerLog, LOG_FORKED, LOG_NOT_AUTHORITATIVE, LOG_TOO_LARGE, MALFORMED_LOG};
pub use members::{
    ROTATE_NEEDS_SNAPSHOT, SNAPSHOT_DROPS_RETIRED_KEY, SNAPSHOT_MALFORMED,
    SNAPSHOT_MEMBER_DID_MISMATCH, SNAPSHOT_MEMBER_KEY_IS_ROOT,
};
pub use ordered::{OrderedMap, OrderedSet};
pub use resolver::{ControllerResolver, FrozenResolver, LoadLog};
pub use state_resolver::{
    DID_METHOD, EPOCH_SATURATED, FoldedView, KEY_REVOKED, MEMBER_NOT_EFFECTIVE,
    MEMBER_NOT_HISTORIC, agreement_keys_from, historic_member_from, member_from, signing_key_from,
};
pub use supersede::{Duplicity, ResolveFailure, ResolveResult, resolve_branches};
