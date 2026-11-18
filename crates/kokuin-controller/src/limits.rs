//! Request limits and saturation, as `packages/controller/src/limits.ts`.

/// Authenticated, causally valid events one epoch may carry before it saturates.
pub const MAX_EPOCH_EVENTS: usize = 4096;
/// Request limit: epoch events in one input.
pub const MAX_LOG_EVENTS: usize = 8192;
/// Request limit: signatures that fail to verify in one input.
pub const MAX_FAILED_SIGNATURES: usize = 64;
/// Request limit: parents one epoch event may list.
pub const MAX_EVENT_PARENTS: usize = 16;
/// Request limit: canonical bytes of one epoch event body.
pub const MAX_EVENT_BYTES: usize = 8192;
/// A member's lease when the caller names none: 90 days, in seconds.
pub const DEFAULT_LEASE_SECONDS: u64 = 7_776_000;
/// Request limit: signatures one epoch event may carry.
pub const MAX_EVENT_SIGNATURES: usize = 16;
