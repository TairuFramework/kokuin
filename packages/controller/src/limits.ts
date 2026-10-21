// Two kinds of limit, never confused. A *request* limit rejects input: unauthenticated or invalid
// events only ever get turned away, they never change remembered state. *Saturation* is the one
// limit authenticated input can reach: an epoch carrying more distinct, causally valid events than
// it allows fails closed until root settles into a fresh one. Work is counted in events, edges and
// signatures, never elapsed time, so every verifier draws the same line.

/** Authenticated, causally valid events one epoch may carry before it saturates. */
export const MAX_EPOCH_EVENTS = 4096

/**
 * Request limit: epoch events in one input. Above {@link MAX_EPOCH_EVENTS}, so a saturating epoch can
 * still be presented whole and remembered as saturated rather than turned away as oversized.
 */
export const MAX_LOG_EVENTS = 8192

/** Request limit: parents one epoch event may list. */
export const MAX_EVENT_PARENTS = 16

/** Request limit: canonical bytes of one epoch event body. */
export const MAX_EVENT_BYTES = 8192

/** A member's lease when the caller names none: 90 days, in seconds. */
export const DEFAULT_LEASE_SECONDS = 7_776_000

/**
 * Request limit: signatures one epoch event may carry. Not counted in {@link MAX_EVENT_BYTES}, so it
 * bounds the walk separately; a member event carries exactly one, a root event one per chain key.
 */
export const MAX_EVENT_SIGNATURES = 16
