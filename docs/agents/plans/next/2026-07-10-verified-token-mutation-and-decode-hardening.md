# Verified-token mutation & residual decode hardening

**Status:** next
**Origin:** `completed/2026-07-10-token-verification-hardening.complete.md` (deferred review findings)

## Context

The token-verification-hardening branch closed the `alg:none` bypass and every base58 DoS
reachable *before* signature verification. Three findings surfaced during its adversarial
reviews that were deliberately left out of that branch's scope — none is remotely exploitable
pre-auth, so none blocked the ship, but each is worth closing.

## Work

### Verified-token re-submit skips signature recheck (in-process integrity gap)

`verifyToken`'s object path returns early when `isVerifiedToken(token)` is true, re-checking
only time and audience claims — not the signature. Membership is a `WeakSet` keyed on object
identity (`verifiedTokens`), and the set only ever admits a freshly-constructed result object,
so an attacker cannot inject identity into it from outside. But in-process code that mutates a
previously-verified token's `payload` in place and re-passes *the same object reference* gets
the tampered payload back as "verified."

Not remotely reachable (requires code holding a genuine verified token to tamper with it), so
this is an integrity-hardening item, not a live vulnerability. Options: freeze the payload on
verification, or drop the early-return fast path and always re-verify. Weigh against the
performance reason the fast path exists.

### `did:peer:4` doc-size check is O(n) before it can reject

The resolver-doc bound must fully `canonicalStringify` the attacker-supplied document before it
can measure and reject it. That serialization is linear (not the O(n²) base58 that was the
actual bug), but a pathological document — e.g. a `verificationMethod` array with millions of
entries — still costs linear time pre-auth (~3.5s measured at 5M entries; ~100ms at the
realistic 100k). Optional O(1) guard: reject when `Array.isArray(doc.verificationMethod) &&
doc.verificationMethod.length` exceeds a sane cap, before calling `canonicalStringify`.

### `cache.ts` DID-cache encode is unbounded

`createInMemoryDIDCache().set()` calls `encodePeer4(doc).shortForm` with no size bound. It is
reached only *after* signature verification succeeds, so it is not a pre-auth DoS, but the doc
it encodes originated from a resolver. Low priority; revisit once the resolver-doc bound above
is considered settled.

## Out of scope

- Anything already shipped on `token-verification-hardening` (see the completed summary).
