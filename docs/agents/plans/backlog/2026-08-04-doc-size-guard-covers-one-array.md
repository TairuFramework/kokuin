# The peer:4 document size pre-guard bounds only `verificationMethod`

**Source:** final whole-branch review of
`completed/2026-08-04-peer4-audienceless-iss-and-verify-hardening.complete.md`
**Priority:** low — bounded linear cost, not the O(n²) class the original hardening closed.

## What

`assertDocWithinMaxSize` (`packages/token/src/peer4.ts`) gained an O(1) entry-count pre-guard so
a pathological `verificationMethod` array is rejected before the document is serialized. The
guard covers that one array. A malicious resolver document with a small `verificationMethod` and
a million-entry `authentication` array — or any other array under the DID document schema's open
`additionalProperties` — still pays a full `canonicalStringify` before it can be measured and
rejected.

This path is reachable ahead of the signature check: `resolveIssuerWithDoc` calls the guard
while resolving `iss`, so it applies to any verifier that passes a `resolver`. The changeset's
wording was narrowed to match what actually landed.

Possible fix: cap the summed length of the known array-valued properties rather than
`verificationMethod` alone, keeping the same derive-from-`maxSize` and deliberate-undercount
approach so the guard can still never reject a document the byte measure would have accepted.

## Related: the DID cache's bound is redundant

`createInMemoryDIDCache().set()` also calls `assertDocWithinMaxSize`, but both in-repo callers
have already bounded the document — resolver docs pass the identical guard in
`resolveIssuerWithDoc`, and long-form docs pass `decodePeer4`'s byte check. Because
`verifySignedPayload` awaits `cache.set`, the guard's only reachable novel effect is turning a
post-verification cache-write rejection into a *failed verification*. It also measures the
canonical serialization where `decodePeer4` measures the raw embedded bytes, so the two can
disagree at the margin.

Defensible as defence in depth, and deliberately left as shipped. Worth deciding separately
whether a cache-write failure should fail verification at all.
