# `did:peer:4` audience-less issuers, and token verification hardening

**Status:** complete
**Date:** 2026-08-04
**Origin:** `next/2026-08-03-peer4-revocation-records-are-unverifiable.md` (security, fail-open),
`next/2026-07-10-verified-token-mutation-and-decode-hardening.md` (findings deferred from
`completed/2026-07-10-token-verification-hardening.complete.md`)
**Branch:** `fix/peer4-audienceless-iss-and-verify-hardening` (13 commits: 5 fixes + tests,
spec/plan, changeset, one post-review fix wave)

## Goal

Make a `did:peer:4` identity's audience-less tokens self-resolving, and close three deferred
token-verification hardening findings living in the same files.

## What was built

### 1. `pickIss` embeds the long form for audience-less payloads

A short-form `did:peer:4` is a hash of the DID document and cannot be resolved without it. The
first-contact policy that embedded the long form was keyed on `payload.aud`, so a payload naming
no single string audience never consulted it and emitted an unresolvable short form. Both
in-repo audience-less producers were affected: `createRevocationRecord` (`@kokuin/capability`)
and `createRotationAssertion`. A peer:4 grantor could revoke nothing — the record bound on the
grantor's own device, which stores its self-minted row without verifying it, and nowhere else.

`pickIss` now returns the long form whenever `typeof payload.aud !== 'string'`.

**Key design decision — fix the issuer policy, not the two producers.** Neither
`createRevocationRecord` nor `createRotationAssertion` changed; they became verifiable by
inheritance, and every future audience-less producer is correct by default. An array-valued
`aud` gets the long form for the same reason: there is no single audience to key first contact
on. `embedLongForm: false` remains the escape hatch for a broadcast path whose recipients are
known to hold the document already — it becomes an explicit opt-in to that assumption rather
than a silent default. The cost is size: a long-form `iss` for a two-key document is roughly 400
characters against 57 for a short form, paid on the rare audience-less token.

The defect was latent rather than live — `chooseMethod` only selects peer:4 for identities
carrying more than one key or a non-signing key. It was a trap door: the first identity to add a
KEM key for key agreement would have made revocation broadcast-unverifiable, with no error at
the point of revocation and a debug-level skip on every recipient.

### 2. The verified-token fast path re-binds the payload to the signed bytes

`verifyToken` returns early for an object already in the `verifiedTokens` `WeakSet`, re-checking
only time and audience claims. In-process code holding a genuine verified token could mutate its
payload in place and re-submit the same reference to get the tampered payload back as verified.

**Key design decision — the signed bytes must be captured out of the caller's reach.** The
original design re-ran `getVerifiableData(token)`, which compares the recomputed header and
payload against `token.data`. The final whole-branch review demonstrated with a working repro
that this is bypassable: `data` lives on the same mutable object, so code that mutates the
payload *and* recomputes `data` passes the check and stays in the `WeakSet`. The shipped fix
records the verified `data` string in a module-level `WeakMap<object, string>` at both
`verifiedTokens.add` sites, and the fast path compares the recomputation against that captured
value, which no mutator can reach. A map miss fails closed. The earlier `data == null` guard and
its error message became unnecessary and were removed.

Freezing the payload was rejected: `result.payload` is the same reference as the caller's input,
so freezing it would freeze the caller's own object, and a shallow freeze would leave nested
claims mutable. Dropping the fast path entirely was rejected for the signature verification and
DID resolution it would pay on every re-submit.

### 3. O(1) entry-count pre-guard on resolver document size

`assertDocWithinMaxSize` had to fully `canonicalStringify` an attacker-supplied document before
it could measure and reject it — linear, not the O(n²) base58 that was the original bug, but a
`verificationMethod` array with millions of entries still cost linear time ahead of the
signature check (~3.5s measured at 5M entries).

**Key design decision — derive the cap from `maxSize`, and undercount deliberately.**
`MIN_VERIFICATION_METHOD_BYTES` is `40` while the true minimum serialized entry is 44 bytes
(`{"id":"","type":"","publicKeyMultibase":""}` at 43, plus an array separator). Undercounting
only widens the cap, so the O(1) guard can never reject a document the full byte measure would
have accepted. The cap tracks any `maxDocSize` the caller passes. The entry-count error message
is distinct from the byte-size one, so the two rejections stay distinguishable in tests and logs.

The guard bounds `verificationMethod` only — a document with a small `verificationMethod` and a
huge `authentication` array still pays the full serialization. Recorded as follow-on work.

### 4. Bounded encode in the DID cache

`createInMemoryDIDCache().set()` called `encodePeer4(doc)` with no size bound. It is reached only
after signature verification succeeds, so it was not a pre-auth DoS, but the document originated
from a resolver. It now applies the same `assertDocWithinMaxSize` guard, returning a rejected
promise to match its two sibling error paths.

## Verification

Six tasks, each implemented against the plan and independently reviewed for spec compliance and
quality; every task passed. The `@sozai/codec` catalog bump to `^0.4.0` rode along on the branch
as separate maintenance.

The final whole-branch review on the most capable model returned findings that per-task review
structurally could not see — most importantly the re-bind bypass in §2, which it proved with a
repro rather than asserting. One fix wave closed it (WeakMap), documented the codec bump's
base64 strictness change in the changeset, narrowed the entry-guard claim, corrected two stale
comments, and added two interaction tests. The scoped re-review confirmed every finding
addressed with no new breakage.

Workspace green: `turbo run test:types test:unit` 22/22, token 250 tests, capability 77.

QA was skipped by the maintainer's decision — this is a library change whose meaningful test is
a downstream consumer.

## Breaking changes (see changeset)

`@kokuin/token` minor, `@kokuin/capability` patch. An existing `did:peer:4` signer now emits the
long-form `iss` instead of the short form whenever the signed payload names no single string
`aud`; pass `embedLongForm: false` to keep the previous short form. Separately, the
`@sozai/codec` `^0.4.0` bump makes `fromB64`/`fromB64U` reject non-canonical base64 by default,
narrowing what `verifyToken`, `decryptToken` and `decodePrivateKey` accept.

## Follow-on work extracted

- `backlog/2026-08-04-isverifiedtoken-does-not-rebind.md` — the published `isVerifiedToken`
  export still returns `true` for a mutated verified token.
- `backlog/2026-08-04-doc-size-guard-covers-one-array.md` — the O(1) pre-guard bounds only
  `verificationMethod`; the DID cache's bound is also redundant with its callers.
- `backlog/2026-07-02-security-model-docs.md` is unblocked by this work and should document the
  settled `iss` rule.
