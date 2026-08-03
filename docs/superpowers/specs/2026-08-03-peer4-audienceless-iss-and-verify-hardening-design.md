# `did:peer:4` audience-less issuers, and token verification hardening

**Date:** 2026-08-03
**Branch:** `fix/peer4-audienceless-iss-and-verify-hardening`
**Sources:** `next/2026-08-03-peer4-revocation-records-are-unverifiable.md` (security, fail-open),
`next/2026-07-10-verified-token-mutation-and-decode-hardening.md` (deferred review findings)

## Problem

A `did:peer:4` identity signing a payload that names no single audience emits a **short-form**
`iss`. A short form is a hash of the DID document and cannot be resolved without that document,
which only the long form carries. A recipient with no prior cache entry for that signer therefore
fails the token at signature verification with `Unknown DID: did:peer:4z…`.

`pickIss` (`packages/token/src/identity.ts`) decides the form:

```ts
if (!isPeer) return id
if (embedLongForm === true) return longForm
if (embedLongForm === false) return id
const aud = payload.aud
if (typeof aud !== 'string') return id   // ← audience-less tokens land here
const normalizedAud = normalizeDID(aud)
if (sentTo.has(normalizedAud)) return id
sentTo.add(normalizedAud)
return longForm
```

The `sentTo` first-contact cache is keyed on `aud`, so an audience-less token never consults it,
no matter how many other tokens the same signer has sent.

Two producers inside kokuin sign audience-less payloads today:

- `createRevocationRecord` (`packages/capability/src/revocation.ts`) — claims are `{jti, rev, iat}`.
  A peer:4 grantor can revoke nothing: the record binds on the grantor's own device, which stores
  its self-minted row without verifying it, and nowhere else. Found from kubun and confirmed
  empirically in kubun's suite, not inferred.
- `createRotationAssertion` (`packages/token/src/rotation.ts`) — claims are
  `{type, to, toLongForm, issuedAt}`. Same shape, same failure.

An array-valued `aud` hits the identical branch, since the check is `typeof aud !== 'string'`.

The defect is latent rather than live: `chooseMethod` only selects peer:4 for identities carrying
more than one key or a non-signing key, and no such identity reaches a revocation in a downstream
repo today. It is a trap door — the first identity that adds a KEM key for key agreement would
silently make revocation broadcast-unverifiable, with no error at the point of revocation and a
debug-level skip on every recipient.

Bundled with it are three findings deferred from the `token-verification-hardening` branch. None is
remotely reachable pre-auth, and each touches the same files.

## Design

### 1. `pickIss`: audience-less means self-resolving

`packages/token/src/identity.ts` — the `typeof aud !== 'string'` branch returns the long form:

```ts
const aud = payload.aud
// No single named audience: there is nothing to key first-contact on, and the recipient may
// never have seen this doc. Embed the long form so the token resolves standalone.
if (typeof aud !== 'string') return longForm
```

Consequences:

- `createRevocationRecord` and `createRotationAssertion` need no change. They become verifiable by
  inheritance, and every future audience-less producer is correct by default.
- Array-`aud` payloads get the long form for the same reason.
- `embedLongForm: false` remains the escape hatch for a hot broadcast path that knows its
  recipients already hold the doc. It becomes an explicit opt-in to that assumption rather than a
  silent default.
- Size cost: a long-form `iss` for a two-key document is roughly 400 characters against 57 for a
  short form. Audience-less tokens are the rare case; the opt-out covers the exception.

The `SignTokenOptions.embedLongForm` JSDoc currently documents the `undefined` default as "use long
form on first token to a given `payload.aud`, short form thereafter". It gains the new rule: always
long form when the payload names no single string audience.

Only `buildIdentity`'s `MultiKeyIdentity` implements `pickIss`. `createSigningIdentity` and
`@kokuin/ledger-device`'s provider are `did:key`-only and unaffected.

### 2. Verified-token fast path re-binds to the signed bytes

`verifyToken`'s object path returns early when `isVerifiedToken(token)` is true, re-checking only
time and audience claims — not the signature. Membership is a `WeakSet` keyed on object identity
and only ever admits a freshly-constructed result object, so identity cannot be injected from
outside. But in-process code that mutates a previously-verified token's `payload` in place and
re-passes the same object reference gets the tampered payload back as verified.

`packages/token/src/token.ts`:

```ts
if (isVerifiedToken(token)) {
  // Signature was checked when this object entered `verifiedTokens`, but the payload may have
  // been mutated in place since. Re-bind it to the signed bytes — cheap next to a signature
  // verification, and enough to reject tampering.
  if (token.data == null) throw new Error('Invalid token: verified token missing data')
  getVerifiableData(token)
  assertTimeClaimsValid(...)
  assertAudienceValid(...)
  return token
}
```

`getVerifiableData` already recomputes the header and payload encodings and compares them against
the signed `data`, falling back to a canonical-form comparison when the serializations differ. A
mutated payload matches neither and throws `Invalid token: data does not match header and payload`.
Two JSON serializations, no signature verification, nothing frozen, no caller-visible change to the
returned object.

The `data == null` assertion is load-bearing: without it, deleting `.data` makes `getVerifiableData`
return a freshly recomputed value and the check becomes vacuous. Every object the `WeakSet` admits
carries `data`, so the assertion rejects nothing legitimate.

Freezing the payload was rejected: `result.payload` is the same reference as the caller's input
payload, so freezing it would freeze the caller's own object, and a shallow freeze would still leave
nested claims mutable. Dropping the fast path entirely was rejected for the signature verification
and DID resolution it would pay on every re-submit.

### 3. O(1) pre-guard on resolver document size

`assertDocWithinMaxSize` (`packages/token/src/peer4.ts`) must fully `canonicalStringify` an
attacker-supplied document before it can measure and reject it. That serialization is linear, not
the O(n²) base58 that was the original bug, but a pathological document — a `verificationMethod`
array with millions of entries — still costs linear time pre-auth (~3.5s measured at 5M entries,
~100ms at a realistic 100k).

Before serializing, reject on entry count:

```ts
if (
  Array.isArray(doc.verificationMethod) &&
  doc.verificationMethod.length > Math.ceil(maxSize / MIN_VERIFICATION_METHOD_BYTES)
) {
  throw new Error(
    `did:peer:4 resolver doc has too many verification methods: ${doc.verificationMethod.length} > ${maxEntries}`,
  )
}
```

`MIN_VERIFICATION_METHOD_BYTES` is derived, not fixed, so the guard tracks any `maxDocSize` the
caller passes. The minimum serialized entry — `{"id":"","type":"","publicKeyMultibase":""}` at 43
bytes plus an array separator — is 44 bytes. The constant is set to **40**: undercounting yields a
larger, more permissive cap, so the guard can never reject a document the full measure would have
accepted.

The error message names the entry count, distinct from the byte-size error, so the two rejections
are distinguishable in tests and in logs.

### 4. Bounded encode in the DID cache

`createInMemoryDIDCache().set()` (`packages/token/src/cache.ts`) calls `encodePeer4(doc)` with no
size bound. It is reached only after signature verification succeeds, so it is not a pre-auth DoS,
but the document it encodes originated from a resolver. It calls `assertDocWithinMaxSize(doc)`
before encoding, returning a rejected promise to match its two sibling error paths:

```ts
try {
  assertDocWithinMaxSize(doc)
} catch (err) {
  return Promise.reject(err)
}
```

## Testing

- **token / identity**: a peer:4 identity signing an audience-less payload emits a long-form `iss`,
  and `verifyToken` succeeds on it with no resolver and no cache. An array-valued `aud` likewise
  yields the long form. `embedLongForm: false` still forces the short form. The existing
  first-per-aud tests pass unchanged.
- **token / rotation**: a peer:4 rotation assertion verifies from a verifier with no prior cache.
- **capability / revocation**: the reported reproduction — a peer:4 signer's revocation record
  verifies with no prior cache, and `createRevocationChecker` rejects the revoked token.
- **token / verification**: mutating a verified token's payload in place and re-submitting the same
  object reference throws. Deleting `data` from a verified token and re-submitting throws.
- **peer4**: a document whose `verificationMethod` array exceeds the derived cap is rejected with
  the entry-count error rather than the byte-size error.
- **cache**: `set()` with an oversized document rejects.

## Release

One changeset. `@kokuin/token` takes a **minor**: the default `iss` for an audience-less peer:4
token changes on the wire, which is more than a patch implies even though it fixes a defect. The
fixed release group (token, capability, browser, node, deterministic) ships together.
`@kokuin/capability` carries no source change — its fix arrives through the token dependency.

## Out of scope

- `backlog/2026-07-02-security-model-docs.md`, which this unblocks and which would document the
  settled `iss` behaviour.
- Anything already shipped on the `token-verification-hardening` branch.
- Recipient-side resolution of a short form from a document the recipient already holds. The
  `DIDCache` already covers that case, and it does not help first contact.
