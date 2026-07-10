# Token verification hardening

**Status:** complete
**Date:** 2026-07-10
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #3, Medium: nullish guards, peer4 DoS)
**Branch:** `token-verification-hardening` (16 commits: 5 fixes + tests, spec/plan, changeset)

## Goal

Make `@kokuin/token` safe for a direct consumer standalone. The package is a public
primitive; the capability layer partly shielded it, but a direct consumer of `verifyToken`
could be spoofed by an unsigned token or DoS'd by a crafted DID. Three audit findings plus a
fourth discovered mid-implementation, all closed.

## What was built

### 1. `verifyToken` rejects `alg:none` by default (Critical #3)

Both the object path and the string path previously returned an unsigned payload with
attacker-chosen claims and skipped `exp`/`nbf`. Now `verifyToken` rejects unsigned tokens
unless the caller passes `allowUnsigned: true`, and validates the header and time claims on
the unsigned path when it does.

**Key design decision — narrowing as the enforcement mechanism, not just a runtime check.**
The strict (default) overload returns `VerifiedToken<Payload>`, a type that structurally
cannot hold an unsigned token (`VerifiedToken = SignedToken & { verifiedPublicKey }` requires
`signature: string` + `data: string`; `UnsignedToken` has `signature?: undefined` and lacks
those fields, so it is not assignable). A consumer who forgets to re-check therefore cannot
reach an attacker-controlled payload — the type system stops them at compile time. This was
verified at the type level in the final review (a `@ts-expect-error` on the unsigned→verified
assignment fired as required), so the defense is structural, not cosmetic.

Three overloads are required, not two: strict (`allowUnsigned?: false` → `VerifiedToken`),
opt-in (`allowUnsigned: true` → `Token` union), and a fallback (`options: VerifyTokenOptions`
→ `Token` union). Without the fallback, a caller passing a widened `boolean` for
`allowUnsigned` matches no overload. The fallback returns the conservative `Token` union, so
it is never unsoundly `VerifiedToken`. Every in-repo caller passes no options or an object
literal, so each binds the intended overload.

`unwrapEnvelope` (`jwe.ts`) opts into `allowUnsigned: true` only on its 3-part-message path,
which handles `'plain'` mode; the `jws-in-jwe` path keeps requiring a signature.

### 2. Total type guards (Medium)

`isSignedToken`, `isUnsignedToken`, `isVerifiedToken` now accept `unknown` and return `false`
for nullish/primitive input instead of throwing `TypeError` (which had propagated to
`assertCapabilityToken(null)`). An input failing all three guards falls through
`verifyTokenInner` to a safe `throw`, never a returned value.

### 3-5. Bounded every attacker-controlled base58 decode reachable before signature verification

`@scure/base`'s base58 is O(n²) big-integer radix conversion. The audit named one path; a
full decode-site inventory during implementation found three, all closed by length-checking
the input *before* the decode:

- **`did:peer:4` long form** (`decodePeer4`): default `maxDocSize` dropped from 64 KiB to
  4 KiB; the encoded pre-check now uses the real base58 expansion ratio (~1.3658) with an
  8-char slack instead of an arbitrary `2x`; the previously unbounded hash segment is capped
  at 64 chars.
- **`did:key`** (`getSignatureInfo`): the payload was decoded in full before any size check,
  and is reachable from `verifyToken` via the attacker-controlled `iss` claim *ahead of* the
  signature check. Now bounded at 64 chars (largest supported key, ES256, is 48).
- **`did:peer:4` short form via a `resolver`** (`resolveIssuerWithDoc`): the resolver-returned
  document was re-encoded (`encodePeer4`, an O(n²) base58 *encode*) and its `publicKeyMultibase`
  decoded, both unbounded and before the signature check — the most reachable of the three and
  with no ceiling (72s measured for a 100 KB field). Now the doc's canonical size is bounded
  (reusing the 4 KiB default) before the encode, and each `publicKeyMultibase` is length-checked
  in the shared `resolveKidFromDoc`.

The three size constants (`MAX_HASH_ENCODED`, `MAX_DID_KEY_ENCODED` = 64; `DEFAULT_MAX_DOC_SIZE`
= 4096; derived `maxEncoded` = 5606) were checked mutually consistent — a legitimate max-size
input passes every bound with no off-by-one.

## Verification

Each task was implemented TDD-first and independently reviewed (adversarial, each reviewer
writing its own smuggle/DoS tests). A final whole-branch review on the most capable model
returned SHIP with zero findings, checking overload soundness, the `VerifiedToken` narrowing
promise, guard×gate and audience×allowUnsigned interactions, bound consistency, changeset
accuracy, and regressions. Workspace green: `turbo run test:types test:unit` 20/20, token 224
tests, capability 76 tests.

## Breaking changes (see changeset)

`@kokuin/token` minor, `@kokuin/capability` patch. `verifyToken` rejects `alg:none` by default
(pass `allowUnsigned: true` to restore); its return type is `VerifiedToken<Payload>` unless
`allowUnsigned` is set; the default `did:peer:4` document size limit is 4 KiB, down from 64 KiB.

## Follow-on work extracted

- `next/2026-07-10-verified-token-mutation-and-decode-hardening.md` — the WeakSet
  verified-token re-submit gap plus two residual base58 hardening items.
