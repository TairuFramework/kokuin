# Capability authorization fixes

**Status:** complete
**Date:** 2026-07-03
**Origin audit:** `2026-07-02-audit.complete.md` (Critical #1; High: kid, aud; Medium: revocation; nit: signerID)

Five authorization-model fixes in `@kokuin/capability` and `@kokuin/token`, implemented
test-first and code-reviewed. 254 unit tests pass. Released via a `minor` changeset (breaking
pre-1.0).

## What was fixed

1. **Permission prefix escalation** — `hasPartsMatch` (`packages/capability/src/index.ts`) now
   iterates the *granted* segments and matches segment-for-segment at equal depth, with a
   trailing `*` grant segment matching the remainder. A grant more specific than the request
   (e.g. `foo/bar/baz` vs requested `foo/bar`) no longer authorizes the broader request — the
   escalation that also let a delegate mint capabilities wider than its parent. No implicit
   descent: `foo/bar` does not cover `foo/bar/baz` without `*`.
2. **kid bypasses authentication** — `resolveKidOrAuth` (`packages/token/src/did.ts`) requires an
   explicit `kid` to be referenced by `doc.authentication`, so a key listed only under
   `assertionMethod` cannot sign. `KidNotFound` still takes precedence for a genuinely absent
   kid.
3. **Audience validation** — `VerifyTokenOptions.audience` (`packages/token/src/token.ts`);
   `verifyToken` rejects when set and `payload.aud` is not among the value(s), and rejects
   unsigned/`alg:none` tokens outright. Applied to the invocation/leaf token only — never
   forwarded into capability-chain verification, where a capability's `aud` is the delegation
   next-hop, not a service audience.
4. **Signed revocation records** — `createRevocationRecord` (`packages/capability/src/revocation.ts`)
   returns a signed token; the checker re-verifies the record signature on use and revokes only
   when the record's `iss` equals the token's issuer (only a token's issuer may revoke it).
5. **signerID** — local rename per conventions.

## Key design decisions

- **Matching semantics:** exact segment match + explicit trailing `*`, not implicit
  hierarchical prefix. Chosen to stay closest to the existing wildcard intent and avoid silently
  broadening every existing grant.
- **Two roles of `aud`:** invocation `aud` = target service (validated); capability `aud` =
  delegation next-hop (enforced by `assertValidDelegation`, never checked against a service
  audience). Audience enforcement is scoped to `verifyToken` on the invocation and is provably
  excluded from chain verification (internal calls pass explicit options with no `audience`).
- **Revocation trust boundary at use:** signature verified both on `add` (ingress hygiene) and
  in the checker (the security boundary), so a custom `RevocationBackend` that stores unverified
  records cannot cause a forged revocation.

## API change (breaking, pre-1.0)

- `RevocationBackend.isRevoked(jti): Promise<boolean>` replaced by
  `get(jti): Promise<RevocationRecord | undefined>`.
- `RevocationRecord` is now a signed token (`SignedToken<RevocationClaims>`), not a plain object.

## Deferred

- Belt-and-suspenders audience check inside `checkCapability` for callers that bypass
  `verifyToken` — deferred (YAGNI); the verify-then-check flow covers the need.
