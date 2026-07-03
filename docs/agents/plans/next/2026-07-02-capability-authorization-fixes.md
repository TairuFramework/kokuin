# Capability authorization fixes

**Status:** next
**Origin:** `completed/2026-07-02-audit.complete.md` (Critical #1, High: kid/aud, Medium: revocation, nit: signerID)

## Context

The capability + token authorization model has a privilege-escalation bug and several
gaps that let tokens authorize more than they should. All are code-level and verified
against source. Fix before external consumers depend on the auth layer.

## Work

### Permission prefix match grants ancestor resources (Critical #1)

`packages/capability/src/index.ts:244` (`hasPartsMatch`) only iterates `expected` parts.
When the requested permission is a path-prefix of the grant, the loop falls off the end
and returns `true`. A grant of `res: 'foo/bar/baz'` authorizes `foo/bar` and `foo`;
`act: 'test/read'` authorizes `act: 'test'`. Affects `checkCapability`,
`assertValidDelegation`, and `createCapability` — a delegate can mint capabilities scoped
*wider* than its parent.

- Fix: return `false` when `actualParts` runs out before all `expectedParts` are matched.
- Test gap: no test covers requested-is-prefix-of-grant. Add one.

### Explicit `kid` bypasses the `authentication` relationship (High)

`packages/token/src/did.ts:132` (`resolveKidOrAuth`) searches all of `verificationMethod`
when a `kid` is present, so a key listed only under `assertionMethod` can sign tokens. The
no-kid fallback correctly uses `authentication[0]`; the kid path must enforce the same
relationship.

### No audience validation (High)

`VerifyTokenOptions` (`packages/token/src/token.ts:27`) has no expected-audience option,
and `checkCapability` (`packages/capability/src/index.ts:357`) never compares the
invocation `aud` to the verifying service. A token for service A replays against B. Add an
expected-audience option and enforce it.

### `createRevocationRecord` signs nothing (Medium)

`packages/capability/src/revocation.ts:38` takes a `signer` but produces unauthenticated
records; nothing checks the revoker issued the revoked token. Either sign the record or
drop the param.

### Naming nit

`signerId` → `signerID` at `packages/capability/src/index.ts:190` (capital `ID`).

## Out of scope

- Token verification safety (`alg:none`, nullish guards, peer4 DoS) — see
  `next/2026-07-02-token-verification-hardening.md`.
- KeyStore contract + adversarial tests — see
  `next/2026-07-02-keystore-contract-and-adversarial-tests.md`.
