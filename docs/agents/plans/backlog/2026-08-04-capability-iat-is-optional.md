# A capability's `iat` is optional, so its lifetime is unbounded

**Status:** backlog
**Origin:** found downstream in kubun, branch `fix/delegation-revocation-binds-on-comembers`,
question 3.1 (2026-08-04). Kubun has compensated locally; nothing is broken today. Filed so the
compensation does not have to be reinvented by the next consumer.

**Related:** `completed/2026-08-04-peer4-audienceless-iss-and-verify-hardening.complete.md`
touched the same verification surface but did not cover `iat` — it was about `peer:4` `iss`
forms. The two are independent, and that work has landed, so this stands on its own.

## The claim

`iat` is optional on a capability payload:

```ts
// packages/capability/src/index.ts:69
iat?: number
```

`createCapability` does not default it — the payload is forwarded verbatim (`index.ts:197-198`
for the root-capability case). So a token with no `iat` is representable, mints cleanly, and
reaches the wire unchanged.

Verification tolerates it explicitly:

```ts
// packages/capability/src/index.ts:306-307
export function assertValidIssuedAt(payload: { iat?: number }, atTime?: number): void {
  if (payload.iat != null && payload.iat > (atTime ?? now())) {
```

The `!= null` short-circuit means an absent `iat` passes. So a capability carrying `exp` but no
`iat` is valid by kokuin's own rules.

## Why it matters

A capability's **lifetime** is `exp - iat`. Any consumer that wants to bound how long a
capability may live — rather than only when it expires — computes that difference, and the
computation is silently unanswerable when `iat` is missing.

The failure mode is the awkward one: it is reachable by *omitting* a claim, not by setting one
badly. A bound written as

```ts
if (payload.exp - payload.iat > MAX) { reject }
```

does not reject an unbounded token; it evaluates `exp - undefined` to `NaN`, and `NaN > MAX` is
`false`. The guard reads as present and enforces nothing. Nothing throws, no test fails, and the
token is accepted.

Kubun hit this while adding a 30-day cap on accepted delegated write capabilities. Its retention
of a revocation is keyed off the revocation's own `iat`, so a capability that outlives that
retention starts being honored again after the revocation is swept — which is what the bound
exists to prevent. Kubun now null-guards `iat` alongside `jti`/`exp` at its receive path
(`packages/plugin-p2p/src/groups/store-received-grant.ts`) and skips a grant without one.

No kokuin consumer is currently broken: both kubun minters stamp `iat`, and the only repo call
sites that omit it are tests that attach the token to a mutation rather than store it.

## Options

1. **Default `iat` in `createCapability`** when the caller omits it — `Math.floor(Date.now() / 1000)`.
   Smallest change, makes every kokuin-minted capability answerable. Does not help a token minted
   elsewhere, which is the case a receiver actually has to defend against.
2. **Make `iat` required** on `CapabilityPayload`. Type-level, catches producers at compile time,
   and a breaking change for any consumer constructing payloads by hand. Still says nothing about
   a token arriving over the wire.
3. **Reject an `iat`-less capability at verification** — the fail-closed reading, in
   `assertValidIssuedAt` or its caller. This is the one that binds a foreign minter, which is the
   only place the guarantee is worth anything to a receiver.
4. **Leave it, and document that lifetime is not a kokuin-level guarantee** — every consumer
   wanting a TTL bound must null-guard `iat` itself. Legitimate if `iat` is deliberately optional
   for a reason not visible from downstream; if so, the reason belongs in a comment on the field,
   because the natural way to write the bound is wrong.

Options 1 and 3 compose and are probably the pair worth taking together — 1 so kokuin's own
tokens are always answerable, 3 so a receiver can rely on it. Deciding between 3 and 4 is the
substantive question: whether "this capability has a computable lifetime" is a property kokuin
guarantees or one each consumer re-derives.

## Note on scope

Checked before filing: **revocation records do not share the problem.** `RevocationClaims` types
`iat: number` as required (`packages/capability/src/revocation.ts:11`) and
`createRevocationRecord` stamps it unconditionally (`:80`, `signToken({ jti, rev: true, iat: now() })`).
So the capability payload is the outlier, which is itself an argument for option 1 or 2 — the
two sibling shapes already disagree about whether an issuance time is optional.

Worth the same check on any other payload shape carrying an issuance time before settling on an
answer, so whichever rule is chosen is applied uniformly.
