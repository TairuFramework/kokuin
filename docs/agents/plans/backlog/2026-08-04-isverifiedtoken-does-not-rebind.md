# `isVerifiedToken` does not re-bind, and its doc comment does not say so

**Source:** final whole-branch review of
`completed/2026-08-04-peer4-audienceless-iss-and-verify-hardening.complete.md`
**Priority:** low — no in-repo consumer is exposed; this is a contract-clarity gap on a
published export.

## What

`verifyToken`'s already-verified fast path now re-binds a token's payload to the signed bytes
captured in a `WeakMap` at verification time, so a mutated payload is rejected. `isVerifiedToken`
(`packages/token/src/token.ts`, exported from the package index) does not: it is a synchronous
`verifiedTokens` `WeakSet` membership check plus a shape check, so it returns `true` for a
verified token whose payload was mutated in place afterwards.

The same applies transitively to `isCapabilityToken` in `@kokuin/capability`, which is also a
published export.

## Why it is not a live bug

Every in-repo consumer is safe. `isCapabilityToken` is only reached via
`assertCapabilityToken`, and each of those call sites is the statement immediately following an
`await verifyToken(...)` on the same object — the re-bind has already run.

The exposure is that both guards' doc comments ("Check if a token was verified by `verifyToken`
in this process") now understate the contract relative to `verifyToken`'s own. An external
consumer could reasonably read `isVerifiedToken(token) === true` as sufficient for an
authorization decision.

## Proposed fix

A doc-comment sentence on `isVerifiedToken` (and on `isCapabilityToken`) stating that it is an
identity check which does not re-bind the payload to the signed bytes, and that authorization
decisions must go through `verifyToken`. No code change.

Making the guard itself re-bind was considered and rejected in passing: it is synchronous and
cheap by design, and callers use it as a type narrowing predicate, not as a gate.
