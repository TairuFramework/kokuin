# `did:kokuin:` controller follow-ons

**Priority:** low. Nothing here is blocked; each is additive or a hardening of something that
already works. See `completed/2026-08-11-controller-key-events.complete.md` for context.
**Origin:** the `did:kokuin:` controller work, 2026-08-11 — items raised in review and adjudicated
as accepted limits rather than defects.

## A revoke signer callback, for the Ledger

`createRevokeWithKey(privateKey, …)` lets a device holding a management capability author a revoke
with its own signing identity rather than the profile seed. That was the point of the tier: the
actor the capability-authorised revoke exists for is a hot device, not the cold root.

It takes a **private key**, so any signer that never exposes one cannot use it — the Ledger, and any
WebCrypto non-extractable key. That shape was chosen because nothing in the stack can sign raw
bytes: `SigningIdentity` signs JWTs, `IdentityProvider` hands back a `SigningIdentity`, and a
`KeyEntry` hands back the private key. A signer callback would have been a new shape invented for
one caller.

Worth noting for whoever takes it: **the firmware can already do this.** `INS.SIGN_MESSAGE` signs
raw bytes on-device; only the host-side `@kokuin/ledger-device` withholds it, exposing `signToken`
alone. So this is a host-side overload plus an exposed instruction, not a firmware change. Additive
either way — the private-key form keeps working.

## Two anchors hold the position-refusal guard

The capability verifier refuses a capability-authorised revoke that arrives without a log position,
rather than falling back to the caller's registry — which was the position bypass verbatim, and is
reachable by version skew as well as by direct call.

The guard is unreachable from typed code by design, so no type-honest mutation can kill it; only the
cast its test uses. It is pinned by exactly two things: that test, and the row in the reason-string
test that writes the refusal sentence out longhand. Deleting both together would go unnoticed. If a
cheaper structural anchor exists, it is worth adding.

## The guard rule has a blind spot

The rule adopted for keeping or deleting a defensive guard: a guard stays when the value it inspects
can reach it in the shape it rejects, and is removed only when it cannot, with the unreachability
pinned by a test. Sound, and better than the alternative of shipping code no test can defend.

Its blind spot is that it does not separate guards that change an **outcome** from guards that
change only a **reason** no caller can observe. Two of the six knowingly-unkillable guards are the
latter. Distinguishing them would make the next audit cheaper.

## `MAX_CANONICAL_DEPTH` is a wire-visible constant

Canonical encoding now rejects values nesting deeper than 64. It never changes the encoding of
anything it accepts, so no issued identifier moves and no existing signature is affected — but
`canonicalBytes` throws above the bound for a direct caller, and `verifyDigest` returns false. 64 was
chosen by judgement as comfortably above any real event and far below the stack limit. Nothing
downstream uses these helpers today (checked in `kubun` and `kumiai`), so revisiting is cheap now
and expensive later.

## A caller's `verifyToken` hook can still wedge a resolver

If a caller's hook resolves the same profile through the same resolver, the resolution deadlocks. It
is a quiet deadlock rather than a spin — reproducible in about a second with a `Promise.race` — and
it is documented in the resolver's docstring and in the auth skill, with the working two-resolver
topology beside it. Pinned as an accepted limit. A recovery timer was rejected twice on the
reasoning that no file here can know a legitimate `loadLog` duration, so any timeout turns
correct-but-slow resolution into intermittent failure.

## DIF registration

`did:kokuin:` is not registered with the DID method registry. Nothing in the design depends on it;
revisit once the event format has stopped moving.
