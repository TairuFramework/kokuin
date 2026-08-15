# Security model — `did:kokuin:`, capabilities, and what a consumer owes

What this layer guarantees, what it assumes, and the handful of things a consumer has to get right for the guarantees to hold. Scoped to the profile DID and the capability system built on it; for the API surface see [./controller.md](./controller.md) and [./capability.md](./capability.md).

Nothing here is aspirational. Every rule below exists because its absence was a defect somebody built and demonstrated, and the ones that are still open are named as open.

---

## What the design is for

A profile identifier that survives key rotation, device theft and total device loss: one stable DID per profile, several concurrent keys, rotation and revocation including recovery from a stolen device key, offline verifiability, and algorithm agility so post-quantum arrives without moving the identifier. A restored mnemonic reproduces the DID with no other input, and the seed is needed for rare ceremonies only.

**Two recovery guarantees, kept distinct.** *Control* recovery — can this profile keep signing and rotating? — needs the mnemonic, plus the head digest and `seq` where the log holds non-reproducible events. It survives total device loss, because the recovery commitment lives in the deterministic inception and the root can author a superseding reset with no log at all. *Provability* recovery — can it prove its key history to a stranger, offline? — needs the full log and does **not** survive total device loss.

## The remedy ladder

Three rungs, in increasing cost and blast radius. Each exists because the one below it is not enough for some compromise.

| Compromise | Remedy | What it costs |
| --- | --- | --- |
| A device is lost or stolen | `rev` naming the device DID | One event. The device's capabilities stop verifying from that log position onward |
| An authority key leaked | `rot`, then `rev` naming the retired key | Two events, in that order. Already-issued material stays valid; the leaked key stops both minting and verifying |
| The management tier has gone bad | Cold `rot` clearing the deny set | Reaching for the root. Every prior denial is discarded — build the snapshot with `pruneDenySet` |
| Everything below has failed | `reset` — a rotate signed by the recovery key | The generation bumps and **every capability minted under the prior one dies** |

The ordering of the second row is not a nicety. A `rev` may not name a key the profile currently publishes: rotation is what an active compromise calls for, its pre-rotation commitment is unforgeable by the holder of the leaked key, and denial is for what the rotation leaves behind. Denying a live key would also let a capability-authorised revoke with a wildcard `res` stop the *root* signing with a single event, straight across the tier boundary.

## The two questions a resolver answers

The single most important distinction on this method.

```typescript
resolve(did, header)          // "can this profile sign with this key NOW?"
resolveHistoric(did, header)  // "did this profile sign with this key at some point?"
```

`resolve` answers from the **head's key set alone**. A key the profile has rotated away answers no, whatever the reason for the rotation was — and the reason that matters is compromise. This is what makes `rotate` genuinely retire a leaked key for new issuance, and it is the only question that authenticating a live signer may ask.

`resolveHistoric` accepts any key that was authoritative at some position **within the current generation**. What it establishes is "this profile did once hold this key", never "this profile holds this key". Use it only where the artefact was minted in the past and must survive the subject's routine key hygiene — an already-issued capability, a revocation record, an archived grant. A `reset` still invalidates: the scan stops dead at the generation boundary.

Callers opt in explicitly with `verifyToken({ historic: true })`. `@kokuin/capability` uses it unconditionally, and has to: head-only resolution there would invalidate every outstanding capability on a routine rotate, and would make a revocation record signed by a since-rotated key raise an error the revocation checker swallows — silently un-revoking, on the one path that must never fail open.

The cost of that, stated plainly: a leaked, since-rotated authority key can still mint a capability that verifies. Rotation cannot be the fix without breaking the promise that a rotate does not invalidate already-issued material. **Retirement is explicit** — that is what a `rev` naming `#<key>` is for, and it is enforced where every `did:kokuin:` signature check reaches a resolved key, so it covers both settings of `historic`, everything the capability package verifies, and the fold's own capability-authorised revoke.

## The deny set

One heterogeneous set with two spellings that cannot collide:

- `did:…` denies a **holder**. `@kokuin/capability` refuses any capability whose `aud` it names, on every link of a chain and on a capability presented directly.
- `#<multibase key>` denies a **signer**. The resolver refuses to answer with that key and drops it from the agreement set.

**Match, never enumerate.** Ask whether the identifier in hand is present; do not treat the set as a list of revoked devices. A consumer that enumerates will see `#`-prefixed entries it has no vocabulary for.

Two different position rules apply, and both are deliberate:

- A **DID denial** is evaluated at the position being verified, inside the fold. An event is authored at one place in the log, and a later clearing must not retroactively validate it.
- A **key denial** is evaluated at the **head**. A denial is a statement about the key, and the position an artefact carries is author-supplied — a thief would otherwise present a token whose `kid` resolves at a position before the revoke.

For the same reason, `resolveDenySet` answers for **now**, never for a position a capability names: `iat` is author-supplied and backdatable, so anchoring to it would let a revoked holder choose a moment before it was denied.

## Things a consumer must do

Each of these is a rule whose violation fails **open** or bricks something, and each was a real defect.

**Forward every optional resolver member through any wrapper.** A wrapper that forwards `resolve` and stops there — caching, metrics, tracing — type-checks and is catastrophic in both directions. Dropping `resolveDenySet` turns every denial into a pass, silently. Dropping `resolveHistoric` makes every capability unverifiable, because the historic question is refused rather than answered from `resolve`.

**Pass `methods` wherever a capability is checked.** `checkCapability` and `checkDelegationChain` now refuse a subject whose deny set no registry can answer for (`DENY_SET_UNAVAILABLE`) rather than skipping the check in silence. A subject whose identifier carries its own keys — `did:key`, `did:peer` — needs no registry and has no deny set to miss.

**Give a `verifyToken` hook its own resolver.** A hook that resolves the profile being folded through the same resolver joins the fold that is calling it and waits on a promise that cannot settle.

**Configure `history` on any resolver that will see a DID twice.** Without it a truncated log is accepted; see below.

**Build a deny snapshot with `pruneDenySet`.** A rotate's `d` replaces the accumulated set. Writing one by hand and forgetting an entry un-revokes a device or un-retires a leaked key, with nothing in the log to say so.

**Read `unverified` on a branch resolution.** Non-zero means a branch could not be checked and the answer is provisional — including a duplicity report, which might have been settled by the branch that was skipped.

**Do not hold the seed on a daily path.** `createControllerIdentityWithKey` signs as the profile with the current authority key alone. A process holding the seed holds the power to rotate, reset, and derive every key at every index — the whole point of the tier boundary is that the daily path does not.

**Rebuild an identity from a re-read log after a reset.** Tokens signed with a prior-generation key fail with `kid names a key outside the current generation`.

## The `cnf` pin, and why the audience is never resolved

A capability authorising a log revoke must pin its audience's signing key in `cnf` (RFC 7800), at mint time, with `audienceConfirmation(key)`. The fold checks the revoke event's own signature against exactly that key.

The pin is mandatory and is **never** resolved. Resolving the audience is the bug it exists to remove: a revoke that stops verifying makes the whole log unfoldable and the profile's DID permanently unresolvable, so an audience rotating its own key could brick somebody else's identity. A capability with no `cnf`, or one whose `cnf` is unreadable, is rejected rather than resolved.

The pin must also **name the audience**, checked against the audience's own identifier and nothing else. Authority on this path follows `cnf` while revocation follows `aud`; nothing makes them the same party unless this does, and a capability where they differ is a revoke authority that revoking cannot reach. That means the audience must be a `did:key`, or a `did:peer:4` **long form** whose `authentication` carries the key. An audience whose identifier carries no key — a `did:kokuin:` profile, a short-form `did:peer:4` — is refused, at verification and, more cheaply, at mint through `assertRevokeCapabilityAudience`. Every audience that remains has immutable key material, so the rotation hazard the rule was written against cannot arise at all.

**A capability authorising a revoke must carry `exp`.** An omitted one is not a long grant but a permanent one — authority over the log for the life of the profile, with the deny set as the only remedy. A bounded grant lapses whether or not anybody notices, which is the asymmetry that matters at an offline verifier: revocation reaches it best-effort, expiry unconditionally. The *length* is not mandated, because the management capability is minted by the cold root and a short ceiling would mean reaching for the hardware to renew — set `maxLifetimeSeconds` on the verifier if you have a policy.

## Delegation

Chains are capped at `DEFAULT_MAX_DELEGATION_DEPTH` (four: management → device → connector, plus headroom), counting the capability presented directly. Every link is checked against the request, not merely the leaf's ancestors: a presented capability's own `act`/`res`, `exp`, `nbf` and `iat` bind exactly like any other link's, and its audience is subject to the subject's deny set. Attenuation at the last hop was once a no-op precisely because those checks were missing.

## Assumptions and named limitations

These are the things this design does **not** protect against. Read them as part of the contract.

**A stolen mnemonic is terminal.** The thief holds every key at every index including the recovery key, and can always rotate ahead of the owner. This is the price of seed-rooting.

**Truncation is only partly closed.** A peer serving a prefix produces a log that folds cleanly, chains every digest, verifies every signature, and yields a deny set missing exactly the entry that matters. The `history` store refuses one that is behind a log this party has already seen — which defeats replaying a stale prefix — but does nothing on a **first encounter**. Closing that needs a witness or an anchor: the profile publishing its head digest somewhere a verifier can reach independently. That is a subsystem, and it is not built. This is *suppression*, and the named limitation about forks does not reach it — there is no second branch to compare, only an honest-looking prefix.

**Cross-group duplicity is detectable, not preventable.** Detection still needs a member of both groups, an external witness, or a public mirror.

**A thief's planted revocations survive the owner's remedy.** A revocation record naming a key the log published and has since denied is honoured — producing it required the private half of a key the DID itself published, and honouring a revocation only ever subtracts authority. So whoever holds a leaked key can plant revocations for `jti`s they know, and those keep biting after the key is denied. The alternative was the owner's own revocations lapsing at the moment they act on a compromise, which is worse. A record naming a key the log **never** published stays ignored, because `kid` is unauthenticated and honouring it would be a plant-a-record denial of service.

**Unanchored capabilities remain backdatable.** `cap.iat` is author-supplied. A seal (`a` on a rotate) is what anchors a high-value grant to a log position.

**No log compaction.** Every rotation is permanent and replayed at every welcome, which is why the design keeps rotations rare.

**Harvest-now-decrypt-later applies to `ka`.** X25519 is the only key agreement algorithm in this release and durable data encrypts to these keys, so this is a real window. The format is ready — `ka` is an OR set and keys are multicodec-tagged — and only the wire standard is missing. Signatures do not share the exposure: forgery needs a quantum computer at the moment of use, which rotation can stay ahead of.

**Post-quantum token size is a first-order constraint.** ML-DSA-65 takes tokens from ~200 bytes to ~7 KB, and every ledger entry is a signed token.

**No quorum.** One authority key per generation; `kt` and `nt` are pinned to n-of-n and checked. A threshold over seed-derived keys is theatre when the seed is the root. Quorum, if it ever lands, needs the check to move with the enforcement.

**Adopted profiles are out of scope.** A profile not derived from the seed sits at no derivation path, is invisible to the cold picker, and falls outside the pure-mnemonic recovery guarantee.

**Profile granularity defaults to coarse personas.** Per-group profiles maximise unlinkability but fragment ownership and scale ceremony cost as profiles × devices.

## Elsewhere in the stack

Two rules from the token layer that apply to everything above and are easy to miss:

- **Check `isVerifiedToken` after `verifyToken`.** A token that was not verified is not a token that failed to verify.
- **Audience enforcement is the caller's.** `verifyToken` does not decide whether a token was meant for you.

Keystore threat models differ by platform — non-extractable keys in the browser against raw Ed25519 in an OS keyring on Node, and a Ledger key that never leaves the device — and are covered in [./auth.md](./auth.md).

## How this document came to be right

Six defects during execution and five more in a review that ran *after* the work had been summarised, the plan deleted and the branch parked at QA. Every one was found by **building the attack**, none by reading a diff, and several were opened by the fix to the defect before them. Four more were found in a design pass before these docs were written, two of them by construction.

Three patterns generalise, and are worth carrying into any change here: a stub agrees with an implementation that checks nothing; deleting a whole options object proves nothing about its fields; and a forgery that breaks two things at once certifies neither. A fourth is about the tests themselves — a probe written to characterise a suspected hole *passes* while the hole is open, so reading "all green" as "no findings" inverts the result.
