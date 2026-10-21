# Security model — `did:kokuin:`, capabilities, and what a consumer owes

What this layer guarantees, what it assumes, and the handful of things a consumer has to get right for the guarantees to hold. Scoped to the profile DID and the capability system built on it; for the API surface see [./controller.md](./controller.md) and [./capability.md](./capability.md).

Nothing here is aspirational. Every rule below exists because its absence was a defect somebody built and demonstrated, and the ones that are still open are named as open.

---

## What the design is for

A profile identifier that survives key rotation, device theft and total device loss: one stable DID per profile, several concurrent keys, rotation and revocation including recovery from a stolen device key, offline verifiability, and algorithm agility so post-quantum arrives without moving the identifier. A restored mnemonic reproduces the DID with no other input, and the seed is needed for rare ceremonies only.

**Two recovery guarantees, kept distinct.** *Control* recovery — can this profile keep signing and rotating? — needs the mnemonic, plus the head digest and `seq` where the log holds non-reproducible events. It survives total device loss, because the recovery commitment lives in the deterministic inception and the root can author a superseding reset with no log at all. *Provability* recovery — can it prove its key history to a stranger, offline? — needs the full log and does **not** survive total device loss.

## The remedy ladder

Five rungs, in increasing cost and blast radius. Each exists because the one below it is not enough for some compromise, and the first two need no root at all.

| Compromise | Remedy | What it costs |
| --- | --- | --- |
| An edge device or agent is lost or stolen | A **member revoke** naming its DID | One epoch event, signed by any single management member. Its grants stop verifying for every verifier whose state holds the revoke; offline verifiers learn it no later than its grants expire |
| A management member is lost or stolen | A **member remove** by another member, or a **root revoke or remove** | One epoch event. The member's log authority ends at the removal, and its grants stop verifying wherever the removal is seen. Root adds the denial a member may not |
| An authority key leaked | `rot`, then a revoke naming the retired key | A settlement and an epoch event, in that order. Already-issued material stays valid; the leaked key stops both minting and verifying |
| The management tier has gone bad — mutual removals, a flood, a saturated epoch | A **settlement `rot`** | Reaching for the root. The rotate's snapshot is root's chosen state; the epoch it closes stops counting. Build it with `snapshotOf` |
| Everything below has failed | `reset` — a rotate signed by the recovery key, blind or carrying a snapshot | The generation bumps and **every grant minted under the prior one dies**, carried members' included |

The ordering of the third row is not a nicety. A revoke may not name a key the chain currently publishes: rotation is what an active compromise calls for, its pre-rotation commitment is unforgeable by the holder of the leaked key, and denial is for what the rotation leaves behind. Denying a live key would also let a single management member stop the *root* signing with one event, straight across the tier boundary.

A member may not revoke a member, and may not renew or remove itself. Members leave through remove, which ends their log authority without denying their key, so root can re-admit the device later; only root may deny a member. A member that could deny another would hold a removal that skips the self-remove rule and that root's own add could never undo short of a settlement.

## The two questions a resolver answers

The single most important distinction on this method.

```typescript
resolve(did, header)          // "can this profile sign with this key NOW?"
resolveHistoric(did, header)  // "did this profile sign with this key at some point?"
```

`resolve` answers from the **head's key set alone**. A key the profile has rotated away answers no, whatever the reason for the rotation was — and the reason that matters is compromise. This is what makes `rotate` genuinely retire a leaked key for new issuance, and it is the only question that authenticating a live signer may ask.

`resolveHistoric` accepts any key that was authoritative at some position **within the current generation**. What it establishes is "this profile did once hold this key", never "this profile holds this key". Use it only where the artefact was minted in the past and must survive the subject's routine key hygiene — an already-issued capability, a revocation record, an archived grant. A `reset` still invalidates: the scan stops dead at the generation boundary.

Callers opt in explicitly with `verifyToken({ historic: true })`. `@kokuin/capability` uses it unconditionally, and has to: head-only resolution there would invalidate every outstanding capability on a routine rotate, and would make a revocation record signed by a since-rotated key raise an error the revocation checker swallows — silently un-revoking, on the one path that must never fail open.

The cost of that, stated plainly: a leaked, since-rotated authority key can still mint a capability that verifies. Rotation cannot be the fix without breaking the promise that a rotate does not invalidate already-issued material. **Retirement is explicit** — that is what a revoke naming `#<key>` is for, and it is enforced where every `did:kokuin:` signature check reaches a resolved key, so it covers both settings of `historic` and everything the capability package verifies.

## The deny set

One heterogeneous set with two spellings that cannot collide:

- `did:…` denies a **holder**. `@kokuin/capability` refuses any capability whose `aud` it names, on every link of a chain and on a capability presented directly.
- `#<multibase key>` denies a **signer**. The resolver refuses to answer with that key and drops it from the agreement set.

**Match, never enumerate.** Ask whether the identifier in hand is present; do not treat the set as a list of revoked devices. A consumer that enumerates will see `#`-prefixed entries it has no vocabulary for.

Two different rules decide which denials count, and both are deliberate:

- **Inside the fold**, an epoch event is judged by the denials in its **causal past** — its ancestors and the epoch's starting snapshot — never by concurrent branches or arrival order. An event is authored on top of a particular state, and a denial its author could not have seen does not void it; a denial in its past does.
- **Outside the fold**, every answer comes from the **head**: the chain's last state merged with the whole current epoch. A denial is a statement about a key or a holder, and the position an artefact carries is author-supplied — a thief would otherwise present a token whose `kid` resolves at a position before the revoke.

For the same reason, `resolveDenySet` answers for **now**, never for a position a capability names: `iat` is author-supplied and backdatable, so anchoring to it would let a revoked holder choose a moment before it was denied.

**Denial dominates membership.** A member whose DID (under canonical DID equivalence) or `#`-pinned key a merged denial names is not an effective member: it authorises nothing, and the resolver refuses it as an issuer, until a settlement says otherwise. That is one predicate, used for both the member-revoke guard and dominance, and nothing broader: a DID document anyone can write containing a member's public key is not that member.

### What the deny set governs, and what it does not

The DID-denial reaches a device **only where that device's authority is mediated by the profile** — a capability the profile issued (`aud` is the device), or a group roster the profile's members maintain. `@kokuin/capability` enforces it on every capability; a roster enforces removal itself. There is deliberately **no path where a device authenticates by a bare token and is governed by the profile's deny set**. A plain token's `iss` is the device's own `did:key`/`did:peer`, resolved through that method, which knows nothing of any profile — so nothing consults the profile's deny set, and nothing should, because under this design a device's authority *is* the capability or the roster membership, never the bare signature.

This is an invariant, not an accident, and it is what every consumer already does: enkaku authorizes each request through `checkCapability`, and kumiai through MLS roster membership whose removal is an MLS Remove proposal. Do not add a path that authenticates a device by plain token and expects revocation to reach it. If such a path is ever genuinely needed, it cannot be a bare `verifyToken` — the verifier has no subject and a token carries none, so revocation would have nowhere to look; it would need the subject supplied at the call site and an `isDenied(state, did)` helper, and the deny set is heterogeneous (**match, never enumerate**). The simpler rule holds until then: authority under a profile is granted by something the profile issued, so revocation reaches it there.

A related, decided case: revoking a **self-issued invocation** (`iss === sub`) by `jti` has no effect, and correctly so. That branch of `checkCapability` is a subject exercising its own intrinsic authority, not a delegated grant — there is no delegation to revoke. The *audience* deny-set check still runs on that branch, so a revoked **device** is caught; only a `jti` revocation record against a self-grant is inapplicable, because you do not revoke your own authority with a delegation-revocation record.

## Things a consumer must do

Each of these is a rule whose violation fails **open** or bricks something, and each was a real defect.

**Forward every optional resolver member through any wrapper.** A wrapper that forwards `resolve` and stops there — caching, metrics, tracing — type-checks and is catastrophic in both directions. Dropping `resolveDenySet` turns every denial into a pass, silently. Dropping `resolveHistoric` makes every capability unverifiable, because the historic question is refused rather than answered from `resolve`.

**Pass `methods` wherever a capability is checked.** `checkCapability` and `checkDelegationChain` now refuse a subject whose deny set no registry can answer for (`DENY_SET_UNAVAILABLE`) rather than skipping the check in silence. A subject whose identifier carries its own keys — `did:key`, `did:peer` — needs no registry and has no deny set to miss.

**Give a `verifyToken` hook its own resolver.** A hook that resolves the profile being folded through the same resolver joins the fold that is calling it and waits on a promise that cannot settle.

**Configure `history` on any resolver that will see a DID twice.** Without it a truncated log is accepted; see below.

**Build a settlement snapshot with `snapshotOf`.** A rotate's snapshot replaces the whole state — members and denials. Writing one by hand and forgetting an entry un-revokes a device, un-retires a leaked key or dismisses a member, with nothing in the log to say so. Dropping a holder DID denial is a deliberate re-authorisation, safe only once every authority that could mint grants to that holder has ended (its members removed or settled away) and their grants have expired; waiting for the grants root has seen to expire is not enough, since a malicious member may keep minting. The log has no clock to check that for you.

**Answer each verification from one frozen view.** `resolver.frozen()` folds each DID once and answers every question from that one state. Asked live, a revoke landing between "is the issuer a member" and "is this audience denied" gives a verdict no single state of the log supports.

**Do not hold the seed on a daily path.** `createControllerIdentityWithKey` signs as the profile with the current authority key alone. A process holding the seed holds the power to rotate, reset, and derive every key at every index — the whole point of the tier boundary is that the daily path does not.

**Rebuild an identity from a re-read log after a reset.** Tokens signed with a prior-generation key fail with `kid names a key outside the current generation`.

**Treat a saturated controller as unavailable, not as "nothing denied".** The resolver throws `EPOCH_SATURATED` for every question while the current epoch is saturated; a wrapper that turns that into an empty answer fails open.

## Delegation

Chains are capped at `DEFAULT_MAX_DELEGATION_DEPTH` (four: issuer → device → connector, plus headroom), counting the capability presented directly. Every link is checked against the request, not merely the leaf's ancestors: a presented capability's own `act`/`res`, `exp`, `nbf` and `iat` bind exactly like any other link's, and its audience is subject to the subject's deny set. Attenuation at the last hop was once a no-op precisely because those checks were missing.

## Assumptions and named limitations

These are the things this design does **not** protect against. Read them as part of the contract.

### Accepted risks of the management tier

Chosen with the design, in this form. Each has a root remedy, and none has an automatic one: any rule that picked a winner between member branches would itself be attackable by copying, cycles or digest grinding.

- **A stolen member.** A thief can remove every honest member — from any point where it was a member, even after its own removal, by building on an older state — and every removal stands, so the member set can collapse. It can also deny edge holders, and flood the epoch with events. One root settlement per theft.
- **A stolen member denying a device root is adding.** A member may not revoke a member of its causal past, but an add concurrent with its revoke is not in that past. So a member building on a branch that has not seen root's add can deny the new member's key or DID: the merged member is not effective, and root's re-add of the same key or DID is refused (`member is denied in the causal state`) for as long as the denial stands. The denial also refuses that DID as a capability audience. Nothing in the epoch undoes a denial; the remedy is a settlement whose snapshot leaves it out.
- **A stolen member against offline verifiers.** A removed member keeps its pre-removal log and can mint fresh short grants that a verifier which never sees the removal accepts, until its lease end. The short grant lifetime bounds how late a verifier learns an *edge holder* was revoked; for a stolen member the lease is the bound.
- **Withheld events.** A peer can withhold member events from a verifier that has never seen them — the first-contact truncation limitation below. A verifier with a `history` store never forgets what it has seen.
- **Flood shutdown.** A stolen member can saturate the epoch, and every grant that depends on it, honest agents' included, stops verifying until root settles. Fail closed is chosen over guessing which events to drop.
- **Incomplete settlement.** A removal or denial root never saw is not in its snapshot and is lost; members re-issue their own revokes on the new epoch. Retired-key denials are the one exception the chain enforces once a snapshot has checkpointed them.

### Verification cost

A request may carry up to `MAX_LOG_EVENTS` (8192) epoch events, and nothing about an event is known until its signature is checked. Two limits bound what checking costs, and they split the work by who can cause it.

**Forgeries cost a few checks, then refuse the presentation.** At most `MAX_FAILED_SIGNATURES` (64) signatures may fail across an input; past that the whole input fails with `TOO_MANY_FAILED_SIGNATURES`, and through `authoritativeLog` nothing remembered changes. The count depends on the presentation, not its order. Nothing honest fails a check, so a relay holding no key can no longer make a verifier pay for its flood: 8192 forged root-shaped revokes took **8.2 s** to fold before the limit and are refused in **0.16 s** (65 checks) now.

**Authentic events are checked once.** A presentation of authenticated events still costs one check per event: folding a fresh 4000-event member-signed epoch costs about **4.5 s**, and `MAX_LOG_EVENTS` genuine signatures about 9 s; the worst shape measured, a 4096-event chain with a side event per link joining back to its end, took **10.1 s and about 400 MB** on first presentation. That needs a key — root, or a stolen member, the accepted risk above — and is paid once: what a `history` store holds is not checked again. Re-resolving that held 4000-event epoch with nothing new took **4.5 s** (every event re-verified on every resolution) and takes **0.57 s** now, and the store is not rewritten (a 1.6 MB row for that epoch). What remains is the causal fold itself — joining each event's parents' state, and matching the epoch's denials against signers — which grows with the epoch and is paid on every resolution; the joins alone were about 1.4 s in the worst shape. The held epoch with 8192 forgeries presented beside it took **14.8 s** and is refused in **0.67 s**.

Resolve through a `history` store wherever the same DIDs come back, and rate-limit presentations per peer where a first presentation's cost matters.

### Other limitations

**A stolen mnemonic is terminal.** The thief holds every key at every index including the recovery key, and can always rotate ahead of the owner. This is the price of seed-rooting.

**Truncation is only partly closed.** A peer serving a chain prefix, or the full chain with an epoch revoke withheld, produces a log that folds cleanly, chains every digest, verifies every signature, and yields a deny set missing exactly the entry that matters. The `history` store refuses one that is behind a log this party has already seen — which defeats replaying a stale prefix — but does nothing on a **first encounter**. Closing that needs a witness or an anchor: the profile publishing its head digest somewhere a verifier can reach independently. That is a subsystem, and it is not built. This is *suppression*, and the named limitation about forks does not reach it — there is no second branch to compare, only an honest-looking prefix.

**Cross-group duplicity is detectable, not preventable.** Detection still needs a member of both groups, an external witness, or a public mirror.

**A thief's planted revocations survive the owner's remedy.** A revocation record naming a key the log published and has since denied is honoured — producing it required the private half of a key the DID itself published, and honouring a revocation only ever subtracts authority. So whoever holds a leaked key can plant revocations for `jti`s they know, and those keep biting after the key is denied. The alternative was the owner's own revocations lapsing at the moment they act on a compromise, which is worse. A record naming a key the log **never** published stays ignored, because `kid` is unauthenticated and honouring it would be a plant-a-record denial of service.

**Unanchored capabilities remain backdatable.** `cap.iat` is author-supplied. A seal (`a` on a rotate) is what anchors a high-value grant to a log position.

**Compaction stops at the generation.** `pruneLog` drops earlier generations and superseded epochs, but every rotate of the current generation is permanent and replayed at every welcome, which is why the design keeps rotations rare.

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
