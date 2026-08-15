# `did:kokuin:` — profile DIDs with rotating keys

**Status:** complete. 30 tasks, a whole-branch review, two fix rounds and three scoped re-reviews.
**Branch:** `key-events-design`. **Shipped:** `@kokuin/controller`, `@kokuin/controller-conformance`,
`@kokuin/jwe`, and breaking changes to `@kokuin/token` and `@kokuin/capability`.

## Goal

A profile identifier that survives key rotation, device theft and total device loss: one stable DID
per profile, several concurrent keys, rotation and revocation including recovery from a stolen
device key, offline verifiability, and algorithm agility so ML-DSA / ML-KEM arrive without moving
the identifier. Added during design: a restored mnemonic reproduces the DID with no other input,
and the seed is needed for rare ceremonies only — nothing on the daily path requires it.

## The identifier

```
did:kokuin:<multibase multihash(inception)>
```

Self-certifying, needs no registry, never changes. It is the only identity value a downstream repo
stores. Not registered with DIF for now; nothing depends on registration.

**It carries no version segment.** Multihash already self-describes the hash function; the
inception format version lives in the event as `v`, which self-addressing makes safe from confusion
— a forged event claiming a later version would have to hash to a DID minted under the earlier
rules. A future construction coexists rather than migrating: v1 profiles keep resolving under v1
rules forever. A version segment would only buy dispatch before fetching, and a resolver fetches the
log either way.

The HKDF `info` string is `did:kokuin/v1` — a protocol identifier deliberately independent of
package naming, because the DID is a function of derived keys and so that string can never change
once a profile exists.

## Architecture

A KERI-style key event log (`icp` / `rot` / `rev` / `reset`) folded into a key state, with
pre-rotation (each event commits the digest of the next key) and superseding recovery. Semantics
were copied from KERI field-for-field rather than invented, with each deliberate delta justified:
JSON/JOSE instead of CESR, MLS groups plus proof-carrying verification instead of a witness network,
and a deny set instead of a separate revocation registry.

Key decisions worth keeping:

- **One authority key per generation. No quorum, no thresholds** — the seed is the root, so a
  threshold over seed-derived keys is theatre. The wire format carries `kt` and `nt` anyway, and
  they are **checked against what the fold enforces**: n-of-n, so `kt` must equal `k.length` and
  `nt` must equal `n.length`, and anything else is a malformed event. They were unread for a while,
  which inside a format the DID derivation freezes is a trap — a reader would take `kt: 1` over two
  keys as a policy, and the fold would demand both signatures regardless. Pinned to the enforcement
  they are a fact instead, and if quorum ever lands the check moves with it and every log written
  until then still means what it said.
- **The seal `a` on a rotate is opaque to the fold on purpose**, and that is what separates it from
  the removed `r`: its meaning belongs to whatever anchored it and no key state can contradict it.
  What the fold owes it is that a non-string `a` is a malformed event, so a reader that finds one
  can read it as the digest it claims to be. It is deliberately not surfaced in `KeyState` — it
  belongs to a position, and the events are in the caller's hands already.
- **Three custody tiers.** Root seed (Ledger or cold mnemonic) may rotate, reset, clear the deny set
  and mint the management capability. The management capability is hot and long-lived, mints device
  capabilities, and holds **no key-event authority beyond `revoke`** — it cannot rotate, cannot
  reset, cannot touch the key set. That preserves the pre-rotation guarantee: a stolen device cannot
  take over the identity, which handing a device the profile sub-seed would have voided.
- **`revoke` is the one exception**, because revocation is the fail-safe direction. Requiring the
  Ledger to revoke a stolen phone is a compromise you cannot undo without the hardware in hand, at
  exactly the moment speed matters. The cost is that a thief holding the management capability can
  revoke your other devices; the remedy is a cold `rotate` clearing the deny set, with `reset` as
  the backstop.
- **Deterministic inception is load-bearing.** It gives three things at once: the DID regenerates
  from the mnemonic alone, profiles are enumerable by index for the cold recovery picker, and
  re-derivation is idempotent — so legitimate recovery cannot be mistaken for duplicity.
- **A canonical algorithm ladder was considered and rejected.** It would have kept post-quantum
  rotations reproducible, but recovery happens in whatever app the user reaches for, so the table
  would have to agree across independent apps on independent release cadences. Two apps at different
  versions produce different bytes at the same index — a genuine fork, not an idempotent
  re-derivation. The consequence is accepted instead: a profile that has performed a
  non-reproducible rotation needs its 32-byte head digest alongside the mnemonic.
- **Two recovery guarantees, kept distinct.** *Control* recovery (can this profile keep signing and
  rotating?) needs the mnemonic plus, where the log holds non-reproducible events, the head digest
  and `seq`; it survives total device loss, because the recovery-key commitment lives in the
  deterministic inception and the root can always author a superseding `reset` with no log at all.
  *Provability* recovery (can it prove its key history to a stranger, offline?) needs the full log
  and does not survive total device loss. Retrieval is not a recovery path: a user who lost every
  device holds no MLS leaf and is authorised to retrieve nothing.
- **Delegation depth capped at 4**, down from 20 — three links (management → device → connector)
  plus headroom. Lowering a default can only reject chains, never accept new ones.
- **The resolver interface is not optional.** `@kokuin/controller` depends on `@kokuin/token` for
  signing, so token resolving `iss` by importing the fold would be a cycle. An injected
  `DIDMethodResolver` keeps the dependency one-way, and the controller became the first out-of-tree
  method — the best available test that the interface is real.
- **Built-in methods stayed behind subpath exports** rather than becoming packages; every new
  package joins the coupled-release judgement. `@kokuin/jwe` is the one split with a measured
  payoff: it was the sole `@noble/ciphers` consumer, so verify-only consumers were paying for a
  cipher dependency they never called.
- **`packages/token/src/rotation.ts` and `createRotationAssertion` were deleted, not deprecated.**
  Rotation chains are what this design replaces, nothing in the workspace consumed them, and the JWE
  split already made this a breaking `@kokuin/token` major.

## What was built

`@kokuin/controller` — derivation, event schema, self-addressing digest, the fold, key state at a
position, duplicity detection, handle derivation, profile enumeration.
`@kokuin/controller-conformance` — private, framework-agnostic contract suite, following the
`@kokuin/keystore-conformance` habit. `@kokuin/jwe` — split out, with an async recipient path for
resolver-backed methods. `@kokuin/token` — `iss` resolved through the injected registry.
`@kokuin/capability` — depth cap, mandated `exp` at the mint and verify policy layer, the
`createControllerCapabilityVerifier` bridge, and deny-set enforcement.

Amendments made during execution, each because the DID had to work for a purpose the spec had not
fully carried:

- A reset anchors to the **inception**, not the log head, so two blind resets at one generation are
  idempotent rather than duplicity.
- `DecryptingIdentity` narrowed to `KeyAgreementIdentity`; the `decrypt` sugar caused a
  `token → jwe → token` cycle.
- The `ka` key agreement set moved into the inception, keys in `k`/`ka` are multicodec-tagged before
  multibase, and `ka` is an **OR set** so hybrid post-quantum arrives as its own codec.
- The registry had to be threaded through `verifyToken`, `checkCapability` and
  `checkDelegationChain` — the interface existed but nothing ever passed one, so `did:kokuin:` could
  neither issue nor verify a token.
- A capability authorising a revoke **pins the audience key** at mint, as an RFC 7800 `cnf` claim.
  An absent pin fails closed and never falls back to resolving the audience — resolving it meant a
  delegate rotating its own key permanently bricked the profile.
- `kid` is `#<the multibase key exactly as it appears in `k`>`, membership-checked. An out-of-set
  `kid` is an error, never a fallback to the first key.
- **The two key questions are separate members.** `resolve()` answers from the **head's `k` alone**
  — "can this profile sign with this key now" — so a rotate does retire the key it rotated away for
  new issuance, and a stolen authority key stops minting verifiable tokens at the next rotate rather
  than at the next reset. `resolveHistoric()` accepts any key that was authoritative at some
  position **within the current generation**, so a routine rotate does not invalidate a grant the
  profile already issued; a generation bump (`reset`) still discards everything under the prior
  generation. Callers verifying archived material — `@kokuin/capability`'s chain walk and its
  revocation records — opt in with `verifyToken({ historic: true })`; everything else gets the safe
  answer without asking for it.
  Originally one permissive scan on `resolve()`, which read the remedy ladder's "already issued
  artefacts survive a rotate" as licence to let a compromised key keep issuing *new* ones. The
  implementation could not tell the two apart, so it granted both; splitting the surface is what
  tells them apart.
- **A `rev` may name a key, and that is what retires one for material it has already signed.** The
  split above left a hole on the capability path, where `historic: true` is unconditional and has to
  be: head-only resolution there would invalidate every outstanding capability on a routine rotate,
  and would make a revocation record signed by a since-rotated key raise `IssuerKeyNotFoundError` —
  which the revocation checker swallows, silently un-revoking, on the one path that must never fail
  open. The cost, demonstrated in `packages/capability/test/zzown-historic-mint.test.ts`, was that a
  leaked, since-rotated authority key could mint a *fresh* `act: '*', res: '*'` capability naming a
  device the thief controlled. Rotation cannot be the fix without breaking the promise that a rotate
  does not invalidate already-issued material, so retirement is explicit: a `rev` target spelled
  `#<the multibase key exactly as it appears in `k`>` — the `kid` spelling, in the same deny set,
  where the two forms cannot collide. Enforcement lives in `signingKeyFrom`, through which every
  `did:kokuin:` signature check reaches a resolved key, so it covers `verifyToken` on both settings
  of `historic`, everything `@kokuin/capability` verifies, and the fold's own capability-authorised
  revoke; `agreementKeysFrom` drops a denied key so the other half of what a profile publishes is
  not left inert. Read at the **head**, unlike a DID denial, which is read at the position being
  verified: a key denial is a statement about the key, and the position an artefact carries is
  author-supplied. Denying a key the profile *currently* publishes is refused — `rotate` is the
  event a live compromise calls for, and a capability-authorised `rev` with a wildcard `res` would
  otherwise let the management tier stop the root tier from signing with one event.
- A capability-authorised revoke is verified **at the log position it sits at**. The fold hands the
  verifier a resolver over the preceding states rather than asking the caller for a prefix — a
  caller configures a resolver once per DID with no way to know which event is asking, so it can
  only be right for one event and is silently wrong for the rest, in the dangerous direction.

## Named limitations, carried forward

- **A stolen mnemonic is terminal.** The thief holds every key at every index including the recovery
  key, and can always rotate ahead of the owner. This is the price of seed-rooting.
- **A thief's planted revocations survive the owner's remedy.** A `jti` revocation record is an
  artefact signed by a key, so denying a leaked key stops its records verifying — which would have
  made the remedy for a compromise silently resurrect every capability that key had revoked, on the
  one path that must never fail open. `createRevocationChecker` therefore separates two failures
  that look identical at the point of verification. A record naming a key the log **never
  published** stays ignored: `kid` is unauthenticated and the backend is an untrusted extension
  point, so honouring it is the plant-a-record denial of service the classification exists to stop.
  A record naming a key the log **published and has since denied** is honoured — producing it
  required the private half of a key the DID itself published, and honouring a revocation only ever
  subtracts authority. What remains is the inverse: whoever holds the leaked key can plant
  revocations for `jti`s they know and those keep biting after the key is denied. That is the
  bounded side of the trade, chosen over the owner's own revocations lapsing at the moment they act
  on a compromise. `zzown-key-denial-check.test.ts` pins both directions, including the control that
  the denial-of-service case is still ignored.
- **Adopted profiles are out of scope, and the field reserved for them is gone.** A rotate used to
  carry an optional `r`, described as a co-signature-gated recovery-commitment update and held for a
  device-generated profile that later adopts an HD-derived authority key. Nothing implemented the
  co-signature: the fold accepted any `r` from an ordinary rotate, `verifyReset` checked
  `inception.r` regardless, and `KeyState.recovery` reported a key that could not author a reset.
  A field written, digested, and read by nothing is a trap in an effectively frozen wire format, so
  it was removed and a rotate carrying one is now refused rather than ignored.
  Moving the commitment is also not merely unimplemented but *unwanted*: a reset anchors to the
  inception so a root holding nothing but its seed can author one with no log knowledge and no log
  availability, and a movable commitment makes the root read the log first. `recoveryPath(profile)`
  carries no index for the same reason. Adoption, if it ever lands, needs a new event type or a
  version bump rather than this member. Such a profile sits at no derivation path either way, so it
  is invisible to the cold picker and outside the pure-mnemonic recovery guarantee.
- **Cross-group duplicity is detectable, not preventable.** Detection still needs a member of both
  groups, an external witness, or a public mirror.
- **Unanchored capabilities remain backdatable** — `cap.iat` is author-supplied.
- **No log compaction path.** Every rotation is permanent and replayed at every welcome, which is
  why the design keeps rotations rare.
- **Harvest-now-decrypt-later applies to `ka`.** X25519 is the only key agreement algorithm in this
  release, and the design says durable data encrypts to these keys, so this is a real window. The
  format is ready; only the wire standard is missing. Signatures do not share it — forgery needs a
  quantum computer at the moment of use, which a rotation can stay ahead of.
- **Post-quantum token size** is a first-order constraint: ML-DSA-65 takes tokens from ~200 bytes to
  ~7 KB, and every ledger entry is a signed token.
- **Profile granularity** defaults to coarse personas. Per-group profiles maximise unlinkability but
  fragment ownership and scale ceremony cost as profiles × devices.

## What the execution actually cost, and why

Six real defects, every one found by **building the attack** and none by reading a diff:

- An unsigned forged revocation record, whose only attacker-chosen fields were the issuer DID and a
  bogus `kid`, denied any `did:kokuin:` capability — because resolvability had moved from a property
  of the DID to a property of an unauthenticated header field.
- `cap`-bearing revokes never had their signatures read at all. The log is public, so anyone able to
  resolve the DID could lift the capability out of it, chain a revoke with empty `sigs`, and have it
  fold — against a wildcard management capability, denying every device on the profile.
- No log could rotate after its first revoke, taking the "cold rotate clears the deny set" rung of
  the recovery ladder with it. A revoke advances the sequence without establishing a key, and two
  places disagreed about which number a rotate derives at.
- The deny set was computed and then read by nothing — the revocation feature was inert.
- The fold, documented as total, could be crashed by a peer-supplied log: first by malformed shape,
  then by nesting depth, which also killed duplicity detection for every well-formed branch.
- The capability verifier's documented 3-argument form was the position bypass verbatim, reachable
  both by direct call and by version skew.

Three of those were opened *by* a fix to a security boundary. The patterns that caught them are
recorded because they generalise: a stub agrees with an implementation that checks nothing; deleting
a whole options object proves nothing about its fields; and a forgery that breaks two things at once
certifies neither.

### The review round after "complete"

A full-branch review — one design pass and two adversarial passes, 152 constructed rows — found
**five more Criticals** on a branch that had already been through per-task review, a whole-branch
review, and `kigu:complete`. Everything above was already true when they were found.

- **A keyless attacker owned the identifier, permanently.** An unknown non-critical event was
  accepted with no signature check and no validation of `g`/`s`, and branch precedence read the
  *raw event* rather than the folded state. One unsigned `nop` at `g = s = MAX_SAFE_INTEGER` beat
  every honest branch, and no reset the root could ever author outranked it.
- **A stolen current key beat the owner's recovering rotate.** Precedence compared heads, and
  supersession ran only on an exact tie, so a thief who could not rotate simply appended cheap
  revokes until its branch was longer.
- **Attenuation at the last hop was a no-op.** `checkCapability` was handed a capability but treated
  it as an invocation, spreading the request over its own `act`/`res` and checking it against the
  *parent*. A narrowed sub-capability wielded the full parent grant.
- **The presented capability's `aud` never reached the deny set**, so a revoked device kept
  authoring capability-authorised revokes through one level of delegation.
- **Duplicity detection was off for the management tier.** `resolveBranches` filtered branches
  through the *sync* fold, which fails closed on a `cap`-bearing revoke, so any profile that used
  the feature reported "no valid history" for a healthy log.

Two more were opened by these fixes, keeping the pattern intact: comparing raw branch arrays would
have turned every honest log into a duplicity report, and making `resolve` head-only silently
un-revoked every revocation record signed by a since-rotated key.

Three lessons this round adds. **The conformance suite passed all five** — it only ever presented
equal-length, cap-free branches, so the properties it certified were never the ones under attack.
**A completed plan is not evidence**; this round ran after the work had been summarised, the
ephemeral plan deleted, and the branch parked at QA. And **probe direction is not uniform**: a probe
written to characterise a suspected hole *passes* while the hole is open, so reading "all green" as
"no findings" inverts the result.

## Remaining at branch finish

Release mechanics were deliberately deferred to one coherent pass rather than accumulated per task:
no versioning intent exists yet for any package, and `@kokuin/token` carries an unambiguous major
while `@kokuin/controller` has breaking signature changes and `@kokuin/capability` gains public API
plus a new hard denial. A changelog note is needed because several rounds of fail-closed turn former
silent passes into hard failures — a consumer upgrading sees new denials that are correct but read
as regressions. Key revocation adds to that list: `resolveDenySet` now answers with a heterogeneous
set (a consumer that enumerates it rather than matching against it sees `#`-prefixed entries), the
fold rejects two shapes it used to accept (`revoke names a key the profile publishes`, `rotate
establishes a denied key`), and a `kid` naming a revoked key is a new `IssuerKeyNotFoundError` on
both resolution members. `@kokuin/controller` should join the co-bump group: it sits across three contracts
nothing enforces (the `verifyCapability` callback, `CapabilityAuthorisation`, and the exported
reason strings). A new `@kokuin/controller` against an older `@kokuin/token` dies with an ESM link
error on a named import, so the peer range matters and not just the version number.

Never exercised in the development environment: `tests/e2e-*`, `tests/ledger`, the on-device
firmware, and `kubun`/`kumiai` built against the changed signatures.

Follow-on work is filed separately — see `next/2026-08-11-did-kokuin-downstream-adoption.md`,
`next/2026-08-11-deny-set-for-plain-tokens.md`, and
`backlog/2026-08-11-controller-follow-ons.md`.
