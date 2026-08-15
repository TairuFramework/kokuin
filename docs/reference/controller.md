# `did:kokuin:` — profile DIDs with rotating keys

`did:kokuin:` is a self-certifying DID whose key set lives in a KERI-style key event log rather than in the identifier. The identifier is the hash of the log's first event, so it needs no registry and never changes; the keys it publishes rotate underneath it. `@kokuin/controller` implements the method: event construction, the fold that turns a log into key state, branch selection, and a `DIDMethodResolver` that plugs the method into `@kokuin/token`, `@kokuin/jwe` and `@kokuin/capability`.

For identities, token signing and keystores see [./auth.md](./auth.md); for capability tokens see [./capability.md](./capability.md). **Read [./security.md](./security.md) before depending on any of this** — the guarantees, the assumptions, and the things a consumer has to do to get them are all there.

---

## The identifier

```
did:kokuin:<multibase multihash of the inception event>
```

Self-certifying: the DID *is* the digest of the event that opens the log, so anyone holding the log can check that it belongs to the identifier, with no registry, no network and no trust in whoever handed it over.

It carries no version segment. Multihash already self-describes the hash function, and the format version lives in the event as `v` — safe from confusion because self-addressing means a forged event claiming a later version would have to hash to a DID minted under the earlier rules. A future construction coexists rather than migrating: v1 profiles keep resolving under v1 rules forever.

The inception is a pure function of `(seed, profile index)` — no timestamp, no nonce, no user label. Three things follow, and all three are load-bearing:

- the DID regenerates from the mnemonic alone,
- profiles are enumerable by index, which is what lets a cold recovery picker list them with no network,
- re-derivation is idempotent, so legitimate recovery cannot be mistaken for a fork.

The HKDF `info` string is `did:kokuin/v1`, deliberately independent of package naming: the DID is a function of derived keys, so that string can never change once a profile exists.

```typescript
import { createInception, didFromInception, enumerateProfiles, handleForDID } from '@kokuin/controller'

const inception = createInception(seed, 0)      // profile index 0
const did = didFromInception(inception.event)   // did:kokuin:z…

enumerateProfiles(seed, 5)  // [{ index, did, handle }, …] — for a cold recovery picker
handleForDID(did)           // 'bo-ta-nes' — three pronounceable syllables, derived from the DID
```

A handle is a label *derived from* the identifier, never an input to it — about 30 bits, enough to tell a handful of profiles apart when read aloud, and not a security boundary. Every index yields a valid-looking DID whether or not the profile was ever used; which ones exist is not seed-derived.

## Key derivation

SLIP-0010 Ed25519 fixes the tree position; HKDF supplies algorithm separation and arbitrary lengths, so a new algorithm needs a new `info` string and no path change.

| Path | Role | Who holds it |
| --- | --- | --- |
| `m/44'/876'/0'/<profile>'/0'/<gen>'/<seq>'` | Authority signing key (`k`) | Root, and delegable by handing out the profile sub-seed |
| `m/44'/876'/0'/<profile>'/1'/<gen>'/<seq>'` | Key agreement key (`ka`) | Same subtree |
| `m/44'/876'/1'/<profile>'` | Recovery key (`r`) | **Root only** — a sibling of the delegable subtree, never a descendant |

Hardened derivation is one-way, so a sub-seed holder cannot reach the recovery key. That is what keeps the root able to supersede a delegate that has gone bad. There is one recovery key per profile for its lifetime: its digest is committed in the inception and no later event can move it, which is what lets a root holding nothing but its seed author a reset with no log knowledge and no log availability.

```typescript
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from '@kokuin/controller'

const { privateKey, publicKey } = deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA')
```

## Custody tiers

| Tier | Holds | May author |
| --- | --- | --- |
| Root | The seed — a Ledger, or a cold mnemonic | `icp`, `rot`, `rev`, `reset`; clears the deny set; mints the management capability |
| Management | A long-lived capability granting `revoke`, and its own key | `rev` only, through a capability-authorised revoke |
| Device | A short-lived delegated capability | Nothing in the log |

The management tier holds **no key-event authority beyond `revoke`**. It cannot rotate, cannot reset, and cannot touch the key set — which is what preserves the pre-rotation guarantee, and why a device is never handed the profile sub-seed. `revoke` is the one exception because revocation is the fail-safe direction: requiring the Ledger to revoke a stolen phone is a compromise you cannot undo without the hardware in hand, at exactly the moment speed matters.

## The event log

Every event carries the same envelope, so a verifier can read the parts that decide its fate without understanding the type:

| Field | Meaning |
| --- | --- |
| `v` | Format version. Always written; an absent one is never inferred |
| `t` | `icp`, `rot`, or `rev`. A reset is a `rot` with a higher `g` |
| `i` | The profile DID. Omitted from an inception, whose hash *is* the DID |
| `g` | Generation. Incremented only by a reset |
| `s` | Sequence within the generation |
| `p` | Digest of the previous event. Absent on an inception |
| `crit` | Criticality. An unknown type fails the fold closed unless this is exactly `false` |

Signatures are base64url Ed25519 over the canonical event bytes, positional against the key set the event is judged by, and carried beside the event rather than inside it:

```typescript
type SignedEvent<E> = { event: E; sigs: Array<string>; recoveryKey?: string }
```

### `icp` — inception

Publishes the first authority keys (`k`), the key agreement set (`ka`), the pre-rotation commitment (`n`), the thresholds (`kt`, `nt`) and the recovery commitment (`r`). Self-signed, and self-certifying: any body an attacker writes is a valid log for the DID it hashes to, which is why everything it publishes is checked against what the fold enforces rather than taken on trust.

`kt` and `nt` **must** equal `k.length` and `n.length`. The fold enforces n-of-n and only n-of-n, so those are the only values they can truthfully carry; anything else is a malformed event. A field nothing reads is a trap inside a format the DID derivation freezes.

`ka` is an **OR set**, never combined: encrypting to this profile means encrypting to one of these keys. It carries no pre-rotation commitment, because an exposed agreement key discloses past ciphertexts but confers no authority.

### `rot` — rotate

Reveals the keys the prior event committed in `n`, commits the next set, and republishes `ka`. Signed by the newly revealed keys, per KERI — which is what makes a stolen *current* key unable to rotate.

Optional members: `a`, a seal anchoring an external digest to this log position (opaque to the fold by design, and checked only to be a string, so a reader can read it as the digest it claims to be), and `d`, a **deny-set snapshot**.

```typescript
createRotate(seed, profile, did, prior, {
  keyPosition: { gen: state.keyGen, seq: state.keySeq },  // where the last icp/rot established a key
  denySnapshot: pruneDenySet(state, [entryToDrop]),       // replaces the set — see below
  seal: digestOf(grant),
})
```

`keyPosition` matters because a `rev` advances `s` without establishing a key, so the log's sequence and the derivation index part company at the first revoke of a generation **and never rejoin**. It is optional where the default is provably right and checked either way: `createRotate` verifies the key it is about to reveal against the prior event's own commitment and throws rather than emitting an event no fold would accept.

`denySnapshot` **replaces** the accumulated deny set rather than adding to it — that is the only way to prune one, and it is why the option is named for what it does. Build it with `pruneDenySet(state, drop)`; writing one by hand and forgetting an entry silently un-revokes a device or un-retires a leaked key, with nothing in the log to say so.

### `rev` — revoke

Adds one target to the deny set. The target has two spellings and they cannot collide:

- a **DID** denies a *holder*: no capability whose `aud` is that DID is valid from this position onward. One entry covers that device for its life, including capabilities the verifier has never seen and future re-mints.
- `#<the multibase key exactly as it appears in k>` denies a *signer*: nothing this profile signed with that key verifies from this position onward. The same spelling a token's `kid` uses.

A key the profile **currently publishes** cannot be denied — the fold refuses such an event. Rotate first, then deny the key the rotate retired. Rotation is what an active compromise calls for, and its pre-rotation commitment is something the holder of the leaked key cannot forge; denial is for what the rotate leaves behind.

```typescript
createRevoke(seed, profile, did, prior, target, { gen, seq })        // signed by the profile
createRevokeWithKey(privateKey, did, prior, target, { cap })         // signed by a capability holder
```

`createRevokeWithKey` is the builder for the management tier: a device holding a capability and no seed at all. The key must be the one the capability pins in `cnf`, because that is what the fold checks the event's signature against.

### Reset

A rotate signed by the **recovery** key that increments the generation and discards everything under the prior one — including every capability minted there.

```typescript
createReset(seed, profile, gen)  // pure function of (seed, profile, gen)
```

It anchors to the **inception**, not to the log head, which the root recomputes from the seed alone. It carries no options: no seal, and `d` is always empty. Two blind resets at one generation therefore produce identical bytes and resolve as idempotent re-derivation rather than as a fork. A root that does not know the current generation starts at `gen = 1` and retries higher; no attacker can author a competing reset at any generation, so the cost of guessing low is a round trip, never loss of control.

## The fold

```typescript
foldLog(did, events): FoldResult                          // sync
foldLogAsync(did, events, { verifyCapability }): Promise<FoldResult>
```

`states[i]` is the state **after** `events[i]`. That is what makes the deny set position-dependent: clearing a DID at a later position never retroactively validates its earlier actions. The fold is total — every rejection is a returned reason, never a throw — because a log arrives from a network peer and a fold that can be crashed is a denial of service on everything built above it.

```typescript
type KeyState = {
  did: string
  gen: number; seq: number        // position of the last event
  keyGen: number; keySeq: number  // where the current keys were established
  keys: Array<string>             // authority keys — `k`
  agreement: Array<string>        // key agreement keys — `ka`, an OR set
  next: Array<string>             // pre-rotation commitments — `n`
  recovery: string                // the inception's commitment, carried unchanged for the log's life
  deny: ReadonlySet<string>       // both spellings; see below
  digest: string                  // digest of the event that produced this state
}
```

**`keySeq` is a derivation index, not an event position.** It counts key-establishing events in this generation, starting at 0. It equals `seq` until a revoke intervenes and diverges permanently after that, because a revoke advances the sequence while establishing no key. Deriving at `seq` after a revoke produces a key the log never committed: an unverifiable token, and a rotate that cannot fold. Take `keyGen`/`keySeq` from the fold whenever you need the currently-active key.

**Invariant:** no key in a state's `keys` or `agreement` is denied in the same state. Both branches of the fold enforce it — a revoke may not name a key the profile publishes, and a rotate may not establish a key its own snapshot denies — so every reader may take a folded head's key set at face value.

### Unknown types, criticality, and the skip budget

Criticality lives in the envelope so the decision can be made without understanding `t`. An unknown **critical** event fails the fold closed; that is what stops a verifier which does not understand `rev` from accepting a revoked device. Only an explicit `crit: false` means "skip me" — an absent flag fails closed too, since a criticality that cannot be read is not a criticality.

A skipped event is the only one the fold accepts without verifying a signature, so it must not be able to claim a position it did not earn: its `p`, `g` and `s` are checked, and it advances neither the sequence nor the digest. It is also bounded. Skipped events may exceed the events the fold understood by at most `MAX_SKIPPED_SLACK`; beyond that the log is refused with `TOO_MANY_UNKNOWN_EVENTS`. Without that bound a relaying peer could pad a log to any length, and log size — with it the verifier's CPU, and the work a group repeats at every welcome — would be an attacker's choice rather than the profile's.

## Branch selection

```typescript
resolveBranches(did, branches): ResolveResult
resolveBranchesAsync(did, branches, { verifyCapability }): Promise<ResolveResult>
```

Two rules, in order:

1. **The highest folded generation wins outright.** Only a reset raises the generation, and only the committed recovery key can author a reset, so this is the root's override and nothing a thief holds can reach it.
2. **Within a generation, branches are compared at the point they diverge**, never at their heads. A rotate signed by the pre-committed keys supersedes the current-key event it forked from, and with it everything that branch went on to accumulate.

Comparing heads would make branch *length* the deciding factor, and length is the one resource a thief has in abundance: a stolen current key cannot rotate, but it can sign an unlimited run of revokes. A longer branch still wins the case it should — when it is the same history carried further, which the divergence walk sees as a prefix.

Two events at the divergence point with no rotate to settle them are **duplicity**, surfaced rather than merged, because rotation is sequential per controller. The comparison is on the folded *spine* — the events that moved the fold — not on the raw arrays, since a skipped event establishes nothing and must not contend for a position.

```typescript
type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number; unverified: number }
  | { ok: false; failure: ResolveFailure; duplicity: Duplicity; unverified: number }

type ResolveFailure = 'duplicity' | 'no-valid-branch' | 'needs-capability-verification'
```

`superseded` counts the state-advancing events discarded from losing branches — what a cache must invalidate, since folded state is not append-only under supersession.

**`unverified` means the answer is provisional.** It counts branches this call could not check, which happens only when a capability-authorised revoke meets a call with no `verifyCapability`: the sync form by construction, the async form when unconfigured. With a verifier it is always zero. A non-zero count is not fatal because it must not be: a capability-bearing revoke reaches the verifier path *before* any signature check — the capability names the signer — so a peer holding no key material could otherwise present the public inception with an unsigned `rev` appended and switch duplicity detection off for any profile. Read the count, and re-resolve through `resolveBranchesAsync` with a verifier when it is not zero.

## Resolution

`createControllerResolver` adapts a log loader into the `DIDMethodResolver` that `@kokuin/token`, `@kokuin/jwe` and `@kokuin/capability` all take as `methods`.

```typescript
import { createControllerResolver, createMemoryLogStore } from '@kokuin/controller'
import { createControllerCapabilityVerifier } from '@kokuin/capability'

const resolver = createControllerResolver({
  loadLog: async (did) => await store.log(did),          // the WHOLE log, or undefined
  verifyCapability: createControllerCapabilityVerifier(), // for capability-authorised revokes
  history: createMemoryLogStore(),                        // refuses a log behind one already seen
})
```

Reuse one instance rather than building one per resolution: concurrent resolutions of a DID share a single in-flight fold. It is not a cache — the entry drops as soon as the fold settles, so a log that has grown since takes effect, and a superseded deny set is never served twice.

| Member | Answers from | Question |
| --- | --- | --- |
| `resolve` | the head's `k` alone | "Can this profile sign with this key **now**?" |
| `resolveHistoric` | any position in the **current generation** | "Did this profile sign with this key at some point?" |
| `resolveDenySet` | the head | "What does this profile currently deny?" |
| `resolveAgreementKey` | the head's `ka`, minus anything denied | "Which keys should a sender encrypt to?" |

The split between the first two is the single most important thing to get right on this method, and [./security.md](./security.md) explains what each answer does and does not establish. `kid` is `#<the multibase key exactly as it appears in k>`, matched by membership; a `kid` outside the set is an `IssuerKeyNotFoundError`, never a fall back to the first key.

`loadLog` answers with the **whole** log, always, including when a `verifyCapability` is configured. The fold verifies a capability-authorised revoke against a resolver it builds from its own prefix, so verifying one never resolves the DID being folded.

`history` is optional and worth configuring for any consumer that resolves the same DID more than once. Without it, truncation is a silent revocation bypass: a peer serving a prefix that stops just before the `rev` denying their device produces a log that folds cleanly and verifies every signature. With it, the loaded log is compared against the last one accepted and refused if it does not supersede it — a real branch comparison, not a high-water mark over `(gen, seq)`, because supersession legitimately lowers the sequence and a naive mark would reject the owner's recovering rotate.

## Signing as a profile

```typescript
createControllerIdentity(seed, profile, log)        // root: derives the key from the seed
createControllerIdentityWithKey(privateKey, log)    // daily: the key, and nothing else
```

Both fold the log and bind to the key its current state establishes, both stamp `kid: #<the key that signed>` on every token, and both refuse a caller-supplied `kid` that names another key rather than dropping it. Async siblings (`…Async`) exist for a log whose revoke carries a capability.

Prefer the key form on any path that runs often. The seed is the root of everything the profile can ever do, and the design keeps it for rare ceremonies; a key holder can sign as the profile and cannot rotate, because a rotate must reveal the key the log pre-committed and only the seed derives that. Both throw when the key they hold is not one of the profile's current authority keys — a stale log, a wrong profile index, or a key the profile has rotated away.

**The log is the caller's freshness contract.** An identity built from a stale log signs with a key later events retired. That is survivable across a rotate (a verifier accepts any key authoritative within the generation, via `resolveHistoric`) and fatal across a reset. Rebuild from a re-read log after either.

## Capability-authorised revoke

The management tier's one power, and the only place the fold calls out to caller-supplied code.

```typescript
verifyCapability(cap, subject, target, subjectAtPosition): Promise<CapabilityAuthorisation>

type CapabilityAuthorisation =
  | { authorised: true; audienceKey: ResolvedSigningKey }
  | { authorised: false; reason: string }
```

`createControllerCapabilityVerifier()` from `@kokuin/capability` is the one real implementation — kubun and kumiai must not each grow their own.

Two details carry the security of this path. The verifier answers with the **key** the capability pins, not a boolean, so the fold itself checks the revoke's signature against it: the log is public, so with a boolean any reader could lift the capability out of it and chain a revoke of their own. And the fold supplies `subjectAtPosition`, a resolver over the states *before* the event being verified — because a registry configured once per DID is right for at most one position of a log and silently wrong for the rest, in the direction that applies a revoke a denied device authored.

Failure reasons are exported constants on both sides (`CAPABILITY_VERIFIER_FAILED`, `CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD`, `REVOKE_NOT_SIGNED_BY_AUDIENCE`, `REVOKE_NOT_AUTHORISED`, `REVOKE_NO_AUDIENCE_KEY`, `REVOKE_AUDIENCE_KEY_MISMATCH`, `REVOKE_UNBOUNDED_LIFETIME`, …), because telling "the grant was rejected" from "the capability is malformed for this use" from "your verifier is broken" should not mean matching English sentences.

## Conformance

`@kokuin/controller-conformance` is private and never published: a framework-agnostic suite (`runControllerConformance(impl)`) that any implementation of this method runs to prove it honours the contract — inception self-certification, pre-rotation, the revoke-then-rotate derivation split, deny-set position dependence, reset supersession, duplicity, and the capability-authorised revoke.

It is a contract, not a proof of security. The 2026-08-15 review found five Criticals that the suite passed, because it only ever presented equal-length, cap-free branches: the properties it certified were never the ones under attack. Rows have since been added for what those attacks reached. Treat a green suite as "this implementation agrees with the others", never as "this implementation is safe".
