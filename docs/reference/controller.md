# `did:kokuin:` — profile DIDs with rotating keys

`did:kokuin:` is a self-certifying DID whose key set lives in a KERI-style key event log rather than in the identifier. The identifier is the hash of the log's first event, so it needs no registry and never changes; the keys it publishes rotate underneath it. `@kokuin/controller` implements the method: event construction, the fold that turns a log into key state and a management set, branch selection, and a `DIDMethodResolver` that plugs the method into `@kokuin/token`, `@kokuin/jwe` and `@kokuin/capability`.

For identities, token signing and keystores see [./auth.md](./auth.md); for capability tokens see [./capability.md](./capability.md). **Read [./security.md](./security.md) before depending on any of this** — the guarantees, the assumptions, the accepted risks, and the things a consumer has to do to get them are all there.

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
| Root | The seed — a Ledger, or a cold mnemonic | Every root-chain event (`icp`, `rot`, reset); member adds; root renewals, removals and revokes; every settlement |
| Management member | Its own Ed25519 key, pinned in the log by a root add, and a lease | Renewals and removals of *other* members, revokes of edge holders and retired keys, edge grants as issuer |
| Edge | A short-lived grant minted by root or a member | Nothing in the log |

The intent is that the root comes out only for first setup, for adding a management device, for settling disputes, and for recovery. Day to day a few trusted management devices — a desktop app that manages agents, a phone — mint grants for edge agents and devices, revoke them, and renew each other, all without the root.

A member holds **no root-chain authority at all**: it cannot rotate, cannot reset, cannot touch `k`, `ka` or `n`, cannot add a member, and cannot renew or remove itself. Root and member keys are disjoint — a member pin may never be a key the current generation's root chain publishes or commits, nor the recovery key — so no management device ever holds a root key, and member authority and root authority cannot be mistaken for each other. That is what preserves the pre-rotation guarantee, and why a device is never handed the profile sub-seed.

Member authority lives **in the log**, not in a capability, and it is clock-free: a member's lease bounds the grants it mints, and nothing else. The fold never reads the lease; only a removal ends a member's log authority.

## The log

```typescript
type ControllerLog = { chain: Array<SignedEvent>; events: Array<SignedEvent<EpochEvent>> }
```

Two lists, because they fold by different rules:

- **The root chain** (`chain`) is linear: an inception, then rotates, with resets raising the generation. Order is meaning. Everything about keys — `s`, `keySeq`, historic resolution, derivation — lives here, and only root signs here.
- **The epoch** (`events`) is everything that built up on the chain's last event since it was written: root adds, root and member revokes, renewals and removals. It is a **set**, not a sequence: concurrent member actions merge rather than compete, because a device cannot know whether its event races another member's, so no member action may fork the log.

Every chain event opens an epoch, and every chain event after the inception closes the one before it. A presentation of one list is no claim about the other.

Signatures are base64url Ed25519 over the canonical event bytes, positional against the key set the event is judged by, and carried beside the event rather than inside it:

```typescript
type SignedEvent<E> = { event: E; sigs: Array<string>; recoveryKey?: string }
```

### Root-chain events

Every chain event carries the same envelope, so a verifier can read the parts that decide its fate without understanding the type:

| Field | Meaning |
| --- | --- |
| `v` | Format version. Always written; an absent one is never inferred |
| `t` | `icp` or `rot`. A reset is a `rot` with a higher `g` |
| `i` | The profile DID. Omitted from an inception, whose hash *is* the DID |
| `g` | Generation. Incremented only by a reset |
| `s` | Sequence within the generation |
| `p` | Digest of the previous event. Absent on an inception |
| `crit` | Criticality. An unknown type fails the fold closed unless this is exactly `false` |

The chain holds key-establishing events and nothing else, so a chain event's sequence and the derivation index of the key it reveals are the same number. Revokes left the chain: a `rev` on the chain — what an older log carries — takes the unknown-type path and, being critical, fails the fold closed.

#### `icp` — inception

Publishes the first authority keys (`k`), the key agreement set (`ka`), the pre-rotation commitment (`n`), the thresholds (`kt`, `nt`) and the recovery commitment (`r`). Self-signed, and self-certifying: any body an attacker writes is a valid log for the DID it hashes to, which is why everything it publishes is checked against what the fold enforces rather than taken on trust. The inception opens the first epoch with an empty management set and an empty deny set.

`kt` and `nt` **must** equal `k.length` and `n.length`. The fold enforces n-of-n and only n-of-n, so those are the only values they can truthfully carry; anything else is a malformed event. A field nothing reads is a trap inside a format the DID derivation freezes.

`ka` is an **OR set**, never combined: encrypting to this profile means encrypting to one of these keys. It carries no pre-rotation commitment, because an exposed agreement key discloses past ciphertexts but confers no authority.

#### `rot` — rotate, and every rotate is a settlement

Reveals the keys the prior event committed in `n`, commits the next set, and republishes `ka`. Signed by the newly revealed keys, per KERI — which is what makes a stolen *current* key unable to rotate.

**Every rotate carries a full state snapshot**: `m`, the management set (each member's DID, pinned key, add digest and lease end), and `d`, the deny set. The state after a rotate **is** its snapshot; nothing before it contributes, and the epoch it closes stops counting. A non-reset rotate without both halves fails the fold with `ROTATE_NEEDS_SNAPSHOT` (`rotate carries no state snapshot`): there is no "carry the prior state forward", because the prior state may hold epoch effects a verifier holding only the chain cannot reproduce, and half a snapshot would read as "no members" or "no denials" when its author meant neither.

```typescript
import { createRotate, foldLog, snapshotOf } from '@kokuin/controller'

const folded = foldLog(did, log)
if (!folded.ok) throw new Error(folded.reason)
const rotate = createRotate({
  seed,
  profile: 0,
  did,
  prior: log.chain[log.chain.length - 1].event,   // the chain's last event
  options: {
    snapshot: snapshotOf(folded.head, { deny: [entryToDrop], members: [addToDismiss] }),
    seal: digestOf(grant),                          // optional
  },
})
```

`snapshot` is **a replacement, not an addition**. Build it with `snapshotOf(head, drop)`, which carries forward every member not removed and every deny entry, minus what `drop` names; writing one by hand and forgetting an entry silently un-revokes a device, un-retires a leaked key or dismisses a member, with nothing in the log to say so. The snapshot is root's **chosen replacement state**, not a proven merge: a removal or denial root never saw is not in it, and root's tooling must present it that way.

The fold judges every snapshot against the generation it lands on, each rule with its own reason:

- **Shape** (`SNAPSHOT_MALFORMED`): `m` is a list of members whose pins decode as Ed25519, no two sharing an add digest or a pinned key; `d` is a list of strings.
- **Disjoint from root** (`SNAPSHOT_MEMBER_KEY_IS_ROOT`): no pin is a `k` or `ka` anywhere on the generation's chain (this rotate's included), committed in one of its `n`, or the recovery key.
- **The DID carries the pin** (`SNAPSHOT_MEMBER_DID_MISMATCH`): each member DID is a `did:key` of exactly that key, or a long-form `did:peer:4` whose document carries that one Ed25519 signing key and no other.
- **Checkpointed retirements stay** (`SNAPSHOT_DROPS_RETIRED_KEY`): a key-target denial naming a key on the generation's chain, once a rotate's snapshot has carried it, must be carried by every later snapshot in the generation. Historic resolution would otherwise accept fresh tokens signed with that key again. The chain alone enforces it, so a pruned and a full store agree; only a reset clears it. A retired-key denial made in an epoch and left out of the next snapshot was never checkpointed — it is lost, which is why root's tooling should surface retired chain keys the snapshot does not deny.

`createRotate` throws rather than emitting an event the fold would reject when the seed is the log's own root and the key it is about to reveal is not the prior event's commitment. Building a rotate from a foreign seed (what the conformance suite does to construct adversarial events) skips that check, because a mismatch there says nothing; the fold is the backstop.

`a` is an optional seal, anchoring an external digest to this log position — opaque to the fold by design, and checked only to be a string.

#### Reset

A rotate signed by the **recovery** key that increments the generation and discards everything under the prior one — including every grant minted there. It anchors to the **inception**, not to the log head, which the root recomputes from the seed alone.

```typescript
createReset(seed, profile, gen)            // blind: a pure function of (seed, profile, gen)
createReset(seed, profile, gen, snapshot)  // carries the whole recovered state
```

- **Blind** (no snapshot): no seal, `d: []` and no `m`. Two blind resets at one generation therefore produce identical bytes and resolve as idempotent re-derivation rather than as a fork. The new epoch starts empty and root re-adds members with individual adds. This is the worst-case path, for a root that does not know the log's state. An empty snapshot is the same state and is written the same way, so it stays byte-identical to a blind reset rather than becoming a second encoding of it.
- **With a snapshot**: the same reset carries the member and deny sets, so one recovery-key signature is the whole recovery. Disjointness is checked against the **new** generation's keys, and no retired-key denial of the old generation need carry over. Members it carries keep their add digests, but every grant names its generation, so every grant minted under the prior generation still dies and members re-mint. Two resets at one generation with different bytes are duplicity — which only the recovery-key holder can cause (a relay can reveal two differing resets root really signed, a snapshot reset and then a blind retry, but cannot forge one) — resolved by a reset at a higher generation.

A root that does not know the current generation starts at `gen = 1` and retries higher; no attacker can author a competing reset at any generation, so the cost of guessing low is a round trip, never loss of control.

### Epoch events

An epoch event shares the envelope's spirit and fields of its own:

| Field | Meaning |
| --- | --- |
| `v`, `t`, `i`, `g` | As on the chain. `t` is `add`, `ren`, `rmv` or `rev` |
| `e` | The epoch: digest of the chain event that opened it |
| `p` | Parents: `e` itself, or digests of events of the same epoch. 1 to `MAX_EVENT_PARENTS`, no duplicates |
| `crit` | Always exactly `true`, so a verifier that predates the management tier fails closed rather than skipping a revoke |
| `by` | The signing member's add digest. Absent means root: n-of-n over the chain head's `k` |

| Type | Fields | Who may sign |
| --- | --- | --- |
| `add` | `did`, `key` (the pin), `lease` | Root only |
| `ren` | `add` (the incarnation renewed), `lease` | Root, or any member whose pinned key is not the target's |
| `rmv` | `add` (the incarnation removed) | Root, or any member whose pinned key is not the target's |
| `rev` | `x`: a DID or a key target | Root, or any single member — never targeting a member |

Parents list every head the author knows — a recommendation the fold cannot enforce. `epochHeads(did, log)` computes them: the applied events of the current epoch that no applied event names as a parent, sorted, or `[head.epoch]` for an empty epoch. It throws if the log does not fold, and returns at most `MAX_EVENT_PARENTS` heads — the smallest digests when the epoch has more tips — so its answer is always a valid `parents`. The tips left out stay tips, and the next event built from `epochHeads` names them: repeated building folds every tip in. Leases are unix seconds as non-negative safe integers. A member is identified by its **add digest**, its *incarnation*: renew and remove name that digest, so a delayed renew or remove never carries over to a re-add of the same key.

```typescript
import {
  createAdd, createRemove, createRenew, createRevoke, DEFAULT_LEASE_SECONDS, epochHeads, foldLog,
} from '@kokuin/controller'

const now = Math.floor(Date.now() / 1000)
// `head` is the fold's head; `parents` the current epoch's heads this party holds (at most
// `MAX_EVENT_PARENTS`).
const folded = foldLog(did, log)
if (!folded.ok) throw new Error(folded.reason)
const head = folded.head
const parents = epochHeads(did, log)

// Root admits a member.
const add = createAdd({ did, head, parents, seed, profile: 0,
  member: { did: phoneDID, key: phoneKey, lease: now + DEFAULT_LEASE_SECONDS } })

// The desktop, itself a member, renews the phone and revokes a lost agent — no root. Each event
// built from the same `parents` is concurrent with the others; refold and recompute `epochHeads`
// to build one that sees them.
const desktop = { member: { privateKey: desktopPrivateKey, add: desktopAdd } }
const renew = createRenew({ did, head, parents, signer: desktop, add: phoneAdd, lease: now + DEFAULT_LEASE_SECONDS })
const revoke = createRevoke({ did, head, parents, signer: desktop, target: agentDID })
const remove = createRemove({ did, head, parents, signer: desktop, add: phoneAdd })
```

`signer` is an `EpochSigner`: `{ root: { seed, profile } }` or `{ member: { privateKey, add } }`. The builders throw rather than emit an event the fold would reject on shape — an empty or oversized parent list, a fractional lease, a body past `MAX_EVENT_BYTES` — and, for a root signer whose seed is this DID's, a `head` whose `keyGen`/`keySeq` do not name its one published key. Nothing in a builder judges authorisation; who may sign what is a question about the causal past, which only the fold has.

A **revoke target** has two spellings and they cannot collide:

- a **DID** denies a *holder*: no capability whose `aud` is that DID is valid. One entry covers that device for its life, including grants the verifier has never seen and future re-mints.
- `keyTarget(key)` — `#<the multibase key exactly as it appears in k>` — denies a *signer*: nothing this profile signed with that key verifies, under `resolve` or `resolveHistoric`. The same spelling a token's `kid` uses.

A key the chain head **currently publishes** in `k` or `ka` cannot be denied — the fold refuses such a revoke (`REVOKE_NAMES_ROOT_KEY`), root's included. Rotate first, then deny the key the rotate retired. Rotation is what an active compromise calls for, and its pre-rotation commitment is something the holder of the leaked key cannot forge; denial is for what the rotate leaves behind.

## The fold

```typescript
foldLog(did, log: ControllerLog): FoldResult   // synchronous

type FoldResult =
  | { ok: true; states: Array<KeyState>; head: KeyState; applied: Array<string>; pending: number; rejected: number }
  | { ok: false; reason: string; index: number }
```

Two stages. **Root-chain selection comes first, epoch evaluation second.** The chain folds to one state per chain event (`states[i]` is the state after `chain[i]`, what `resolveHistoric` scans). The epoch events then merge into the chain's last state to give `head`, whose `deny`, `members` and `saturated` are the live answers. `applied` lists the digests that took effect (parents first, ties by ascending digest), `pending` counts well-formed events still waiting on a parent, `rejected` counts refusals by distinct event.

```typescript
type KeyState = {
  did: string
  gen: number; seq: number        // position of the chain event
  keyGen: number; keySeq: number  // where the current keys were established — the derivation index
  keys: Array<string>             // authority keys — `k`
  agreement: Array<string>        // key agreement keys — `ka`, an OR set
  next: Array<string>             // pre-rotation commitments — `n`
  recovery: string                // the inception's commitment, carried unchanged for the log's life
  deny: ReadonlySet<string>       // both spellings
  members: ReadonlyMap<string, MemberState>   // keyed by add digest
  epoch: string                   // digest of the chain event that opened this epoch
  saturated: boolean
  digest: string                  // digest of the chain event that produced this state
}
type MemberState = MemberEntry & { removed: boolean; effective: boolean }
```

`keySeq` names where to derive the current key, `seq` where the event sits. On a chain of key-establishing events they are the same number, but an inception's `s` is wire data this package does not derive from, so take `keyGen`/`keySeq` from the fold whenever you need the active key.

**The fold is total** — every rejection is a returned reason, never a throw — because a log arrives from a network peer and a fold that can be crashed is a denial of service on everything built above it. Only the chain can fail it. Past the request limit, nothing in `log.events` can: an entry that is not a valid epoch event is counted and dropped, so a relay cannot make a log unfoldable by padding it. It is also **clock-free**: nothing reads the time or a lease, so the same input folds the same way forever.

**Invariant:** no key in a head's `keys` or `agreement` is denied in the same state. A rotate may not establish a key its own snapshot denies, and a revoke may not name a key the chain publishes, so every reader may take a folded head's key set at face value.

### Folding an epoch

- **Authorisation is causal.** An epoch event is valid iff its signer is authorised in the state of its ancestors: the epoch's starting snapshot plus the effects of every ancestor event. Never concurrent branches, arrival order, or wall time. A member signs under the key its add pinned and nothing else; the signer must be present, not removed and not denied in that causal state.
- **Effects merge by union.** The epoch's state is the starting snapshot plus the union of every valid event's effects: denials union, removals union, adds union, a lease is the maximum renewal per incarnation, and removal dominates renewal. It is a join-semilattice, so the result is the same for any presentation order, any number of duplicates, and either copy of an event presented under two valid signature lists (the fold keeps the one whose signature list sorts first, so two parties that saw both remember the same bytes).
- **Denial dominates membership.** One predicate decides whether a denial targets a membership: the entry is the member's DID under canonical DID equivalence (the long and short forms of a `did:peer:4` are one DID), or `#` plus its pinned key. Nothing broader — "any DID containing that public key" is not an alias, since anyone can manufacture such a document. A member a merged denial targets is not effective: an event whose causal past holds the denial is not authorised by the membership, and the resolver refuses it as an issuer. Its events concurrent with the denial are not voided, and a root add merging with a concurrent revoke of the same DID or key yields a member that is present and not effective. Neither event is dropped for arriving second; only a settlement can say otherwise.
- **Old epochs never count.** An event naming any epoch other than the current one has no effect: its effect is either in the newer snapshot or was dropped by it.
- **No cross-epoch parents.** A parent is the event's own epoch digest or an event of that epoch. An event naming another chain event, or an event of another epoch that was presented, is refused; snapshot add digests are identifiers the snapshot attests, not parents.
- **Incomplete input is pending, never an empty past.** An event whose parents are not all present and applied waits (`pending`), and is applied once a later presentation supplies them. Cycles never apply.

Each rule refuses with a reason of its own, recorded per event inside the fold; `FoldResult` reports refusals only as the `rejected` count:

| Rule | Refusal |
| --- | --- |
| Only root adds | `only root may add a member` |
| The DID carries exactly its Ed25519 pin | `member DID does not carry its key` |
| The pin is no root key of the generation, nor the recovery key | `member key is a root key` |
| No add of a DID or key a causal denial targets | `member is denied in the causal state` |
| No second effective add of one key along a causal line | `member key is already an effective member` |
| No self-renew, no self-remove, judged by pinned key across DIDs and incarnations | `a member may not renew itself` / `a member may not remove itself` |
| Renew and remove name an incarnation of the causal state | `target is not a member of the causal state` |
| A member revoke targets no member of its causal past, removed or denied ones included | `a member may not revoke a member` |
| No revoke of a key the chain head publishes | `revoke targets a key the chain publishes` |

Concurrent adds of one key (a retry) cannot see each other, so both stand; pinned-key equality is what keeps them from renewing each other. A member may not revoke a member because a revoke would be a removal that skips the self-remove rule and that root's own add could never undo short of a settlement; members leave through remove, and only root may deny one.

### Request limits and saturation

Two kinds of limit, never confused:

- **Request limits reject input.** `MAX_LOG_EVENTS` (8192) epoch events per input — more fails the whole input with `LOG_TOO_LARGE` at index `-1`, since it is no event's fault — and, per event, `MAX_EVENT_PARENTS` (16) parents, `MAX_EVENT_SIGNATURES` (16) signatures and `MAX_EVENT_BYTES` (8192) canonical body bytes. `MAX_FAILED_SIGNATURES` (64) bounds the signature checks an input can make fail: each distinct copy that does not verify is charged for every signature it carries, and past the limit the whole input fails with `TOO_MANY_FAILED_SIGNATURES` at index `-1`. Nothing honest fails a check — every copy a verifier keeps verified when it was kept — so the limit costs an honest relay nothing; the count is a function of the presentation, never its order. `epochHeads`, `pruneLog` and `mergeLogs` take a held log, and accept up to `MAX_EPOCH_EVENTS + 1 + MAX_LOG_EVENTS` events (one saturated epoch plus one presentation); more throws `LOG_TOO_LARGE`. Unauthenticated or invalid input only ever gets rejected; it never changes remembered state. Work is counted in events, edges and signatures, never elapsed time.
- **Saturation is the one limit authenticated input can reach.** An epoch with more than `MAX_EPOCH_EVENTS` (4096) distinct, authenticated, causally valid events is `saturated`. The resolver then refuses every answer for the controller until root settles into a fresh epoch. The chain still folds, so root can always settle, and a verifier never needs to ingest a superseded epoch to fold the new one. Fail closed is chosen over guessing which events to drop.

`MAX_LOG_EVENTS` sits above `MAX_EPOCH_EVENTS` so a saturating epoch can still be presented whole and remembered as saturated, rather than turned away as oversized. The price is verification cost: see [./security.md](./security.md#verification-cost).

### Unknown types, criticality, and the skip budget

Criticality lives in the envelope so the decision can be made without understanding `t`. An unknown **critical** chain event fails the fold closed — a chain `rev` from an older log included; that is what stops a verifier that does not understand a type accepting what that type would have refused. Only an explicit `crit: false` means "skip me" — an absent flag fails closed too, since a criticality that cannot be read is not a criticality.

A skipped event is the only one the fold accepts without verifying a signature, so it must not be able to claim a position it did not earn: its `p`, `g` and `s` are checked, and it advances neither the sequence nor the digest. It is also bounded. Skipped events may exceed the events the fold understood by at most `MAX_SKIPPED_SLACK`; beyond that the log is refused with `TOO_MANY_UNKNOWN_EVENTS`. Without that bound a relaying peer could pad a log to any length, and log size — with it the verifier's CPU, and the work a group repeats at every welcome — would be an attacker's choice rather than the profile's.

## Branch selection

```typescript
resolveBranches(did, chains: Array<Array<SignedEvent>>): ResolveResult

type ResolveResult =
  | { ok: true; winner: Array<SignedEvent>; superseded: number }
  | { ok: false; failure: 'duplicity' | 'no-valid-branch'; duplicity: Duplicity }
```

Root chains only: epoch events never fork the log, so they are never a branch to choose between. Two rules, in order:

1. **The highest folded generation wins outright.** Only a reset raises the generation, and only the committed recovery key can author a reset, so this is the root's override and nothing a thief holds can reach it.
2. **Within that generation, chains are compared from the top generation's reset (or the inception, at generation 0), at the point they diverge** — never at their heads. A chain ending at the divergence point is a prefix of the other and loses to it; two chains that each carry an event there are **duplicity**, surfaced rather than merged.

Comparison starts at the top generation's first event because a reset chains to the inception, not to what preceded it: one reset can sit on a generation-0 chain in one party's copy and straight after the inception in another's pruned copy. Once both contain it, what came before cannot change the winner.

Comparing heads would make chain *length* the deciding factor, and length is the one resource a thief has in abundance. The precedence is unchanged from before the management tier — a rotate signed by the pre-committed keys outranks a competing current-key event — but the comparison inputs changed: root adds and root revokes now live in epochs, so the current-key event a cold rotate outranks is one in the epoch that rotate closes, where the fold gives it no effect. The chain holds only `icp` and `rot`, so duplicity on it is always two rotates at one position or two resets at one generation, both signed by keys only the controller holds, settled only by a reset at a higher generation. The comparison is on the folded *spine* — the events that moved the fold — so a skipped event establishes nothing and cannot contend for a position, and chains that do not fold are filtered out first, so a thief who cannot produce a valid event cannot create a duplicity report.

`superseded` counts the state-advancing events discarded from losing chains — what a cache must invalidate, since folded state is not append-only under supersession.

## Merging and pruning

```typescript
mergeLogs(did, a, b): ControllerLog   // a party's log joined with one it was handed
pruneLog(did, log): ControllerLog     // the least of a log that still folds to the same head
```

`mergeLogs` is a pure merge, for joining what a party holds with what it was handed — a grant's proof bundle, a peer's copy — before folding. The chain is settled by the branch rules and a fork throws (`LOG_FORKED`) rather than merging two histories root never wrote as one; the events are a union, deduplicated by digest *and* signatures, since keeping only the first copy would let a forged copy shadow the genuine one. Nothing here authenticates an event: the result is input to a fold, not memory.

`pruneLog` keeps the inception, the current generation's chain, and the current epoch's applied events. Earlier generations go because a reset chains to the inception; earlier epochs' events go because they have no effect; unapplied ones because they were never authenticated. Pruning is optional: a consumer may keep the full log, and a store holding more is never contradicted by one holding less.

## Resolution

`createControllerResolver` adapts a log loader into the `DIDMethodResolver` that `@kokuin/token`, `@kokuin/jwe` and `@kokuin/capability` all take as `methods`.

```typescript
import { createControllerResolver, createMemoryLogStore } from '@kokuin/controller'

const resolver = createControllerResolver({
  loadLog: async (did) => await fetchLog(did),   // the WHOLE log, or undefined
  history: createMemoryLogStore(),               // refuses a log behind one already seen
})
```

Reuse one instance rather than building one per resolution: concurrent resolutions of a DID share a single in-flight fold. It is not a cache — the entry drops as soon as the fold settles, so a log that has grown since takes effect.

| Member | Answers from | Question |
| --- | --- | --- |
| `resolve` | the head's `k` alone | "Can this profile sign with this key **now**?" |
| `resolveHistoric` | any chain state in the **current generation** | "Did this profile sign with this key at some point?" |
| `resolveDenySet` | the head (chain merged with the current epoch) | "What does this profile currently deny?" |
| `resolveAgreementKey` | the head's `ka`, minus anything denied | "Which keys should a sender encrypt to?" |
| `resolveMember` | the head's management set | "Which key does this member pin, and until when, right now?" |

The split between the first two is the single most important thing to get right on this method, and [./security.md](./security.md) explains what each answer does and does not establish. `kid` is `#<the multibase key exactly as it appears in k>`, matched by membership; a `kid` outside the set is an `IssuerKeyNotFoundError`, never a fall back to the first key. A key denial is evaluated against the **head** deny set, never the position a token's `kid` selects at — an author-supplied position must not let a thief resolve at a moment before the key was denied — so a key retired by an epoch revoke is refused as surely as one a settlement checkpointed.

**A saturated epoch answers nothing.** While `head.saturated`, every member throws `EPOCH_SATURATED` (`controller epoch is saturated: <did>`) — `resolveHistoric` and `resolveAgreementKey` included — because the epoch's denials can no longer be read and any answer could be one a denial withdrew. A plain error, not `IssuerKeyNotFoundError`: the controller as a whole cannot be answered for, and `@kokuin/capability` denies on exactly that. The refusal ends when root settles.

### `resolveMember`

```typescript
resolver.resolveMember(subject, { did, add, gen }): Promise<{ key: ResolvedSigningKey; lease: number }>
```

Every condition is asked of the head: the member must be present under that add digest, effective (not removed, not denied), and its DID must be the queried one under canonical DID equivalence — any other DID is another member, even one carrying the same key. **The generation is part of the identity**: a reset carrying a snapshot keeps each member's add digest, so only `gen` can tell a grant minted before the reset from one minted after, and a query naming any generation but the head's is refused. That is what makes a reset kill every grant of the generation it replaces, carried members' included. A refusal is an `IssuerKeyNotFoundError` carrying `MEMBER_NOT_EFFECTIVE`. The lease is reported, never judged: the log has no clock, and bounding a grant by it is the verifier's step.

### One frozen view per verification

```typescript
const view = resolver.frozen()   // a DIDMethodResolver that folds each DID at most once
```

A verification asking several questions of one controller — is the issuer a member, which key does it pin, until when, is any audience on the delegation chain denied — must get them all from one state of the log. Answered live, a revoke landing between two of them gives a verdict no single state supports: a member checked before its removal, a denial checked after a settlement dropped it. Use one view per verification and drop it after, since it never sees anything newer than its first fold.

### Memory: `history` and `LogStore`

`loadLog` answers with the **whole** log: every chain event and every current-epoch event. A prefix resolves to a head missing whatever came after it, and a withheld epoch revoke is a denial the resolution does not see.

`history` is optional and worth configuring for any consumer that resolves the same DID more than once. Without it, truncation is a silent revocation bypass: a peer serving a chain prefix that stops before the settlement denying their device, or a full chain with the epoch revoke withheld, produces a log that folds cleanly and verifies every signature. With it, each presentation is folded against what this party has already accepted (`authoritativeLog`):

- **The chain** must extend the one seen or win against it under the branch rules. One that loses is refused (`LOG_NOT_AUTHORITATIVE`); a genuine fork is refused outright (`LOG_FORKED`). This is a real branch comparison, not a high-water mark over `(gen, seq)`, because a reset legitimately replaces a longer lower-generation chain.
- **The epoch** is the union of what was seen and what was loaded, folded on the settled chain: a presentation that withholds an event this party has seen cannot make it forget it. The answer is that union's fold, not the presentation's.
- **What is remembered** is the settled chain and the current epoch's **applied** events, one verified copy each — nothing else. An unsigned, forged, malformed or pending entry was never authenticated and never reaches the store, so a relay flooding a presentation changes nothing remembered and cannot saturate the epoch. A pending event is not lost, only not vouched for: presenting it again once its parents are known applies it. Old epochs' events are dropped at the settlement that supersedes them, which is what bounds memory to one epoch.
- **Memory is not authenticated twice.** A stored event of the current epoch was authenticated when it was stored, and a copy that verified under an epoch verifies under it every time, so the fold takes the stored copy as authentic, still judging its authorisation afresh, and checks no presented copy of the same body. Only what a presentation adds is checked, and a presentation refused by a request limit (`LOG_TOO_LARGE`, `TOO_MANY_FAILED_SIGNATURES`) is refused whole, memory untouched. This trusts the store for signatures, not only for completeness: anyone who can write it can plant an unsigned event of the current epoch and have it applied — a member added, not merely an event forgotten. Write to a `LogStore` only what `authoritativeLog` returned for that DID; never peer bytes, nor a `mergeLogs` union.
- **Saturation is remembered until a settlement.** A saturated epoch is stored as exactly enough applied events to stay saturated on every refold, so a later presentation of a subset does not clear it. Without a `history` store there is nothing to remember, and each resolution answers for its presentation alone.

A stored log whose chain no longer folds is treated as no memory: local corruption or a tightened fold rule is one round of the guarantee to give up, since refusing forever would brick every cached profile.

```typescript
type LogStore = {
  get(did: string): Promise<ControllerLog | undefined>
  merge(did: string, update: (current: ControllerLog | undefined) => Promise<ControllerLog>): Promise<ControllerLog>
}
```

`merge` is **atomic per DID**: no two updates for one DID interleave, so two presentations merged concurrently both land rather than the second overwriting the first with a log built from a stale read. When `update` throws, nothing is written. `update` **may run more than once** — a persistent store reruns it when it loses a first-insert race — so it must be free of side effects; only its last result is written. `createMemoryLogStore()` covers a process lifetime; `@kokuin/store-controller` persists one (see [./stores.md](./stores.md)). The store writes whatever `update` returns, except `current` itself — the very object it was handed — which means nothing changed and is not written. `authoritativeLog` answers that way whenever a resolution learned nothing new, so a resolution that only re-reads what is held writes nothing. Arbitration lives in `authoritativeLog`, never in the store.

## Management members

The lifecycle, end to end:

1. **Setup.** The desktop install creates the mnemonic. Root, still in hand, publishes the inception and adds the desktop with `createAdd`.
2. **A second device.** Adding the phone later is one more root signature. From then on desktop and phone renew each other (`createRenew`) and manage edge holders (`createRevoke`, and grants they mint as issuer) without the root.
3. **A member goes bad or is lost.** Any other member removes it (`createRemove`); its log authority ends at the removal, and every verifier whose state holds the removal stops accepting its grants. Removal writes no deny entry. A member may not deny a member; root may, with a root revoke in the epoch or in its next snapshot.
4. **A dispute, or a flood.** Root settles: a `rot` whose snapshot (built with `snapshotOf`) is root's chosen state. The epoch it closes stops counting.
5. **Recovery.** A reset — blind, then root re-adds members; or with a snapshot, one signature for the whole recovery. Either way every grant of the old generation dies.

**Members are Ed25519 only**: a `did:key`, or a long-form `did:peer:4` carrying exactly the pinned key. The add carries both the DID and the key, and the fold refuses an add whose DID does not carry that key, any other DID form (a short-form `did:peer:4`, a network-backed DID), or a document carrying a second signing key — a verifier that reads the DID and one that reads the pin must agree on the key.

**"Another member" is another pinned key.** Self-renew and self-remove are judged by pinned-key equality, whatever the DID or incarnation, so one key added twice — concurrent retries, or once as a `did:key` and once as a peer DID — cannot renew itself through the alias.

**Leases bound grants, not log authority.** A lease is unix seconds; `DEFAULT_LEASE_SECONDS` is 90 days, a duration the caller adds to the time it adds or renews. The lease is how long a user can stay away before the root is needed: members renew each other, and a member left unrenewed past its lease end still acts on the log but issues no grant a verifier accepts past that end. Only a removal ends log authority.

**Mutual removal removes both.** Two members removing each other concurrently both stand — removals union — and the set can collapse to empty; root settles. That is the stolen-member risk in [./security.md](./security.md#accepted-risks-of-the-management-tier), and it is accepted: any automatic choice between member branches would itself be attackable.

**Grants minted by a member.** `resolveMember` is everything a grant verifier needs from the log: the pinned key the grant must be signed by, and the lease end its `exp` must not pass, for the generation and incarnation the grant names, answered from the frozen view the rest of the verification uses. The verifier is `@kokuin/capability`'s `assertMemberRoot`, run by `checkCapability` and `checkDelegationChain` for a root carrying `mbr` — see [Grants issued by management members](./capability.md#grants-issued-by-management-members).

## Signing as a profile

```typescript
createControllerIdentity({ seed, profile, log })      // root: derives the key from the seed
createControllerIdentityWithKey({ privateKey, log })  // daily: the key, and nothing else
```

Both fold the log's chain and bind to the key its current state establishes, both stamp `kid: #<the key that signed>` on every token, and both refuse a caller-supplied `kid` that names another key rather than dropping it. They fold the chain alone: epoch events never change a root key, so folding them would cost up to `MAX_EPOCH_EVENTS` signature checks on a path that must stay synchronous and cheap.

Prefer the key form on any path that runs often. The seed is the root of everything the profile can ever do, and the design keeps it for rare ceremonies; a key holder can sign as the profile and cannot rotate, because a rotate must reveal the key the log pre-committed and only the seed derives that. Both throw when the key they hold is not one of the profile's current authority keys — a stale log, a wrong profile index, or a key the profile has rotated away.

**The log is the caller's freshness contract.** An identity built from a stale log signs with a key later events retired. That is survivable across a rotate (a verifier accepts any key authoritative within the generation, via `resolveHistoric`) and fatal across a reset. Rebuild from a re-read log after either.

## Conformance

`@kokuin/controller-conformance` is private and never published: a framework-agnostic suite (`runControllerConformance(impl)`) that any implementation of this method runs to prove it honours the contract — inception self-certification, pre-rotation, state snapshots and retired-key tombstones, key denial, reset supersession and snapshot resets, duplicity, criticality, the epoch merge (order independence, causal authorisation, old-epoch and cross-epoch events, saturation) and the management-member rules.

It is a contract, not a proof of security. The 2026-08-15 review found five Criticals that the suite passed, because it only ever presented equal-length branches: the properties it certified were never the ones under attack. Rows have since been added for what those attacks reached. Treat a green suite as "this implementation agrees with the others", never as "this implementation is safe".
