# Management tier on the controller log

**Status:** design, awaiting approval. Supersedes
`docs/agents/plans/next/2026-10-21-revoke-capability-expiry-in-folded-logs.md` (delete it when this
lands).

## Intent

The root signer (Ledger or cold mnemonic) should come out only for first setup, for adding a
management device, for settling disputes, and for recovery. Day to day, a few trusted **management
devices** (e.g. a desktop app that manages AI agents, plus the user's phone) mint grants for
**edge** agents and devices and revoke them, and renew each other.

Today the management tier is a capability: a `rev` carrying `cap` is verified against the clock.
Once that capability expires, every log containing a revoke it authorised stops folding
(`REVOKE_NOT_AUTHORISED`): the DID becomes unresolvable for any newcomer, and a truncated prefix wins
anti-truncation. With an offline root, anchoring by a later authority event almost never fires, and a
management capability cannot be renewed without root.

The fix: **management authority lives in the log**, and member actions **merge** instead of
competing. A device cannot know whether its event races another member's, so no member action may
make the log fork; every member action is monotonic and all of them are combined. Only root events
form a single chain, and only root settles.

## Goals

- The fold is deterministic and clock-free. The same input folds the same way forever.
- Member actions never fork the log: concurrent member events merge.
- Management devices hold a lease and renew each other without root.
- Any single management device can revoke an edge holder alone.
- Edge grants are minted by management devices, not by the root key.
- Most verifiers work offline: a grant plus the log it travels with is enough to verify it.
- Root signs only: every add, settlement, recovery.
- Consumers may prune: only the root chain and the current epoch are needed.

## Non-goals

- A trusted clock, witnesses, or timestamped events.
- Grants on the log. Grants stay off-log signed tokens; the log holds the management set and denials.
- Revoking an individual capability `jti` on the log (stays off-log via `revocation.ts`).
- ES256 / P-256 member keys. Members are Ed25519 only.
- kubun / kumiai adoption. They get their own plans; this design defines what kokuin offers them.
- Threshold (m-of-n) root keys; root stays n-of-n on `k`.

## Anti-goals

- Any rule under which the same input folds differently later.
- Any automatic choice of a winner between member branches (copying, cycles and digest grinding all
  attack such a choice).
- Any way for a member to add a member (sock-puppets would renew each other forever), rotate, reset,
  touch `k`/`ka`/`n`, or renew itself.
- An ordinary root action (an add, a root revoke) silently undoing a member's removal or revoke. Only
  an explicit settlement may drop member events.
- Pruning being required: a consumer may keep the full log.

## Decided rules

Decided with the user, in this form.

| Action | Who may sign | Root needed |
| --- | --- | --- |
| Add a management member (with a lease end) | root only | yes, every time |
| Renew a member's lease | root, or any member **other than** the one renewed | no |
| Remove a member | root, or any member other than the one removed | no |
| Revoke an edge holder (target a DID or retired key) | root, or any single member | no |
| Mint an edge grant | any member (as issuer) | no |
| Settle (new epoch, full state snapshot) | root | yes |

- **Members** are an Ed25519 `did:key`, or a long-form `did:peer:4` carrying the pinned Ed25519 key
  (the rule the `cnf` pin uses today). The add carries the DID and the key; the fold refuses an add
  whose DID does not carry that key, or any other DID form.
- **"Other member" means another pinned key.** Self-renew and self-remove are judged by pinned-key
  equality, irrespective of DID or incarnation, so one key added twice (concurrent retries, or once
  as `did:key` and once as a peer DID) cannot renew itself through the alias.
- **Root and member keys are disjoint.** A member pin may never be a key in `k`, `ka` or committed
  in `n` on the current generation's root chain; adds, snapshots and rotations all enforce it. No
  management device holds the seed or any root key.
- **The fold never reads the lease.** Lease end is carried in the state; it bounds grants only. Only a
  removal ends a member's log authority.
- **Grants are bounded at mint.** A member grant verifies only if `exp` ≤ the issuer's lease end in
  the state the verifier holds, plus the normal `exp` check.
- **Short grants, long leases.** Lease (months) is how long a user can stay away before root is
  needed. Edge grant lifetime bounds how late an offline verifier learns an **edge holder** was
  revoked: default **12 hours**, configurable, enforced by the verifier as a maximum `exp - iat`.
- **Removal kills the member's grants** for any verifier whose state contains the removal.
- **Capability-authorised revoke is removed** (breaking change, accepted as safer).
- **Example flow:** desktop install creates the mnemonic; root (still in hand) publishes the
  inception and adds the desktop. Adding the phone later is one root signature. From then on,
  desktop and phone renew each other and manage edge agents without root.

### Accepted risks

- **Stolen member.** A thief can remove every honest member (from any point where it was a member,
  even after its own removal, by building on an older state). All removals stand, so the member set
  can collapse; root settles. It can also deny edge holders and flood the epoch with events until
  root settles. One root ceremony per theft.
- **Stolen member vs offline verifiers.** A removed member keeps its pre-removal log and can mint
  fresh 12-hour grants that verifiers which never see the removal accept, until its lease end. The
  12-hour bound applies to revoked edge holders, not to stolen members; the lease is the bound here.
- **Withheld events.** A peer can withhold member events from a verifier that has never seen them
  (the existing first-contact truncation limitation). A verifier never forgets what it has seen.
- **Flood shutdown.** A stolen member can saturate the epoch, and every grant that depends on it,
  honest agents' included, stops verifying until root settles. Fail closed is chosen over guessing
  which events to drop.
- **Incomplete settlement.** A removal or denial withheld from root is not in its snapshot and is
  lost; members re-issue their own revokes on the new epoch.

## Design

### Two layers

- **The root chain** is linear: `icp`, `rot`, reset. **Root-chain selection comes first, epoch
  evaluation second.** The precedence is today's: a higher generation wins; a `rot` signed by the
  pre-committed keys supersedes a competing current-key event; anything else is duplicity, which a
  reset resolves. Since root adds and root revokes now live in epochs, a current-key event competing
  with a `rot` is one in the epoch that `rot` closes; the comparison inputs change, the precedence
  does not. `s`, `keySeq`, `resolveHistoric` and key derivation live on this chain only.
- **Every `rot` is a settlement:** it carries the full state snapshot (management set with each
  member's add reference and lease end; deny set; `ka` as today). `icp` starts the first epoch with
  an empty set. **A reset stays blind and deterministic** (`createReset` is unchanged: no options,
  empty deny set): it starts the new generation's first epoch with an empty set, and root re-adds
  members with adds. The state after a `rot` **is** its snapshot; nothing before it contributes.
  Root's tooling builds the snapshot from every branch it knows (all members, all pulled
  revocations), minus what root chooses to drop. The snapshot is root's **chosen replacement
  state**, not a proven complete merge: a removal or denial root never saw is not in it, and tooling
  must present it that way.
- **An epoch** is everything between one root-chain event and the next. Within an epoch, non-`rot`
  events (member actions, root adds, root revokes) form a DAG rooted at the epoch's root-chain event.
  Each such event names its epoch (the digest of that root-chain event) and lists the parent digests
  it builds on (every head its author knows; a recommendation, not enforceable).

### Folding an epoch

- **Authorisation is causal.** An epoch event is valid iff its signer is authorised in the state of
  its ancestors: the epoch's starting snapshot plus the effects of all its ancestor events. Never
  concurrent branches, arrival order, or wall time.
- **Effects merge.** The epoch's state is the starting snapshot plus the union of effects of all
  valid events: denials union; removals union; adds union; lease is the maximum renewal per member
  incarnation; removal dominates renewal.
- **Incarnations.** A member is identified by its add event's digest. Renew and remove target that
  digest, so a delayed renew or remove never carries over to a re-add, and a grant names the
  incarnation and generation it was minted under (below). A snapshot keeps each member's add
  reference.
- **Member revoke** may not target a member of its causal-past state (its DID or pinned key):
  members are removed through remove. Existing rules (no denying a published `k`/`ka` key) apply.
- **Denial dominates membership.** A member whose DID (any alias) or pinned key is denied in the
  merged state is not an effective member: its later events are not authorised by that membership
  and it issues no valid grants, until a settlement says otherwise. This covers a root add merging
  with a concurrent revoke of the same DID or key. Both events are kept; neither is rejected for
  arriving second.
- **Old epochs never count.** An event naming an epoch other than the current one has no effect: its
  effect is either in the newer snapshot or was dropped by it. A consumer that keeps the full log
  keeps such events as history only.
- **No cross-epoch parents.** Every parent is the named epoch's root-chain event or an event of the
  same epoch; an event listing any other parent is refused. Snapshot add references are identifiers
  the snapshot attests, not parent dependencies. This keeps a pruned and a full store in agreement.
- **Incomplete input.** A missing parent means the input is incomplete, never an empty past; the
  event is not applied until its parents are present. Cycles and malformed references are refused.
- **Limits.** Two kinds, never confused:
  - *Request limits* (event bytes, parents per event, pending unresolved events, deterministic
    validation work per request) reject input. Unauthenticated or invalid input only ever gets
    rejected; it never changes remembered state.
  - *Epoch saturation:* more than a fixed number of distinct, authenticated, causally valid events
    in one epoch. Saturation fails the epoch closed and is remembered until a settlement: a later
    presentation of a subset does not clear it (unlike today's `history` fallback, which treats a
    stored log that stops folding as no memory). While saturated, verifiers refuse every
    authorisation that depends on that epoch, including root-issued grants whose holder denials can
    no longer be read. The root chain still folds, so root can always settle into a fresh epoch, and
    a verifier never needs to ingest a superseded epoch to fold the new one.
  - Work is counted deterministically (events, edges, signatures), never by elapsed time; events are
    deduplicated by digest.
- **Root adds and root revokes** are ordinary epoch events (signed by the current `k`, no rotation,
  so they do not burn pre-rotation). They merge like member events and never drop anything.
- All new event types are `crit: true`, so a verifier that predates this fails closed. All are pure
  signature checks, so the sync and async folds accept the same inputs.

### Pruning (optional)

The minimum a consumer must keep: the inception, the current generation's root chain, and the
current epoch's events. Everything else (old epochs' member events, earlier generations) may be
dropped or kept as history. A store holding more is never contradicted by one holding less, since
old epochs have no effect.

Dropping deny entries in a snapshot:

- **Retired signer keys** (`#key` of a key on the current generation's root chain) are never dropped
  within the generation: historic resolution would accept fresh tokens signed with them again. Only
  a reset retires them.
- **Holder DIDs:** dropping one is a deliberate re-authorisation. It is safe only when every
  authority that could mint grants to that holder has ended (members removed or settled away) and
  their grants have expired; waiting for the grants root has seen to expire is not enough, since a
  malicious member may keep minting. Root's tooling must say so; the log has no clock.

### Storage and verification views

The log is no longer an array: it is the root chain plus a set of epoch events. `LogStore` gains an
atomic merge (union of authenticated events), so two writers never lose each other's events; the
store packages use `withStoreTransaction`. History becomes: never forget an event seen in the
current epoch, and accept a newer root chain only through the existing branch rules. A verification
uses one frozen view for issuer membership, incarnation, pin, lease and every delegation-link denial
check.

### Edge grants and offline verification

A capability with `sub` = controller DID and `iss` = a member DID is a chain root when, in the view
the verifier holds: the grant names the current generation and the issuer's add digest; that
incarnation is an effective member (present, not removed, its DID and pinned key not denied); the
grant is signed by the pinned member key (no other key a `did:peer:4` carries); and `exp` ≤ that
incarnation's lease end. `checkCapability` and the delegation walk gain
that arm next to `iss === sub`. Same power as a root grant; it cannot confer management power, since
membership comes only from a root add. The edge holder may delegate further under existing rules.

A grant travels with a proof: the root chain up to the current `rot`, plus the epoch events that
establish the issuer's membership and lease (their ancestor closure). A verifier merges it with what
it holds, then folds offline.

## Left to the builder

- Event type names and field spellings; how epoch and parents are encoded; signer identification.
- Limit values; default lease (suggest 90 days) and where it is configured.
- The proof bundle format and `LogStore` merge API; resolver method names.
- Whether removal also writes a deny entry for the member key.
- Removal of the capability-authorised revoke surface (`FoldOptions.verifyCapability`, the
  `capability` step outcome, `createControllerCapabilityVerifier`, `createRevokeWithKey`'s `cap`,
  the `unverified` / `needs-capability-verification` plumbing).
- Conformance cases in `@kokuin/controller-conformance`, at minimum: member revoke folds with no
  clock; concurrent member events merge in every presentation order; copying an honest event onto a
  hostile branch, removal cycles and digest grinding change nothing; mutual removal removes both;
  self-renew (including through an alias of the same key), member add, member revoke of a member,
  non-Ed25519 or short-form-peer adds, and a member pin equal to a root key all fail; old-epoch
  events have no effect; cross-epoch parents are refused; a delayed remove does not hit a re-add;
  a root add merged with a concurrent revoke of the same key yields no effective member; missing
  parents are incomplete; saturation fails the epoch but not the root chain, survives a subset
  presentation, and cannot be triggered by unauthenticated input; a snapshot cannot drop a retired
  signer key's denial; a reset carries no snapshot; a cold `rot` beats a
  current-key root event; a root add never drops a concurrent removal; a pruned and a full store
  fold to the same state; a member grant past the lease, past 12 h, from a removed incarnation, from
  a previous generation, or signed by an unpinned key fails. Mutate each rule alone.
- Docs: `docs/reference/controller.md` (custody tiers, events, fold, branch selection, resolution),
  `docs/reference/security.md` remedy ladder; release note for the breaking changes.
