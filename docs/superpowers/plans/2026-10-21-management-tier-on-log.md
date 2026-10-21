# Management Tier on the Controller Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the clock-dependent capability-authorised revoke with an on-log management set whose member actions merge, so a `did:kokuin:` log that folds once folds forever.

**Architecture:** The log splits into a linear **root chain** (`icp`, `rot`, reset; every `rot` carries a full state snapshot) and **epochs**: a DAG of `add`/`ren`/`rmv`/`rev` events anchored at the latest chain event. An epoch folds by causal authorisation and semilattice union; old-epoch events never count. Member-issued grants become a new chain-root arm in `@kokuin/capability`, checked against the folded member set through a new optional resolver member.

**Tech Stack:** TypeScript (ESM), vitest, `@noble/curves` ed25519, `@kokuin/token` resolver registry, `@hozon/db` (Kysely) for the store package, pnpm workspaces + turbo.

**Spec:** `docs/superpowers/specs/2026-10-21-management-tier-on-log-design.md` — read it first; this plan argues from it and does not repeat its rationale.

## Global Constraints

- pnpm only. Run repo scripts as `rtk proxy pnpm ...` (an `rtk` shim hijacks bare `pnpm run`); `pnpm --filter <pkg> exec vitest run <file>` is fine as is.
- Follow the `kigu:conventions` skill: no `any`, no plan/task labels in code, comments, test names or identifiers; match the surrounding comment density (these files document *why* at length — keep that register).
- Members are Ed25519 only: a `did:key`, or a long-form `did:peer:4` carrying the pinned key. No ES256.
- Every new event type is `crit: true`.
- The fold is total and clock-free: every rejection is a returned reason; nothing reads `Date.now()` or a lease.
- Edge grant default maximum lifetime: **12 hours** (`43200` s), configurable.
- Lease is unix seconds (integer). Default lease constant: **90 days** (`7776000` s).
- Breaking changes are accepted (capability-authorised revoke removed, `rev` leaves the root chain, log becomes `ControllerLog`). Old logs carrying a chain `rev` stop folding; say so in the release note.
- `@kokuin/store-*` methods use `withStoreTransaction` from `@hozon/db`, never `.transaction()`.
- Private packages (`@kokuin/controller-conformance`) are not released.

## Review Focus

1. **A relay floods a log with thousands of unsigned or malformed epoch events.** Expected: the request is rejected or the events dropped; nothing is stored, nothing saturates. Test in Task 7.
2. **The same epoch events presented in different orders, or twice.** Expected: an identical head (deny set, members, leases). Test in Task 5.
3. **An epoch event whose parent arrives in a later presentation.** Expected: pending at first, then applied once merged with the later log. Test in Task 7.
4. **A legacy stored row (the old event-array shape) in `@kokuin/store-controller`.** Expected: decoded as `{ chain, events: [] }` without throwing. Test in Task 9.
5. **A member grant with no `iat`, or with `iat` in the future.** Expected: refused (a lifetime cannot be bounded without `iat`), with the existing time-claim errors. Test in Task 10.

## Shared Interfaces

Defined once here; tasks name which they produce. Paths are under `packages/`.

```ts
// controller/src/events.ts (chain)
export type EventType = 'icp' | 'rot'                        // `rev` leaves the chain
export type MemberEntry = { did: string; key: string; add: string; lease: number }
// RotateEvent gains: m?: Array<MemberEntry>  (required with `d` on a non-reset rot; optional on a reset)
export type StateSnapshot = { members: Array<MemberEntry>; deny: Array<string> }

// controller/src/epoch-events.ts
export type EpochEventType = 'add' | 'ren' | 'rmv' | 'rev'
export type EpochEventCommon = {
  v: 1; t: EpochEventType; i: string; g: number
  e: string             // digest of the chain event that opened the epoch
  p: Array<string>      // parents: `e` itself or same-epoch event digests; 1..MAX_EVENT_PARENTS, no duplicates
  crit: boolean
  by?: string           // signing member's add digest; absent = root (n-of-n over the chain head's `k`)
}
export type AddEvent = EpochEventCommon & { t: 'add'; did: string; key: string; lease: number }
export type RenewEvent = EpochEventCommon & { t: 'ren'; add: string; lease: number }
export type RemoveEvent = EpochEventCommon & { t: 'rmv'; add: string }
export type RevokeEvent = EpochEventCommon & { t: 'rev'; x: string }
export type EpochEvent = AddEvent | RenewEvent | RemoveEvent | RevokeEvent
export type EpochSigner =
  | { root: { seed: Uint8Array; profile: number } }
  | { member: { privateKey: Uint8Array; add: string } }

// controller/src/log.ts
export type ControllerLog = { chain: Array<SignedEvent>; events: Array<SignedEvent<EpochEvent>> }

// controller/src/fold.ts
export type MemberState = MemberEntry & { removed: boolean; effective: boolean }
// KeyState gains: members: ReadonlyMap<string, MemberState> (keyed by add digest),
//                 epoch: string (digest of the chain event opening the current epoch),
//                 saturated: boolean
export type FoldResult =
  | { ok: true; states: Array<KeyState>; head: KeyState; applied: Array<string>; pending: number; rejected: number }
  | { ok: false; reason: string; index: number }
export function foldLog(did: string, log: ControllerLog): FoldResult

// controller/src/limits.ts
export const MAX_EPOCH_EVENTS = 4096    // authenticated saturation threshold
export const MAX_LOG_EVENTS = 8192      // request limit: epoch events in one input
export const MAX_EVENT_PARENTS = 16
export const MAX_EVENT_BYTES = 8192     // canonical bytes of one epoch event body
export const DEFAULT_LEASE_SECONDS = 7_776_000

// token/src/method.ts
export type MemberQuery = { did: string; add: string; gen: number }
export type ResolvedMember = { key: ResolvedSigningKey; lease: number }
// DIDMethodResolver gains: resolveMember?(subject: string, member: MemberQuery): Promise<ResolvedMember>
```

`states` stays per chain event (what `resolveHistoric` scans). `head` is the last chain state merged with the current epoch: its `deny`, `members` and `saturated` are the live answers.

---

### Task 1: Token helpers for member keys and member resolution

**Files:**
- Modify: `token/src/method.ts` (add `MemberQuery`, `ResolvedMember`, optional `resolveMember`)
- Modify: `token/src/did.ts` (add `signingKeysOf`)
- Modify: `token/src/index.ts` (export the three)
- Modify: `capability/src/controller.ts` (replace the local `identifierKeys` with `signingKeysOf`)
- Test: `token/test/signing-keys-of.test.ts`

**Interfaces:**
- Produces: `signingKeysOf(did: string): Array<ResolvedSigningKey> | null` — the keys an identifier carries without resolution: one for a `did:key`, the `authentication` keys of a long-form `did:peer:4`, `null` for any identifier carrying none (short-form peer, `did:kokuin:`). Throws on an identifier that claims to carry a key and does not decode. `MemberQuery`, `ResolvedMember`, `DIDMethodResolver.resolveMember?`.

- [ ] **Step 1: Write the failing test** — move the cases `capability/test/atk-cnf.test.ts` already has for `identifierKeys` behaviour into the new file, plus:

```ts
test('a did:key carries exactly its key', () => {
  const { publicKey } = ed25519.keygen()
  expect(signingKeysOf(getDID(CODECS.EdDSA, publicKey))).toEqual([{ alg: 'EdDSA', publicKey }])
})
test('a short-form did:peer:4 and a did:kokuin carry none', () => {
  expect(signingKeysOf(getPeer4ShortForm(longFormPeer))).toBeNull()
  expect(signingKeysOf('did:kokuin:abc')).toBeNull()
})
test('a long-form did:peer:4 carries only its authentication keys', () => {
  expect(signingKeysOf(longFormPeerWithAgreementKey)).toEqual([{ alg: 'EdDSA', publicKey }])
})
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/token exec vitest run test/signing-keys-of.test.ts` — Expected: FAIL, `signingKeysOf` not exported.
- [ ] **Step 3: Implement** `signingKeysOf` in `token/src/did.ts` by moving `identifierKeys` (and its `MAX_KEY_ENCODED` guard) out of `capability/src/controller.ts`; add the types and the optional resolver member (document it like its siblings: optional, absence fails closed for member-issued grants).
- [ ] **Step 4: Run** the new test and `rtk proxy pnpm --filter @kokuin/token run test` and `rtk proxy pnpm --filter @kokuin/capability run test` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Move identifier key extraction into token and add member resolution types"`

---

### Task 2: Remove the capability-authorised revoke

Pure deletion; `rev` stays on the chain until Task 3.

**Files:**
- Modify: `controller/src/fold.ts` — delete `foldLogAsync`, `FoldOptions`, `VerifyCapabilityParams`, `CapabilityAuthorisation`, `isCapabilityAuthorisation`, the `capability` step outcome, `CAPABILITY_*` and `REVOKE_NOT_SIGNED_BY_AUDIENCE`; a `rev` with any `cap` member now fails with `'revoke capability is not supported'`.
- Modify: `controller/src/events.ts` — drop `cap` from `RevokeEvent`, `CreateRevokeParams`, `CreateRevokeOptions`; delete `createRevokeWithKey` and `verifyEventSignedBy`.
- Modify: `controller/src/state.ts` — delete `allStatesAsync`, `currentStateAsync`; add `allStates(did, events, context)` (sync).
- Modify: `controller/src/supersede.ts` — delete `resolveBranchesAsync`, `needsCapabilityVerification`, `unverified`, the `needs-capability-verification` failure.
- Modify: `controller/src/history.ts`, `controller/src/resolver.ts` — drop `options`/`verifyCapability`; fold synchronously.
- Modify: `controller/src/identity.ts` — delete both `…Async` identity factories.
- Modify: `controller/src/index.ts` — remove the deleted exports.
- Modify: `capability/src/controller.ts` — delete `createControllerCapabilityVerifier`, `REVOKE_*` reasons, `assertRevokeCapabilityAudience`, `ControllerCapabilityVerifierParams`. Keep `audienceConfirmation`/`cnf` helpers (kubun mints leaf grants with them). `capability/src/index.ts`, `capability/src/types.ts` follow.
- Modify: `controller-conformance/src/index.ts` — remove `resolveBranchesAsync`, `ConformanceFoldOptions`, `ConformanceCapabilityAuthorisation`, `authorityPublicKey` and the capability group.
- Delete tests: `capability/test/controller-revoke.test.ts`; remove cap-revoke cases from `capability/test/{atk-resolver-seam,atk-delegated-leaf,atk-chain,atk-cnf,own-denied-key-reach,controller-deny,lib}.test.ts` and `controller/test/{own-design-round,own-c1-precedence,revoke,identity,fold-totality,resolver,supersede,keystore-identity,criticality,deleted-guards,atk-wire-types,atk-nonfinite-totality,exports}.test.ts`. Keep every non-cap case.

**Interfaces:**
- Produces: `foldLog(did, events)` (sync only, unchanged shape for now); `resolveBranches(did, branches)` with `ResolveResult` minus `unverified`; `createControllerResolver({ loadLog, history? })`.

- [ ] **Step 1: Write the failing test** in `controller/test/revoke.test.ts`:

```ts
test('a revoke carrying a capability no longer folds', () => {
  const rev = { ...createRevoke({ seed, profile, did, prior: icp.event, target: 'did:key:z6Mk', keyPosition: { gen: 0, seq: 0 } }) }
  const withCap = { ...rev, event: { ...rev.event, cap: 'x' } }
  const result = foldLog(did, [icp, withCap])
  expect(result).toEqual({ ok: false, reason: 'revoke capability is not supported', index: 1 })
})
test('the async fold and capability verifier are gone', async () => {
  const controller = await import('../src/index.js')
  expect('foldLogAsync' in controller).toBe(false)
  expect('resolveBranchesAsync' in controller).toBe(false)
  const capability = await import('@kokuin/capability')
  expect('createControllerCapabilityVerifier' in capability).toBe(false)
})
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/revoke.test.ts` — Expected: FAIL.
- [ ] **Step 3: Delete** the surface listed above; pruned tests keep their non-cap cases.
- [ ] **Step 4: Run** `rtk proxy pnpm run test:types` and `pnpm --filter @kokuin/controller --filter @kokuin/capability exec vitest run` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Remove capability-authorised revoke"`

---

### Task 3: Root chain with state snapshots

`rev` leaves the chain; every non-reset `rot` carries `m` and `d`; a reset takes an optional snapshot.

**Files:**
- Modify: `controller/src/events.ts` — `EventType = 'icp' | 'rot'`; delete `RevokeEvent`, `createRevoke`, `verifyRevoke` (they return as epoch events in Task 4; `keyTarget`/`keyFromTarget` stay); add `MemberEntry`, `StateSnapshot`, `isMemberEntry(value: unknown): value is MemberEntry`; `RotateEvent.m?`; `CreateRotateOptions` replaces `denySnapshot` with `snapshot: StateSnapshot` (**required**) and drops `keyPosition` (with `rev` gone, `s` and `keySeq` coincide again — delete the divergence prose); `createReset(seed, profile, gen, snapshot?: StateSnapshot)`; `verifyReset` accepts `d`/`m` only together, both absent meaning empty.
- Modify: `controller/src/fold.ts` — chain-only `stepEvent` (`icp`/`rot`/unknown-skip); `KeyState` gains `members`, `epoch`, `saturated` (`false` for chain states); `pruneDenySet` replaced by `snapshotOf`.
- Create: `controller/src/members.ts` — snapshot validation shared by fold and epoch.
- Modify: `controller-conformance/src/index.ts` — `createRotate` options and `createReset` signature; delete `createRevoke` from `ControllerImplementation` (re-added in Task 4); rewrite the `position-dependence`, `key revocation` and `rotate after a revoke` groups around snapshots.
- Test: `controller/test/snapshot.test.ts`; update `rotate.test.ts`, `reset.test.ts`, `generation-lifecycle.test.ts`, `atk-retired-key.test.ts`.

**Interfaces:**
- Produces:
  - `snapshotOf(state: KeyState, drop?: { deny?: Iterable<string>; members?: Iterable<string> }): StateSnapshot` — every non-removed member (by add digest) and deny entry of `state`, minus `drop`.
  - `validateSnapshot(params: { snapshot: StateSnapshot; generationKeys: Array<string>; generationCommitments: Array<string>; tombstones: ReadonlySet<string> }): string | null` in `members.ts` — `null` when valid, else the fold reason. `generationKeys` is every `k`/`ka` on the current generation's chain *including the new event's*; `generationCommitments` every `n`.
  - `memberCarriesKey(did: string, key: string): boolean` in `members.ts` — `did:key` whose key equals `key`, or long-form `did:peer:4` whose `signingKeysOf` is exactly one Ed25519 key equal to `key`; everything else false.
- Fold reasons (exported constants from `fold.ts`): `ROTATE_NEEDS_SNAPSHOT = 'rotate carries no state snapshot'`, `SNAPSHOT_MALFORMED = 'malformed state snapshot'`, `SNAPSHOT_MEMBER_KEY_IS_ROOT = 'snapshot member key is a root key'`, `SNAPSHOT_MEMBER_DID_MISMATCH = 'snapshot member DID does not carry its key'`, `SNAPSHOT_DROPS_RETIRED_KEY = 'snapshot drops a retired key denial'`.

Rules `validateSnapshot` enforces, each with its own reason: entries are `MemberEntry` (`lease` a non-negative safe integer, `add` a string, `key` decodes as EdDSA via `tryDecodeKey`), no duplicate `add`, no two entries sharing a `key`; `memberCarriesKey`; `key` not in `generationKeys` and `digestOf(key)` not in `generationCommitments`; `d` is a key list; every entry of `tombstones` is in `d`. **Tombstones** = the previous chain state's `deny` entries that are key targets naming a key in `generationKeys` (the checkpointed retirements). A reset starts a new generation: no tombstones.

- [ ] **Step 1: Write the failing tests** in `controller/test/snapshot.test.ts`:

```ts
test('a rotate without a snapshot does not fold')            // reason ROTATE_NEEDS_SNAPSHOT
test('the state after a rotate is its snapshot', () => {
  const rot = createRotate({ seed, profile, did, prior: icp.event, options: { snapshot: { members: [member], deny: ['did:key:zA'] } } })
  const result = foldLog(did, [icp, rot])
  const head = at(result.states, 1)
  expect([...head.deny]).toEqual(['did:key:zA'])
  expect(head.members.get(member.add)).toEqual({ ...member, removed: false, effective: true })
})
test('a snapshot member pinning a root key is refused')       // member.key = rot.event.k[0] → SNAPSHOT_MEMBER_KEY_IS_ROOT
test('a snapshot member pinning a committed next key is refused') // digestOf(key) ∈ n
test('a did:peer:4 member carrying two signing keys is refused')  // SNAPSHOT_MEMBER_DID_MISMATCH
test('a later rotate may not drop a checkpointed retired key', () => {
  // r1 rotates K0→K1 with d: [keyTarget(K0)]; r2 snapshot omits it → SNAPSHOT_DROPS_RETIRED_KEY at index 2
})
test('a holder DID denial may be dropped by a later snapshot')
test('a blind reset is byte-identical per seed, profile and generation', () => {
  expect(createReset(seed, profile, 1)).toEqual(createReset(seed, profile, 1))
})
test('a reset with a snapshot folds to that snapshot and starts a new generation')
test('a reset snapshot is checked against the new generation keys')  // member key = new gen k → refused
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/snapshot.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement** per the interfaces. `createRotate` writes `m` and `d` from `options.snapshot`; `createReset` writes both only when given a snapshot (blind bytes unchanged). The rotate branch of `stepEvent` builds tombstones from `prior`, collects `generationKeys`/`generationCommitments` from the chain states of `prior.gen` plus the event, calls `validateSnapshot`, and sets `members` from `m` (`removed: false`, `effective` = not targeted by a `d` entry — define `denialTargetsMember(entry: string, member: MemberEntry): boolean` in `members.ts`, the one predicate every later task uses: = `entry === keyTarget(member.key)` or (`entry` starts with `did:` and `normalizeDID(entry) === normalizeDID(member.did)`)). `epoch` = the state's own `digest`.
- [ ] **Step 4: Run** `rtk proxy pnpm --filter @kokuin/controller run test` and `pnpm --filter @kokuin/controller exec vitest run test/conformance.test.ts` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Move controller state into rotate snapshots and drop revoke from the root chain"`

---

### Task 4: Epoch event types, builders and signatures

**Files:**
- Create: `controller/src/epoch-events.ts`
- Create: `controller/src/limits.ts` (constants from Shared Interfaces)
- Modify: `controller/src/index.ts`
- Modify: `controller-conformance/src/index.ts` — `ControllerImplementation` gains `createEpochEvent` (one builder taking the event fields and an `EpochSigner`) and `memberKeyPair()` test support.
- Test: `controller/test/epoch-events.test.ts`

**Interfaces:**
- Consumes: `KeyState` with `epoch`, `keyGen`, `keySeq` (Task 3).
- Produces:
  - `createAdd(params: { seed: Uint8Array; profile: number; did: string; head: KeyState; parents: Array<string>; member: { did: string; key: string; lease: number } }): SignedEvent<AddEvent>`
  - `createRenew(params: { signer: EpochSigner; did: string; head: KeyState; parents: Array<string>; add: string; lease: number }): SignedEvent<RenewEvent>`
  - `createRemove(params: { signer: EpochSigner; did: string; head: KeyState; parents: Array<string>; add: string }): SignedEvent<RemoveEvent>`
  - `createRevoke(params: { signer: EpochSigner; did: string; head: KeyState; parents: Array<string>; target: string }): SignedEvent<RevokeEvent>`
  - `isEpochEventShape(value: unknown): value is SignedEvent<EpochEvent>` — envelope + per-type fields + `p` rules + `isCanonicalizable` + `canonicalBytes(event).length <= MAX_EVENT_BYTES`.
  - `verifyEpochSignature(signed: SignedEvent<EpochEvent>, signer: { rootKeys: Array<string> } | { memberKey: string }): boolean` — root: `verifySignatures` n-of-n; member: exactly one signature, verifying under `memberKey`.
- Builders set `v: 1`, `i: did`, `g: head.gen`, `e: head.epoch`, `p: parents` (sorted, deduplicated), `crit: true`, `by` = `member.add` for a member signer and absent for root. A root signer derives the key at `authorityPath(profile, head.keyGen, head.keySeq)`. `createAdd` is root-only by type. Builders throw on an empty `parents`.

- [ ] **Step 1: Write the failing tests:**

```ts
test('a root add names the epoch and its parents and verifies under the chain keys', () => {
  const add = createAdd({ seed, profile, did, head, parents: [head.epoch], member })
  expect(add.event).toMatchObject({ t: 'add', e: head.epoch, p: [head.epoch], crit: true })
  expect(add.event.by).toBeUndefined()
  expect(verifyEpochSignature(add, { rootKeys: head.keys })).toBe(true)
})
test('a member revoke names its signer and verifies only under the pinned key', () => {
  const rev = createRevoke({ signer: { member: { privateKey: m.privateKey, add: 'A' } }, did, head, parents: [head.epoch], target: 'did:key:zX' })
  expect(rev.event.by).toBe('A')
  expect(verifyEpochSignature(rev, { memberKey: m.key })).toBe(true)
  expect(verifyEpochSignature(rev, { memberKey: other.key })).toBe(false)
})
test('the shape guard refuses: no parents, duplicate parents, more than MAX_EVENT_PARENTS, a non-string parent, an oversized body, a missing crit')
test('parents are written sorted and deduplicated')
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/epoch-events.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement** in `epoch-events.ts` and `limits.ts`.
- [ ] **Step 4: Run** the test — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add epoch event types and builders"`

---

### Task 5: Folding an epoch

`foldLog` takes a `ControllerLog` and merges the current epoch. Member authorisation here is only "signer is an effective member of the causal state"; the lifecycle rules land in Task 6.

**Files:**
- Create: `controller/src/log.ts` (`ControllerLog`, `isControllerLog`)
- Create: `controller/src/epoch.ts` (merge algorithm)
- Modify: `controller/src/fold.ts` (`foldLog(did, log: ControllerLog)`, new `FoldResult`), `controller/src/state.ts`, every caller of `foldLog` in `controller/src` (history, supersede fold a chain via `foldLog(did, { chain, events: [] })`)
- Modify: `controller-conformance/src/index.ts` — `foldLog` takes the log; new group `epoch merge`.
- Test: `controller/test/epoch-fold.test.ts`

**Interfaces:**
- Consumes: Task 3 chain fold, Task 4 shape/signature helpers.
- Produces: `foldLog(did: string, log: ControllerLog): FoldResult` (Shared Interfaces), reasons `LOG_TOO_LARGE = 'controller log exceeds request limits'`, `MALFORMED_LOG = 'malformed log'`. `foldEpoch(params: { did: string; chainStates: Array<KeyState>; events: Array<unknown> }): { head: KeyState; applied: Array<string>; pending: number; rejected: number }` in `epoch.ts`.

**Algorithm (`foldEpoch`)** — the order matters; nothing below may depend on input order:
1. `anchor` = last chain state. Keep events that pass `isEpochEventShape`, have `i === did`, `g === anchor.gen`, `e === anchor.epoch`, and every parent equal to `anchor.epoch` or the digest of another event in this input naming the same epoch (any other parent ⇒ rejected: no cross-epoch parents). Deduplicate by `digestOf(event)`. Events naming an older epoch are ignored silently (not counted as rejected).
2. Topological order by Kahn's algorithm, ties broken by ascending digest. Events whose parents never all apply are counted in `pending`.
3. For each ready event `x`: `causal(x)` = join over its parents of `after(parent)`, where `after(anchor)` = the anchor's snapshot state and `after(y)` = `causal(y)` joined with `y`'s effect. The state joined is `EpochState = { added: Map<add, MemberEntry>; removed: Set<add>; leases: Map<add, number>; deny: Set<string> }`; join = union of `added`/`removed`/`deny`, maximum lease per add. Validate `x` against `causal(x)` (signer check below); valid ⇒ record `after(x)` and push to `applied`; invalid ⇒ `rejected++` and its descendants end up pending.
4. Signer check: `by` absent ⇒ `verifyEpochSignature(x, { rootKeys: anchor.keys })`; `by` present ⇒ `causal(x).added.get(by)` exists, is not removed, is not targeted by any `deny` entry (`denialTargetsMember`), and `verifyEpochSignature(x, { memberKey })`.
5. Effects in this task: `rev` adds `x` to `deny` (refuse a target naming a key in `anchor.keys`/`anchor.agreement`, as today). `add`/`ren`/`rmv` are accepted by root only and apply naively here; Task 6 replaces their rules.
6. `head` = anchor with `deny`, `members` (from the join of all applied `after`, `effective` computed with `denialTargetsMember`), and `saturated = applied.length > MAX_EPOCH_EVENTS`.
7. Request limit: more than `MAX_LOG_EVENTS` entries in `log.events` ⇒ the whole fold fails with `LOG_TOO_LARGE` (index `-1`). Nothing in steps 1–6 can fail the fold.

Memoise `after` per digest; the work is bounded by the limits, so `O(events × parents)` joins over sets is acceptable.

- [ ] **Step 1: Write the failing tests:**

```ts
test('two concurrent member revokes merge', () => {
  // A and B both members via the rotate snapshot; each revokes a different DID from [epoch]
  const result = foldLog(did, { chain, events: [revA, revB] })
  expect(result.ok && [...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zB'])
})
test('the head is identical in every presentation order', () => {
  for (const order of permutations([revA, revB, renew, child])) {
    expect(summary(foldLog(did, { chain, events: order }))).toEqual(expected)
  }
})
test('an event presented twice applies once')
test('an event naming an older epoch has no effect')   // built against icp's epoch, chain head is a later rot
test('an event with a parent from an older epoch is rejected')
test('an event whose parent is missing is pending, not applied')
test('an unsigned or wrongly signed event is rejected and its children stay pending')
test('a member revoke after the member was removed in its causal past is rejected')
test('a member revoke concurrent with the member being removed still applies')  // no voiding
test('more than MAX_EPOCH_EVENTS valid events saturate the head but the chain still folds', () => {
  expect(result.ok && result.head.saturated).toBe(true)
  expect(result.ok && result.states.length).toBe(chain.length)
})
test('more than MAX_LOG_EVENTS entries fail the request with LOG_TOO_LARGE')
test('a member revoke folds with no clock', () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2100-01-01'))
  expect(foldLog(did, log)).toEqual(foldedEarlier)
})
```

Add matching cases to the conformance `epoch merge` group (`foldLog` order independence, older-epoch no effect, cross-epoch parent refused, missing parent pending).

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/epoch-fold.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement** `log.ts`, `epoch.ts`, and the new `foldLog`. Saturation tests may lower the threshold through a test-only parameter on `foldEpoch` (`limits?: Partial<typeof LIMITS>`), never through `foldLog`'s public signature.
- [ ] **Step 4: Run** `rtk proxy pnpm --filter @kokuin/controller run test` and the conformance test — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Fold the current epoch by causal authorisation and union"`

---

### Task 6: Member lifecycle rules

**Files:**
- Modify: `controller/src/epoch.ts`, `controller/src/members.ts`
- Modify: `controller-conformance/src/index.ts` — new group `management members`
- Test: `controller/test/members.test.ts`

**Interfaces:**
- Consumes: `foldEpoch` (Task 5), `memberCarriesKey`, `denialTargetsMember`, `validateSnapshot` key-disjointness inputs (Task 3).
- Produces: epoch reasons, exported from `epoch.ts` for tests (they land in `rejected`, never fail the fold): `ADD_NOT_ROOT`, `ADD_KEY_IS_ROOT`, `ADD_DID_MISMATCH`, `ADD_KEY_DENIED`, `ADD_KEY_ALREADY_MEMBER`, `SELF_RENEW`, `SELF_REMOVE`, `UNKNOWN_MEMBER`, `MEMBER_REVOKES_MEMBER`, `REVOKE_NAMES_ROOT_KEY`. `FoldResult` gains nothing; a test helper `rejectionsOf(did, log): Map<digest, reason>` reads them via a test-only export `foldEpochDetailed`.

Rules, all judged against `causal(x)` and the anchor:
- **add**: `by` absent (root) else `ADD_NOT_ROOT`; `memberCarriesKey(did, key)` else `ADD_DID_MISMATCH`; `key` not in any `k`/`ka` and `digestOf(key)` not in any `n` on the current generation's chain else `ADD_KEY_IS_ROOT`; no `deny` entry targets the new entry else `ADD_KEY_DENIED`; no *effective* member in `causal(x)` has the same `key` else `ADD_KEY_ALREADY_MEMBER`; `lease` a non-negative safe integer. Effect: `added.set(digestOf(x), { did, key, add: digestOf(x), lease })`, `leases` max.
- **ren**: target `add` in `causal(x).added` else `UNKNOWN_MEMBER`; member signer's key ≠ target key (pinned-key equality, regardless of DID or add digest) else `SELF_RENEW`. Effect: `leases` max. Removal dominates: a removed member stays removed whatever its lease.
- **rmv**: target known else `UNKNOWN_MEMBER`; member signer's key ≠ target key else `SELF_REMOVE`. Effect: `removed.add`.
- **rev**: by a member, no effective member of `causal(x)` is targeted by `x` (`denialTargetsMember`) else `MEMBER_REVOKES_MEMBER`; any signer: a key target naming an anchor `k`/`ka` key ⇒ `REVOKE_NAMES_ROOT_KEY`. Root may target a member.
- **Effective member** (head and causal): added, not removed, not targeted by any `deny` entry.

- [ ] **Step 1: Write the failing tests** (one rule per test; mutate one field at a time from a valid event — see project memory "Mutate each option alone"):

```ts
test('a root add makes an effective member with its lease')
test('a member cannot add a member')                          // ADD_NOT_ROOT
test('a member cannot renew itself, even through a second add of the same key', () => {
  // root adds K as did:key (addA) and as long-form peer of K (addB) concurrently; member addA renews addB
  expect(rejectionsOf(did, log).get(digestOf(renew.event))).toBe(SELF_RENEW)
})
test('a member cannot remove itself')
test('another member renews: the lease is the maximum')
test('a removal beats a concurrent renewal')
test('mutual removal removes both members')
test('a removal cycle of three removes all three')
test('copying an honest event onto a hostile branch changes nothing')  // same digest, deduplicated
test('a delayed renew or remove of an old add does not touch a re-add of the same key')
test('a member revoke of another member is refused, a root revoke of a member disables it')
test('a root add merged with a concurrent revoke of the same key yields no effective member')
test('a denied member issues no further authorised events in its causal future but its concurrent events stand')
test('an add pinning a root key, a committed next key, a non-Ed25519 key or a short-form peer is refused')
```

Mirror the self-renew-through-alias, mutual removal, cycle, copying, and concurrent add/revoke cases in the conformance `management members` group.

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/members.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement** the rules in `epoch.ts`, reusing `members.ts` helpers.
- [ ] **Step 4: Run** the controller suite and conformance — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Enforce management member rules in the epoch fold"`

---

### Task 7: Branch selection, log merge and history

**Files:**
- Modify: `controller/src/supersede.ts` — `resolveBranches(did: string, chains: Array<Array<SignedEvent>>): ResolveResult` (chains only; algorithm unchanged otherwise).
- Modify: `controller/src/log.ts` — `mergeLogs`, `pruneLog`.
- Modify: `controller/src/history.ts` — `LogStore`, `createMemoryLogStore`, `authoritativeLog`.
- Modify: `controller-conformance/src/index.ts` — `resolveBranches` takes chains; root-chain group asserts a cold `rot` beats a current-key duplicate chain and two differing resets at one generation are duplicity resolved by a higher one.
- Test: `controller/test/history.test.ts` (new), update `supersede.test.ts`, `resolver.test.ts`.

**Interfaces:**
- Consumes: `foldLog(did, log)` (Task 5).
- Produces:
  - `LogStore = { get(did: string): Promise<ControllerLog | undefined>; merge(did: string, update: (current: ControllerLog | undefined) => Promise<ControllerLog>): Promise<ControllerLog> }` — `merge` is atomic per DID: no two `update`s for one DID interleave.
  - `createMemoryLogStore(): LogStore` — serialises `merge` per DID with a promise chain.
  - `authoritativeLog(params: { did: string; loaded: ControllerLog; seen: ControllerLog | undefined; context: string }): { log: ControllerLog; result: Extract<FoldResult, { ok: true }> }` — throws `LOG_NOT_AUTHORITATIVE` / `LOG_FORKED` as today.
  - `mergeLogs(did: string, a: ControllerLog, b: ControllerLog): ControllerLog` — chain: `b.chain` if it extends `a.chain` (passes through `a`'s chain head digest), else the `resolveBranches` winner (throws on failure); events: union by digest.
  - `pruneLog(did: string, log: ControllerLog): ControllerLog` — inception, the current generation's chain, and the current epoch's applied events.

`authoritativeLog` steps: fold `loaded` (chain) and `seen`; settle the chain exactly as today's `authoritativeStates` (extension, else `resolveBranches`, refuse forks and losers); then fold `{ chain: winner, events: union(seen.events, loaded.events) }` and return `log = { chain: winner, events: seen.events ∪ (applied events from loaded) }` — an event from `loaded` is stored **only if the fold applied it**, so unauthenticated input never reaches the store. When the merged head is saturated, store the ancestor-closed prefix of the first `MAX_EPOCH_EVENTS + 1` applied events in topological order: enough to stay saturated on every refold, never more. A stored log that no longer folds is still "no memory" (unchanged), **except** a stored log whose head was saturated — that refusal stands.

- [ ] **Step 1: Write the failing tests** in `history.test.ts`:

```ts
test('a verifier never forgets an event it has seen', async () => {
  const store = createMemoryLogStore()
  await store.merge(did, async (c) => authoritativeLog({ did, loaded: withRevA, seen: c, context }).log)
  await store.merge(did, async (c) => authoritativeLog({ did, loaded: withRevB, seen: c, context }).log)
  const result = foldLog(did, (await store.get(did))!)
  expect(result.ok && [...result.head.deny].sort()).toEqual(['did:key:zA', 'did:key:zB'])
})
test('a pending event applies once its parent arrives in a later presentation')
test('thousands of unsigned epoch events are neither stored nor saturating', async () => {
  const flood = { chain, events: Array.from({ length: 5000 }, (_, n) => unsignedRevoke(n)) }
  const { log, result } = authoritativeLog({ did, loaded: flood, seen: undefined, context })
  expect(log.events).toHaveLength(0)
  expect(result.head.saturated).toBe(false)
})
test('saturation persists when a later presentation carries only a subset')
test('concurrent merges for one DID never lose an event', async () => {
  await Promise.all([merge(withRevA), merge(withRevB)])
  // both denials present
})
test('a pruned and a full store fold to the same head')
test('a settlement drops a flood: the next epoch folds without ingesting the old one')
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/history.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement.** Delete `authoritativeStates`; export `authoritativeLog`, `mergeLogs`, `pruneLog`.
- [ ] **Step 4: Run** the controller suite and conformance — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Merge controller logs by union under a linear root chain"`

---

### Task 8: Resolver, identities and member resolution

**Files:**
- Modify: `controller/src/resolver.ts`, `controller/src/state-resolver.ts`, `controller/src/identity.ts`, `controller/src/keystore-identity.ts`, `controller/src/state.ts`, `controller/src/index.ts`
- Test: update `resolver.test.ts`, `identity.test.ts`, `keystore-identity.test.ts`, `verify-token.test.ts`; new `controller/test/resolve-member.test.ts`

**Interfaces:**
- Consumes: `authoritativeLog`, `LogStore.merge` (Task 7); `MemberQuery`, `ResolvedMember` (Task 1).
- Produces:
  - `createControllerResolver(options: { loadLog(did: string): Promise<ControllerLog | undefined>; history?: LogStore }): DIDMethodResolver` — with `history`, resolution runs inside `history.merge(did, …)` around `authoritativeLog`.
  - Every member (`resolve`, `resolveHistoric`, `resolveDenySet`, `resolveAgreementKey`, `resolveMember`) throws `Error(EPOCH_SATURATED + ': ' + did)` when `head.saturated`; `EPOCH_SATURATED = 'controller epoch is saturated'` exported from `state-resolver.ts`.
  - `resolveMember(subject, { did, add, gen })` → `{ key, lease }` when `gen === head.gen`, `head.members.get(add)` is effective and `normalizeDID(member.did) === normalizeDID(did)`; else throws `IssuerKeyNotFoundError` with `MEMBER_NOT_EFFECTIVE = 'not an effective management member'`.
  - Deny and key checks read `head` (`head.deny`); historic keys scan `states` (chain) as today.
  - `createControllerIdentity({ seed, profile, log: ControllerLog })`, `createControllerIdentityWithKey({ privateKey, log: ControllerLog })`; `provideControllerIdentity` writes through `logStore.merge`.
  - `createStateResolver(did, states, head)` gains the `head` parameter.
  - **Frozen view.** `createControllerResolver` returns `ControllerResolver = DIDMethodResolver & { frozen(): DIDMethodResolver }`. `frozen()` returns a resolver that loads and folds each DID at most once for its lifetime and answers every member from that one fold. A caller verifying one capability passes `frozen()` as its `did:kokuin:` method, so issuer membership, lease, pin and every delegation-link denial come from the same view (spec: "one frozen view"). Export the type.

- [ ] **Step 1: Write the failing tests** in `resolve-member.test.ts`:

```ts
test('an effective member resolves to its pinned key and lease')
test('a removed member, a denied member, a wrong DID or a previous generation does not resolve', async () => {
  await expect(resolver.resolveMember!(did, { did: m.did, add, gen: 0 })).rejects.toThrow(MEMBER_NOT_EFFECTIVE)
})
test('a long-form and short-form did:peer:4 member DID resolve alike')
test('a saturated epoch refuses every resolver member')
test('a frozen view answers membership and denials from one fold even if the store changes between calls', async () => {
  const view = resolver.frozen()
  await view.resolveMember!(did, query)            // folds once
  await appendRevokeOfAudience()                   // store changes
  expect((await view.resolveDenySet!(did)).has(audience)).toBe(false)
  expect((await resolver.resolveDenySet!(did)).has(audience)).toBe(true)
})
test('a reset with a snapshot carrying the member does not revive the previous generation', async () => {
  await expect(resolver.resolveMember!(did, { did: m.did, add, gen: 0 })).rejects.toThrow()
  expect(await resolver.resolveMember!(did, { did: m.did, add, gen: 1 })).toMatchObject({ lease })
})
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/controller exec vitest run test/resolve-member.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `rtk proxy pnpm --filter @kokuin/controller run test` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Resolve controller logs with epochs and expose management members"`

---

### Task 9: Persistent store merge

**Files:**
- Modify: `store-controller/src/api.ts`, `store-controller/src/tables.ts`
- Test: `store-controller/test/cases.ts`

**Interfaces:**
- Consumes: `LogStore`, `ControllerLog`, `isControllerLog` (Tasks 5, 7).
- Produces: `ControllerStoreAPI = LogStore & { getObservedAt(did: string): Promise<Date | undefined> }`. `merge` runs `update` inside `withStoreTransaction`, reading the row first (lock it where the dialect supports `forUpdate`), then upserts. `decodeLog(value)` returns a `ControllerLog`; a stored **array** (the legacy shape) decodes as `{ chain: value, events: [] }`. No migration: the column is JSON.

- [ ] **Step 1: Write the failing tests** in `cases.ts` (run on both adapters by the existing harness):

```ts
test('merge applies the update to the stored log atomically')
test('two concurrent merges for one DID both land', async () => {
  await Promise.all([store.merge(did, addEvent(a)), store.merge(did, addEvent(b))])
  expect((await store.get(did))!.events.map(digestOfSigned).sort()).toEqual([a, b].sort())
})
test('a legacy array row decodes as a chain with no epoch events')
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/store-controller exec vitest run` — Expected: FAIL.
- [ ] **Step 3: Implement.** Remove `set`.
- [ ] **Step 4: Run** the store tests and `rtk proxy pnpm run test:types` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Merge controller logs atomically in the store"`

---

### Task 10: Member-issued grants in `@kokuin/capability`

**Files:**
- Create: `capability/src/member.ts`
- Modify: `capability/src/delegation.ts` (`checkCapability` and `checkDelegationChain` root arms; `createCapability`), `capability/src/types.ts`, `capability/src/index.ts`
- Test: `capability/test/member-grant.test.ts`

**Interfaces:**
- Consumes: `resolveMember`, `signingKeysOf` (Task 1); a `did:kokuin:` resolver from Task 8 in tests.
- Produces:
  - Grant claim `mbr: { add: string; g: number }` on a capability whose `iss` is a member DID and `sub` the controller.
  - `assertMemberRoot(payload: CapabilityPayload, options: DelegationChainOptions | undefined, time: number): Promise<void>` in `member.ts`.
  - `DelegationChainOptions.maxMemberGrantLifetime?: number` (default `DEFAULT_MEMBER_GRANT_LIFETIME = 43200`).
  - `CreateCapabilityOptions.member?: { add: string; g: number }` — `createCapability` with this option and `signer.id !== sub` mints a member root (writes `mbr`, requires `exp` and `iat`) instead of demanding `parentCapability`.
  - Reasons: `MEMBER_GRANT_NO_RESOLVER`, `MEMBER_GRANT_NOT_MEMBER`, `MEMBER_GRANT_KEY_MISMATCH`, `MEMBER_GRANT_PAST_LEASE`, `MEMBER_GRANT_TOO_LONG`, `MEMBER_GRANT_NO_IAT`.

`assertMemberRoot` checks, in order: `mbr` well-formed; subject's method resolver has `resolveMember` (else `MEMBER_GRANT_NO_RESOLVER`); `resolveMember(sub, { did: iss, add, gen: g })` (any throw ⇒ `MEMBER_GRANT_NOT_MEMBER`); `signingKeysOf(iss)` is exactly the returned key (else `MEMBER_GRANT_KEY_MISMATCH`); `exp` present and `exp <= lease` (else `MEMBER_GRANT_PAST_LEASE`); `iat` present (else `MEMBER_GRANT_NO_IAT`) and `exp - iat <= maxMemberGrantLifetime` (else `MEMBER_GRANT_TOO_LONG`); then the same time claims (`assertNonExpired`, `assertValidNotBefore`, `assertValidIssuedAt`) and `assertAudienceNotRevoked` as the `iss === sub` arm. It is the root arm in `checkDelegationChain` when `capabilities.length === 0` and `iss !== sub`, and in `checkCapability` when `iss !== sub`, `payload.cap == null` and `mbr` is present (then the presented grant must cover `permission`). A member root without `mbr` stays `'Invalid capability: issuer should be subject'`.

- [ ] **Step 1: Write the failing tests:**

```ts
test('a member grant within its lease and 12 hours verifies, directly and as a chain root')
test('a member grant past the issuer lease is refused')          // MEMBER_GRANT_PAST_LEASE
test('a member grant longer than 12 hours is refused, and the limit is configurable')
test('a member grant with no iat, or iat in the future, is refused')
test('a grant from a removed member, a denied member, or a previous generation is refused')
test('a grant signed by a did:peer:4 that is not the pinned key is refused')
test('a grant whose audience the controller denied is refused')
test('an edge holder may delegate a member grant further under the existing chain rules')
test('createCapability mints a member root with mbr, exp and iat')
// Tests pass `resolver.frozen()` in `methods`; document in `member.ts` that callers should too.
```

- [ ] **Step 2: Run** `pnpm --filter @kokuin/capability exec vitest run test/member-grant.test.ts` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `rtk proxy pnpm --filter @kokuin/capability run test` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Accept grants issued by controller management members"`

---

### Task 11: Docs, release intent, cleanup

**Files:**
- Modify: `docs/reference/controller.md` (custody tiers, events, the fold, branch selection, resolution, a new "Management members" section; delete "Capability-authorised revoke"), `docs/reference/security.md` (remedy ladder, accepted risks from the spec), `docs/reference/auth.md` (drop cap-revoke mentions), `docs/skills/discover.skill.md` (API index).
- Delete: `docs/agents/plans/next/2026-10-21-revoke-capability-expiry-in-folded-logs.md` (untracked; plain `rm`).
- Create: release intents via `pnpm change` (follow the `kigu:releasing` skill): minor bumps for `@kokuin/token`, `@kokuin/controller`, `@kokuin/capability`, `@kokuin/store-controller`, each naming the breaking change.

- [ ] **Step 1:** Write the docs from the spec's rules and accepted risks; no plan labels.
- [ ] **Step 2: Run** `rtk proxy pnpm run lint` and `rtk proxy pnpm run test` from the repo root — Expected: PASS.
- [ ] **Step 3: Commit** `git commit -m "Document the management tier and record release intents"`
