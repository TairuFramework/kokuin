// Structural mirror of `@kokuin/controller`'s wire shapes. Declared here rather than imported so
// this package never depends on `@kokuin/controller` — the implementation under test is injected,
// and depending on it would cycle against the devDependency the controller package takes on this
// suite.

/** The envelope every did:kokuin event shares, plus whatever fields its type adds. */
export type ConformanceEvent = {
  v: 1
  t: string
  i?: string
  g: number
  s: number
  p?: string
  crit: boolean
  [key: string]: unknown
}

export type ConformanceSigned = {
  event: ConformanceEvent
  /** base64url signatures, positional against the event's current keys. */
  sigs: Array<string>
  /** The revealed recovery public key — present only on a reset. */
  recoveryKey?: string
}

/** One management member as a snapshot carries it. Mirrors `@kokuin/controller`'s `MemberEntry`. */
export type ConformanceMemberEntry = { did: string; key: string; add: string; lease: number }

/** The whole state a root-chain event leaves behind. Mirrors `StateSnapshot`. */
export type ConformanceStateSnapshot = {
  members: Array<ConformanceMemberEntry>
  deny: Array<string>
}

/** Per-position folded state. Mirrors `@kokuin/controller`'s `KeyState`. */
export type ConformanceKeyState = {
  gen: number
  seq: number
  keyGen: number
  keySeq: number
  keys: Array<string>
  /** Key agreement keys — an OR set, established by the same icp/rot as `keys`. */
  agreement: Array<string>
  next: Array<string>
  recovery: string
  deny: ReadonlySet<string>
  /** The management set, keyed by each member's `add` digest. */
  members: ReadonlyMap<string, ConformanceMemberEntry & { removed: boolean; effective: boolean }>
  /** Digest of the chain event opening this state's epoch — a chain state's own `digest`. */
  epoch: string
  saturated: boolean
  digest: string
}

/** A controller's whole log: the root chain and the epoch events built on its last event. */
export type ConformanceLog = {
  chain: Array<ConformanceSigned>
  events: Array<ConformanceEpochSigned>
}

export type ConformanceFoldResult =
  | {
      ok: true
      states: Array<ConformanceKeyState>
      /** The last chain state merged with the current epoch. */
      head: ConformanceKeyState
      applied: Array<string>
      pending: number
      rejected: number
    }
  | { ok: false; reason: string; index: number }

export type ConformanceDuplicity = {
  gen: number
  seq: number
  digests: [string, string]
}

/**
 * Why branch selection could not name a winner.
 */
export type ConformanceResolveFailure = 'duplicity' | 'no-valid-branch'

export type ConformanceResolveResult =
  | { ok: true; winner: Array<ConformanceSigned>; superseded: number }
  | { ok: false; failure: ConformanceResolveFailure; duplicity: ConformanceDuplicity }

export type ConformanceProfileEntry = {
  index: number
  did: string
  handle: string
}

export type CreateRotateOptions = {
  seal?: string
  /**
   * The complete state the rotate leaves behind — a **replacement**, not an addition. Required: every
   * rotate is a settlement, and the state after it is its snapshot and nothing before it.
   */
  snapshot: ConformanceStateSnapshot
}

/** A signed management-tier event: an epoch event has no root-chain `s`, so it is not a {@link ConformanceSigned}. */
export type ConformanceEpochSigned = { event: Record<string, unknown>; sigs: Array<string> }

/** Who signs an epoch event: the root, from its seed, or a member, from its pinned key's private half. */
export type ConformanceEpochSigner =
  | { root: { seed: Uint8Array; profile: number } }
  | { member: { privateKey: Uint8Array; add: string } }

/** The fields an epoch event adds to its envelope, by type. An add is root-only. */
export type ConformanceEpochBody =
  | { t: 'add'; member: { did: string; key: string; lease: number } }
  | { t: 'ren'; add: string; lease: number }
  | { t: 'rmv'; add: string }
  | { t: 'rev'; target: string }

export type ConformanceEpochEventParams = {
  signer: ConformanceEpochSigner
  did: string
  /** The folded head the event builds on, naming the generation, the epoch and the signing key. */
  head: ConformanceKeyState
  parents: Array<string>
  body: ConformanceEpochBody
}

/**
 * The contract every did:kokuin controller implementation owes, typed against its real
 * signatures rather than `(...args: never[]) => unknown` — an assertion suite can only exercise a
 * surface it can actually call.
 */
export type ControllerImplementation = {
  name: string
  createInception: (seed: Uint8Array, profile: number) => ConformanceSigned
  createRotate: (
    seed: Uint8Array,
    profile: number,
    did: string,
    prior: ConformanceEvent,
    options: CreateRotateOptions,
  ) => ConformanceSigned
  /** A blind reset without `snapshot`; with one, the reset carries the whole state. */
  createReset: (
    seed: Uint8Array,
    profile: number,
    gen: number,
    snapshot?: ConformanceStateSnapshot,
  ) => ConformanceSigned
  didFromInception: (event: ConformanceEvent) => string
  foldLog: (did: string, log: ConformanceLog) => ConformanceFoldResult
  resolveBranches: (
    did: string,
    branches: Array<Array<ConformanceSigned>>,
  ) => ConformanceResolveResult
  enumerateProfiles: (seed: Uint8Array, count: number) => Array<ConformanceProfileEntry>
  /** Self-addressing digest of a canonicalized value. Several assertions need to compute one. */
  digestOf: (value: unknown) => string
  /**
   * Test-support only, not the wire protocol: the recovery private key. Lets the root-override group
   * build a reset whose signature is genuinely valid but signed by a key the inception never
   * committed to — the only way to isolate the recovery digest check from signature verification.
   */
  recoveryPrivateKey: (seed: Uint8Array, profile: number) => Uint8Array
  /**
   * Test-support only, not the wire protocol: the authority signing private key at a position. Lets
   * the agreement-key group build an inception that genuinely verifies and matches its DID but
   * declares an empty `ka`, isolating that check like `recoveryPrivateKey` does the root-override one.
   */
  authorityPrivateKey: (seed: Uint8Array, profile: number, gen: number, seq: number) => Uint8Array
  /** Builds and signs one epoch event; throws on what the real builders refuse. */
  createEpochEvent: (params: ConformanceEpochEventParams) => ConformanceEpochSigned
  /** Test-support only: a fresh Ed25519 member key pair and the `did:key` that carries it. */
  memberKeyPair: () => { privateKey: Uint8Array; key: string; did: string }
  /** Test-support only: sign an event with arbitrary private keys. Used only for the forgeries above. */
  signEvent: (event: ConformanceEvent, privateKeys: Array<Uint8Array>) => Array<string>
}

/**
 * The minimal matcher surface the suite calls. Kept narrow and explicit rather than
 * `(value: unknown) => any` so the suite's own assertions stay typed — a real test runner's
 * `expect` (vitest, jest, node:test wrappers, ...) is always structurally wider than this and can
 * be passed in directly, or cast once at the call site if the runner's typings do not narrow
 * cleanly.
 */
export type ConformanceExpectation = {
  toBe: (expected: unknown) => void
  toEqual: (expected: unknown) => void
  toBeUndefined: () => void
  toHaveLength: (expected: number) => void
  not: ConformanceExpectation
}

export type ConformanceSuite = {
  describe: (name: string, fn: () => void) => void
  test: (name: string, fn: () => void | Promise<void>) => void
  expect: (value: unknown) => ConformanceExpectation
}

/** Index into an array where the element is known to exist, narrowing away `undefined`. */
function at<T>(items: ReadonlyArray<T>, index: number): T {
  const item = items[index]
  if (item === undefined) {
    throw new Error(`expected an element at index ${index}`)
  }
  return item
}

/**
 * The contract every did:kokuin controller implementation owes, framework-agnostic so it can run
 * under any runner. Mirrors the `@kokuin/keystore-conformance` habit, but — because the protocol
 * has state-machine properties a per-case `run(): Promise<void>` list cannot express as cleanly —
 * drives `describe`/`test`/`expect` directly instead of returning a case array.
 */
export function runControllerConformance(
  suite: ConformanceSuite,
  impl: ControllerImplementation,
): void {
  const { describe, test, expect } = suite

  const seedA = new Uint8Array(32).fill(1)
  const seedB = new Uint8Array(32).fill(2)
  const seedC = new Uint8Array(32).fill(9)

  // Real Ed25519 `did:key` identifiers, so the ones a snapshot carries as members decode.
  const deviceA = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
  const deviceB = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
  const deviceC = 'did:key:z6MkfriQZgZXhtFA6kFHzuvhLHGRDDNzGRxeLnpKmZzHwUXR'

  /** A member pinned to the key its `did:key` carries. */
  function memberOf(did: string, add: string): ConformanceMemberEntry {
    return { did, key: did.slice('did:key:'.length), add, lease: 1_900_000_000 }
  }

  /** A rotate on `prior` whose snapshot is `snapshot` (empty by default), signed by `seed`. */
  function rotate(
    seed: Uint8Array,
    did: string,
    prior: ConformanceEvent,
    snapshot: ConformanceStateSnapshot = { members: [], deny: [] },
  ): ConformanceSigned {
    return impl.createRotate(seed, 0, did, prior, { snapshot })
  }

  /** A rotate on `prior` denying `deny` and carrying no members. */
  function denying(did: string, prior: ConformanceEvent, deny: Array<string>): ConformanceSigned {
    return rotate(seedA, did, prior, { members: [], deny })
  }

  describe(`${impl.name} controller conformance`, () => {
    // 1. Determinism — same seed and index reproduce byte-identical inception and the same DID.
    // A stub that always returns one hard-coded inception would trivially pass "same input twice
    // gives the same output", so the group also asserts that *different* input gives different
    // output — closing the gap a constant-returning stub would otherwise slip through.
    describe('determinism', () => {
      test('same seed and profile index reproduce byte-identical inception', () => {
        expect(impl.createInception(seedA, 0)).toEqual(impl.createInception(seedA, 0))
      })

      test('same seed and profile index reproduce the same DID', () => {
        const first = impl.didFromInception(impl.createInception(seedA, 0).event)
        const second = impl.didFromInception(impl.createInception(seedA, 0).event)
        expect(first).toBe(second)
      })

      test('a different seed produces a different DID', () => {
        const didA = impl.didFromInception(impl.createInception(seedA, 0).event)
        const didB = impl.didFromInception(impl.createInception(seedB, 0).event)
        expect(didA).not.toBe(didB)
      })

      test('a different profile index produces a different DID for the same seed', () => {
        const did0 = impl.didFromInception(impl.createInception(seedA, 0).event)
        const did1 = impl.didFromInception(impl.createInception(seedA, 1).event)
        expect(did0).not.toBe(did1)
      })
    })

    // 2. No ambient state — an inception carries no timestamp, nonce, or label. Asserting the
    // exact key set catches any extra field a real implementation might smuggle in; it is not
    // defeated by a constant stub, because a constant stub with an ambient field would still fail
    // it, and the determinism group above already rules out a stub that ignores its input.
    describe('no ambient state', () => {
      test('an inception carries exactly the protocol fields', () => {
        const { event } = impl.createInception(seedA, 0)
        const keys = Object.keys(event).sort()
        expect(keys).toEqual(['crit', 'g', 'k', 'ka', 'kt', 'n', 'nt', 'r', 's', 't', 'v'])
      })

      test('the DID is absent from the inception body — it is the hash of the event', () => {
        expect(impl.createInception(seedA, 0).event.i).toBeUndefined()
      })
    })

    // 3. Pre-rotation — a rotate not signed by the keys the prior event pre-committed is
    // rejected by the fold. Both directions are asserted, so an always-reject fold cannot pass
    // alongside an always-accept one.
    describe('pre-rotation', () => {
      test('a rotate signed by the pre-committed next keys folds successfully', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = rotate(seedA, did, icp.event)
        const result = impl.foldLog(did, { chain: [icp, rot], events: [] })
        expect(result.ok).toBe(true)
      })

      test('a rotate not signed by the pre-committed keys is rejected', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        // seedC derives an unrelated key pair — the revealed keys will not match the digests the
        // inception pre-committed to.
        const forged = rotate(seedC, did, icp.event)
        const result = impl.foldLog(did, { chain: [icp, forged], events: [] })
        expect(result.ok).toBe(false)
      })
    })

    // 4. Root override — a reset signed by anything but the committed recovery key is rejected.
    // The forged case reuses the victim's own legitimately-shaped reset event byte-for-byte (so
    // `i`, `p`, `g`, `s` all chain correctly) and re-signs it with a thief's recovery private
    // key, revealing the thief's matching public key. That signature genuinely verifies against
    // the key it reveals — the only thing wrong with the event is that the revealed key is not
    // the one the inception committed to. A splice of `i`/`p` into a thief's own reset would
    // instead break the signature outright, which an implementation with no commitment check at
    // all would *also* reject — certifying an implementation that never checks the commitment.
    // Isolating the property needs a genuinely valid signature from an uncommitted key, which is
    // why `recoveryPrivateKey`/`signEvent` exist on the contract as test-support members.
    describe('root override', () => {
      test('a reset signed by the committed recovery key folds successfully', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const reset = impl.createReset(seedA, 0, 1)
        const result = impl.foldLog(did, { chain: [icp, reset], events: [] })
        expect(result.ok).toBe(true)
      })

      test('a reset with a genuinely valid signature from an uncommitted recovery key is rejected', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        // Correctly shaped and chained for the victim — everything but the signer.
        const legitimate = impl.createReset(seedA, 0, 1)
        // The thief's own reset reveals a genuinely valid recovery public key, just not the one
        // committed in the victim's inception.
        const thiefReset = impl.createReset(seedC, 0, 1)
        const thiefRecoveryPrivateKey = impl.recoveryPrivateKey(seedC, 0)
        const forged: ConformanceSigned = {
          event: legitimate.event,
          sigs: impl.signEvent(legitimate.event, [thiefRecoveryPrivateKey]),
          recoveryKey: thiefReset.recoveryKey,
        }
        const result = impl.foldLog(did, { chain: [icp, forged], events: [] })
        expect(result.ok).toBe(false)
      })
    })

    // 5. Position-dependence — a device denied at sequence N is not denied at N-1. Checked via
    // `states` at two positions rather than a final state, which is exactly what would hide a
    // fold that (incorrectly) applied the deny set retroactively.
    describe('position-dependence', () => {
      test('a device denied at sequence N is not denied at N-1', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = rotate(seedA, did, icp.event)
        const denied = denying(did, rot.event, [deviceA])
        const result = impl.foldLog(did, { chain: [icp, rot, denied], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(at(result.states, 1).deny.has(deviceA)).toBe(false)
        expect(at(result.states, 2).deny.has(deviceA)).toBe(true)
      })
    })

    // 5a. Every rotate is a settlement: it carries the whole state — members and denials — and the
    // state after it is that snapshot, nothing before it. A rotate missing either half does not
    // fold; that case is a re-signed copy of a valid rotate with both halves removed, so the
    // signature genuinely verifies and only the snapshot rule can reject it.
    describe('state snapshots', () => {
      test('the state after a rotate is its snapshot', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const member = memberOf(deviceB, impl.digestOf('the add that admitted it'))
        const first = rotate(seedA, did, icp.event, { members: [member], deny: [deviceA] })
        const second = rotate(seedA, did, first.event)
        const result = impl.foldLog(did, { chain: [icp, first, second], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect([...at(result.states, 1).deny]).toEqual([deviceA])
        expect(at(result.states, 1).members.get(member.add)).toEqual({
          ...member,
          removed: false,
          effective: true,
        })
        // The next settlement replaces the state outright.
        expect(at(result.states, 2).deny.size).toBe(0)
        expect(at(result.states, 2).members.size).toBe(0)
        // Every chain state opens its own epoch.
        expect(at(result.states, 1).epoch).toBe(at(result.states, 1).digest)
        expect(at(result.states, 1).saturated).toBe(false)
      })

      test('a rotate carrying no snapshot does not fold', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const valid = rotate(seedA, did, icp.event)
        const { m: _m, d: _d, ...bare } = valid.event
        const revealed = impl.authorityPrivateKey(seedA, 0, 0, 1)
        const resign = (event: ConformanceEvent): ConformanceSigned => ({
          event,
          sigs: impl.signEvent(event, [revealed]),
        })
        expect(impl.foldLog(did, { chain: [icp, resign({ ...valid.event })], events: [] }).ok).toBe(
          true,
        )
        expect(
          impl.foldLog(did, { chain: [icp, resign(bare as ConformanceEvent)], events: [] }).ok,
        ).toBe(false)
      })

      test('a snapshot member may not pin a root key', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        // The inception's own key, as a `did:key` member: everything else about it is valid.
        const rootKey = at(icp.event.k as Array<string>, 0)
        const root = memberOf(`did:key:${rootKey}`, impl.digestOf('root as a member'))
        const other = memberOf(deviceB, impl.digestOf('root as a member'))
        const refused = rotate(seedA, did, icp.event, { members: [root], deny: [] })
        expect(impl.foldLog(did, { chain: [icp, refused], events: [] }).ok).toBe(false)
        const control = rotate(seedA, did, icp.event, { members: [other], deny: [] })
        expect(impl.foldLog(did, { chain: [icp, control], events: [] }).ok).toBe(true)
      })
    })

    // 5b. A deny entry may name a KEY instead of a DID, spelled `#<the multibase key exactly as it
    // appears in `k`>` — the same spelling a token's `kid` uses, which is what makes the two forms
    // tellable apart on sight. It is what retires a leaked key for material it has *already*
    // signed: a rotate retires a key for new issuance only, because historic resolution is designed
    // to survive one, so retirement has to be an explicit denial.
    //
    // Two properties an implementation is most likely to skip: a rotate may not establish a key its
    // own snapshot denies, and once a rotate has denied a key of the generation's chain (a
    // checkpointed retirement) no later rotate in the generation may drop it.
    describe('key denial', () => {
      test('a `#<key>` entry lands in the deny set under that spelling', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = rotate(seedA, did, icp.event)
        // The inception's key, which the rotate has since retired.
        const retired = `#${at(icp.event.k as Array<string>, 0)}`
        const denied = denying(did, rot.event, [retired])
        const result = impl.foldLog(did, { chain: [icp, rot, denied], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(at(result.states, 1).deny.has(retired)).toBe(false)
        expect(at(result.states, 2).deny.has(retired)).toBe(true)
      })

      test('a rotate cannot establish a key its own snapshot denies', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        // The key this rotate reveals, read off an identical rotate with an empty snapshot.
        const own = `#${at(rotate(seedA, did, icp.event).event.k as Array<string>, 0)}`
        expect(
          impl.foldLog(did, { chain: [icp, denying(did, icp.event, [own])], events: [] }).ok,
        ).toBe(false)
        const retired = `#${at(icp.event.k as Array<string>, 0)}`
        expect(
          impl.foldLog(did, { chain: [icp, denying(did, icp.event, [retired])], events: [] }).ok,
        ).toBe(true)
      })

      test('a later rotate may not drop a checkpointed retired key', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const retired = `#${at(icp.event.k as Array<string>, 0)}`
        const first = denying(did, icp.event, [retired])
        expect(
          impl.foldLog(did, { chain: [icp, first, denying(did, first.event, [])], events: [] }).ok,
        ).toBe(false)
        expect(
          impl.foldLog(did, {
            chain: [icp, first, denying(did, first.event, [retired])],
            events: [],
          }).ok,
        ).toBe(true)
        // A holder DID carries no such rule: dropping one is a deliberate re-authorisation.
        const holder = denying(did, icp.event, [deviceA])
        expect(
          impl.foldLog(did, { chain: [icp, holder, denying(did, holder.event, [])], events: [] })
            .ok,
        ).toBe(true)
      })
    })

    // 6. Reset clears the state and increments the generation; a blind reset is a pure function of
    // `(seed, profile, gen)`, and a reset carrying a snapshot folds to it.
    describe('reset', () => {
      test('clears the deny set and increments the generation', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = rotate(seedA, did, icp.event)
        const denied = denying(did, rot.event, [deviceA])
        const reset = impl.createReset(seedA, 0, 1)
        const result = impl.foldLog(did, { chain: [icp, rot, denied, reset], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        const state = at(result.states, 3)
        expect(state.gen).toBe(1)
        expect(state.seq).toBe(0)
        expect(state.deny.has(deviceA)).toBe(false)
      })

      test('a blind reset is byte-identical per seed, profile and generation', () => {
        expect(impl.createReset(seedA, 0, 1)).toEqual(impl.createReset(seedA, 0, 1))
        expect(impl.createReset(seedA, 0, 1)).not.toEqual(impl.createReset(seedA, 0, 2))
      })

      test('a reset with a snapshot folds to that snapshot', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const member = memberOf(deviceB, impl.digestOf('carried across the reset'))
        const reset = impl.createReset(seedA, 0, 1, { members: [member], deny: [deviceA] })
        const result = impl.foldLog(did, { chain: [icp, reset], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(at(result.states, 1).gen).toBe(1)
        expect([...at(result.states, 1).deny]).toEqual([deviceA])
        expect(at(result.states, 1).members.get(member.add)?.effective).toBe(true)
      })
    })

    // 7. Precedence — higher (gen, seq) wins when one branch extends the other; two rotates that
    // contradict each other at one position are duplicity however far one branch runs ahead, and
    // the report does not depend on presentation order. The root chain carries only `icp`/`rot`,
    // so any two valid branches diverge on two rotates, neither superseding the other.
    describe('precedence', () => {
      test('a higher sequence at the same generation wins', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = rotate(seedA, did, icp.event)
        const result = impl.resolveBranches(did, [[icp], [icp, rot]])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.winner).toHaveLength(2)
      })

      test('a longer branch does not outrank a rotate it contradicts', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const first = denying(did, icp.event, [deviceA])
        const longer = [icp, first, denying(did, first.event, [deviceB])]
        const shorter = [icp, denying(did, icp.event, [deviceC])]
        for (const order of [
          [longer, shorter],
          [shorter, longer],
        ]) {
          const result = impl.resolveBranches(did, order)
          expect(result.ok).toBe(false)
          if (result.ok) {
            continue
          }
          expect(result.duplicity.seq).toBe(1)
        }
      })

      test('a three-way fork reports the same duplicity regardless of presentation order', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const branchA = [icp, denying(did, icp.event, [deviceA])]
        const branchB = [icp, denying(did, icp.event, [deviceB])]
        const branchC = [icp, denying(did, icp.event, [deviceC])]
        const first = impl.resolveBranches(did, [branchA, branchB, branchC])
        expect(first.ok).toBe(false)
        for (const order of [
          [branchA, branchC, branchB],
          [branchC, branchA, branchB],
        ]) {
          expect(impl.resolveBranches(did, order)).toEqual(first)
        }
      })
    })

    // 8. Idempotence — identical re-derived branches are not duplicity.
    describe('idempotence', () => {
      test('identical re-derived branches are not duplicity', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const a = rotate(seedA, did, icp.event)
        const b = rotate(seedA, did, icp.event)
        const result = impl.resolveBranches(did, [
          [icp, a],
          [icp, b],
        ])
        expect(result.ok).toBe(true)
      })
    })

    // 9. Duplicity — two distinct rotates at one position are surfaced, not merged.
    describe('duplicity', () => {
      test('two distinct rotates at one position are surfaced', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const result = impl.resolveBranches(did, [
          [icp, denying(did, icp.event, [deviceA])],
          [icp, denying(did, icp.event, [deviceB])],
        ])
        expect(result.ok).toBe(false)
        if (result.ok) {
          return
        }
        expect(result.duplicity.gen).toBe(0)
        expect(result.duplicity.seq).toBe(1)
      })
    })

    // 10. Criticality — an unknown critical event fails the fold closed; an unknown non-critical
    // one is skipped and the fold continues. Both directions are asserted so a fold that always
    // fails closed (or always skips) cannot pass the whole group.
    //
    // The skip path is the only one on which an implementation accepts an event without verifying
    // a signature — it cannot, not knowing the type's rules — so the last two properties bound what
    // that acceptance may claim. Criticality must be *declared*, not merely absent, and the event
    // must sit at the position it says it does: an implementation that lets an unsigned event carry
    // an arbitrary `(g, s)` hands branch selection to anyone who can read the log, since precedence
    // is a position comparison.
    describe('criticality', () => {
      test('an unknown critical event fails the fold closed', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const unknown: ConformanceSigned = {
          event: { v: 1, t: 'xyz', i: did, g: 0, s: 1, p: impl.digestOf(icp.event), crit: true },
          sigs: [],
        }
        const result = impl.foldLog(did, { chain: [icp, unknown], events: [] })
        expect(result.ok).toBe(false)
      })

      test('an unknown non-critical event is skipped and the fold continues', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const unknown: ConformanceSigned = {
          event: { v: 1, t: 'xyz', i: did, g: 0, s: 1, p: impl.digestOf(icp.event), crit: false },
          sigs: [],
        }
        const result = impl.foldLog(did, { chain: [icp, unknown], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states).toHaveLength(2)
        // Skipped events carry the prior state forward unchanged, so the sequence does not
        // advance to the skipped event's own `s`.
        expect(at(result.states, 1).seq).toBe(0)
      })

      test('a chain revoke is an unknown critical event', () => {
        // Revokes live in epochs, never on the root chain: one there, from an older log, fails the
        // fold closed rather than being read as anything.
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const revoke: ConformanceSigned = {
          event: {
            v: 1,
            t: 'rev',
            i: did,
            g: 0,
            s: 1,
            p: impl.digestOf(icp.event),
            crit: true,
            x: deviceA,
          },
          sigs: [],
        }
        expect(impl.foldLog(did, { chain: [icp, revoke], events: [] }).ok).toBe(false)
      })

      test('an unknown event with no criticality flag fails closed', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const unknown = {
          event: { v: 1, t: 'xyz', i: did, g: 0, s: 1, p: impl.digestOf(icp.event) },
          sigs: [],
        } as unknown as ConformanceSigned
        const result = impl.foldLog(did, { chain: [icp, unknown], events: [] })
        expect(result.ok).toBe(false)
      })

      test('a skipped event claiming a position it does not hold is rejected', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        // The inception sits at (0, 0), so the only position this event may claim is (0, 1).
        for (const position of [
          { g: 0, s: Number.MAX_SAFE_INTEGER },
          { g: Number.MAX_SAFE_INTEGER, s: Number.MAX_SAFE_INTEGER },
          { g: 0, s: 0 },
          { g: 0, s: 2 },
          { g: 1, s: 1 },
        ]) {
          const unknown: ConformanceSigned = {
            event: {
              v: 1,
              t: 'xyz',
              i: did,
              ...position,
              p: impl.digestOf(icp.event),
              crit: false,
            },
            sigs: [],
          }
          expect(impl.foldLog(did, { chain: [icp, unknown], events: [] }).ok).toBe(false)
        }
      })
    })

    // 11. Enumeration — profiles are a pure function of the seed and handles are stable.
    describe('enumeration', () => {
      test('profiles are a pure function of the seed', () => {
        expect(impl.enumerateProfiles(seedA, 3)).toEqual(impl.enumerateProfiles(seedA, 3))
      })

      test('DIDs match the inception-derived identifiers', () => {
        const first = at(impl.enumerateProfiles(seedA, 1), 0)
        expect(first.did).toBe(impl.didFromInception(impl.createInception(seedA, 0).event))
      })

      test('different seeds produce different profiles', () => {
        const fromA = at(impl.enumerateProfiles(seedA, 1), 0)
        const fromB = at(impl.enumerateProfiles(seedB, 1), 0)
        expect(fromA.did).not.toBe(fromB.did)
      })

      test('handles are stable for the same DID', () => {
        const first = at(impl.enumerateProfiles(seedA, 1), 0)
        const again = at(impl.enumerateProfiles(seedA, 1), 0)
        expect(first.handle).toBe(again.handle)
      })
    })

    // 12. Agreement keys — an inception publishes a non-empty key agreement set and a rotate
    // replaces it. Property 2 asserts the post-rotate set *differs* from the inception's rather than
    // merely being non-empty — an implementation that carried the inception's `ka` forward on
    // rotate would pass a mere non-empty check. Properties 1-2 also assert the folded value equals
    // the `ka` the triggering event actually declared, not just that it changes shape — otherwise an
    // implementation folding an entirely unrelated (but still non-empty, still-changing) value would
    // pass both. Property 3
    // forges an inception with a genuinely valid signature and a genuinely matching DID whose only
    // defect is an empty declared `ka` — the same isolation technique as the root-override group
    // above, using `authorityPrivateKey` in place of `recoveryPrivateKey`. A byte-level splice
    // (mutating `ka` on an already-signed event) was tried first and rejected: canonicalization
    // covers every field, so a spliced `ka` also invalidates the signature, and a fold that never
    // checks `ka` at all still gets rejected by signature verification alone — confirmed by
    // deleting the `ka` guard at `events.ts:158-161` and observing the splice-based version of
    // this test still pass. The signed forgery below closes that gap: with a signature that
    // genuinely verifies and a DID that genuinely matches, the empty `ka` guard is the only check
    // left that can reject it.
    describe('agreement keys', () => {
      test('a folded inception exposes a non-empty agreement set', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const result = impl.foldLog(did, { chain: [icp], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(at(result.states, 0).agreement.length > 0).toBe(true)
        expect(at(result.states, 0).agreement).toEqual(icp.event.ka)
      })

      test('a rotate replaces the agreement set', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = rotate(seedA, did, icp.event)
        const result = impl.foldLog(did, { chain: [icp, rot], events: [] })
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(at(result.states, 1).agreement).not.toEqual(at(result.states, 0).agreement)
        expect(at(result.states, 1).agreement).toEqual(rot.event.ka)
      })

      test('an inception with a genuinely valid signature but an empty agreement set is rejected', () => {
        const icp = impl.createInception(seedA, 0)
        const forgedEvent: ConformanceEvent = { ...icp.event, ka: [] }
        const did = impl.didFromInception(forgedEvent)
        const authorityPrivateKey = impl.authorityPrivateKey(seedA, 0, 0, 0)
        const forged: ConformanceSigned = {
          event: forgedEvent,
          sigs: impl.signEvent(forgedEvent, [authorityPrivateKey]),
        }
        const result = impl.foldLog(did, { chain: [forged], events: [] })
        expect(result.ok).toBe(false)
      })
    })

    // The epoch is a set of events folded by causal authorisation and union, so what it yields must
    // be a function of the set alone. Each case below breaks a different way an implementation could
    // let presentation leak in: its order, a stale epoch, a parent it cannot see.
    describe('epoch merge', () => {
      const icp = impl.createInception(seedA, 0)
      const did = impl.didFromInception(icp.event)
      const keyA = impl.memberKeyPair()
      const keyB = impl.memberKeyPair()
      const entryA = {
        ...keyA,
        add: impl.digestOf('the add that admitted A'),
        lease: 1_900_000_000,
      }
      const entryB = {
        ...keyB,
        add: impl.digestOf('the add that admitted B'),
        lease: 1_900_000_000,
      }
      const toEntry = ({ did: d, key, add, lease }: typeof entryA) => ({ did: d, key, add, lease })
      const rot = rotate(seedA, did, icp.event, {
        members: [toEntry(entryA), toEntry(entryB)],
        deny: [],
      })
      const chain = [icp, rot]
      const settled = impl.foldLog(did, { chain, events: [] })
      if (!settled.ok) {
        throw new Error(`fixture chain does not fold: ${settled.reason}`)
      }
      const head = settled.head
      const root: ConformanceEpochSigner = { root: { seed: seedA, profile: 0 } }
      const memberA: ConformanceEpochSigner = {
        member: { privateKey: keyA.privateKey, add: entryA.add },
      }
      const memberB: ConformanceEpochSigner = {
        member: { privateKey: keyB.privateKey, add: entryB.add },
      }

      function revoke(
        signer: ConformanceEpochSigner,
        target: string,
        parents: Array<string> = [head.epoch],
        on: ConformanceKeyState = head,
      ): ConformanceEpochSigned {
        return impl.createEpochEvent({
          signer,
          did,
          head: on,
          parents,
          body: { t: 'rev', target },
        })
      }

      const revA = revoke(memberA, 'did:key:zA')
      const revB = revoke(memberB, 'did:key:zB')
      const renew = impl.createEpochEvent({
        signer: root,
        did,
        head,
        parents: [head.epoch],
        body: { t: 'ren', add: entryA.add, lease: 2_000_000_000 },
      })
      const child = revoke(root, 'did:key:zC', [
        impl.digestOf(revA.event),
        impl.digestOf(revB.event),
      ])

      function summary(events: Array<ConformanceEpochSigned>, presented = chain) {
        const result = impl.foldLog(did, { chain: presented, events })
        if (!result.ok) {
          return { ok: false, deny: [], members: [], applied: [], pending: 0, rejected: 0 }
        }
        return {
          ok: true,
          deny: [...result.head.deny].sort(),
          members: [...result.head.members.entries()].sort(([x], [y]) => (x < y ? -1 : 1)),
          applied: result.applied,
          pending: result.pending,
          rejected: result.rejected,
        }
      }

      function permutations<T>(items: Array<T>): Array<Array<T>> {
        if (items.length <= 1) {
          return [items]
        }
        return items.flatMap((item, i) =>
          permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [
            item,
            ...rest,
          ]),
        )
      }

      test('concurrent member revokes merge, in every presentation order', () => {
        const expected = summary([revA, revB, renew, child])
        expect(expected.ok).toBe(true)
        expect(expected.deny).toEqual(['did:key:zA', 'did:key:zB', 'did:key:zC'])
        expect(expected.applied).toHaveLength(4)
        expect(expected.pending).toBe(0)
        expect(expected.rejected).toBe(0)
        for (const order of permutations([revA, revB, renew, child])) {
          expect(summary(order)).toEqual(expected)
        }
      })

      test('an event presented twice applies once', () => {
        expect(summary([revA, revA, revB])).toEqual(summary([revA, revB]))
      })

      test('an event naming an older epoch has no effect', () => {
        const atInception = impl.foldLog(did, { chain: [icp], events: [] })
        if (!atInception.ok) {
          throw new Error('inception does not fold')
        }
        const stale = revoke(root, 'did:key:zOld', [atInception.head.epoch], atInception.head)
        expect(summary([stale])).toEqual(summary([]))
      })

      test('an event with a parent from an older epoch is refused', () => {
        const crossing = revoke(root, 'did:key:zX', [head.epoch, impl.digestOf(icp.event)])
        const result = summary([crossing])
        expect(result).toEqual({ ...summary([]), rejected: 1 })
        // Control: the same event with only same-epoch parents applies.
        expect(summary([revoke(root, 'did:key:zX')])).toEqual({
          ...summary([]),
          deny: ['did:key:zX'],
          applied: [impl.digestOf(revoke(root, 'did:key:zX').event)],
        })
      })

      test('an event whose parent is missing waits, and applies once the parent is presented', () => {
        const waiting = summary([child])
        expect(waiting).toEqual({ ...summary([]), pending: 1 })
        const complete = summary([child, revA, revB])
        expect(complete).toEqual(summary([revA, revB, child]))
        expect(complete.pending).toBe(0)
        expect(complete.applied).toHaveLength(3)
      })
    })
  })
}
