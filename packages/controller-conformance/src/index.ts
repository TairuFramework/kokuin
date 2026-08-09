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

/** Per-position folded state. Mirrors `@kokuin/controller`'s `KeyState`. */
export type ConformanceKeyState = {
  gen: number
  seq: number
  keyGen: number
  keySeq: number
  keys: Array<string>
  /** Key agreement keys — an OR set. Established by icp/rot, carried forward across rev. */
  agreement: Array<string>
  next: Array<string>
  recovery: string
  deny: ReadonlySet<string>
  digest: string
}

export type ConformanceFoldResult =
  | { ok: true; states: Array<ConformanceKeyState> }
  | { ok: false; reason: string; index: number }

export type ConformanceDuplicity = {
  gen: number
  seq: number
  digests: [string, string]
}

export type ConformanceResolveResult =
  | { ok: true; winner: Array<ConformanceSigned>; superseded: number }
  | { ok: false; duplicity: ConformanceDuplicity }

export type ConformanceProfileEntry = {
  index: number
  did: string
  handle: string
}

export type CreateRotateOptions = {
  seal?: string
  deny?: Array<string>
}

export type CreateRevokeOptions = {
  cap?: string
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
    options?: CreateRotateOptions,
  ) => ConformanceSigned
  createReset: (seed: Uint8Array, profile: number, gen: number) => ConformanceSigned
  createRevoke: (
    seed: Uint8Array,
    profile: number,
    did: string,
    prior: ConformanceEvent,
    target: string,
    keyPosition: { gen: number; seq: number },
    options?: CreateRevokeOptions,
  ) => ConformanceSigned
  didFromInception: (event: ConformanceEvent) => string
  foldLog: (did: string, events: Array<ConformanceSigned>) => ConformanceFoldResult
  resolveBranches: (
    did: string,
    branches: Array<Array<ConformanceSigned>>,
  ) => ConformanceResolveResult
  enumerateProfiles: (seed: Uint8Array, count: number) => Array<ConformanceProfileEntry>
  /** Self-addressing digest of a canonicalized value. Several assertions need to compute one. */
  digestOf: (value: unknown) => string
  /**
   * Test-support only, not part of the wire protocol: the recovery private key for a seed and
   * profile. Every implementation of this protocol derives one internally to sign a reset; this
   * exposes it so the root-override group can build a reset whose signature is genuinely valid
   * but signed by a key the inception never committed to — the only way to isolate the recovery
   * digest check from signature verification without either breaking the signature (a splice) or
   * failing the chain check first (an untouched foreign branch).
   */
  recoveryPrivateKey: (seed: Uint8Array, profile: number) => Uint8Array
  /**
   * Test-support only, not part of the wire protocol: the authority (signing) private key for a
   * seed, profile, and key position. Lets the agreement-key group build an inception whose
   * signature genuinely verifies and whose DID genuinely matches, but whose declared `ka` is
   * empty — isolating the empty-agreement-set check from signature and DID verification the same
   * way `recoveryPrivateKey` isolates the root-override check above.
   */
  authorityPrivateKey: (seed: Uint8Array, profile: number, gen: number, seq: number) => Uint8Array
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

  const deviceA = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
  const deviceB = 'did:key:z6MkAnotherStolenDeviceDidHere111111111111'
  const deviceC = 'did:key:z6MkAThirdStolenDeviceDidHereForGoodMeasure0'

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
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const result = impl.foldLog(did, [icp, rot])
        expect(result.ok).toBe(true)
      })

      test('a rotate not signed by the pre-committed keys is rejected', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        // seedC derives an unrelated key pair — the revealed keys will not match the digests the
        // inception pre-committed to.
        const forged = impl.createRotate(seedC, 0, did, icp.event)
        const result = impl.foldLog(did, [icp, forged])
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
        const result = impl.foldLog(did, [icp, reset])
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
        const result = impl.foldLog(did, [icp, forged])
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
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const rev = impl.createRevoke(seedA, 0, did, rot.event, deviceA, { gen: 0, seq: 1 })
        const result = impl.foldLog(did, [icp, rot, rev])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states[1].deny.has(deviceA)).toBe(false)
        expect(result.states[2].deny.has(deviceA)).toBe(true)
      })
    })

    // 6. Reset clears the deny set and increments the generation.
    describe('reset', () => {
      test('clears the deny set and increments the generation', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const rev = impl.createRevoke(seedA, 0, did, rot.event, deviceA, { gen: 0, seq: 1 })
        const reset = impl.createReset(seedA, 0, 1)
        const result = impl.foldLog(did, [icp, rot, rev, reset])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        const state = result.states[3]
        expect(state.gen).toBe(1)
        expect(state.seq).toBe(0)
        expect(state.deny.has(deviceA)).toBe(false)
      })
    })

    // 7. Precedence — higher (gen, seq) wins; at an equal position a superseding rotate beats a
    // current-key event. Includes the three-branch tie regression: a pairwise reduction can bury
    // the legitimate winner between two losing branches, which order-dependence would hide.
    describe('precedence', () => {
      test('a higher sequence at the same generation wins', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const result = impl.resolveBranches(did, [[icp], [icp, rot]])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.winner).toHaveLength(2)
      })

      test('at an equal position, a superseding rotate beats a current-key event', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const thiefRevoke = impl.createRevoke(seedA, 0, did, icp.event, deviceA, {
          gen: 0,
          seq: 0,
        })
        const ownerRotate = impl.createRotate(seedA, 0, did, icp.event)
        const result = impl.resolveBranches(did, [
          [icp, thiefRevoke],
          [icp, ownerRotate],
        ])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.winner[1].event.t).toBe('rot')
        expect(result.superseded).toBe(1)
      })

      test('a superseding rotate wins a three-way tie regardless of presentation order', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const thiefA = impl.createRevoke(seedA, 0, did, icp.event, deviceA, { gen: 0, seq: 0 })
        const thiefB = impl.createRevoke(seedA, 0, did, icp.event, deviceB, { gen: 0, seq: 0 })
        const owner = impl.createRotate(seedA, 0, did, icp.event)
        const branchA = [icp, thiefA]
        const branchB = [icp, thiefB]
        const branchOwner = [icp, owner]
        const orderings = [
          [branchA, branchB, branchOwner],
          [branchA, branchOwner, branchB],
          [branchOwner, branchA, branchB],
        ]
        for (const order of orderings) {
          const result = impl.resolveBranches(did, order)
          expect(result.ok).toBe(true)
          if (!result.ok) {
            continue
          }
          expect(result.winner[1].event.t).toBe('rot')
          expect(result.superseded).toBe(2)
        }
      })
    })

    // 8. Idempotence — identical re-derived branches are not duplicity.
    describe('idempotence', () => {
      test('identical re-derived branches are not duplicity', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const a = impl.createRotate(seedA, 0, did, icp.event)
        const b = impl.createRotate(seedA, 0, did, icp.event)
        const result = impl.resolveBranches(did, [
          [icp, a],
          [icp, b],
        ])
        expect(result.ok).toBe(true)
      })
    })

    // 9. Duplicity — two distinct current-key events at one position are surfaced, not merged.
    describe('duplicity', () => {
      test('two distinct current-key events at one position are surfaced', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const revokeA = impl.createRevoke(seedA, 0, did, icp.event, deviceA, { gen: 0, seq: 0 })
        const revokeB = impl.createRevoke(seedA, 0, did, icp.event, deviceB, { gen: 0, seq: 0 })
        const result = impl.resolveBranches(did, [
          [icp, revokeA],
          [icp, revokeB],
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
    describe('criticality', () => {
      test('an unknown critical event fails the fold closed', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const unknown: ConformanceSigned = {
          event: { v: 1, t: 'xyz', i: did, g: 0, s: 1, p: impl.digestOf(icp.event), crit: true },
          sigs: [],
        }
        const result = impl.foldLog(did, [icp, unknown])
        expect(result.ok).toBe(false)
      })

      test('an unknown non-critical event is skipped and the fold continues', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const unknown: ConformanceSigned = {
          event: { v: 1, t: 'xyz', i: did, g: 0, s: 1, p: impl.digestOf(icp.event), crit: false },
          sigs: [],
        }
        const result = impl.foldLog(did, [icp, unknown])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states).toHaveLength(2)
        // Skipped events carry the prior state forward unchanged, so the sequence does not
        // advance to the skipped event's own `s`.
        expect(result.states[1].seq).toBe(0)
      })
    })

    // 11. Enumeration — profiles are a pure function of the seed and handles are stable.
    describe('enumeration', () => {
      test('profiles are a pure function of the seed', () => {
        expect(impl.enumerateProfiles(seedA, 3)).toEqual(impl.enumerateProfiles(seedA, 3))
      })

      test('DIDs match the inception-derived identifiers', () => {
        const [first] = impl.enumerateProfiles(seedA, 1)
        expect(first.did).toBe(impl.didFromInception(impl.createInception(seedA, 0).event))
      })

      test('different seeds produce different profiles', () => {
        const [fromA] = impl.enumerateProfiles(seedA, 1)
        const [fromB] = impl.enumerateProfiles(seedB, 1)
        expect(fromA.did).not.toBe(fromB.did)
      })

      test('handles are stable for the same DID', () => {
        const [first] = impl.enumerateProfiles(seedA, 1)
        const [again] = impl.enumerateProfiles(seedA, 1)
        expect(first.handle).toBe(again.handle)
      })
    })

    // Regression: a revoke chained onto another revoke must sign at the key position carried in
    // `keyGen`/`keySeq` — the position of the last icp/rot — not at the prior revoke's own
    // position, which establishes no key at all.
    describe('revoke chaining', () => {
      test('a revoke chained onto another revoke folds successfully', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const rev1 = impl.createRevoke(seedA, 0, did, rot.event, deviceA, { gen: 0, seq: 1 })
        const afterFirst = impl.foldLog(did, [icp, rot, rev1])
        expect(afterFirst.ok).toBe(true)
        if (!afterFirst.ok) {
          return
        }
        const keyState = afterFirst.states[2]
        const rev2 = impl.createRevoke(seedA, 0, did, rev1.event, deviceC, {
          gen: keyState.keyGen,
          seq: keyState.keySeq,
        })
        const result = impl.foldLog(did, [icp, rot, rev1, rev2])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states[3].deny.has(deviceA)).toBe(true)
        expect(result.states[3].deny.has(deviceC)).toBe(true)
      })
    })

    // 12. Agreement keys — an inception publishes a non-empty key agreement set, a rotate
    // replaces it, and a revoke leaves it unchanged. Property 2 asserts the post-rotate set
    // *differs* from the inception's rather than merely being non-empty — an implementation that
    // carried the inception's `ka` forward on rotate would pass a mere non-empty check. Properties
    // 1-3 also assert the folded value equals the `ka` the triggering event actually declared, not
    // just that it changes/holds shape — otherwise an implementation folding an entirely unrelated
    // (but still non-empty, still-changing, still-stable) value would pass all three. Property 4
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
        const result = impl.foldLog(did, [icp])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states[0].agreement.length > 0).toBe(true)
        expect(result.states[0].agreement).toEqual(icp.event.ka)
      })

      test('a rotate replaces the agreement set', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const result = impl.foldLog(did, [icp, rot])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states[1].agreement).not.toEqual(result.states[0].agreement)
        expect(result.states[1].agreement).toEqual(rot.event.ka)
      })

      test('a revoke leaves the agreement set unchanged', () => {
        const icp = impl.createInception(seedA, 0)
        const did = impl.didFromInception(icp.event)
        const rot = impl.createRotate(seedA, 0, did, icp.event)
        const rev = impl.createRevoke(seedA, 0, did, rot.event, deviceA, { gen: 0, seq: 1 })
        const result = impl.foldLog(did, [icp, rot, rev])
        expect(result.ok).toBe(true)
        if (!result.ok) {
          return
        }
        expect(result.states[2].agreement).toEqual(result.states[1].agreement)
        expect(result.states[2].agreement).toEqual(rot.event.ka)
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
        const result = impl.foldLog(did, [forged])
        expect(result.ok).toBe(false)
      })
    })
  })
}
