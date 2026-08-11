import { describe, expect, test } from 'vitest'

import { canonicalBytes, MAX_CANONICAL_DEPTH, withinCanonicalDepth } from '../src/canonical.js'
import { authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRevoke,
  createRotate,
  didFromInception,
  type EventCommon,
  encodeKey,
  type InceptionEvent,
  type RotateEvent,
  type SignedEvent,
  signEvent,
  verifyReset,
  verifyRotate,
  verifySignatures,
} from '../src/events.js'
import { type FoldResult, foldLog, foldLogAsync } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

// A log arrives from a network peer or an untrusted store, so every shape below is reachable from
// ordinary parsed JSON. `foldLog` and `foldLogAsync` document themselves as total — every rejection
// a returned reason, never a throw — and `resolveBranches` filters branches by folding them, so a
// throw here is a denial of service on duplicity detection for every well-formed branch too.

const seed = new Uint8Array(32).fill(23)
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const other = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

const icp = createInception(seed, 0)
const did = didFromInception(icp.event)
const rot = createRotate(seed, 0, did, icp.event)
const reset = createReset(seed, 0, 1)
const inceptionKeyPosition = { gen: 0, seq: 0 }
const capRevoke = createRevoke(seed, 0, did, icp.event, target, inceptionKeyPosition, {
  cap: 'a-serialized-capability',
})
const revoke = createRevoke(seed, 0, did, icp.event, target, inceptionKeyPosition)

/** A copy of `signed` with one member of its event removed — a field a peer simply did not send. */
function withoutEventMember(signed: SignedEvent, member: string): unknown {
  const event = { ...(signed.event as unknown as Record<string, unknown>) }
  delete event[member]
  return { ...signed, event }
}

/** A copy of `signed` with one member of its event replaced by a value of the wrong type. */
function withEventMember(signed: SignedEvent, member: string, value: unknown): unknown {
  return { ...signed, event: { ...signed.event, [member]: value } }
}

/**
 * Every malformed log the fold must answer with a reason. The whole {@link FoldResult} is asserted,
 * not just `ok: false`: a guard that fails the log for the wrong reason — or at the wrong index —
 * is a guard that will move the moment someone reorders the checks.
 */
const malformed: Array<[string, Array<unknown>, FoldResult]> = [
  ['a null entry', [icp, null], { ok: false, reason: 'malformed event', index: 1 }],
  [
    'an entry that is not an object',
    [icp, 'rot'],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  ['an entry carrying no `event`', [icp, {}], { ok: false, reason: 'malformed event', index: 1 }],
  [
    'an entry whose `event` is not an object',
    [icp, { event: 'rot', sigs: [] }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'an entry carrying no `sigs`',
    [icp, { event: rot.event }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'an entry whose `sigs` holds something that is not a string',
    [icp, { event: rot.event, sigs: [42] }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'a capability-authorised revoke carrying no `sigs`',
    [icp, { event: capRevoke.event }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'a rotate whose `k` is absent',
    [icp, withoutEventMember(rot, 'k')],
    { ok: false, reason: 'invalid rotate', index: 1 },
  ],
  [
    'a rotate whose `k` is not an array',
    [icp, withEventMember(rot, 'k', 'zNotAnArray')],
    { ok: false, reason: 'invalid rotate', index: 1 },
  ],
  [
    'a rotate whose `ka` is absent',
    [icp, withoutEventMember(rot, 'ka')],
    { ok: false, reason: 'invalid rotate', index: 1 },
  ],
  [
    'a reset whose `ka` is absent',
    [icp, withoutEventMember(reset, 'ka')],
    { ok: false, reason: 'invalid reset', index: 1 },
  ],
  [
    'a reset whose `k` is absent',
    [icp, withoutEventMember(reset, 'k')],
    { ok: false, reason: 'invalid reset', index: 1 },
  ],
  [
    'a revoke naming no target',
    [icp, withoutEventMember(capRevoke, 'x')],
    { ok: false, reason: 'revoke names no target', index: 1 },
  ],
  // The envelope's third member, on an otherwise perfectly valid reset. Deleting `recoveryKey`
  // proves nothing about the guard — an absent one is already `invalid reset` — so these two carry
  // a *present* value of the wrong type, which only the envelope guard can tell apart from a
  // recovery key that does not match the commitment.
  [
    'a reset whose `recoveryKey` is a number',
    [icp, { ...reset, recoveryKey: 42 }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'a reset whose `recoveryKey` is null',
    [icp, { ...reset, recoveryKey: null }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  ['an inception that is null', [null], { ok: false, reason: 'malformed event', index: 0 }],
  ['an inception carrying no `event`', [{}], { ok: false, reason: 'malformed event', index: 0 }],
  [
    'an inception carrying no `sigs`',
    [{ event: icp.event }],
    { ok: false, reason: 'malformed event', index: 0 },
  ],
  [
    'an inception whose `k` is absent',
    [withoutEventMember(icp, 'k')],
    { ok: false, reason: 'invalid inception', index: 0 },
  ],
  [
    'an inception whose `ka` is absent',
    [withoutEventMember(icp, 'ka')],
    { ok: false, reason: 'invalid inception', index: 0 },
  ],
  // --- envelopes that are the wrong *kind* of object ------------------------------------------
  [
    'an entry that is a nested array',
    [icp, [rot]],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'an inception that is a nested array',
    [[icp]],
    { ok: false, reason: 'malformed event', index: 0 },
  ],
  [
    'a log with an empty slot',
    [icp, undefined],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    'an entry whose `sigs` is an array-like object',
    [icp, { event: rot.event, sigs: { 0: 'x', length: 1 } }],
    { ok: false, reason: 'malformed event', index: 1 },
  ],
  [
    // `typeof [] === 'object'`, so the envelope guard admits it and the controller-name check is
    // what stops it. Total either way; recorded because the guard that catches it is not the one
    // that appears to — and it is the only row that reaches that check with a hostile value.
    'an entry whose `event` is an array',
    [icp, { event: [], sigs: [] }],
    { ok: false, reason: 'event names a different controller', index: 1 },
  ],
  // --- well-formed envelope, hostile body ------------------------------------------------------
  [
    'a rotate whose `g` is an object',
    [icp, { event: { ...rot.event, g: {} }, sigs: rot.sigs }],
    { ok: false, reason: 'sequence gap', index: 1 },
  ],
  [
    'a rotate whose `g` is a fractional generation bump',
    [icp, { event: { ...rot.event, g: 0.5, s: 0 }, sigs: rot.sigs }],
    { ok: false, reason: 'invalid reset', index: 1 },
  ],
  [
    'a rotate whose `g` is the string "1"',
    [icp, { event: { ...rot.event, g: '1', s: 0 }, sigs: rot.sigs }],
    { ok: false, reason: 'invalid reset', index: 1 },
  ],
  [
    'a rotate whose `s` is an object',
    [icp, { event: { ...rot.event, s: {} }, sigs: rot.sigs }],
    { ok: false, reason: 'sequence gap', index: 1 },
  ],
  [
    'an event whose `t` is an object',
    [icp, { event: { ...revoke.event, t: { evil: true } }, sigs: revoke.sigs }],
    { ok: false, reason: 'unknown critical event type: [object Object]', index: 1 },
  ],
  [
    'an event whose `t` is an array and `crit` is a truthy string',
    [icp, { event: { ...revoke.event, t: ['rev'], crit: 'no' }, sigs: revoke.sigs }],
    { ok: false, reason: 'unknown critical event type: rev', index: 1 },
  ],
]

describe('foldLog() is total', () => {
  for (const [name, log, expected] of malformed) {
    test(`answers ${name} with a reason`, () => {
      expect(foldLog(did, log as Array<SignedEvent>)).toEqual(expected)
    })
  }

  test('answers a log that is not an array with a reason', () => {
    expect(foldLog(did, undefined as unknown as Array<SignedEvent>)).toEqual({
      ok: false,
      reason: 'malformed log',
      index: 0,
    })
  })
})

describe('foldLogAsync() is total', () => {
  for (const [name, log, expected] of malformed) {
    test(`answers ${name} with a reason`, async () => {
      // With a verifier configured, so a capability-bearing revoke reaches the same guards the sync
      // fold reaches rather than stopping at "needs an async fold".
      await expect(
        foldLogAsync(did, log as Array<SignedEvent>, {
          verifyCapability: async () => ({ authorised: false, reason: 'not checked here' }),
        }),
      ).resolves.toEqual(expected)
    })
  }
})

describe('the exported verifiers are total', () => {
  test('verifySignatures answers non-array `sigs` and `keys` with false', () => {
    expect(verifySignatures(rot.event, undefined as unknown as Array<string>, rot.event.k)).toBe(
      false,
    )
    expect(verifySignatures(rot.event, rot.sigs, undefined as unknown as Array<string>)).toBe(false)
    // Control: the same call with both arrays present verifies.
    expect(verifySignatures(rot.event, rot.sigs, rot.event.k)).toBe(true)
  })

  test('verifyReset answers a non-array `sigs` with false', () => {
    // The one exported verifier that reads `sigs` before handing it to `verifySignatures`.
    expect(verifyReset({ event: reset.event } as unknown as never, icp.event)).toBe(false)
    // Control: the same reset with its signatures present verifies against the same inception.
    expect(verifyReset(reset, icp.event)).toBe(true)
  })

  test('verifyRotate answers a malformed `k`, `n` and `d` with false', () => {
    const prior = { digest: rot.event.p ?? '', n: icp.event.n }
    for (const [member, value] of [
      ['k', 'zNotAnArray'],
      ['n', 'zNotAnArray'],
      ['k', [42]],
      ['d', 'did:key:zNotAnArray'],
      ['d', 7],
    ] as Array<[string, unknown]>) {
      expect(verifyRotate(withEventMember(rot, member, value) as never, prior)).toBe(false)
    }
    // Control: the untouched rotate verifies against the same prior, so each rejection above is the
    // member it names and not the surrounding event.
    expect(verifyRotate(rot, prior)).toBe(true)
  })
})

describe('a malformed event its own author signed', () => {
  // Every case above is caught by a signature that no longer matches, which is not the guard under
  // test — it is the guard that happens to run first. These are events the key holder published,
  // signed correctly, with a member of the wrong shape. Only the shape guards reject them, and a
  // reset in particular verifies against the revealed recovery key rather than against `k`, so
  // nothing else ever looks at what it publishes.

  const authority = (seq: number) => deriveKeyPair(seed, authorityPath(0, 0, seq), 'EdDSA')
  const recovery = deriveKeyPair(seed, recoveryPath(0), 'EdDSA')

  /** The rotate, mutated and re-signed by the next key it legitimately reveals. */
  function signedRotate(member: string, value: unknown): SignedEvent<RotateEvent> {
    const event = { ...rot.event, [member]: value } as RotateEvent
    return { event, sigs: signEvent(event, [authority(1).privateKey]) }
  }

  /** The reset, mutated and re-signed by the recovery key it reveals. */
  function signedReset(member: string, value: unknown): SignedEvent<RotateEvent> {
    const event = { ...reset.event, [member]: value } as RotateEvent
    return {
      event,
      sigs: signEvent(event, [recovery.privateKey]),
      recoveryKey: encodeKey(recovery.publicKey, 'EdDSA'),
    }
  }

  /** The revoke, mutated and re-signed by the profile's own current authority key. */
  function signedRevoke(member: string, value: unknown): SignedEvent {
    const event = { ...revoke.event, [member]: value }
    return { event, sigs: signEvent(event as EventCommon, [authority(0).privateKey]) }
  }

  /**
   * An inception, mutated and re-signed. Self-certifying works against us here: the DID is the
   * hash of the event, so *any* body is a legitimate inception for the DID it hashes to.
   */
  function signedInception(member: string, value: unknown): [string, SignedEvent<InceptionEvent>] {
    const event = { ...icp.event, [member]: value } as InceptionEvent
    const signed = { event, sigs: signEvent(event as EventCommon, [authority(0).privateKey]) }
    return [didFromInception(event), signed]
  }

  const cases: Array<[string, Array<unknown>, FoldResult]> = [
    [
      'a rotate whose deny snapshot is a scalar',
      [icp, signedRotate('d', 7)],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose deny snapshot is a string',
      [icp, signedRotate('d', 'did:key:zAbc')],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose deny snapshot holds a non-string',
      [icp, signedRotate('d', ['did:key:zAbc', 7])],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose `n` is null',
      [icp, signedRotate('n', null)],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose recovery commitment is not a string',
      // `KeyState.recovery` is exported and typed `string`. Nothing in this package reads it yet,
      // which is exactly why it would drift: a rotate is the only event that can replace it.
      [icp, signedRotate('r', 42)],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a reset whose `k` is a string',
      [icp, signedReset('k', 'zNotAnArray')],
      { ok: false, reason: 'invalid reset', index: 1 },
    ],
    [
      'a reset whose `n` is null',
      [icp, signedReset('n', null)],
      { ok: false, reason: 'invalid reset', index: 1 },
    ],
    [
      'a reset whose deny snapshot is a scalar',
      [icp, signedReset('d', 7)],
      { ok: false, reason: 'invalid reset', index: 1 },
    ],
    [
      'a rotate whose `k` holds a nested array',
      [icp, signedRotate('k', [[]])],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose `n` holds a nested array',
      [icp, signedRotate('n', [[icp.event.n[0]]])],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose `ka` holds a number',
      [icp, signedRotate('ka', [7])],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose `ka` is an empty array',
      [icp, signedRotate('ka', [])],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose deny snapshot holds a nested array',
      [icp, signedRotate('d', [[target]])],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a rotate whose recovery commitment is an object',
      [icp, signedRotate('r', { evil: true })],
      { ok: false, reason: 'invalid rotate', index: 1 },
    ],
    [
      'a reset whose recovery commitment is an object',
      [icp, signedReset('r', { evil: true })],
      { ok: false, reason: 'invalid reset', index: 1 },
    ],
    [
      'a reset whose `ka` holds a nested array',
      [icp, signedReset('ka', [[]])],
      { ok: false, reason: 'invalid reset', index: 1 },
    ],
    [
      'a reset whose `n` holds a number',
      [icp, signedReset('n', [7])],
      { ok: false, reason: 'invalid reset', index: 1 },
    ],
    // The target goes into a `ReadonlySet<string>` and, for a capability-authorised revoke, into
    // the verifier as the resource being asked for — where a wildcard grant would happily
    // authorise denying an object.
    [
      'an authority-signed revoke naming an object as its target',
      [icp, signedRevoke('x', { evil: true })],
      { ok: false, reason: 'revoke names no target', index: 1 },
    ],
    [
      'an authority-signed revoke naming an array as its target',
      [icp, signedRevoke('x', [target])],
      { ok: false, reason: 'revoke names no target', index: 1 },
    ],
    [
      'an authority-signed revoke naming null as its target',
      [icp, signedRevoke('x', null)],
      { ok: false, reason: 'revoke names no target', index: 1 },
    ],
  ]

  for (const [name, log, expected] of cases) {
    test(`${name} is rejected`, () => {
      expect(foldLog(did, log as Array<SignedEvent>)).toEqual(expected)
    })
  }

  test('a rotate whose deny snapshot is well formed still folds', () => {
    // The control for the three rows above: the same re-signing machinery with a legal `d`.
    const result = foldLog(did, [icp, signedRotate('d', [target])])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
  })

  test('an inception whose `n` is null is rejected before the next event reads it', () => {
    // The commitment goes into `KeyState.next`, which the *next* rotate reads — one event away
    // from the log that caused it. Rejecting at publication is what keeps that read safe.
    const [forgedDid, forged] = signedInception('n', null)
    const following = createRotate(seed, 0, forgedDid, forged.event)
    expect(foldLog(forgedDid, [forged, following])).toEqual({
      ok: false,
      reason: 'invalid inception',
      index: 0,
    })
  })

  test('an inception whose recovery commitment is not a string is rejected', () => {
    const [forgedDid, forged] = signedInception('r', 42)
    expect(foldLog(forgedDid, [forged])).toEqual({
      ok: false,
      reason: 'invalid inception',
      index: 0,
    })
  })

  for (const value of [42, {}, [], ['a'], true]) {
    test(`a revoke whose \`cap\` is ${JSON.stringify(value)} is rejected, not thrown`, async () => {
      // `cap` is handed straight to the verifier, which is caller code: a non-string reaches
      // `verifyToken` and throws there, and the fold has to turn that into a reason.
      const evil = signedRevoke('cap', value)
      let sync: unknown
      expect(() => {
        sync = foldLog(did, [icp, evil])
      }).not.toThrow()
      expect(sync).toEqual({
        ok: false,
        reason: `capability-authorised revoke needs an async fold: ${String(value)}`,
        index: 1,
      })

      const seen: Array<unknown> = []
      await expect(
        foldLogAsync(did, [icp, evil], {
          verifyCapability: async (cap) => {
            seen.push(cap)
            throw new Error(`cap is ${typeof cap}`)
          },
        }),
      ).resolves.toEqual({
        ok: false,
        reason: `capability verifier failed: cap is ${typeof value}`,
        index: 1,
      })
      expect(seen).toEqual([value])
    })
  }

  test('an unmutated inception still folds', () => {
    // Control for both rows above: the same re-signing path with nothing changed.
    const [forgedDid, forged] = signedInception('kt', 1)
    expect(foldLog(forgedDid, [forged]).ok).toBe(true)
  })
})

describe('an event body nested deeper than the canonicalizer will go', () => {
  // `canonicalize` recurses once per nesting level and every path out of the fold canonicalizes the
  // whole body — the signature check hashes it, `digestOf` chains it — so before the bound a member
  // the fold never reads decided how much stack the fold used. V8's `JSON.parse` is iterative and
  // accepts arbitrary depth, so each shape below arrives from ordinary wire bytes.

  const authority = (seq: number) => deriveKeyPair(seed, authorityPath(0, 0, seq), 'EdDSA')

  /** `levels` nested arrays around a string, round-tripped through the wire. */
  function nest(levels: number): unknown {
    let json = '"seal"'
    for (let i = 0; i < levels; i++) {
      json = `[${json}]`
    }
    return JSON.parse(json)
  }

  /** The rotate carrying `a`, re-signed, so only the depth guard can reject it. */
  function rotateWithSeal(seal: unknown): SignedEvent<RotateEvent> {
    const event = { ...rot.event, a: seal } as unknown as RotateEvent
    return JSON.parse(
      JSON.stringify({ event, sigs: signEvent(event, [authority(1).privateKey]) }),
    ) as SignedEvent<RotateEvent>
  }

  // The event body is the top-level value the canonicalizer sees, so it is depth 1 and the value of
  // its `a` member is depth 2. `nest(n)` puts its string n levels below that.
  const deepestAccepted = MAX_CANONICAL_DEPTH - 2
  const shallowestRejected = MAX_CANONICAL_DEPTH - 1

  test(`a body reaching exactly ${MAX_CANONICAL_DEPTH} levels folds`, () => {
    // The control, and the reason the bound is a bound rather than a rejection of nesting: a log
    // this deep is canonicalized, hashed and accepted like any other.
    const result = foldLog(did, [icp, rotateWithSeal(nest(deepestAccepted))])
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].keys).toEqual(rot.event.k)
  })

  test('one level further is rejected with a reason, by both folds', async () => {
    // Unsigned, because this package cannot sign a body it cannot canonicalize — which is also why
    // the depth guard has to run before the signature check rather than instead of it.
    const log = [
      icp,
      { ...rot, event: { ...rot.event, a: nest(shallowestRejected) } },
    ] as Array<SignedEvent>
    expect(foldLog(did, log)).toEqual({ ok: false, reason: 'malformed event', index: 1 })
    await expect(foldLogAsync(did, log)).resolves.toEqual({
      ok: false,
      reason: 'malformed event',
      index: 1,
    })
  })

  // 5000 is past the stack, not merely past the bound: before the guard each of these threw a
  // `RangeError` out of the fold. The member is one no verifier reads, so nothing but the envelope
  // guard has a reason to look at it.
  const wire = (value: unknown) => JSON.parse(JSON.stringify(value)) as Array<SignedEvent>
  const abyss = () => nest(5000)
  const chasms: Array<[string, Array<SignedEvent>, FoldResult]> = [
    [
      'an inception carrying an unread member 5000 levels deep',
      wire([{ ...icp, event: { ...icp.event, zz: abyss() } }]),
      { ok: false, reason: 'malformed event', index: 0 },
    ],
    [
      'a rotate whose seal is 5000 levels deep',
      wire([icp, { ...rot, event: { ...rot.event, a: abyss() } }]),
      { ok: false, reason: 'malformed event', index: 1 },
    ],
    [
      'a revoke carrying an unread member 5000 levels deep',
      wire([
        icp,
        {
          ...createRevoke(seed, 0, did, icp.event, target, inceptionKeyPosition),
          event: {
            ...createRevoke(seed, 0, did, icp.event, target, inceptionKeyPosition).event,
            zz: abyss(),
          },
        },
      ]),
      { ok: false, reason: 'malformed event', index: 1 },
    ],
  ]

  for (const [name, log, expected] of chasms) {
    test(`${name} is answered with a reason, not a RangeError`, async () => {
      let sync: unknown
      expect(() => {
        sync = foldLog(did, log)
      }).not.toThrow()
      expect(sync).toEqual(expected)
      await expect(foldLogAsync(did, log)).resolves.toEqual(expected)
    })
  }

  test('one hostile branch no longer kills duplicity detection for the well-formed ones', () => {
    // The denial of service `isSignedEventShape`'s docstring names: a thief who cannot produce a
    // valid event crashing duplicity resolution for every well-formed branch beside it.
    const forkA = [icp, createRevoke(seed, 0, did, icp.event, target, inceptionKeyPosition)]
    const forkB = [icp, createRevoke(seed, 0, did, icp.event, other, inceptionKeyPosition)]
    const hostile = wire([icp, { ...rot, event: { ...rot.event, a: abyss() } }])

    const clean = resolveBranches(did, [forkA, forkB])
    expect(clean.ok).toBe(false)
    if (clean.ok) return
    expect(clean.duplicity.seq).toBe(1)

    let withHostile: unknown
    expect(() => {
      withHostile = resolveBranches(did, [forkA, hostile, forkB])
    }).not.toThrow()
    // Byte-identical to the clean pair: the hostile branch is filtered, not merged.
    expect(withHostile).toEqual(clean)
  })

  test('canonicalBytes itself throws above the bound, for a caller holding its own input', () => {
    // The guard above is what turns this into a reason on the fold's path. Direct callers —
    // `digestOf`, `didFromInception` — still get the throw, which is why the fold checks first.
    // A value nested at the top level is itself depth 1, so `nest(n)` reaches depth n + 1.
    expect(() => canonicalBytes(nest(MAX_CANONICAL_DEPTH - 1))).not.toThrow()
    expect(() => canonicalBytes(nest(MAX_CANONICAL_DEPTH))).toThrow(/nests deeper than/)
    expect(() => canonicalBytes(abyss())).toThrow(/nests deeper than/)
  })

  test('withinCanonicalDepth agrees with canonicalBytes on the boundary', () => {
    // The two are separate implementations of one rule, which is exactly how a guard drifts one
    // level away from the thing it guards.
    for (const levels of [0, 1, deepestAccepted, MAX_CANONICAL_DEPTH - 1]) {
      expect(withinCanonicalDepth(nest(levels)), `${levels} levels`).toBe(true)
      expect(() => canonicalBytes(nest(levels))).not.toThrow()
    }
    for (const levels of [MAX_CANONICAL_DEPTH, MAX_CANONICAL_DEPTH + 1, 5000]) {
      expect(withinCanonicalDepth(nest(levels)), `${levels} levels`).toBe(false)
      expect(() => canonicalBytes(nest(levels))).toThrow()
    }
    // A cycle is not reachable from `JSON.parse`, but it is reachable from a caller — and it is the
    // one input where an unbounded recursion never returns at all.
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic
    expect(withinCanonicalDepth(cyclic)).toBe(false)
  })
})

describe('resolveBranches() survives a hostile branch', () => {
  // Two well-formed branches that genuinely fork, plus one an attacker fabricated. Before the shape
  // guards the fabricated branch threw a TypeError out of `resolveBranches`, which is a denial of
  // service on the one mechanism that exists to detect a key-takeover fork.
  const forkA = [icp, createRevoke(seed, 0, did, icp.event, target, inceptionKeyPosition)]
  const forkB = [icp, createRevoke(seed, 0, did, icp.event, other, inceptionKeyPosition)]
  const hostile = [icp, withoutEventMember(rot, 'k')] as Array<SignedEvent>

  test('still reports duplicity among the well-formed branches', () => {
    const result = resolveBranches(did, [forkA, hostile, forkB])
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.duplicity.gen).toBe(0)
    expect(result.duplicity.seq).toBe(1)
    // Control: the same two branches without the hostile one report the same duplicity, so the
    // hostile branch is filtered rather than participating.
    expect(resolveBranches(did, [forkA, forkB])).toEqual(result)
  })

  test('still picks the winner when one exists', () => {
    const result = resolveBranches(did, [hostile, [icp, rot], [icp]])
    expect(result).toEqual({ ok: true, winner: [icp, rot], superseded: 1 })
  })

  test('reports no valid history when every branch is hostile', () => {
    expect(resolveBranches(did, [hostile, [null] as unknown as Array<SignedEvent>])).toEqual({
      ok: false,
      duplicity: { gen: -1, seq: -1, digests: ['', ''] },
    })
  })

  // One row per shape a branch can arrive in, each asserted equal to the clean pair's answer:
  // filtering a hostile branch has to be indistinguishable from never having been handed it, or a
  // thief can change what duplicity resolution reports by adding branches nobody can verify.
  const clean = resolveBranches(did, [forkA, forkB])
  const hostiles: Array<[string, unknown]> = [
    ['a nested-array entry', [icp, [rot]]],
    ['a rotate whose `g` is an object', [icp, { event: { ...rot.event, g: {} }, sigs: rot.sigs }]],
    ['a branch that is not an array', 'nope'],
    ['a branch that is null', null],
    ['an empty branch', []],
    ['a branch of one hostile entry', [null]],
  ]

  for (const [name, branch] of hostiles) {
    test(`duplicity is still reported alongside ${name}`, () => {
      let result: unknown
      expect(() => {
        result = resolveBranches(did, [forkA, branch as Array<SignedEvent>, forkB])
      }).not.toThrow()
      expect(result).toEqual(clean)
    })
  }

  test('every branch hostile reports the no-valid-history sentinel', () => {
    const result = resolveBranches(did, hostiles.map(([, h]) => h) as Array<Array<SignedEvent>>)
    expect(result).toEqual({ ok: false, duplicity: { gen: -1, seq: -1, digests: ['', ''] } })
  })
})
