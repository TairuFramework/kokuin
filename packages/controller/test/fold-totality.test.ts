import { describe, expect, test } from 'vitest'

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

  test('an unmutated inception still folds', () => {
    // Control for both rows above: the same re-signing path with nothing changed.
    const [forgedDid, forged] = signedInception('kt', 1)
    expect(foldLog(forgedDid, [forged]).ok).toBe(true)
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
})
