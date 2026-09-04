import { describe, expect, test } from 'vitest'

import {
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  type SignedEvent,
  verifySignatures,
} from '../src/events.js'
import { foldLog, foldLogAsync } from '../src/fold.js'
import { resolveBranches } from '../src/supersede.js'

const seed = new Uint8Array(32).fill(1)
const deviceX = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

/** Exactly what a peer puts on the wire. `1e400` overflows to Infinity in every JSON parser. */
function fromWire(json: string): unknown {
  return JSON.parse(json)
}

function build() {
  const icp = createInception(seed, 0)
  const did = didFromInception(icp.event)
  const rot = createRotate({ seed, profile: 0, did, prior: icp.event })
  const rev = createRevoke({
    seed,
    profile: 0,
    did,
    prior: rot.event,
    target: deviceX,
    keyPosition: { gen: 0, seq: 1 },
  })
  return { icp, did, rot, rev, honest: [icp, rot, rev] }
}

// CLOSED. The fold's envelope guard now asks `isCanonicalizable` rather than `withinCanonicalDepth`,
// so a body carrying `Infinity` is a `malformed event` — a returned `FoldResult` — instead of a
// throw out of `canonicalize`. `verifySignatures` and `verifyEventSignedBy` carry the same guard,
// because both are exported and documented total and a direct caller reaches them with a parsed
// body and nothing else. Every construction below is byte-for-byte what it was; the assertions
// changed from "it throws" to "it answers", and each row keeps its control.
describe('ATTACK: a non-finite number reaches `canonicalBytes` and breaks fold totality', () => {
  test('ROW 0 (premise): `1e400` off the wire is Infinity, and the envelope guard admits it', () => {
    const parsed = fromWire('{"v":1,"junk":1e400}') as Record<string, unknown>
    expect(Number.isFinite(parsed.junk as number)).toBe(false)
  })

  test('ROW 1 (closed): a forged inception carrying `1e400` makes foldLog FAIL, not throw', () => {
    const { did } = build()
    const hostile = fromWire(
      '{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":1e400},"sigs":[]}',
    ) as SignedEvent

    let thrown: unknown
    let returned: unknown
    try {
      returned = foldLog(did, [hostile])
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(returned).toEqual({ ok: false, reason: 'malformed event', index: 0 })
  })

  test('ROW 2 (control): the identical event with a FINITE `junk` returns a FoldResult', () => {
    const { did } = build()
    // One field mutated: `1e400` -> `1`. Everything else is byte-identical to ROW 1.
    const tame = fromWire(
      '{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":1},"sigs":[]}',
    ) as SignedEvent

    let thrown: unknown
    let returned: unknown
    try {
      returned = foldLog(did, [tame])
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(returned).toEqual({ ok: false, reason: 'invalid inception', index: 0 })
  })

  test('ROW 3 (closed): the same trick on a `rev` — answered at any log position', () => {
    const { icp, did, honest } = build()
    const good = foldLog(did, [icp])
    if (!good.ok) throw new Error('fixture')
    const head = good.states[0]
    if (head === undefined) throw new Error('fixture')
    // Length of `sigs` must match `prior.keys` (one key) to get past the arity check; the bytes
    // themselves are junk, because the throw happens before any signature is examined.
    const raw = `{"event":{"v":1,"t":"rev","i":${JSON.stringify(did)},"g":0,"s":1,"p":${JSON.stringify(
      head.digest,
    )},"crit":true,"x":${JSON.stringify(deviceX)},"junk":JUNK},"sigs":["AAAA"]}`
    const wire = fromWire(raw.replace('JUNK', '1e400')) as SignedEvent

    let thrown: unknown
    let hostileResult: unknown
    try {
      hostileResult = foldLog(did, [icp, wire])
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeUndefined()
    expect(hostileResult).toEqual({ ok: false, reason: 'malformed event', index: 1 })

    // ROW 3 control: identical rev with a finite `junk` -> a returned failure, and a *different*
    // reason, so the rejection above is the non-finite member and not the junk signature bytes.
    const tame = fromWire(raw.replace('JUNK', '1')) as SignedEvent
    const control = foldLog(did, [icp, tame])
    expect(control).toEqual({ ok: false, reason: 'invalid revoke', index: 1 })
    expect(honest.length).toBe(3)
  })

  test('ROW 4 (closed): a hostile branch is filtered, and the honest one still wins', () => {
    const { did, honest } = build()
    const hostile = fromWire(
      '{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":1e400},"sigs":[]}',
    ) as SignedEvent

    const aloneOk = resolveBranches(did, [honest])

    let thrown: unknown
    let together: unknown
    try {
      together = resolveBranches(did, [honest, [hostile]])
    } catch (error) {
      thrown = error
    }
    expect(aloneOk.ok).toBe(true)
    expect(thrown).toBeUndefined()
    // The hostile branch does not fold, so it is filtered like any other invalid branch and the
    // honest branch wins outright — not a duplicity report, and not "no valid history".
    expect(together).toEqual(aloneOk)
  })

  test('ROW 5 (closed): `foldLogAsync` resolves to a FoldResult rather than rejecting', async () => {
    const { did } = build()
    const hostile = fromWire(
      '{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":1e400},"sigs":[]}',
    ) as SignedEvent
    let rejected: unknown
    const resolvedWith = await foldLogAsync(did, [hostile]).catch((error) => {
      rejected = error
      return undefined
    })
    expect(rejected).toBeUndefined()
    expect(resolvedWith).toEqual({ ok: false, reason: 'malformed event', index: 0 })
  })

  test('ROW 6 (closed): the exported `verifySignatures` is documented total and now is', () => {
    const event = fromWire('{"v":1,"t":"rev","g":0,"s":1,"crit":true,"junk":1e400}') as never
    let thrown: unknown
    let answered: unknown
    try {
      answered = verifySignatures(event, ['AAAA'], ['zAbc'])
    } catch (error) {
      thrown = error
    }
    // Control: the same call with a finite member also returns `false` (via the ordinary bad-signature
    // path), so the non-finite case is handled as a plain `false` and not as a throw.
    const tame = fromWire('{"v":1,"t":"rev","g":0,"s":1,"crit":true,"junk":1}') as never
    expect(thrown).toBeUndefined()
    expect(answered).toBe(false)
    expect(verifySignatures(tame, ['AAAA'], ['zAbc'])).toBe(false)
  })

  test('ROW 7 (the other spellings): NaN and -Infinity are refused, `-0` and 2^53+1 are not', () => {
    const { did } = build()
    const body = (junk: string) =>
      fromWire(
        `{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":${junk}},"sigs":[]}`,
      ) as SignedEvent

    // `-1e400` is the second non-finite spelling reachable from the wire. `NaN` is not valid JSON,
    // so it is injected the only way it can arrive: from a caller's own object.
    for (const [, event] of [
      ['-1e400', body('-1e400')],
      ['NaN', { event: { ...(body('1').event as object), junk: Number.NaN }, sigs: [] }],
    ] as Array<[string, SignedEvent]>) {
      const result = foldLog(did, [event])
      expect(result).toEqual({ ok: false, reason: 'malformed event', index: 0 })
    }

    // `-0` and an integer past `Number.MAX_SAFE_INTEGER` are *accepted*, and reach the ordinary
    // `invalid inception` rejection rather than the malformed-event one — so the guard above
    // discriminates the non-finite values specifically and does not simply refuse every number.
    for (const junk of ['-0', '9007199254740993', '1e21']) {
      const result = foldLog(did, [body(junk)])
      expect(result).toEqual({ ok: false, reason: 'invalid inception', index: 0 })
    }
  })
})
