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
  const rot = createRotate(seed, 0, did, icp.event)
  const rev = createRevoke(seed, 0, did, rot.event, deviceX, { gen: 0, seq: 1 })
  return { icp, did, rot, rev, honest: [icp, rot, rev] }
}

describe('ATTACK: a non-finite number reaches `canonicalBytes` and breaks fold totality', () => {
  test('ROW 0 (premise): `1e400` off the wire is Infinity, and the envelope guard admits it', () => {
    const parsed = fromWire('{"v":1,"junk":1e400}') as Record<string, unknown>
    console.log('typeof junk:', typeof parsed.junk, '| value:', parsed.junk)
    expect(Number.isFinite(parsed.junk as number)).toBe(false)
  })

  test('ROW 1 (attack): a forged inception carrying `1e400` makes foldLog THROW, not fail', () => {
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
    console.log('foldLog returned:', returned)
    console.log('foldLog THREW:', thrown instanceof Error ? thrown.message : thrown)
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).message).toMatch(/numbers must be finite/)
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
    console.log('CONTROL foldLog returned:', returned)
    console.log('CONTROL foldLog threw:', thrown)
    expect(thrown).toBeUndefined()
    expect(returned).toEqual({ ok: false, reason: 'invalid inception', index: 0 })
  })

  test('ROW 3 (attack): the same trick on a `rev` — reachable at any log position', () => {
    const { icp, did, honest } = build()
    const good = foldLog(did, [icp])
    if (!good.ok) throw new Error('fixture')
    // Length of `sigs` must match `prior.keys` (one key) to get past the arity check; the bytes
    // themselves are junk, because the throw happens before any signature is examined.
    const raw = `{"event":{"v":1,"t":"rev","i":${JSON.stringify(did)},"g":0,"s":1,"p":${JSON.stringify(
      good.states[0].digest,
    )},"crit":true,"x":${JSON.stringify(deviceX)},"junk":JUNK},"sigs":["AAAA"]}`
    const wire = fromWire(raw.replace('JUNK', '1e400')) as SignedEvent
    console.log(
      'junk on the wire is finite:',
      Number.isFinite((wire.event as never as Record<string, number>).junk),
    )

    let thrown: unknown
    try {
      foldLog(did, [icp, wire])
    } catch (error) {
      thrown = error
    }
    console.log(
      'foldLog([icp, hostile rev]) THREW:',
      thrown instanceof Error ? thrown.message : thrown,
    )
    expect(thrown).toBeInstanceOf(Error)

    // ROW 3 control: identical rev with a finite `junk` -> a returned failure, not a throw.
    const tame = fromWire(raw.replace('JUNK', '1')) as SignedEvent
    const control = foldLog(did, [icp, tame])
    console.log('CONTROL (finite junk) returned:', control)
    expect(control).toEqual({ ok: false, reason: 'invalid revoke', index: 1 })
    expect(honest.length).toBe(3)
  })

  test('ROW 4 (impact): one hostile branch takes down `resolveBranches` for every honest branch', () => {
    const { did, honest } = build()
    const hostile = fromWire(
      '{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":1e400},"sigs":[]}',
    ) as SignedEvent

    const aloneOk = resolveBranches(did, [honest])
    console.log('honest branch alone resolves:', aloneOk.ok)

    let thrown: unknown
    try {
      resolveBranches(did, [honest, [hostile]])
    } catch (error) {
      thrown = error
    }
    console.log(
      'resolveBranches([honest, hostile]) THREW:',
      thrown instanceof Error ? thrown.message : thrown,
    )
    expect(aloneOk.ok).toBe(true)
    expect(thrown).toBeInstanceOf(Error)
  })

  test('ROW 5: `foldLogAsync` rejects rather than resolving to a FoldResult', async () => {
    const { did } = build()
    const hostile = fromWire(
      '{"event":{"v":1,"t":"icp","g":0,"s":0,"crit":true,"k":["zAbc"],"ka":["zAbc"],"n":["zAbc"],"kt":1,"nt":1,"r":"zAbc","junk":1e400},"sigs":[]}',
    ) as SignedEvent
    let rejected: unknown
    await foldLogAsync(did, [hostile]).catch((error) => {
      rejected = error
    })
    console.log(
      'foldLogAsync rejected with:',
      rejected instanceof Error ? rejected.message : rejected,
    )
    expect(rejected).toBeInstanceOf(Error)
  })

  test('ROW 6: the exported `verifySignatures` is documented total and also throws', () => {
    const event = fromWire('{"v":1,"t":"rev","g":0,"s":1,"crit":true,"junk":1e400}') as never
    let thrown: unknown
    try {
      verifySignatures(event, ['AAAA'], ['zAbc'])
    } catch (error) {
      thrown = error
    }
    console.log('verifySignatures THREW:', thrown instanceof Error ? thrown.message : thrown)
    // Control: the same call with a finite member returns `false`.
    const tame = fromWire('{"v":1,"t":"rev","g":0,"s":1,"crit":true,"junk":1}') as never
    console.log('CONTROL verifySignatures returned:', verifySignatures(tame, ['AAAA'], ['zAbc']))
    expect(thrown).toBeInstanceOf(Error)
  })
})
