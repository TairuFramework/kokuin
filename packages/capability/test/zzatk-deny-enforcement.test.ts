import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  didFromInception,
  foldLog,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createSigningIdentity,
  type MethodRegistry,
  normalizeDID,
  randomIdentity,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { checkCapability, createCapability, now } from '../src/index.js'

const seed = new Uint8Array(32).fill(31)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const controller = createControllerIdentity(seed, 0, [inception])
const inceptionKeyPosition = { gen: 0, seq: 0 }

let log: Array<SignedEvent> = [inception]
const methods: MethodRegistry = [
  createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) }),
]

function revokeOf(target: string): SignedEvent {
  return createRevoke(seed, 0, did, inception.event, target, inceptionKeyPosition)
}

async function mintFor(audienceId: string): Promise<string> {
  const capability = await createCapability(
    controller,
    { sub: did, aud: audienceId, act: 'write', res: 'doc/1', exp: now() + 3600 },
    undefined,
    { methods },
  )
  return stringifyToken(capability)
}

async function invoke(holder: SigningIdentity, cap: string): Promise<void> {
  await checkCapability(
    { act: 'write', res: 'doc/1' },
    { iss: holder.id, sub: did, cap: [cap] },
    { methods },
  )
}

const delegate = createSigningIdentity(new Uint8Array(32).fill(41))
const bystander = createSigningIdentity(new Uint8Array(32).fill(43))

describe('deny-set enforcement: is a revoked audience actually REFUSED?', () => {
  test('ROW 1 (attack): a revoked device presents its still-unexpired capability', async () => {
    log = [inception]
    const cap = await mintFor(delegate.id)
    let before: unknown = 'accepted'
    await invoke(delegate, cap).catch((e) => {
      before = e
    })
    console.log('before the revoke:', before === 'accepted' ? 'ACCEPTED' : String(before))

    log = [inception, revokeOf(delegate.id)]
    const folded = foldLog(did, log)
    console.log('deny set at head:', folded.ok ? [...folded.states[1].deny] : 'n/a')
    let after: unknown = 'accepted'
    await invoke(delegate, cap).catch((e) => {
      after = e
    })
    console.log('after the revoke:', after === 'accepted' ? 'ACCEPTED' : String(after))
    expect(String(after)).toMatch(/audience is revoked by the subject/)
  })

  test('ROW 2 (control: denial is the cause, not the revoke event): a bystander still verifies', async () => {
    log = [inception]
    const capB = await mintFor(bystander.id)
    log = [inception, revokeOf(delegate.id)]
    // The SAME log, the SAME revoke event — only the audience differs.
    let outcome: unknown = 'accepted'
    await invoke(bystander, capB).catch((e) => {
      outcome = e
    })
    console.log(
      'non-denied audience against the same revoking log:',
      outcome === 'accepted' ? 'ACCEPTED' : String(outcome),
    )
    expect(outcome).toBe('accepted')
  })

  // CLOSED by a stronger guard than this row was written against, and only visible once
  // `@kokuin/controller` was rebuilt: a skipped event must now occupy the *next* sequence position,
  // so the forged `s: 99` makes the whole log unfoldable instead of being carried forward. The
  // revoked device is still refused, which is what this row exists to assert; the reason moved from
  // "the deny set survived the tail" to "the tail is not a log". Construction untouched, assertion
  // corrected, and a control added below for the deny path itself.
  test('ROW 3: a forged unsigned non-critical event appended after the revoke does NOT clear it', async () => {
    log = [inception]
    const cap = await mintFor(delegate.id)
    const revoke = revokeOf(delegate.id)
    const base = foldLog(did, [inception, revoke])
    if (!base.ok) throw new Error('fixture')
    const forged = {
      event: {
        v: 1,
        t: 'nop',
        i: did,
        g: 0,
        s: 99,
        p: base.states[1].digest,
        crit: false,
        d: [],
      },
      sigs: [],
    } as unknown as SignedEvent
    log = [inception, revoke, forged]
    const folded = foldLog(did, log)
    console.log('log with the forged tail folds:', folded.ok)
    console.log('deny set at head:', folded.ok ? [...folded.states[2].deny] : 'n/a')
    let outcome: unknown = 'accepted'
    await invoke(delegate, cap).catch((e) => {
      outcome = e
    })
    console.log(
      'revoked device after the forged tail:',
      outcome === 'accepted' ? 'ACCEPTED' : String(outcome),
    )
    expect(folded.ok).toBe(false)
    expect(outcome).not.toBe('accepted')
    expect(String(outcome)).toMatch(/sequence gap at event 2/)

    // ROW 3 control: drop the forged event and nothing else. The same device, the same capability,
    // the same registry — and the refusal is the deny set, so the rejection above is the forged
    // tail being refused and not the deny path having stopped working.
    log = [inception, revoke]
    let control: unknown = 'accepted'
    await invoke(delegate, cap).catch((e) => {
      control = e
    })
    console.log('CONTROL without the forged tail:', String(control))
    expect(String(control)).toMatch(/audience is revoked by the subject/)
  })

  test('ROW 4: an unloadable log fails the check CLOSED rather than answering "nobody is revoked"', async () => {
    log = [inception, revokeOf(delegate.id)]
    const cap = await mintFor(delegate.id)
    const broken: MethodRegistry = [createControllerResolver({ loadLog: async () => undefined })]
    let outcome: unknown = 'accepted'
    await checkCapability(
      { act: 'write', res: 'doc/1' },
      { iss: delegate.id, sub: did, cap: [cap] },
      { methods: broken },
    ).catch((e) => {
      outcome = e
    })
    console.log('unloadable log:', outcome === 'accepted' ? 'ACCEPTED' : String(outcome))
    expect(outcome).not.toBe('accepted')
  })

  test('ROW 5 (evasion attempt): peer:4 long/short spelling asymmetry', async () => {
    const device = await randomIdentity()
    const long = device.id
    const short = normalizeDID(long)
    console.log('identity id is the long form:', long !== short)
    console.log('normalizeDID(short) === short:', normalizeDID(short) === short)

    // (a) revoke recorded in the SHORT form, capability audience in the LONG form.
    log = [inception]
    const capLong = await mintFor(long)
    log = [inception, revokeOf(short)]
    let a: unknown = 'accepted'
    await invoke(device, capLong).catch((e) => {
      a = e
    })
    console.log('revoke=short, aud=long ->', a === 'accepted' ? 'ACCEPTED (evasion)' : 'refused')

    // (b) revoke recorded in the LONG form, capability audience in the SHORT form.
    log = [inception]
    const capShort = await mintFor(short)
    log = [inception, revokeOf(long)]
    let b: unknown = 'accepted'
    await invoke(device, capShort).catch((e) => {
      b = e
    })
    console.log(
      'revoke=long,  aud=short ->',
      b === 'accepted' ? 'ACCEPTED (evasion)' : `refused: ${String(b)}`,
    )
    expect(String(a)).toMatch(/audience is revoked/)
  })
})
