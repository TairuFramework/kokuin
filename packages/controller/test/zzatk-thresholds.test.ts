import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  didFromInception,
  encodeKey,
  type InceptionEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'

const seedA = new Uint8Array(32).fill(1)
const seedB = new Uint8Array(32).fill(23)

/**
 * A hand-built inception publishing two authority keys, with `kt`/`nt` under test. An inception is
 * self-certifying, so any body an attacker (or an implementer) writes is a valid log for the DID it
 * hashes to — which is exactly why the published thresholds have to mean something.
 */
function twoKeyInception(kt: unknown, nt: unknown, signers: 'both' | 'first') {
  const a = deriveKeyPair(seedA, authorityPath(0, 0, 0), 'EdDSA')
  const aNext = deriveKeyPair(seedA, authorityPath(0, 0, 1), 'EdDSA')
  const b = deriveKeyPair(seedB, authorityPath(0, 0, 0), 'EdDSA')
  const bNext = deriveKeyPair(seedB, authorityPath(0, 0, 1), 'EdDSA')
  const agreement = deriveKeyPair(seedA, agreementPath(0, 0, 0), 'X25519')
  const recovery = deriveKeyPair(seedA, recoveryPath(0), 'EdDSA')

  const event = {
    v: 1,
    t: 'icp',
    g: 0,
    s: 0,
    crit: true,
    k: [encodeKey(a.publicKey, 'EdDSA'), encodeKey(b.publicKey, 'EdDSA')],
    ka: [encodeKey(agreement.publicKey, 'X25519')],
    n: [
      digestOf(encodeKey(aNext.publicKey, 'EdDSA')),
      digestOf(encodeKey(bNext.publicKey, 'EdDSA')),
    ],
    kt,
    nt,
    r: digestOf(encodeKey(recovery.publicKey, 'EdDSA')),
  } as unknown as InceptionEvent

  const keys = signers === 'both' ? [a.privateKey, b.privateKey] : [a.privateKey]
  const signed: SignedEvent<InceptionEvent> = { event, sigs: signEvent(event, keys) }
  return { signed, did: didFromInception(event) }
}

describe('ATTACK: are the published `kt` / `nt` thresholds enforced at all?', () => {
  test('ROW 1: a 2-key set declaring `kt: 1` still demands BOTH signatures (fail-closed)', () => {
    const { signed, did } = twoKeyInception(1, 1, 'first')
    const r = foldLog(did, [signed])
    console.log('kt:1, 2 keys, 1 signature ->', r.ok ? 'ACCEPTED' : `rejected: ${r.reason}`)
    expect(r.ok).toBe(false)
  })

  test('ROW 2 (control): the identical body with both signatures folds', () => {
    const { signed, did } = twoKeyInception(1, 1, 'both')
    const r = foldLog(did, [signed])
    console.log('kt:1, 2 keys, 2 signatures ->', r.ok ? 'ACCEPTED' : `rejected: ${r.reason}`)
    expect(r.ok).toBe(true)
  })

  test('ROW 3: `kt` is never read — an impossible threshold folds cleanly', () => {
    for (const [kt, nt] of [
      [99, 99],
      [0, 0],
      [-5, -5],
      ['banana', 'banana'],
      [null, null],
    ] as Array<[unknown, unknown]>) {
      const { signed, did } = twoKeyInception(kt, nt, 'both')
      const r = foldLog(did, [signed])
      console.log(
        `kt=${JSON.stringify(kt)} nt=${JSON.stringify(nt)} ->`,
        r.ok ? 'ACCEPTED' : `rejected: ${r.reason}`,
      )
      expect(r.ok).toBe(true)
      if (!r.ok) return
      console.log('  folded keys:', r.states[0].keys.length, '| effective policy: all-of-n')
    }
  })

  test('ROW 4 (control: the fold DOES read `k`): a tampered key set is rejected', () => {
    const { signed, did } = twoKeyInception(1, 1, 'both')
    const tampered: SignedEvent<InceptionEvent> = {
      ...signed,
      event: { ...signed.event, k: [signed.event.k[0]] },
    }
    const r = foldLog(did, [tampered])
    console.log('one key removed ->', r.ok ? 'ACCEPTED' : `rejected: ${r.reason}`)
    expect(r.ok).toBe(false)
  })
})
