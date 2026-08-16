import { describe, expect, test } from 'vitest'

import { digestOf } from '../src/canonical.js'
import { agreementPath, authorityPath, deriveKeyPair, recoveryPath } from '../src/derivation.js'
import {
  didFromInception,
  type InceptionEvent,
  type SignedEvent,
  signEvent,
} from '../src/events.js'
import { foldLog } from '../src/fold.js'
import { encodeKey } from '../src/keys.js'

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

// CLOSED. `kt` and `nt` are now checked against what the fold actually enforces — n-of-n, since
// `verifySignatures` demands one valid signature per published key and `verifyRotate` demands every
// committed key be revealed and sign. So `kt` must equal `k.length` and `nt` must equal `n.length`,
// and anything else is a malformed event rather than a policy nobody honours. Constructions below
// are byte-for-byte what they were; ROW 2 and ROW 3 asserted the old acceptance and now assert the
// rejection, and ROW 2 gains the control that a *truthful* threshold on the same body still folds.
describe('ATTACK: are the published `kt` / `nt` thresholds enforced at all?', () => {
  test('ROW 1: a 2-key set declaring `kt: 1` still demands BOTH signatures (fail-closed)', () => {
    const { signed, did } = twoKeyInception(1, 1, 'first')
    const r = foldLog(did, [signed])
    expect(r.ok).toBe(false)
  })

  test('ROW 2 (closed): both signatures are not enough — `kt: 1` over 2 keys is a lie', () => {
    const { signed, did } = twoKeyInception(1, 1, 'both')
    const r = foldLog(did, [signed])
    expect(r).toEqual({ ok: false, reason: 'invalid inception', index: 0 })

    // ROW 2 control: the identical body with the truthful thresholds, signed the same way. It
    // folds — so what ROW 1 and ROW 2 reject is the declaration, not the two-key shape.
    const truthful = twoKeyInception(2, 2, 'both')
    const ok = foldLog(truthful.did, [truthful.signed])
    expect(ok.ok).toBe(true)
    if (!ok.ok) return
    expect(ok.states[0].keys.length).toBe(2)
  })

  test('ROW 3 (closed): every impossible threshold is now a malformed event', () => {
    for (const [kt, nt] of [
      [99, 99],
      [0, 0],
      [-5, -5],
      ['banana', 'banana'],
      [null, null],
    ] as Array<[unknown, unknown]>) {
      const { signed, did } = twoKeyInception(kt, nt, 'both')
      const r = foldLog(did, [signed])
      expect(r).toEqual({ ok: false, reason: 'invalid inception', index: 0 })
    }
    // ROW 3 control: an absent member is refused too — the check is `===` against the set size, so
    // `undefined` is not quietly coerced, and neither is the string `"2"`.
    for (const kt of [undefined, '2'] as Array<unknown>) {
      const { signed, did } = twoKeyInception(kt, 2, 'both')
      const r = foldLog(did, [signed])
      expect(r.ok).toBe(false)
    }
  })

  test('ROW 4 (control: the fold DOES read `k`): a tampered key set is rejected', () => {
    const { signed, did } = twoKeyInception(1, 1, 'both')
    const tampered: SignedEvent<InceptionEvent> = {
      ...signed,
      event: { ...signed.event, k: [signed.event.k[0]] },
    }
    const r = foldLog(did, [tampered])
    expect(r.ok).toBe(false)
  })
})
