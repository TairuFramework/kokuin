import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRevokeWithKey,
  didFromInception,
  encodeKey,
  foldLogAsync,
  type SignedEvent,
} from '@kokuin/controller'
import { type MethodRegistry, randomIdentity, stringifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  audienceConfirmation,
  type ConfirmationClaim,
  createCapability,
  createControllerCapabilityVerifier,
  now,
} from '../src/index.js'

// ATTACK on the RFC 7800 `cnf` pin. Real fold, real state resolver, real capabilities.

const seed = new Uint8Array(32).fill(7)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const controller = createControllerIdentity({ seed, profile: 0, log: [inception] })
const inceptionKeyPosition = { gen: 0, seq: 0 }
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

const methods: MethodRegistry = [
  createControllerResolver({ loadLog: async (asked) => (asked === did ? [inception] : undefined) }),
]

async function mint(aud: string, cnf: ConfirmationClaim | undefined): Promise<string> {
  return stringifyToken(
    await createCapability(
      controller,
      { sub: did, aud, act: 'revoke', res: '*', exp: now() + 3600, cnf },
      undefined,
      { methods },
    ),
  )
}

function foldWith(events: Array<SignedEvent>) {
  return foldLogAsync(did, events, {
    verifyCapability: createControllerCapabilityVerifier({ methods }),
  })
}

function revokeOf(who: string): SignedEvent {
  return createRevoke({
    seed,
    profile: 0,
    did,
    prior: inception.event,
    target: who,
    keyPosition: inceptionKeyPosition,
  })
}

describe('ATTACK: the cnf pin', () => {
  test('authority follows `cnf`, revocation follows `aud`, and they need not agree', async () => {
    const nominal = randomIdentity() // the DID named in `aud`
    const holder = randomIdentity() // the key actually pinned in `cnf`

    const cap = await mint(
      nominal.id,
      audienceConfirmation({ alg: 'EdDSA', publicKey: holder.publicKey }),
    )

    // CONTROL E1b — REWRITTEN after the fix (495af73), which removed this control's premise.
    //
    // As written it asserted that a capability pinning a key its `aud` does not carry folds when
    // nobody is revoked — the separation between authority and revocation that E1 goes on to
    // attack. Binding `cnf` to `aud` is exactly the fix, so the mismatch is now refused at every
    // position, revoked or not, and the control can no longer be satisfied alongside the attack.
    // What it now establishes is the same thing at the new boundary: the refusal is caused by the
    // binding and not by the deny set, because nobody is revoked here.
    const clean = createRevokeWithKey({
      privateKey: holder.privateKey,
      did,
      prior: inception.event,
      target,
      cap,
    })
    const cleanResult = await foldWith([inception, clean])
    expect(cleanResult.ok).toBe(false)

    // CONTROL E1a — revoke the DID in `aud`: the deny set bites, proving it is live here.
    const revokeNominal = revokeOf(nominal.id)
    const afterNominal = createRevokeWithKey({
      privateKey: holder.privateKey,
      did,
      prior: revokeNominal.event,
      target,
      cap,
    })
    const nominalResult = await foldWith([inception, revokeNominal, afterNominal])
    expect(nominalResult.ok).toBe(false)

    // ATTACK — revoke the DID of the key that actually wields the capability.
    const revokeHolder = revokeOf(holder.id)
    const attack = createRevokeWithKey({
      privateKey: holder.privateKey,
      did,
      prior: revokeHolder.event,
      target,
      cap,
    })
    const attacked = await foldWith([inception, revokeHolder, attack])

    expect(attacked.ok, 'UNREVOKABLE HOLDER: revoking the pinned key holder does nothing').toBe(
      false,
    )
  })

  test('one mutation at a time on the pin', async () => {
    const device = randomIdentity()
    const good = audienceConfirmation({ alg: 'EdDSA', publicKey: device.publicKey })
    const other = randomIdentity()

    // CONTROL — the unmutated pin folds.
    const okResult = await foldWith([
      inception,
      createRevokeWithKey({
        privateKey: device.privateKey,
        did,
        prior: inception.event,
        target,
        cap: await mint(device.id, good),
      }),
    ])
    expect(okResult.ok).toBe(true)

    const rows: Array<[string, ConfirmationClaim | undefined]> = [
      ['absent cnf', undefined],
      ['empty object', {}],
      ['empty-string kid', { kid: '' }],
      ['numeric kid', { kid: 42 as unknown as string }],
      ['null kid', { kid: null as unknown as string }],
      ['array kid', { kid: [good.kid] as unknown as string }],
      ['bare base58, no multibase prefix', { kid: (good.kid as string).slice(1) }],
      ['fragment form, as a header kid would spell it', { kid: `#${good.kid}` }],
      ['truncated', { kid: (good.kid as string).slice(0, -2) }],
      ['extra character', { kid: `${good.kid}a` }],
      ['an X25519 key', { kid: encodeKey(device.publicKey, 'X25519') }],
      ['jwk instead of kid', { jwk: { kty: 'OKP', crv: 'Ed25519' } }],
      ['jku instead of kid', { jku: 'https://attacker.example/keys' }],
      [
        'another identity’s key',
        audienceConfirmation({ alg: 'EdDSA', publicKey: other.publicKey }),
      ],
    ]

    const results: Array<[string, string]> = []
    for (const [name, cnf] of rows) {
      const cap = await mint(device.id, cnf)
      const result = await foldWith([
        inception,
        createRevokeWithKey({
          privateKey: device.privateKey,
          did,
          prior: inception.event,
          target,
          cap,
        }),
      ])
      results.push([name, result.ok ? 'ACCEPTED' : result.reason])
    }
    for (const [name, outcome] of results) {
      expect(outcome, name).not.toBe('ACCEPTED')
    }
  })
})
