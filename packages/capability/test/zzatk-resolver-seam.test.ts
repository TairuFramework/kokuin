import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRevokeWithKey,
  didFromInception,
  foldLogAsync,
  type SignedEvent,
} from '@kokuin/controller'
import {
  type DIDMethodResolver,
  type MethodRegistry,
  randomIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  audienceConfirmation,
  createCapability,
  createControllerCapabilityVerifier,
  now,
  REVOKE_NO_POSITION,
} from '../src/index.js'

// ATTACK on the injected-resolver seam. The fold is real; the resolvers under attack are the ones
// a caller supplies.

const seed = new Uint8Array(32).fill(23)
const inception = createInception(seed, 0)
const did = didFromInception(inception.event)
const controller = createControllerIdentity({ seed, profile: 0, log: [inception] })
const inceptionKeyPosition = { gen: 0, seq: 0 }
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function registryFor(log: Array<SignedEvent>): MethodRegistry {
  return [createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) })]
}

const prefixMethods = registryFor([inception])

async function manageCap(holder: { id: string; publicKey: Uint8Array }): Promise<string> {
  return stringifyToken(
    await createCapability(
      controller,
      {
        sub: did,
        aud: holder.id,
        act: 'revoke',
        res: '*',
        exp: now() + 3600,
        cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: holder.publicKey }),
      },
      undefined,
      { methods: prefixMethods },
    ),
  )
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

/** A wrapper of the kind the docs warn about: forwards `resolve`, drops `resolveDenySet`. */
function dropDenySet(inner: DIDMethodResolver): DIDMethodResolver {
  return {
    method: inner.method,
    resolve: (asked, header) => inner.resolve(asked, header),
    // resolveAgreementKey and resolveDenySet deliberately not forwarded.
  }
}

describe('ATTACK: the injected resolver seam', () => {
  test('a caller registry that drops resolveDenySet cannot disable the fold’s own deny set', async () => {
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    const revokeManager = revokeOf(manager.id)
    const attack = createRevokeWithKey({
      privateKey: manager.privateKey,
      did,
      prior: revokeManager.event,
      target,
      cap,
    })
    const log = [inception, revokeManager, attack]

    const wrapped: MethodRegistry = [dropDenySet(registryFor([inception])[0])]
    expect(wrapped[0].resolveDenySet).toBeUndefined()

    const attacked = await foldLogAsync(did, log, {
      verifyCapability: createControllerCapabilityVerifier({ methods: wrapped }),
    })

    // CONTROL — the same wrapper, the same capability, with the manager NOT revoked: the fold
    // accepts, so what fails above is the denial and not the wrapper breaking resolution.
    const clean = createRevokeWithKey({
      privateKey: manager.privateKey,
      did,
      prior: inception.event,
      target,
      cap,
    })
    const cleanResult = await foldLogAsync(did, [inception, clean], {
      verifyCapability: createControllerCapabilityVerifier({ methods: wrapped }),
    })
    expect(cleanResult.ok).toBe(true)
    expect(attacked.ok, 'wrapper disables the fold deny set').toBe(false)
  })

  test('a subjectAtPosition that drops resolveDenySet, handed straight to the verifier', async () => {
    // The fourth argument is the one place the fold cannot police: a third-party fold (kubun,
    // kumiai) builds its own. Wrap the REAL state resolver and drop only `resolveDenySet`.
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    const revokeManager = revokeOf(manager.id)
    const attack = createRevokeWithKey({
      privateKey: manager.privateKey,
      did,
      prior: revokeManager.event,
      target,
      cap,
    })

    let captured: DIDMethodResolver | undefined
    const verify = createControllerCapabilityVerifier({ methods: prefixMethods })
    // Fold once with a pass-through that captures the real resolver the fold builds.
    await foldLogAsync(did, [inception, revokeManager, attack], {
      verifyCapability: async (c, subject, t, atPosition) => {
        captured = atPosition
        return await verify(c, subject, t, atPosition)
      },
    })
    expect(captured).toBeDefined()
    if (captured == null) return

    const full = await verify(cap, did, target, captured)
    const stripped = await verify(cap, did, target, dropDenySet(captured))

    // CONTROL — the same two calls at a position where nobody is revoked: both authorise, so the
    // difference above is the deny set and not the wrapper.
    let cleanPosition: DIDMethodResolver | undefined
    const clean = createRevokeWithKey({
      privateKey: manager.privateKey,
      did,
      prior: inception.event,
      target,
      cap,
    })
    await foldLogAsync(did, [inception, clean], {
      verifyCapability: async (c, subject, t, atPosition) => {
        cleanPosition = atPosition
        return await verify(c, subject, t, atPosition)
      },
    })
    if (cleanPosition == null) return
    const cleanFull = await verify(cap, did, target, cleanPosition)
    const cleanStripped = await verify(cap, did, target, dropDenySet(cleanPosition))
    // REWRITTEN after the fix (c1c0c4f), which removed this control's premise. As written it
    // asserted that a stripped resolver authorises at a clean position, so that the refusal below
    // could be attributed to the deny set rather than to the wrapper. The decided fix makes a
    // position resolver without `resolveDenySet` a refusal at every position — there is nothing to
    // decide from, and the subject arm must not answer "nobody is denied" on its behalf — so the
    // two lines cannot both hold. The attribution is preserved by the row above it: the *real*
    // resolver authorises at this same clean position, so what refuses the stripped one is the
    // missing member and not the position.
    expect(cleanFull.authorised).toBe(true)
    expect(cleanStripped.authorised).toBe(false)

    expect(full.authorised, 'real resolver, revoked manager').toBe(false)
    expect(stripped.authorised, 'FAIL-OPEN: dropped resolveDenySet on the position resolver').toBe(
      false,
    )
  })

  test('a fourth argument that answers for the WRONG DID, or for a later state', async () => {
    const manager = randomIdentity()
    const cap = await manageCap(manager)
    const revokeManager = revokeOf(manager.id)
    const attack = createRevokeWithKey({
      privateKey: manager.privateKey,
      did,
      prior: revokeManager.event,
      target,
      cap,
    })

    // A resolver built from the whole log — a *later* state than the position being verified —
    // supplied where the fold would supply the prefix. It must not make an earlier, legitimate
    // event fail, and it must not make a later, illegitimate one pass.
    let atPosition1: DIDMethodResolver | undefined
    const verify = createControllerCapabilityVerifier({ methods: prefixMethods })
    const clean = createRevokeWithKey({
      privateKey: manager.privateKey,
      did,
      prior: inception.event,
      target,
      cap,
    })
    await foldLogAsync(did, [inception, clean], {
      verifyCapability: async (c, s, t, atPosition) => {
        atPosition1 = atPosition
        return await verify(c, s, t, atPosition)
      },
    })

    const results = {
      'undefined fourth argument': await (
        verify as unknown as (c: string, s: string, t: string) => Promise<unknown>
      )(cap, did, target),
      'null fourth argument': await verify(cap, did, target, null as unknown as DIDMethodResolver),
      'a resolver for another DID': await verify(cap, did, target, {
        method: 'kokuin',
        resolve: async () => {
          throw new Error('Unknown DID')
        },
        resolveDenySet: async () => new Set<string>(),
      }),
      'the legitimate earlier position (control)': atPosition1
        ? await verify(cap, did, target, atPosition1)
        : undefined,
    }

    expect(results['undefined fourth argument']).toEqual({
      authorised: false,
      reason: REVOKE_NO_POSITION,
    })
    expect(results['null fourth argument']).toEqual({
      authorised: false,
      reason: REVOKE_NO_POSITION,
    })
    expect((results['a resolver for another DID'] as { authorised: boolean }).authorised).toBe(
      false,
    )
    expect(
      (results['the legitimate earlier position (control)'] as { authorised: boolean }).authorised,
    ).toBe(true)
    // The log with the revoke of the manager still folds to a rejection.
    const folded = await foldLogAsync(did, [inception, revokeManager, attack], {
      verifyCapability: verify,
    })
    expect(folded.ok).toBe(false)
  })
})
