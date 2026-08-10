import {
  authorityPath,
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  deriveKeyPair,
  didFromInception,
  type FoldResult,
  foldLogAsync,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createSigningIdentity,
  type MethodRegistry,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createCapability, createControllerCapabilityVerifier, now } from '../src/index.js'

// Every object on this path is real: a real inception, a real `createCapability`, a real revoke
// event signed by the delegate's own key, folded by the real `foldLogAsync`. A stub
// `verifyCapability` agrees with a broken adapter, which is exactly what this file exists to stop.

const controllerSeed = new Uint8Array(32).fill(3)
const otherControllerSeed = new Uint8Array(32).fill(5)
const delegateSeed = new Uint8Array(32).fill(11)
const outsiderSeed = new Uint8Array(32).fill(13)

/** The device being denied, and one that is not. */
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const bystander = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

/** The authority key the inception establishes lives at gen 0 / seq 0. */
const inceptionKeyPosition = { gen: 0, seq: 0 }

/**
 * A signing identity for a seed, using the same derivation `createRevoke` uses for its signature.
 * That is what makes the delegate's `did:key` and the key that signs the revoke the same key.
 */
function identityForSeed(seed: Uint8Array): SigningIdentity {
  return createSigningIdentity(deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').privateKey)
}

const delegate = identityForSeed(delegateSeed)
const outsider = identityForSeed(outsiderSeed)

type Controller = {
  did: string
  inception: SignedEvent
  identity: SigningIdentity
  seed: Uint8Array
}

function buildController(seed: Uint8Array): Controller {
  const inception = createInception(seed, 0)
  const did = didFromInception(inception.event)
  return { did, inception, identity: createControllerIdentity(seed, 0, [inception]), seed }
}

const controller = buildController(controllerSeed)
const otherController = buildController(otherControllerSeed)

/**
 * A registry resolving both controllers from the state their inception establishes.
 *
 * Deliberately *not* the same `loadLog` the fold is running over. The capability is issued by the
 * controller whose log contains the revoke, so a registry that loaded the full log would resolve
 * the issuer by folding it, which would reach the same capability-authorised revoke and call the
 * verifier again — unbounded recursion. A capability must in any case be checked against the key
 * state at the position *before* the event that carries it, which is what the prefix here is.
 */
const methods: MethodRegistry = [
  createControllerResolver({
    loadLog: async (did) => {
      if (did === controller.did) return [controller.inception]
      if (did === otherController.did) return [otherController.inception]
      return undefined
    },
  }),
]

type CapabilityFields = {
  issuer?: Controller
  sub?: string
  aud?: string
  act?: string | Array<string>
  res?: string | Array<string>
  exp?: number
}

async function mintCapability(fields: CapabilityFields = {}): Promise<string> {
  const issuer = fields.issuer ?? controller
  const capability = await createCapability(issuer.identity, {
    sub: fields.sub ?? issuer.did,
    aud: fields.aud ?? delegate.id,
    act: fields.act ?? 'revoke',
    res: fields.res ?? target,
    exp: fields.exp ?? now() + 3600,
  })
  return stringifyToken(capability)
}

/**
 * Fold `[inception, revoke]` for the controller, with the revoke authorised by `cap` and signed by
 * `signerSeed` — the delegate's seed unless a test is exercising the audience binding.
 */
async function foldWithCapability(
  cap: string,
  options: { signerSeed?: Uint8Array; deny?: string } = {},
): Promise<FoldResult> {
  const revoke = createRevoke(
    options.signerSeed ?? delegateSeed,
    0,
    controller.did,
    controller.inception.event,
    options.deny ?? target,
    inceptionKeyPosition,
    { cap },
  )
  return await foldLogAsync(controller.did, [controller.inception, revoke], {
    verifyCapability: createControllerCapabilityVerifier({ methods }),
  })
}

describe('createControllerCapabilityVerifier()', () => {
  test('a real capability authorises a real revoke through the fold', async () => {
    const result = await foldWithCapability(await mintCapability())

    expect(result.ok).toBe(true)
    if (!result.ok) return
    // The state after the revoke — position 1 — is where the deny takes effect.
    expect(result.states[1].deny.has(target)).toBe(true)
    // Position-dependence: the inception's state never learns about it.
    expect(result.states[0].deny.has(target)).toBe(false)
  })

  test('a wildcard `res` authorises revoking any device — the management capability shape', async () => {
    // The capability a management device actually holds: one grant covering every device, minted
    // before any of them existed. An adapter that only ever matched `res` exactly would pass every
    // other test in this file and fail here.
    const cap = await mintCapability({ res: '*' })

    const first = await foldWithCapability(cap, { deny: target })
    expect(first.ok).toBe(true)
    if (first.ok) expect(first.states[1].deny.has(target)).toBe(true)

    const second = await foldWithCapability(cap, { deny: bystander })
    expect(second.ok).toBe(true)
    if (second.ok) expect(second.states[1].deny.has(bystander)).toBe(true)
  })

  test('a capability whose `res` names a different DID does not authorise the revoke', async () => {
    const result = await foldWithCapability(await mintCapability({ res: bystander }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability whose `res` names the controller does not authorise revoking a device', async () => {
    // `res` is the *target* of the revoke, never its subject. Passing the controller DID as the
    // resource would make this grant — which names no device at all — revoke any device.
    const result = await foldWithCapability(await mintCapability({ res: controller.did }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability minted for a different controller does not authorise this revoke', async () => {
    // Everything else is impeccable: signed by its issuer, unexpired, `act: revoke`, `res` naming
    // exactly this target, audience the delegate that signed the event. The only thing wrong is
    // that it speaks for another profile. Without the `sub === subject` binding, one profile's
    // management capability revokes devices on every other profile.
    const cap = await mintCapability({ issuer: otherController })
    const result = await foldWithCapability(cap)

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })

    // Control: the identical capability, differing only in which controller minted it, folds.
    const sameShape = await mintCapability({ issuer: controller })
    await expect(foldWithCapability(sameShape)).resolves.toMatchObject({ ok: true })
  })

  test('an expired capability does not authorise the revoke', async () => {
    const result = await foldWithCapability(await mintCapability({ exp: now() - 60 }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('a capability whose `aud` is not the revoke signer does not authorise it', async () => {
    // The capability is valid and grants exactly this revoke — to the outsider. The delegate
    // signs the event anyway. The log is public, so the serialized capability inside it is
    // readable by anyone; without binding the audience to the event's signature, every reader of
    // the log could lift a management capability out of it and revoke whatever its `res` covers.
    const cap = await mintCapability({ aud: outsider.id })
    const result = await foldWithCapability(cap, { signerSeed: delegateSeed })

    expect(result).toEqual({
      ok: false,
      reason: 'revoke is not signed by the capability audience',
      index: 1,
    })

    // Control: the same capability, with the event signed by the audience it names, folds.
    await expect(foldWithCapability(cap, { signerSeed: outsiderSeed })).resolves.toMatchObject({
      ok: true,
    })
  })

  test('the verifyToken hook runs on the capability the event names', async () => {
    // Where a revocation check goes. `checkCapability` only runs the hook on the parents of the
    // capability it is given, so an undelegated management capability — the common shape — would
    // never be checked at all if this call site did not run it.
    const cap = await mintCapability()
    const seen: Array<string> = []
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap },
    )
    const events = [controller.inception, revoke]

    const observed = await foldLogAsync(controller.did, events, {
      verifyCapability: createControllerCapabilityVerifier({
        methods,
        verifyToken: (_token, raw) => {
          seen.push(raw)
        },
      }),
    })
    expect(observed.ok).toBe(true)
    expect(seen).toEqual([cap])

    // A hook that throws — a revoked capability — denies the revoke rather than being swallowed
    // somewhere that leaves the log folding.
    const rejected = await foldLogAsync(controller.did, events, {
      verifyCapability: createControllerCapabilityVerifier({
        methods,
        verifyToken: () => {
          throw new Error('revoked')
        },
      }),
    })
    expect(rejected).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })

  test('an audience that itself needs resolving is resolved through the registry', async () => {
    // The audience need not be a `did:key` carrying its own key. Here it is another profile — the
    // shape a delegation between two `did:kokuin:` identities takes — so the audience side of the
    // binding goes through the registry exactly as the issuer side does.
    const cap = await mintCapability({ aud: otherController.did })
    const result = await foldWithCapability(cap, { signerSeed: otherControllerSeed })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
  })

  test('without the method registry the capability cannot be verified at all', async () => {
    // `did:kokuin:` cannot be resolved from the identifier alone, so a verifier built without
    // `methods` can never authorise a revoke — it fails closed rather than accepting one it could
    // not check.
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap: await mintCapability() },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier(),
    })

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })
  })
})
