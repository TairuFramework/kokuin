import {
  authorityPath,
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  deriveKeyPair,
  didFromInception,
  encodeKey,
  type FoldResult,
  foldLogAsync,
  type InceptionEvent,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createSigningIdentity,
  type MethodRegistry,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  audienceConfirmation,
  type ConfirmationClaim,
  createCapability,
  createControllerCapabilityVerifier,
  now,
} from '../src/index.js'

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

/** The public key `createRevoke(seed, …)` signs with — what a capability pins as its audience key. */
function confirmationForSeed(seed: Uint8Array): ConfirmationClaim {
  return audienceConfirmation({
    alg: 'EdDSA',
    publicKey: deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').publicKey,
  })
}

const delegate = identityForSeed(delegateSeed)
const outsider = identityForSeed(outsiderSeed)

type Controller = {
  did: string
  inception: SignedEvent<InceptionEvent>
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
  signer?: SigningIdentity
  sub?: string
  aud?: string
  act?: string | Array<string>
  res?: string | Array<string>
  exp?: number
  /** Explicit `undefined` mints a capability with no pin at all — not the same as omitting it. */
  cnf?: ConfirmationClaim | undefined
  /** The parent chain carried in the payload, which is where `checkCapability` walks it from. */
  cap?: Array<string>
  parentCapability?: string
}

async function mintCapability(fields: CapabilityFields = {}): Promise<string> {
  const issuer = fields.issuer ?? controller
  const capability = await createCapability(
    fields.signer ?? issuer.identity,
    {
      sub: fields.sub ?? issuer.did,
      aud: fields.aud ?? delegate.id,
      act: fields.act ?? 'revoke',
      res: fields.res ?? target,
      exp: fields.exp ?? now() + 3600,
      cnf: 'cnf' in fields ? fields.cnf : confirmationForSeed(delegateSeed),
      cap: fields.cap,
    },
    undefined,
    { parentCapability: fields.parentCapability, methods },
  )
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

  test('a capability whose audience is not the revoke signer does not authorise it', async () => {
    // The capability is valid and grants exactly this revoke — to the outsider. The delegate
    // signs the event anyway. The log is public, so the serialized capability inside it is
    // readable by anyone; without binding the audience to the event's signature, every reader of
    // the log could lift a management capability out of it and revoke whatever its `res` covers.
    const cap = await mintCapability({
      aud: outsider.id,
      cnf: confirmationForSeed(outsiderSeed),
    })
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

  test('a capability granting a different action does not authorise a revoke', async () => {
    // The `act` half of the convention. A narrow grant over the very same device — read it, do not
    // revoke it — must not deny it. An adapter that asked for whatever action the capability
    // happened to grant, rather than for `revoke`, would accept this.
    const result = await foldWithCapability(await mintCapability({ act: 'read' }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability does not authorise this revoke',
      index: 1,
    })

    // Control: the identical capability differing only in `act` folds, so the rejection is the
    // action and not the resource, the audience or the pin.
    await expect(
      foldWithCapability(await mintCapability({ act: 'revoke' })),
    ).resolves.toMatchObject({ ok: true })
  })

  test('a capability pinning no audience key is rejected, and says so', async () => {
    // Mandatory on this path, and never filled in by resolving the audience — that fallback is the
    // bug the pin exists to remove. Its own reason, because a sound grant with a missing pin is a
    // minting fault, not a rejected delegation.
    const result = await foldWithCapability(await mintCapability({ cnf: undefined }))

    expect(result).toEqual({
      ok: false,
      reason: 'capability pins no audience key',
      index: 1,
    })
  })

  test('a capability whose pinned key is unreadable is rejected as a missing pin', async () => {
    const result = await foldWithCapability(
      await mintCapability({ cnf: { kid: 'not-a-multibase-key' } }),
    )

    expect(result).toEqual({
      ok: false,
      reason: 'capability pins no audience key',
      index: 1,
    })
  })

  test('a pinned key that did not sign the revoke fails differently from an absent pin', async () => {
    // Two failure modes that must stay apart: nothing was pinned, versus something was pinned and
    // somebody else signed. The `aud` claim here still names the delegate — only the pin moves —
    // so this also shows the binding is to the pinned key rather than to the `aud` string.
    const result = await foldWithCapability(
      await mintCapability({ cnf: confirmationForSeed(outsiderSeed) }),
    )

    expect(result).toEqual({
      ok: false,
      reason: 'revoke is not signed by the capability audience',
      index: 1,
    })
  })

  test('a delegated capability authorises the revoke, and the hook sees every link', async () => {
    // Two levels — controller → manager → delegate — so `checkCapability`'s delegation branch runs
    // rather than its self-issued one, and the pin on the leaf is what the fold checks.
    const manager = identityForSeed(new Uint8Array(32).fill(17))
    const root = await mintCapability({
      aud: manager.id,
      res: '*',
      cnf: confirmationForSeed(new Uint8Array(32).fill(17)),
    })
    const leaf = await mintCapability({
      signer: manager,
      sub: controller.did,
      aud: delegate.id,
      res: target,
      parentCapability: root,
      cap: [root],
    })

    const seen: Array<string> = []
    const revoke = createRevoke(
      delegateSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap: leaf },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier({
        methods,
        verifyToken: (_token, raw) => {
          seen.push(raw)
        },
      }),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
    // The adapter supplies the leaf, `checkCapability` supplies the root — no link unchecked, and
    // no double invocation on the leaf.
    expect(seen).toEqual([leaf, root])
  })

  test('the audience rotating its own key does not stop the revoke verifying', async () => {
    // The pin's whole purpose. The audience is another profile, which rotates — a routine action
    // by someone who is not the profile owner. Resolving the audience at verification time would
    // make this revoke stop verifying, and a revoke that stops verifying makes the log unfoldable
    // and this controller's DID permanently unresolvable.
    const rotated = createRotate(
      otherControllerSeed,
      0,
      otherController.did,
      otherController.inception.event,
    )
    const rotatingMethods: MethodRegistry = [
      createControllerResolver({
        loadLog: async (did) => {
          if (did === controller.did) return [controller.inception]
          if (did === otherController.did) return [otherController.inception, rotated]
          return undefined
        },
      }),
    ]

    const cap = await mintCapability({
      aud: otherController.did,
      cnf: confirmationForSeed(otherControllerSeed),
    })
    const revoke = createRevoke(
      otherControllerSeed,
      0,
      controller.did,
      controller.inception.event,
      target,
      inceptionKeyPosition,
      { cap },
    )
    const result = await foldLogAsync(controller.did, [controller.inception, revoke], {
      verifyCapability: createControllerCapabilityVerifier({ methods: rotatingMethods }),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.states[1].deny.has(target)).toBe(true)
    // The rotation really happened: the audience profile no longer publishes the pinned key.
    expect(rotated.event.k[0]).not.toBe(otherController.inception.event.k[0])
  })

  test('the pinned key is encoded exactly as a controller log encodes the keys in `k`', async () => {
    // One format, two implementations — the packages cannot share code without a cycle. A drift
    // here would only surface as a signature that mysteriously does not match. This is also what
    // makes `cnf.kid` honest as a key *identifier* rather than a reference needing resolution: the
    // string is the same one the log publishes for that key.
    const { publicKey } = deriveKeyPair(delegateSeed, authorityPath(0, 0, 0), 'EdDSA')
    expect(audienceConfirmation({ alg: 'EdDSA', publicKey })).toEqual({
      kid: encodeKey(publicKey, 'EdDSA'),
    })
  })

  test('a confirmation claim with no member this understands is rejected as a missing pin', async () => {
    // RFC 7800 allows `jwk`, `jwe` and `jku` alongside `kid`. None is understood here: `jwk` would
    // be a second encoding of a key this stack already encodes, and `jwe`/`jku` are references to
    // resolve, which is the thing the pin exists to stop. All fail closed, and as a *missing* pin
    // rather than as a rejected delegation.
    // Every RFC 7800 member below type-checks against `ConfirmationClaim` without a cast, which is
    // the point of leaving it open — carrying a `jwk` alongside is a typing question, not a fight
    // with excess-property checking. Only the non-string `kid` needs one, because the type is
    // right to reject it.
    const claims: Array<ConfirmationClaim> = [
      {},
      { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } },
      { jku: 'https://example.com/keys' },
      { kid: 42 } as unknown as ConfirmationClaim,
      { kid: confirmationForSeed(delegateSeed).kid?.slice(0, 12) },
      // The delegate's real key, correctly encoded, under the wrong member. Only `kid` is read,
      // so this authorises nothing — an implementation scanning `cnf` for any usable string would
      // accept it and quietly widen the claim to members it does not implement.
      { jwk: confirmationForSeed(delegateSeed).kid },
    ]

    for (const cnf of claims) {
      const result = await foldWithCapability(await mintCapability({ cnf }))
      expect(result).toEqual({
        ok: false,
        reason: 'capability pins no audience key',
        index: 1,
      })
    }

    // Control: the same shape with a readable `kid` folds, so the rejections above are the claim
    // and not the surrounding capability.
    await expect(foldWithCapability(await mintCapability())).resolves.toMatchObject({ ok: true })
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
