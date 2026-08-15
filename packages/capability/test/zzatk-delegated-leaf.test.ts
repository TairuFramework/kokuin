import {
  authorityPath,
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRevokeWithKey,
  deriveKeyPair,
  didFromInception,
  foldLogAsync,
  type SignedEvent,
} from '@kokuin/controller'
import {
  createSigningIdentity,
  type MethodRegistry,
  randomIdentity,
  type SigningIdentity,
  stringifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  audienceConfirmation,
  createCapability,
  createControllerCapabilityVerifier,
  now,
} from '../src/index.js'

// ATTACK: everything real. Real inception, real createCapability, real foldLogAsync, real
// createStateResolver injected by the fold. No stubs anywhere.

const controllerSeed = new Uint8Array(32).fill(3)
const inception = createInception(controllerSeed, 0)
const did = didFromInception(inception.event)
const controller = createControllerIdentity(controllerSeed, 0, [inception])
const inceptionKeyPosition = { gen: 0, seq: 0 }

const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const bystander = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

function identityForSeed(seed: Uint8Array): SigningIdentity {
  return createSigningIdentity(deriveKeyPair(seed, authorityPath(0, 0, 0), 'EdDSA').privateKey)
}

/** Prefix registry: the inception only, so resolving the capability issuer never re-enters the fold. */
const methods: MethodRegistry = [
  createControllerResolver({ loadLog: async (asked) => (asked === did ? [inception] : undefined) }),
]

type Holder = { id: string; publicKey: Uint8Array; privateKey: Uint8Array }

async function mintRoot(holder: Holder, res: string, act = 'revoke'): Promise<string> {
  return stringifyToken(
    await createCapability(
      controller,
      {
        sub: did,
        aud: holder.id,
        act,
        res,
        exp: now() + 3600,
        cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: holder.publicKey }),
      },
      undefined,
      { methods },
    ),
  )
}

async function mintLeaf(
  manager: SigningIdentity,
  holder: Holder,
  root: string,
  act: string,
  res: string,
): Promise<string> {
  return stringifyToken(
    await createCapability(
      manager,
      {
        sub: did,
        aud: holder.id,
        act,
        res,
        exp: now() + 3600,
        cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: holder.publicKey }),
        cap: [root],
      },
      undefined,
      { parentCapability: root, methods },
    ),
  )
}

function foldWith(events: Array<SignedEvent>) {
  return foldLogAsync(did, events, {
    verifyCapability: createControllerCapabilityVerifier({ methods }),
  })
}

describe('ATTACK: the leaf of a delegation chain, presented directly to checkCapability', () => {
  test('A1 — a narrowed leaf does not attenuate: the holder gets the parent grant', async () => {
    const manager = randomIdentity()
    const device = randomIdentity()

    // Root: manager may revoke ANYTHING.
    const root = await mintRoot(manager, '*')
    // Leaf: manager delegates to device the right to revoke `bystander` ONLY.
    const leaf = await mintLeaf(manager, device, root, 'revoke', bystander)

    // The attack: device revokes `target`, which its own capability does not name.
    const attack = createRevokeWithKey(device.privateKey, did, inception.event, target, {
      cap: leaf,
    })
    const attacked = await foldWith([inception, attack])
    console.log(
      'A1 attack (revoke target, leaf grants only bystander):',
      JSON.stringify(
        attacked.ok ? { ok: true, deniedTarget: [...attacked.states[1].deny] } : attacked,
      ),
    )

    // CONTROL A1a — same leaf, same device, revoking what the leaf DOES name. Proves the grant
    // path itself works, so a rejection above would be the attenuation and nothing else.
    const legit = createRevokeWithKey(device.privateKey, did, inception.event, bystander, {
      cap: leaf,
    })
    const legitResult = await foldWith([inception, legit])
    console.log(
      'A1a control (revoke bystander, leaf grants bystander):',
      JSON.stringify(legitResult.ok ? { ok: true } : legitResult),
    )
    expect(legitResult.ok).toBe(true)

    // CONTROL A1b — the parent is narrowed too. Proves the chain check does compare the request
    // against the parent, so the ONLY invalid thing in A1 is the leaf's own narrowing.
    const narrowRoot = await mintRoot(manager, bystander)
    const narrowLeaf = await mintLeaf(manager, device, narrowRoot, 'revoke', bystander)
    const blocked = createRevokeWithKey(device.privateKey, did, inception.event, target, {
      cap: narrowLeaf,
    })
    const blockedResult = await foldWith([inception, blocked])
    console.log('A1b control (parent narrowed too):', JSON.stringify(blockedResult))
    expect(blockedResult.ok).toBe(false)

    // The finding: A1 must be rejected. It is not.
    expect(attacked.ok, 'ATTENUATION BYPASS: leaf act/res ignored').toBe(false)
  })

  test('A2 — a leaf granting a different action still authorises a revoke', async () => {
    const manager = randomIdentity()
    const device = randomIdentity()
    const root = await mintRoot(manager, '*')
    // Leaf grants `read`, not `revoke`. Hand-signed by the manager rather than minted through
    // `createCapability`, because the mint path refuses a *different* action as a delegation — the
    // attacker holds the key and signs whatever it likes. Nothing else differs.
    const leaf = stringifyToken(
      await manager.signToken({
        sub: did,
        aud: device.id,
        act: 'read',
        res: '*',
        exp: now() + 3600,
        cnf: audienceConfirmation({ alg: 'EdDSA', publicKey: device.publicKey }),
        cap: [root],
      }),
    )

    const attack = createRevokeWithKey(device.privateKey, did, inception.event, target, {
      cap: leaf,
    })
    const result = await foldWith([inception, attack])
    console.log('A2 attack (leaf act=read):', JSON.stringify(result.ok ? { ok: true } : result))

    // CONTROL A2a — root granting `read` only: the request really is checked against the parent.
    const readRoot = await mintRoot(manager, '*', 'read')
    const readLeaf = await mintLeaf(manager, device, readRoot, 'read', '*')
    const blocked = createRevokeWithKey(device.privateKey, did, inception.event, target, {
      cap: readLeaf,
    })
    const blockedResult = await foldWith([inception, blocked])
    console.log('A2a control (root act=read):', JSON.stringify(blockedResult))
    expect(blockedResult.ok).toBe(false)

    expect(result.ok, 'ACT WIDENING: leaf act ignored').toBe(false)
  })

  test('A3 — a revoked leaf holder keeps authoring revokes', async () => {
    const manager = randomIdentity()
    const device = randomIdentity()
    const root = await mintRoot(manager, '*')
    const leaf = await mintLeaf(manager, device, root, 'revoke', '*')

    // The profile revokes the DEVICE, at event 1.
    const revokeDevice = createRevoke(
      controllerSeed,
      0,
      did,
      inception.event,
      device.id,
      inceptionKeyPosition,
    )
    const attack = createRevokeWithKey(device.privateKey, did, revokeDevice.event, target, {
      cap: leaf,
    })
    const attacked = await foldWith([inception, revokeDevice, attack])
    console.log(
      'A3 attack (device revoked at 1, authors revoke at 2):',
      JSON.stringify(attacked.ok ? { ok: true, deny: [...attacked.states[2].deny] } : attacked),
    )

    // CONTROL A3a — revoke the MANAGER instead. Its aud is on the chain that IS walked, so this
    // proves the deny-set machinery is live in exactly this fold, with the same capability.
    const revokeManager = createRevoke(
      controllerSeed,
      0,
      did,
      inception.event,
      manager.id,
      inceptionKeyPosition,
    )
    const managerAttack = createRevokeWithKey(device.privateKey, did, revokeManager.event, target, {
      cap: leaf,
    })
    const managerResult = await foldWith([inception, revokeManager, managerAttack])
    console.log('A3a control (manager revoked):', JSON.stringify(managerResult))
    expect(managerResult.ok).toBe(false)

    // CONTROL A3b — nobody revoked: the same event folds.
    const clean = createRevokeWithKey(device.privateKey, did, inception.event, target, {
      cap: leaf,
    })
    const cleanResult = await foldWith([inception, clean])
    console.log(
      'A3b control (nobody revoked):',
      JSON.stringify(cleanResult.ok ? { ok: true } : cleanResult),
    )
    expect(cleanResult.ok).toBe(true)

    expect(attacked.ok, 'DENY BYPASS: revoked leaf audience still authorises').toBe(false)
  })
})
