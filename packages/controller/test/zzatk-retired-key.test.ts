import { createSigningIdentityForDID, stringifyToken, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { authorityPath, deriveKeyPair } from '../src/derivation.js'
import {
  createInception,
  createReset,
  createRotate,
  didFromInception,
  encodeKey,
  type SignedEvent,
} from '../src/events.js'
import { createControllerResolver } from '../src/resolver.js'

const seed = new Uint8Array(32).fill(1)
const strangerSeed = new Uint8Array(32).fill(88)

function registry(log: Array<SignedEvent>, did: string) {
  return [createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) })]
}

/**
 * Mint a *fresh* token now, signed with the key at `(gen, seq)`, naming that key in `kid`. This is
 * what a thief holding a stolen authority key does after the owner has rotated away from it.
 */
async function mintWithKeyAt(did: string, gen: number, seq: number, keySeed = seed) {
  const pair = deriveKeyPair(keySeed, authorityPath(0, gen, seq), 'EdDSA')
  const identity = createSigningIdentityForDID(did as never, pair.privateKey)
  const token = await identity.signToken(
    { hello: 'world' },
    { header: { kid: `#${encodeKey(pair.publicKey, 'EdDSA')}` } },
  )
  return stringifyToken(token)
}

// CLOSED. `resolve` now answers from the head's `k` alone and the whole-generation scan moved to
// `resolveHistoric`, reached only by `verifyToken({ historic: true })`. Every attack construction
// below is byte-for-byte what it was; the assertions are the ones that changed, from "the attack
// succeeds" to "the attack is refused". ROW 5 is new and shows the historic opt-in still accepting
// the same token, which is what keeps an already-issued capability verifiable across a rotate.
describe('ATTACK: does a rotate retire a compromised signing key?', () => {
  test('ROW 1 (closed): after two rotations, the ORIGINAL key mints nothing that verifies', async () => {
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rot1 = createRotate(seed, 0, did, icp.event)
    const rot2 = createRotate(seed, 0, did, rot1.event, { keyPosition: { gen: 0, seq: 1 } })
    const log = [icp, rot1, rot2]

    // The stolen key is the inception's — (gen 0, seq 0) — two rotations behind the head.
    const stolen = await mintWithKeyAt(did, 0, 0)
    let error: unknown
    const verified = await verifyToken(stolen, { methods: registry(log, did) }).catch((e) => {
      error = e
      return undefined
    })
    console.log('log head keySeq is 2; token signed with keySeq 0')
    console.log('verifyToken accepted the retired key:', verified?.payload.hello === 'world')
    console.log('refused with:', error instanceof Error ? error.message : error)
    expect(verified).toBeUndefined()
    expect((error as Error).message).toMatch(/kid names a key that is not current/)

    // ROW 1 control: the head's own key still mints a token that verifies against the same log and
    // the same registry, so the refusal above is the retirement and not the fixture.
    const live = await mintWithKeyAt(did, 0, 2)
    const ok = await verifyToken(live, { methods: registry(log, did) })
    console.log('CONTROL head key accepted:', ok.payload.hello === 'world')
    expect(ok.payload.hello).toBe('world')
  })

  test('ROW 2 (control): a `kid` the profile NEVER published is refused', async () => {
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rot1 = createRotate(seed, 0, did, icp.event)
    const log = [icp, rot1]
    const stranger = await mintWithKeyAt(did, 0, 0, strangerSeed)
    let error: unknown
    await verifyToken(stranger, { methods: registry(log, did) }).catch((e) => {
      error = e
    })
    console.log('stranger key refused with:', error instanceof Error ? error.message : error)
    expect(error).toBeInstanceOf(Error)
  })

  test('ROW 3 (control): after a RESET the same retired key is refused', async () => {
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rot1 = createRotate(seed, 0, did, icp.event)
    const reset = createReset(seed, 0, 1)
    const stolen = await mintWithKeyAt(did, 0, 0)

    const before = await verifyToken(stolen, {
      methods: registry([icp, rot1], did),
      historic: true,
    })
    console.log('before the reset, accepted historically:', before.payload.hello === 'world')

    let error: unknown
    await verifyToken(stolen, {
      methods: registry([icp, rot1, reset], did),
      historic: true,
    }).catch((e) => {
      error = e
    })
    console.log('after the reset, refused with:', error instanceof Error ? error.message : error)
    expect(error).toBeInstanceOf(Error)
  })

  test('ROW 4 (closed): a rotate carrying an empty deny snapshot retires the key too', async () => {
    // Nothing about the deny set touches the profile's own retired authority keys — the deny set
    // names *audiences*, and the fold carries every past key set forward inside the generation.
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rot1 = createRotate(seed, 0, did, icp.event, { deny: [] })
    const stolen = await mintWithKeyAt(did, 0, 0)
    let error: unknown
    const verified = await verifyToken(stolen, { methods: registry([icp, rot1], did) }).catch(
      (e) => {
        error = e
        return undefined
      },
    )
    console.log('a deny-snapshot rotate retires the key as well:', verified === undefined)
    console.log('refused with:', error instanceof Error ? error.message : error)
    expect(verified).toBeUndefined()
    expect((error as Error).message).toMatch(/kid names a key that is not current/)
  })

  test('ROW 5 (the other half): the same token still verifies under the historic opt-in', async () => {
    // What the split preserves. A capability or revocation record this profile issued before the
    // rotate must not stop verifying because of routine key hygiene — the caller verifying such an
    // artefact says so, and gets the whole current generation.
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rot1 = createRotate(seed, 0, did, icp.event)
    const rot2 = createRotate(seed, 0, did, rot1.event, { keyPosition: { gen: 0, seq: 1 } })
    const log = [icp, rot1, rot2]

    const issued = await mintWithKeyAt(did, 0, 0)
    const verified = await verifyToken(issued, { methods: registry(log, did), historic: true })
    console.log(
      'historic opt-in accepted the rotated-away key:',
      verified.payload.hello === 'world',
    )
    expect(verified.payload.hello).toBe('world')

    // Control: a key the profile NEVER published is still refused under the opt-in, so `historic`
    // widens the answer to this generation and no further.
    const stranger = await mintWithKeyAt(did, 0, 0, strangerSeed)
    let error: unknown
    await verifyToken(stranger, { methods: registry(log, did), historic: true }).catch((e) => {
      error = e
    })
    console.log(
      'CONTROL stranger key under historic:',
      error instanceof Error ? error.message : error,
    )
    expect(error).toBeInstanceOf(Error)
  })
})
