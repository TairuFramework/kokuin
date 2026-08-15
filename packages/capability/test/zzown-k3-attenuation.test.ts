import { randomIdentity, stringifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { checkCapability, createCapability } from '../src/index.js'

describe('attenuation at the last hop (independent reproduction)', () => {
  test('a narrowed sub-capability cannot wield the parent wildcard grant', async () => {
    const profile = await randomIdentity()
    const manager = await randomIdentity()
    const device = await randomIdentity()

    // The profile grants the manager everything.
    const parent = await createCapability(profile, {
      sub: profile.id,
      aud: manager.id,
      act: '*',
      res: '*',
    })
    const parentRaw = stringifyToken(parent)

    // The manager delegates a DELIBERATELY NARROW capability to the device: read one document.
    const narrow = await createCapability(
      manager,
      { sub: profile.id, aud: device.id, act: 'read', res: 'doc:A', cap: parentRaw },
      undefined,
      { parentCapability: parentRaw },
    )

    // The device presents its narrow capability and asks to revoke someone.
    let refused: string | undefined
    try {
      await checkCapability({ act: 'revoke', res: 'did:kokuin:zVictim' }, narrow.payload as never)
    } catch (err) {
      refused = (err as Error).message
    }

    // Control: the same capability used for what it actually grants must still work.
    let allowed = true
    try {
      await checkCapability({ act: 'read', res: 'doc:A' }, narrow.payload as never)
    } catch {
      allowed = false
    }

    expect(refused).toBeDefined()
    expect(allowed).toBe(true)
  })
})
