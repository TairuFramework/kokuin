import { randomIdentity, type SigningIdentity, stringifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  checkCapability,
  createCapability,
  DEFAULT_MAX_DELEGATION_DEPTH,
  hasPermission,
  now,
} from '../src/index.js'

// ATTACK on the plain capability chain — no controller, no method registry: `did:key` only, so
// nothing here depends on the fold. This is the surface every downstream consumer calls.

const at = <T>(items: ReadonlyArray<T>, i: number): T => {
  const v = items[i]
  if (v === undefined) throw new Error(`expected element at ${i}`)
  return v
}

const decodePayload = (raw: string): Record<string, unknown> => {
  const part = raw.split('.')[1]
  if (part === undefined) throw new Error('expected JWT payload')
  return JSON.parse(Buffer.from(part, 'base64url').toString()) as Record<string, unknown>
}

const root = randomIdentity()

async function delegate(
  from: SigningIdentity,
  to: SigningIdentity,
  fields: { act?: string; res?: string; exp?: number; parent?: string },
): Promise<string> {
  const token = await createCapability(
    from,
    {
      sub: root.id,
      aud: to.id,
      act: fields.act ?? 'write',
      res: fields.res ?? '*',
      exp: fields.exp,
      cap: fields.parent == null ? undefined : [fields.parent],
    },
    undefined,
    { parentCapability: fields.parent },
  )
  return stringifyToken(token)
}

describe('ATTACK: a delegated capability presented directly to checkCapability', () => {
  test('the presented capability’s own act/res are enforced, not just its parent’s', async () => {
    const manager = randomIdentity()
    const device = randomIdentity()

    // root → manager: everything. manager → device: `write doc/1` only.
    const parent = await delegate(root, manager, { act: 'write', res: '*', exp: now() + 3600 })
    const leafRaw = await delegate(manager, device, {
      act: 'write',
      res: 'doc/1',
      exp: now() + 3600,
      parent,
    })
    const leaf = decodePayload(leafRaw)

    // ATTACK: ask for a resource the presented capability does not name.
    let outcome = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/999' }, leaf as never)
    } catch (error) {
      outcome = (error as Error).message
    }

    // CONTROL Ia — the same call for what the leaf DOES grant.
    let control = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, leaf as never)
    } catch (error) {
      control = (error as Error).message
    }
    expect(control).toBe('ACCEPTED')

    // CONTROL Ib — a request the PARENT does not grant is refused, so the chain check is live.
    let beyondParent = 'ACCEPTED'
    try {
      await checkCapability({ act: 'delete', res: 'doc/1' }, leaf as never)
    } catch (error) {
      beyondParent = (error as Error).message
    }
    expect(beyondParent).not.toBe('ACCEPTED')

    expect(outcome, 'ATTENUATION BYPASS on the plain API').not.toBe('ACCEPTED')
  })

  test('the presented capability’s own exp and iat are enforced', async () => {
    const manager = randomIdentity()
    const device = randomIdentity()
    // Both minted valid now; the check runs at `later`, by which time the leaf has expired and
    // the parent has not. Minting an already-expired leaf is impossible — `createCapability`
    // verifies the parent, and a token minted in the past cannot be produced here — so the
    // expiry is moved by the reference time instead. One variable.
    const later = now() + 1800
    const parent = await delegate(root, manager, { act: 'write', res: '*', exp: now() + 3600 })

    const expiredRaw = await delegate(manager, device, {
      act: 'write',
      res: '*',
      exp: now() + 60, // expired by the time `later` comes round
      parent,
    })
    const expired = decodePayload(expiredRaw)

    let outcome = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, expired as never, { atTime: later })
    } catch (error) {
      outcome = (error as Error).message
    }

    // CONTROL — the PARENT is the one that has expired at `later`, the leaf has not. Refused, so
    // expiry is enforced on this exact path and the only difference is which link expired.
    const shortParent = await delegate(root, manager, { act: 'write', res: '*', exp: now() + 60 })
    const childRaw = await delegate(manager, device, {
      act: 'write',
      res: '*',
      exp: now() + 3600,
      parent: shortParent,
    })
    const child = decodePayload(childRaw)
    let control = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, child as never, { atTime: later })
    } catch (error) {
      control = (error as Error).message
    }
    expect(control).not.toBe('ACCEPTED')

    expect(outcome, 'EXPIRY EVASION on the presented capability').not.toBe('ACCEPTED')
  })
})

describe('ATTACK: the depth cap', () => {
  test('the default admits no more than DEFAULT_MAX_DELEGATION_DEPTH links', async () => {
    const holders = [root]
    const chain: Array<string> = []
    for (let i = 0; i < 8; i++) {
      const next = randomIdentity()
      chain.unshift(
        await delegate(at(holders, i), next, {
          act: 'write',
          res: '*',
          exp: now() + 3600,
          parent: chain[0],
        }),
      )
      holders.push(next)
    }

    const results: Array<[number, string]> = []
    for (let links = 1; links <= 8; links++) {
      const used = chain.slice(chain.length - links) // the first `links` capabilities, leaf first
      const invocation = {
        iss: at(holders, links).id,
        sub: root.id,
        cap: used,
      }
      let outcome = 'ACCEPTED'
      try {
        await checkCapability({ act: 'write', res: 'doc/1' }, invocation as never)
      } catch (error) {
        outcome = (error as Error).message
      }
      results.push([links, outcome])
    }
    const accepted = results.filter(([, outcome]) => outcome === 'ACCEPTED').map(([n]) => n)
    expect(Math.max(...accepted)).toBeLessThanOrEqual(DEFAULT_MAX_DELEGATION_DEPTH)
  })
})

describe('ATTACK: a capability with no expiry at all', () => {
  test('a capability with no exp verifies arbitrarily far in the future, by decision', async () => {
    const device = randomIdentity()
    const eternal = await delegate(root, device, { act: 'write', res: '*' })
    const invocation = { iss: device.id, sub: root.id, cap: [eternal] }
    const farFuture = now() + 100 * 365 * 24 * 3600

    let outcome = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, invocation as never, {
        atTime: farFuture,
      })
    } catch (error) {
      outcome = (error as Error).message
    }
    // CONTROL — the same capability with an expiry is refused at the same instant.
    const bounded = await delegate(root, device, { act: 'write', res: '*', exp: now() + 3600 })
    let control = 'ACCEPTED'
    try {
      await checkCapability(
        { act: 'write', res: 'doc/1' },
        { iss: device.id, sub: root.id, cap: [bounded] } as never,
        {
          atTime: farFuture,
        },
      )
    } catch (error) {
      control = (error as Error).message
    }
    expect(control).not.toBe('ACCEPTED')
    // A recorded design decision, not an open hole: `exp` is optional, and expiry is mandated at the
    // *policy* layer (`assertDeviceCapabilityPolicy`, `DEFAULT_MAX_DEVICE_LIFETIME_SECONDS`), which is
    // opt-in and which `createControllerCapabilityVerifier` does not apply. Asserting the current
    // behaviour keeps this as a tripwire: if a change makes an unbounded capability start expiring,
    // this fails and the decision is revisited deliberately. Whether the controller-revoke path should
    // mandate a bounded lifetime — a migration, since an already-issued capability without `exp` would
    // stop authorising — is tracked in
    // `docs/agents/plans/next/2026-08-15-log-completeness-and-capability-lifetime.md`.
    expect(outcome, 'a capability with no exp is eternal, by decision').toBe('ACCEPTED')
  })
})

describe('ATTACK: the permission matcher itself', () => {
  test('a grant does not match a request at a different depth in either direction', async () => {
    // No implicit descent: a grant of `a` does not cover `a/b`. And no ascent: a grant deeper than
    // the request (`a/b`) does not cover the broader `a` — the privilege-escalation direction.
    expect(hasPermission({ act: 'x', res: 'a/b' }, { act: 'x', res: 'a' })).toBe(false)
    expect(hasPermission({ act: 'x', res: 'a' }, { act: 'x', res: 'a/b' })).toBe(false)
  })
})

describe('ATTACK: nbf and iat on the presented capability', () => {
  test('a not-yet-valid, future-issued presented capability is rejected', async () => {
    const manager = randomIdentity()
    const device = randomIdentity()
    const parent = await delegate(root, manager, { act: 'write', res: '*', exp: now() + 3600 })
    const future = now() + 86400

    // Hand-signed by the manager so the mint path cannot normalise the claims away. The only
    // thing wrong with it is the time claim under test.
    const leaf = await manager.signToken({
      sub: root.id,
      aud: device.id,
      act: 'write',
      res: '*',
      exp: now() + 3600,
      nbf: future,
      iat: future,
      cap: [parent],
    })

    let outcome = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, leaf.payload as never)
    } catch (error) {
      outcome = (error as Error).message
    }

    // CONTROL — the same two claims on the PARENT instead: refused, so both are enforced on this
    // path and the only difference is which link carries them.
    const badParent = await root.signToken({
      sub: root.id,
      aud: manager.id,
      act: 'write',
      res: '*',
      exp: now() + 3600,
      nbf: future,
      iat: future,
    })
    const childOfBad = await manager.signToken({
      sub: root.id,
      aud: device.id,
      act: 'write',
      res: '*',
      exp: now() + 3600,
      cap: [stringifyToken(badParent)],
    })
    let control = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, childOfBad.payload as never)
    } catch (error) {
      control = (error as Error).message
    }
    expect(control).not.toBe('ACCEPTED')
    expect(outcome, 'nbf/iat evasion on the presented capability').not.toBe('ACCEPTED')
  })
})
