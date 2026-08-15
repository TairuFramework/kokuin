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

const root = randomIdentity()

type Link = { raw: string; holder: SigningIdentity }

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
  test('I1 — the presented capability’s own act/res are never checked', async () => {
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
    const leaf = JSON.parse(Buffer.from(leafRaw.split('.')[1], 'base64url').toString()) as Record<
      string,
      unknown
    >

    // ATTACK: ask for a resource the presented capability does not name.
    let outcome = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/999' }, leaf as never)
    } catch (error) {
      outcome = (error as Error).message
    }
    console.log('I1 attack (leaf grants doc/1, request doc/999):', outcome)

    // CONTROL Ia — the same call for what the leaf DOES grant.
    let control = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, leaf as never)
    } catch (error) {
      control = (error as Error).message
    }
    console.log('I1a control (request doc/1):', control)
    expect(control).toBe('ACCEPTED')

    // CONTROL Ib — a request the PARENT does not grant is refused, so the chain check is live.
    let beyondParent = 'ACCEPTED'
    try {
      await checkCapability({ act: 'delete', res: 'doc/1' }, leaf as never)
    } catch (error) {
      beyondParent = (error as Error).message
    }
    console.log('I1b control (act the parent never granted):', beyondParent)
    expect(beyondParent).not.toBe('ACCEPTED')

    expect(outcome, 'ATTENUATION BYPASS on the plain API').not.toBe('ACCEPTED')
  })

  test('I2 — the presented capability’s own exp and iat are never checked', async () => {
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
    const expired = JSON.parse(
      Buffer.from(expiredRaw.split('.')[1], 'base64url').toString(),
    ) as Record<string, unknown>

    let outcome = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, expired as never, { atTime: later })
    } catch (error) {
      outcome = (error as Error).message
    }
    console.log('I2 attack (presented capability expired at the reference time):', outcome)

    // CONTROL — the PARENT is the one that has expired at `later`, the leaf has not. Refused, so
    // expiry is enforced on this exact path and the only difference is which link expired.
    const shortParent = await delegate(root, manager, { act: 'write', res: '*', exp: now() + 60 })
    const childRaw = await delegate(manager, device, {
      act: 'write',
      res: '*',
      exp: now() + 3600,
      parent: shortParent,
    })
    const child = JSON.parse(Buffer.from(childRaw.split('.')[1], 'base64url').toString()) as Record<
      string,
      unknown
    >
    let control = 'ACCEPTED'
    try {
      await checkCapability({ act: 'write', res: 'doc/1' }, child as never, { atTime: later })
    } catch (error) {
      control = (error as Error).message
    }
    console.log('I2 control (parent expired at the same reference time):', control)
    expect(control).not.toBe('ACCEPTED')

    expect(outcome, 'EXPIRY EVASION on the presented capability').not.toBe('ACCEPTED')
  })
})

describe('ATTACK: the depth cap', () => {
  test('I3 — how many links the default actually admits', async () => {
    const holders = [root]
    const chain: Array<string> = []
    for (let i = 0; i < 8; i++) {
      const next = randomIdentity()
      chain.unshift(
        await delegate(holders[i], next, {
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
        iss: holders[links].id,
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
    console.log(
      `I3 (DEFAULT_MAX_DELEGATION_DEPTH = ${DEFAULT_MAX_DELEGATION_DEPTH}):`,
      JSON.stringify(results, null, 1),
    )
    const accepted = results.filter(([, outcome]) => outcome === 'ACCEPTED').map(([n]) => n)
    console.log('I3 accepted link counts:', JSON.stringify(accepted))
    expect(Math.max(...accepted)).toBeLessThanOrEqual(DEFAULT_MAX_DELEGATION_DEPTH)
  })
})

describe('ATTACK: a capability with no expiry at all', () => {
  test('I4 — verifies arbitrarily far in the future', async () => {
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
    console.log('I4:', JSON.stringify({ noExp: outcome, withExp: control }))
    expect(control).not.toBe('ACCEPTED')
    expect(outcome, 'a capability with no exp is eternal').not.toBe('ACCEPTED')
  })
})

describe('ATTACK: the permission matcher itself', () => {
  test('I5 — grant/request pairs that must not match', async () => {
    const rows: Array<[string, string, string]> = [
      // [grant act/res, request, note]
      ['*', 'anything', 'wildcard grant'],
      ['a/*', 'a', 'grant of children, request of the parent'],
      ['a', 'a/b', 'no implicit descent'],
      ['a/b', 'a', 'grant deeper than request'],
      ['*/x', 'anything/at/all', 'wildcard in a non-final component'],
      ['a*', 'ab', 'wildcard glued to a component'],
      ['a', 'A', 'case'],
      ['a', 'a ', 'trailing space'],
      ['', 'a', 'empty grant'],
      ['a', '', 'empty request'],
    ]
    const results = rows.map(([granted, expected, note]) => [
      `${note}: grant ${JSON.stringify(granted)} vs request ${JSON.stringify(expected)}`,
      hasPermission({ act: 'x', res: expected }, { act: 'x', res: granted }),
    ])
    console.log('I5:', JSON.stringify(results, null, 1))
    // The two that must hold whatever else does.
    expect(hasPermission({ act: 'x', res: 'a/b' }, { act: 'x', res: 'a' })).toBe(false)
    expect(hasPermission({ act: 'x', res: 'a' }, { act: 'x', res: 'a/b' })).toBe(false)
  })
})

describe('ATTACK: nbf and iat on the presented capability', () => {
  test('I6 — a not-yet-valid, future-issued capability is accepted', async () => {
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
    console.log('I6:', JSON.stringify({ presentedLeaf: outcome, sameClaimsOnParent: control }))
    expect(control).not.toBe('ACCEPTED')
    expect(outcome, 'nbf/iat evasion on the presented capability').not.toBe('ACCEPTED')
  })
})
