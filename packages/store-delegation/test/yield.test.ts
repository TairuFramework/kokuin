import { HozonDB } from '@hozon/db'
import { checkCapability, createCapability, createRevocationRecord } from '@kokuin/capability'
import { randomIdentity, stringifyToken } from '@kokuin/token'
import type * as SozaiAsync from '@sozai/async'
import { describe, expect, test, vi } from 'vitest'

import { clearVerifiedSignatureMemo } from '../../token/lib/verified-memo.js'
import {
  createDelegationRevocationChecker,
  delegationStoreDefinition,
  getDelegationStore,
  VerifiedRevocationError,
} from '../src/index.js'
import type { StoreHarness } from './cases.js'

const timers = vi.hoisted(() =>
  vi.fn((callback: () => void) => {
    setTimeout(callback, 0)
  }),
)
vi.mock('@sozai/async', async (importOriginal) => {
  const original = await importOriginal<typeof SozaiAsync>()
  return {
    ...original,
    maybeYield: original.createYielder({ budgetMs: 0, schedule: timers }).maybeYield,
  }
})

const harnessURL = new URL('../../../tests/integration/src/backends.ts', import.meta.url).href
const { backends } = (await import(harnessURL)) as { backends(): Array<StoreHarness> }

describe.each(backends())('stored revocation yield ($name)', (harness) => {
  for (const captured of [undefined, true, false]) {
    for (const override of [undefined, false, true]) {
      for (const path of ['checker', 'verdict'] as const) {
        test(`${path}: captured=${captured}, override=${override}`, async () => {
          const db = new HozonDB({ adapter: await harness.createAdapter() })
          try {
            db.register(delegationStoreDefinition)
            const store = await getDelegationStore(db)
            const issuer = randomIdentity()
            const holder = randomIdentity()
            const jti = crypto.randomUUID()
            const now = Math.floor(Date.now() / 1000)
            const cap = await createCapability({
              signer: issuer,
              yield: false,
              payload: {
                sub: issuer.id,
                aud: holder.id,
                act: 'document/write',
                res: '*',
                jti,
                iat: now,
                exp: now + 3600,
              },
            })
            const raw = stringifyToken(cap)
            const record = await createRevocationRecord({ signer: issuer, jti, yield: false })
            const revocation = {
              jti,
              revoker_did: issuer.id,
              revoked_iat: now,
              revocation_token: stringifyToken(record),
              verified_at: now,
              cap_exp: now + 3600,
              hlc: '2026-01-02T00:00:00.000Z:00000000:yield',
            }
            await store.addRevocation(revocation)
            expect(await store.getRevocationByIssuer({ jti, issuer: issuer.id })).toMatchObject(
              revocation,
            )
            for (const revoked of [true, false]) {
              if (!revoked) {
                const record = await issuer.signToken({
                  payload: { jti, rev: false, iat: now },
                  yield: false,
                })
                await store.addRevocation({
                  ...revocation,
                  revocation_token: stringifyToken(record),
                  hlc: '2026-01-02T00:00:00.000Z:00000001:yield',
                })
              }
              clearVerifiedSignatureMemo()
              await db.withTransaction(async (tx) => {
                const writer = await getDelegationStore(tx)
                const checker = createDelegationRevocationChecker({ api: writer, yield: captured })
                await writer.addDelegationToken({
                  jti,
                  grantor: issuer.id,
                  audience: holder.id,
                  token: raw,
                  resource: '*',
                  act: 'document/write',
                  exp: now + 3600,
                  hlc: revocation.hlc,
                })
                let calls = 0
                const result = checkCapability({
                  permission: { act: 'document/write', res: '*' },
                  payload: { iss: holder.id, sub: issuer.id, cap: [raw] },
                  yield: override,
                  verifyToken: async (params) => {
                    calls += 1
                    // Observe only stored revocation verification, after the capability verifies.
                    timers.mockClear()
                    if (path === 'checker') await checker(params)
                    else expect(await checker.verdict(params)).toBe(revoked)
                  },
                })
                if (revoked && path === 'checker') {
                  await expect(result).rejects.toBeInstanceOf(VerifiedRevocationError)
                } else {
                  await expect(result).resolves.toBeUndefined()
                }
                expect(calls).toBe(1)
                expect(timers.mock.calls.length > 0).toBe((override ?? captured) !== false)
              })
            }
          } finally {
            await db.close()
            await harness.cleanup()
          }
        })
      }
    }
  }
})
