import { HozonDB } from '@hozon/db'
import {
  type DelegationStoreAPI,
  delegationStoreDefinition,
  getDelegationStore,
} from '@kokuin/store-delegation'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'

import { backendsNamed } from '../src/backends.js'

const ROUNDS = 20

// Zero-padded so lexical order matches numeric order, as the store requires.
function hlc(counter: number): string {
  return counter.toString().padStart(12, '0')
}

const postgresBackends = backendsNamed('postgres')

// Vitest fails a file that registers no test, so a run without Postgres reports a skip.
if (postgresBackends.length === 0) {
  test.skip('concurrent writers need Postgres', () => {})
}

describe.each(postgresBackends)('$name', (b) => {
  let first: HozonDB
  let second: HozonDB
  let stores: [DelegationStoreAPI, DelegationStoreAPI]

  beforeAll(async () => {
    first = new HozonDB({ adapter: await b.createAdapter() })
    first.register(delegationStoreDefinition)
    // Migrate before the second instance opens, so the writers contend on rows only.
    const firstStore = await getDelegationStore(first)
    second = new HozonDB({ adapter: await b.reopen() })
    second.register(delegationStoreDefinition)
    stores = [firstStore, await getDelegationStore(second)]
  }, 120_000)

  afterAll(async () => {
    await first?.close()
    await second?.close()
    await b.cleanup()
  })

  test('concurrent addDelegationToken on one key keeps the higher hlc', async () => {
    for (let round = 0; round < ROUNDS; round++) {
      const key = { grantor: `did:key:g-${round}`, audience: `did:key:a-${round}` }
      const token = (counter: number) => ({
        ...key,
        jti: `jti-${round}-${counter}`,
        token: `token-${round}-${counter}`,
        resource: 'doc:1',
        act: 'write',
        exp: 5_000_000_000,
        hlc: hlc(counter),
      })
      await Promise.all([
        stores[0].addDelegationToken(token(1)),
        stores[1].addDelegationToken(token(2)),
      ])
      const rows = await stores[0].getDelegationTokens(key)
      expect(rows.map((row) => [row.jti, row.hlc])).toEqual([[`jti-${round}-2`, hlc(2)]])
    }
  })

  test('concurrent addRevocation on one key keeps the higher hlc', async () => {
    for (let round = 0; round < ROUNDS; round++) {
      const jti = `jti-revoked-${round}`
      const revokerDID = `did:key:r-${round}`
      const revocation = (counter: number) => ({
        jti,
        revoker_did: revokerDID,
        revoked_iat: 1_700_000_000 + counter,
        revocation_token: `revocation-${round}-${counter}`,
        verified_at: null,
        cap_exp: null,
        hlc: hlc(counter),
      })
      await Promise.all([
        stores[0].addRevocation(revocation(1)),
        stores[1].addRevocation(revocation(2)),
      ])
      const row = await stores[0].getRevocationByIssuer(jti, revokerDID)
      expect([row?.revocation_token, row?.hlc]).toEqual([`revocation-${round}-2`, hlc(2)])
    }
  })
})
