import { HozonDB } from '@hozon/db'
import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import { expect, test } from 'vitest'

import { delegationStoreDefinition, getDelegationStore } from '../src/index.js'

test('token replacement, revocation upsert and promotion persist caller wall time', async () => {
  const adapter = new NodeSQLiteAdapter({ database: ':memory:' })
  const db = new HozonDB({ adapter })
  db.register(delegationStoreDefinition)
  let wall = 1_700_000_000_123
  const now = () => wall
  const timestamp = () => adapter.encodeTimestamp(new Date(now()))
  const token = {
    jti: 'first',
    grantor: 'did:key:grantor',
    audience: 'did:key:audience',
    resource: '*',
    token: 'signed',
    act: 'document/write',
    exp: 2_000_000_000,
    hlc: '1',
  }
  try {
    const store = await getDelegationStore(db)
    await store.addDelegationToken({ ...token, atTime: now() / 1000 })
    wall += 1000
    await store.addDelegationToken({ ...token, jti: 'second', hlc: '2', atTime: now() / 1000 })
    expect((await store.getDelegationTokenByGrantorJTI(token))?.updated_at).toBe(timestamp())
    wall += 1000
    await store.addDelegationToken({ ...token, jti: 'second', hlc: '3', atTime: now() / 1000 })
    expect(
      (await store.getDelegationTokenByGrantorJTI({ ...token, jti: 'second' }))?.updated_at,
    ).toBe(timestamp())
    const revocation = {
      jti: token.jti,
      revoker_did: token.grantor,
      revoked_iat: 1,
      revocation_token: 'revoked',
      hlc: '1',
    }
    await store.addRevocation({ ...revocation, atTime: now() / 1000 })
    wall += 1000
    await store.addRevocation({ ...revocation, hlc: '2', atTime: now() / 1000 })
    expect((await store.listRevocations(token.jti))[0]?.updated_at).toBe(timestamp())
    wall += 1000
    await store.markRevocationVerified({
      jti: token.jti,
      issuer: token.grantor,
      cap_exp: token.exp,
      atTime: now() / 1000,
    })
    expect((await store.listRevocations(token.jti))[0]?.updated_at).toBe(timestamp())
    expect((await store.listRevocations(token.jti))[0]?.verified_at).toBe(Math.floor(now() / 1000))
  } finally {
    await db.close()
  }
})
