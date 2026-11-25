import { randomIdentity, stringifyToken, verifyToken } from '@kokuin/token'
import { expect, test } from 'vitest'

import { createCapability } from '../src/index.js'

const atTime = 1_700_000_000

test('subdelegation uses atTime for parent checks and defaults to ambient time', async () => {
  const owner = randomIdentity()
  const delegate = randomIdentity()
  const recipient = randomIdentity()
  const parentCapability = stringifyToken(
    await createCapability({
      signer: owner,
      payload: {
        sub: owner.id,
        aud: delegate.id,
        act: 'read',
        res: '*',
        iat: atTime,
        exp: atTime + 3600,
        jti: 'parent',
      },
    }),
  )
  const params = {
    signer: delegate,
    parentCapability,
    payload: {
      sub: owner.id,
      aud: recipient.id,
      act: 'read',
      res: '*',
      iat: atTime,
      exp: atTime + 1800,
      jti: 'child',
    },
  }
  await expect(createCapability(params)).rejects.toThrow('Token expired')
  const child = await createCapability({ ...params, atTime })
  const verified = await verifyToken({ token: stringifyToken(child), atTime })
  expect(verified.payload).toMatchObject(params.payload)
})
