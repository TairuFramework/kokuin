import type { DIDMethodResolver } from '@kokuin/token'
import { createIdentity } from '@kokuin/token'
import { createRuntime } from '@sozai/runtime'
import { describe, expect, test } from 'vitest'

import { getSuite } from '../src/index.js'

const runtime = createRuntime()
const suite = getSuite(1)
const recipientDID = 'did:kokuin:test-recipient'
const address = { keyID: 'key', keyVersion: 1, wrappingID: 'wrap' }

describe('async recipient agreement', () => {
  test('a resolver-backed recipient wraps and opens without a recipient resolver', async () => {
    const identity = await createIdentity({
      didMethod: 'peer:4',
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const kem = identity.keys.find((key) => key.purpose === 'kem' && key.alg === 'X25519')
    if (kem == null) throw new Error('missing agreement key')
    const resolver: DIDMethodResolver = {
      method: 'kokuin',
      resolve() {
        throw new Error('unexpected signature resolution')
      },
      async resolveAgreementKey(subject) {
        expect(subject).toBe(recipientDID)
        return [{ alg: 'X25519', publicKey: kem.publicKey }]
      },
    }
    const contentKey = suite.generateContentKey(runtime)
    const wrapped = await suite.wrap({
      ...address,
      runtime,
      contentKey,
      factors: [{ kind: 'did', recipientDID }],
      methods: [resolver],
    })
    expect(await suite.unwrap({ ...address, ...wrapped, identity })).toEqual(contentKey)
  })

  test('an unresolvable recipient fails closed', async () => {
    await expect(
      suite.wrap({
        ...address,
        runtime,
        contentKey: suite.generateContentKey(runtime),
        factors: [{ kind: 'did', recipientDID }],
        methods: [],
      }),
    ).rejects.toThrow(/no resolver registered/i)
  })
})
