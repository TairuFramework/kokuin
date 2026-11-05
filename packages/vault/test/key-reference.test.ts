import { describe, expect, test } from 'vitest'

import { createVaultKeyID, createVaultKeyReference } from '../src/index.js'

describe('vault key references', () => {
  test('pairs owner-bound IDs with canonical unique bytes for signed metadata', async () => {
    const unique = Uint8Array.from({ length: 16 }, (_, i) => i)
    expect(await createVaultKeyReference({ owner: 'did:example:owner', unique })).toEqual({
      keyID: await createVaultKeyID({ owner: 'did:example:owner', unique }),
      keyUnique: 'AAECAwQFBgcICQoLDA0ODw',
    })
    expect((await createVaultKeyReference({ owner: 'did:example:other', unique })).keyID).not.toBe(
      await createVaultKeyID({ owner: 'did:example:owner', unique }),
    )
  })
})
