import { describe, expect, test } from 'vitest'

import { createVaultKeyID, createVaultKeyReference } from '../src/index.js'

describe('vault key references', () => {
  test('pairs owner-bound IDs with canonical unique bytes for signed metadata', () => {
    const unique = Uint8Array.from({ length: 16 }, (_, i) => i)
    expect(createVaultKeyReference('did:example:owner', unique)).toEqual({
      keyID: createVaultKeyID('did:example:owner', unique),
      keyUnique: 'AAECAwQFBgcICQoLDA0ODw',
    })
    expect(createVaultKeyReference('did:example:other', unique).keyID).not.toBe(
      createVaultKeyID('did:example:owner', unique),
    )
  })
})
