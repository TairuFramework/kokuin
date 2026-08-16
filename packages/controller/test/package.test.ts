import { describe, expect, test } from 'vitest'

import { VERSION_TAG } from '../src/index.js'

describe('@kokuin/controller', () => {
  test('exposes the protocol version tag used for key derivation', () => {
    expect(VERSION_TAG).toBe('did:kokuin/v1')
  })
})
