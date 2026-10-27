import { expect, test, vi } from 'vitest'

const registration = vi.hoisted(() => ({ missing: true, abiVersion: 1 }))

vi.mock('react-native-nitro-modules', () => ({
  NitroModules: {
    createHybridObject() {
      if (registration.missing) throw new Error('Native module is not registered')
      return { abiVersion: registration.abiVersion, execute: async () => [] }
    },
  },
}))

import { createNativeCrypto } from '../src/index.js'

test('explicit construction rejects missing native registration', () => {
  registration.missing = true
  expect(() => createNativeCrypto()).toThrow('not registered')
})

test('explicit construction rejects incompatible native binaries', () => {
  registration.missing = false
  registration.abiVersion = 2
  expect(() => createNativeCrypto()).toThrow('ABI mismatch')
})
