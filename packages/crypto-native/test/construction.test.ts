import { expect, test, vi } from 'vitest'

const registration = vi.hoisted(() => ({ missing: true, abiVersion: 1, created: 0 }))

vi.mock('react-native-nitro-modules', () => ({
  NitroModules: {
    hasHybridObject(name: string) {
      return name === 'Crypto' && !registration.missing
    },
    createHybridObject() {
      registration.created++
      if (registration.missing) throw new Error('Native module is not registered')
      return { abiVersion: registration.abiVersion, execute: async () => [] }
    },
  },
}))

import * as api from '../src/index.js'
import { createNativeCrypto } from '../src/index.js'

test('explicit construction rejects missing native registration with a clear error', () => {
  registration.missing = true
  registration.created = 0
  expect(() => createNativeCrypto()).toThrow(
    /hybrid object "Crypto" is not registered.*native library is missing or failed to load.*unsupported ABI/,
  )
  expect(registration.created).toBe(0)
})

test('explicit construction rejects incompatible native binaries', () => {
  registration.missing = false
  registration.abiVersion = 2
  expect(() => createNativeCrypto()).toThrow('ABI mismatch')
})

test('explicit construction succeeds when the native object is registered', () => {
  registration.missing = false
  registration.abiVersion = 1
  expect(typeof createNativeCrypto().sign).toBe('function')
})

test('public API exposes no spike alias', () => {
  expect(Object.keys(api)).toEqual(['createNativeCrypto'])
})
