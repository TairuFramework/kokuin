import { keyStoreConformanceCases } from '@kokuin/keystore-conformance'
import { describe, expect, test } from 'vitest'

import { HDKeyStore } from '../src/store.js'

const SEED = new Uint8Array(64).fill(7)

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

describe('HDKeyStore conformance', () => {
  // HD derives rather than stores: getAsync can always produce a key, so it never returns
  // null. That is contract-legal — every other invariant still applies.
  const cases = keyStoreConformanceCases({
    createStore: () => HDKeyStore.fromSeed(SEED),
    isSameKey: sameBytes,
    neverAbsent: true,
    keyIDs: ['0', '1'],
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('HDKeyEntry', () => {
  test('keyID is the caller’s keyID, not the derivation path', () => {
    const entry = HDKeyStore.fromSeed(SEED).entry('0')
    expect(entry.keyID).toBe('0')
    expect(entry.path).toBe("m/44'/876'/0'")
  })

  test('a full path keyID round-trips as both keyID and path', () => {
    const entry = HDKeyStore.fromSeed(SEED).entry("m/44'/876'/5'")
    expect(entry.keyID).toBe("m/44'/876'/5'")
    expect(entry.path).toBe("m/44'/876'/5'")
  })

  test('has no setAsync or removeAsync — the substrate cannot do either', () => {
    const entry = HDKeyStore.fromSeed(SEED).entry('0')
    expect('setAsync' in entry).toBe(false)
    expect('removeAsync' in entry).toBe(false)
  })
})
