import { describe, expect, test } from 'vitest'

import {
  type VaultEntryDigestInput,
  type VaultKeyDigestInput,
  type VaultWrappingDigestInput,
  vaultEntriesDigest,
  vaultEntryDigest,
  vaultKeyDigest,
  vaultWrappingDigest,
} from '../src/digest.js'

const WRAPPING: VaultWrappingDigestInput = {
  wrappingID: 'wrap-1',
  recipientDID: 'did:key:z6MkiAjt8YP2SCmeAy7M5xY8FpDWgLC76tKQh8etSC17iJTN',
  iv: 'AAECAwQFBgcICQoL',
  wrappedKey: 'DQ4PEBESExQVFhcY',
  factors: [
    { kind: 'did', params: { epk: 'AAAA' } },
    { kind: 'pin', params: { salt: 'ZZZZ', m: 65536, t: 3, p: 1 } },
  ],
}

const [WRAPPING_FACTOR_0, WRAPPING_FACTOR_1] = WRAPPING.factors
if (WRAPPING_FACTOR_0 == null || WRAPPING_FACTOR_1 == null) {
  throw new Error('WRAPPING requires two factors')
}

const KEY: VaultKeyDigestInput = {
  ownerDID: 'did:key:z6MkiAjt8YP2SCmeAy7M5xY8FpDWgLC76tKQh8etSC17iJTN',
  suite: 1,
  version: 2,
  state: 'active',
}

const ENTRY: VaultEntryDigestInput = {
  entryID: 'entry-1',
  iv: 'AAECAwQFBgcICQoL',
  ciphertext: 'GRobHB0eHyAhIiMk',
  hlc: '2026-08-11T00:00:00.000Z-0000-node',
}

const wrappingBaseline = await vaultWrappingDigest(WRAPPING)
const keyBaseline = await vaultKeyDigest(KEY)
const entryBaseline = await vaultEntryDigest(ENTRY)

describe('every field a wrapping digest covers moves it', () => {
  const baseline = wrappingBaseline

  test.each<[string, VaultWrappingDigestInput]>([
    ['wrappingID', { ...WRAPPING, wrappingID: 'wrap-2' }],
    [
      'recipientDID',
      { ...WRAPPING, recipientDID: 'did:key:z6MkjChhTKPDTvxYYFJHrsvHrbmYAzJdmhCoUcSbLU4NWq3F' },
    ],
    ['iv', { ...WRAPPING, iv: 'CwoJCAcGBQQDAgEA' }],
    ['wrappedKey', { ...WRAPPING, wrappedKey: 'GBcWFRQTEhEQDw4N' }],
    [
      'a factor kind',
      {
        ...WRAPPING,
        factors: [{ ...WRAPPING_FACTOR_0, kind: 'passphrase' }, WRAPPING_FACTOR_1],
      },
    ],
    [
      'a factor param',
      { ...WRAPPING, factors: [{ kind: 'did', params: { epk: 'BBBB' } }, WRAPPING_FACTOR_1] },
    ],
    [
      'an added factor param',
      {
        ...WRAPPING,
        factors: [{ kind: 'did', params: { epk: 'AAAA', extra: 1 } }, WRAPPING_FACTOR_1],
      },
    ],
    ['factor order', { ...WRAPPING, factors: [WRAPPING_FACTOR_1, WRAPPING_FACTOR_0] }],
    ['a dropped factor', { ...WRAPPING, factors: [WRAPPING_FACTOR_0] }],
    ['an absent recipient', { ...WRAPPING, recipientDID: null }],
  ])('%s', async (_name, changed) => {
    expect(await vaultWrappingDigest(changed)).not.toBe(baseline)
  })

  test('param key order does not, because a params record is an unordered bag', async () => {
    const reordered: VaultWrappingDigestInput = {
      ...WRAPPING,
      factors: [WRAPPING_FACTOR_0, { kind: 'pin', params: { p: 1, t: 3, m: 65536, salt: 'ZZZZ' } }],
    }
    expect(await vaultWrappingDigest(reordered)).toBe(baseline)
  })

  test('a field moved between neighbours does not collide', async () => {
    const shifted = await vaultWrappingDigest({
      ...WRAPPING,
      wrappingID: 'wrap-1x',
      iv: 'AECAwQFBgcICQoL',
    })
    expect(shifted).not.toBe(baseline)
  })
})

describe('every field a key digest covers moves it', () => {
  const baseline = keyBaseline

  test.each<[string, VaultKeyDigestInput]>([
    ['ownerDID', { ...KEY, ownerDID: 'did:key:z6MkjChhTKPDTvxYYFJHrsvHrbmYAzJdmhCoUcSbLU4NWq3F' }],
    ['suite', { ...KEY, suite: 2 }],
    ['version', { ...KEY, version: 3 }],
    ['state', { ...KEY, state: 'retired' }],
  ])('%s', async (_name, changed) => {
    expect(await vaultKeyDigest(changed)).not.toBe(baseline)
  })
})

describe('every field an entry digest covers moves it', () => {
  const baseline = entryBaseline

  test.each<[string, VaultEntryDigestInput]>([
    ['entryID', { ...ENTRY, entryID: 'entry-2' }],
    ['iv', { ...ENTRY, iv: 'CwoJCAcGBQQDAgEA' }],
    ['ciphertext', { ...ENTRY, ciphertext: 'JCMiISAfHh0cGxoZ' }],
    ['hlc', { ...ENTRY, hlc: '2026-08-11T00:00:00.001Z-0000-node' }],
  ])('%s', async (_name, changed) => {
    expect(await vaultEntryDigest(changed)).not.toBe(baseline)
  })

  test('one entry digests as the one-element set, not as a second framing', async () => {
    expect(await vaultEntryDigest(ENTRY)).toBe(await vaultEntriesDigest([ENTRY]))
  })

  test('a set digests the same however it is ordered', async () => {
    const other = { ...ENTRY, entryID: 'entry-0' }
    expect(await vaultEntriesDigest([ENTRY, other])).toBe(await vaultEntriesDigest([other, ENTRY]))
  })

  test('an entry added to a set moves it', async () => {
    expect(await vaultEntriesDigest([ENTRY, { ...ENTRY, entryID: 'entry-0' }])).not.toBe(
      await vaultEntriesDigest([ENTRY]),
    )
  })
})
