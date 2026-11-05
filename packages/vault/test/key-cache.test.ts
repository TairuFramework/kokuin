import { describe, expect, test } from 'vitest'

import { createKeyCache } from '../src/key-cache.js'

const KEY_ID = 'k-key-1'

function contentKey(fill = 7): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

describe('the key cache', () => {
  test('holds a key for its version and hands the same bytes and branch back', () => {
    const cache = createKeyCache()
    const key = contentKey()
    cache.set({ keyID: KEY_ID, contentKey: key, keyVersion: 1, branchID: 'branch-1' })

    expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).toEqual({
      contentKey: key,
      branchID: 'branch-1',
    })
    expect(cache.get({ keyID: 'k-key-other', keyVersion: 1 })).toBeNull()
  })

  test('an old-version read keeps the current-version key cached', () => {
    const cache = createKeyCache()
    cache.set({ keyID: KEY_ID, contentKey: contentKey(1), keyVersion: 1, branchID: 'branch-1' })
    cache.set({ keyID: KEY_ID, contentKey: contentKey(2), keyVersion: 2, branchID: 'branch-2' })

    expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey).toEqual(contentKey(1))
    expect(cache.get({ keyID: KEY_ID, keyVersion: 2 })?.contentKey).toEqual(contentKey(2))
  })

  test('evicting a losing branch leaves another version cached', () => {
    const cache = createKeyCache()
    cache.set({ keyID: KEY_ID, contentKey: contentKey(1), keyVersion: 1, branchID: 'branch-1' })
    cache.set({ keyID: KEY_ID, contentKey: contentKey(2), keyVersion: 2, branchID: 'branch-2' })
    cache.evictVersion({ keyID: KEY_ID, keyVersion: 1 })

    expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).toBeNull()
    expect(cache.get({ keyID: KEY_ID, keyVersion: 2 })?.contentKey).toEqual(contentKey(2))
  })

  describe('the cache owns its buffers exclusively', () => {
    test('set stores a clone, so mutating the caller buffer does not change the cache', () => {
      const cache = createKeyCache()
      const key = contentKey(1)
      cache.set({ keyID: KEY_ID, contentKey: key, keyVersion: 1, branchID: '' })

      key.fill(9)

      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey).toEqual(contentKey(1))
    })

    test('get returns a fresh clone each time, distinct from the cached buffer', () => {
      const cache = createKeyCache()
      cache.set({ keyID: KEY_ID, contentKey: contentKey(1), keyVersion: 1, branchID: '' })

      const first = cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey
      const second = cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey
      expect(first).not.toBe(second)

      first?.fill(0)
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey).toEqual(contentKey(1))
      expect(second).toEqual(contentKey(1))
    })

    test('an explicit evict drops the key and never touches the caller buffer', () => {
      const cache = createKeyCache()
      const key = contentKey()
      cache.set({ keyID: KEY_ID, contentKey: key, keyVersion: 1, branchID: '' })

      cache.evict(KEY_ID)

      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).toBeNull()
      expect(key).toEqual(contentKey())
    })

    test('evictAll drops every key and leaves the callers buffers untouched', () => {
      const cache = createKeyCache()
      const first = contentKey(1)
      const second = contentKey(2)
      cache.set({ keyID: 'k-a', contentKey: first, keyVersion: 1, branchID: '' })
      cache.set({ keyID: 'k-b', contentKey: second, keyVersion: 1, branchID: '' })

      cache.evictAll()

      expect(cache.get({ keyID: 'k-a', keyVersion: 1 })).toBeNull()
      expect(cache.get({ keyID: 'k-b', keyVersion: 1 })).toBeNull()
      expect(first).toEqual(contentKey(1))
      expect(second).toEqual(contentKey(2))
    })

    test('a TTL expiry drops the key without touching the caller buffer', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      const key = contentKey()
      cache.set({ keyID: KEY_ID, contentKey: key, keyVersion: 1, branchID: '' })

      clock += 60_000
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).toBeNull()
      expect(key).toEqual(contentKey())
    })

    test('replacing a key does not touch the caller buffer it replaced', () => {
      const cache = createKeyCache()
      const first = contentKey(1)
      cache.set({ keyID: KEY_ID, contentKey: first, keyVersion: 1, branchID: '' })
      cache.set({ keyID: KEY_ID, contentKey: contentKey(2), keyVersion: 1, branchID: '' })

      expect(first).toEqual(contentKey(1))
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey).toEqual(contentKey(2))
    })

    test('a missing version leaves another version and the caller buffer untouched', () => {
      const cache = createKeyCache()
      const key = contentKey()
      cache.set({ keyID: KEY_ID, contentKey: key, keyVersion: 1, branchID: '' })

      expect(cache.get({ keyID: KEY_ID, keyVersion: 2 })).toBeNull()
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })?.contentKey).toEqual(key)
      expect(key).toEqual(contentKey())
    })

    test('has reports presence and validity without materialising a copy', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      cache.set({ keyID: KEY_ID, contentKey: contentKey(), keyVersion: 1, branchID: '' })

      expect(cache.has({ keyID: KEY_ID, keyVersion: 1 })).toBe(true)
      expect(cache.has({ keyID: 'k-key-other', keyVersion: 1 })).toBe(false)
      expect(cache.has({ keyID: KEY_ID, keyVersion: 2 })).toBe(false)
      expect(cache.has({ keyID: KEY_ID, keyVersion: 1 })).toBe(true)

      cache.set({ keyID: 'k-ttl', contentKey: contentKey(), keyVersion: 1, branchID: '' })
      clock += 60_000
      expect(cache.has({ keyID: 'k-ttl', keyVersion: 1 })).toBe(false)
    })
  })

  describe('the TTL boundary', () => {
    test('a key survives up to the TTL and not past it', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      cache.set({ keyID: KEY_ID, contentKey: contentKey(), keyVersion: 1, branchID: '' })

      clock += 59_999
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).not.toBeNull()

      clock += 1
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).toBeNull()
    })

    test('the clock runs from the set, so a re-unlock extends the life', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      cache.set({ keyID: KEY_ID, contentKey: contentKey(), keyVersion: 1, branchID: '' })

      clock += 50_000
      cache.set({ keyID: KEY_ID, contentKey: contentKey(), keyVersion: 1, branchID: '' })

      clock += 50_000
      expect(cache.get({ keyID: KEY_ID, keyVersion: 1 })).not.toBeNull()
    })
  })
})
