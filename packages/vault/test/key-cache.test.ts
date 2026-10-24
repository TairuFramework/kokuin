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
    cache.set(KEY_ID, key, 1, 'branch-1')

    expect(cache.get(KEY_ID, 1)).toEqual({ contentKey: key, branchID: 'branch-1' })
    expect(cache.get('k-key-other', 1)).toBeNull()
  })

  test('an old-version read keeps the current-version key cached', () => {
    const cache = createKeyCache()
    cache.set(KEY_ID, contentKey(1), 1, 'branch-1')
    cache.set(KEY_ID, contentKey(2), 2, 'branch-2')

    expect(cache.get(KEY_ID, 1)?.contentKey).toEqual(contentKey(1))
    expect(cache.get(KEY_ID, 2)?.contentKey).toEqual(contentKey(2))
  })

  test('evicting a losing branch leaves another version cached', () => {
    const cache = createKeyCache()
    cache.set(KEY_ID, contentKey(1), 1, 'branch-1')
    cache.set(KEY_ID, contentKey(2), 2, 'branch-2')
    cache.evictVersion(KEY_ID, 1)

    expect(cache.get(KEY_ID, 1)).toBeNull()
    expect(cache.get(KEY_ID, 2)?.contentKey).toEqual(contentKey(2))
  })

  describe('the cache owns its buffers exclusively', () => {
    test('set stores a clone, so mutating the caller buffer does not change the cache', () => {
      const cache = createKeyCache()
      const key = contentKey(1)
      cache.set(KEY_ID, key, 1, '')

      key.fill(9)

      expect(cache.get(KEY_ID, 1)?.contentKey).toEqual(contentKey(1))
    })

    test('get returns a fresh clone each time, distinct from the cached buffer', () => {
      const cache = createKeyCache()
      cache.set(KEY_ID, contentKey(1), 1, '')

      const first = cache.get(KEY_ID, 1)?.contentKey
      const second = cache.get(KEY_ID, 1)?.contentKey
      expect(first).not.toBe(second)

      first?.fill(0)
      expect(cache.get(KEY_ID, 1)?.contentKey).toEqual(contentKey(1))
      expect(second).toEqual(contentKey(1))
    })

    test('an explicit evict drops the key and never touches the caller buffer', () => {
      const cache = createKeyCache()
      const key = contentKey()
      cache.set(KEY_ID, key, 1, '')

      cache.evict(KEY_ID)

      expect(cache.get(KEY_ID, 1)).toBeNull()
      expect(key).toEqual(contentKey())
    })

    test('evictAll drops every key and leaves the callers buffers untouched', () => {
      const cache = createKeyCache()
      const first = contentKey(1)
      const second = contentKey(2)
      cache.set('k-a', first, 1, '')
      cache.set('k-b', second, 1, '')

      cache.evictAll()

      expect(cache.get('k-a', 1)).toBeNull()
      expect(cache.get('k-b', 1)).toBeNull()
      expect(first).toEqual(contentKey(1))
      expect(second).toEqual(contentKey(2))
    })

    test('a TTL expiry drops the key without touching the caller buffer', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      const key = contentKey()
      cache.set(KEY_ID, key, 1, '')

      clock += 60_000
      expect(cache.get(KEY_ID, 1)).toBeNull()
      expect(key).toEqual(contentKey())
    })

    test('replacing a key does not touch the caller buffer it replaced', () => {
      const cache = createKeyCache()
      const first = contentKey(1)
      cache.set(KEY_ID, first, 1, '')
      cache.set(KEY_ID, contentKey(2), 1, '')

      expect(first).toEqual(contentKey(1))
      expect(cache.get(KEY_ID, 1)?.contentKey).toEqual(contentKey(2))
    })

    test('a missing version leaves another version and the caller buffer untouched', () => {
      const cache = createKeyCache()
      const key = contentKey()
      cache.set(KEY_ID, key, 1, '')

      expect(cache.get(KEY_ID, 2)).toBeNull()
      expect(cache.get(KEY_ID, 1)?.contentKey).toEqual(key)
      expect(key).toEqual(contentKey())
    })

    test('has reports presence and validity without materialising a copy', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      cache.set(KEY_ID, contentKey(), 1, '')

      expect(cache.has(KEY_ID, 1)).toBe(true)
      expect(cache.has('k-key-other', 1)).toBe(false)
      expect(cache.has(KEY_ID, 2)).toBe(false)
      expect(cache.has(KEY_ID, 1)).toBe(true)

      cache.set('k-ttl', contentKey(), 1, '')
      clock += 60_000
      expect(cache.has('k-ttl', 1)).toBe(false)
    })
  })

  describe('the TTL boundary', () => {
    test('a key survives up to the TTL and not past it', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      cache.set(KEY_ID, contentKey(), 1, '')

      clock += 59_999
      expect(cache.get(KEY_ID, 1)).not.toBeNull()

      clock += 1
      expect(cache.get(KEY_ID, 1)).toBeNull()
    })

    test('the clock runs from the set, so a re-unlock extends the life', () => {
      let clock = 1_000_000
      const cache = createKeyCache({ ttl: 60_000, now: () => clock })
      cache.set(KEY_ID, contentKey(), 1, '')

      clock += 50_000
      cache.set(KEY_ID, contentKey(), 1, '')

      clock += 50_000
      expect(cache.get(KEY_ID, 1)).not.toBeNull()
    })
  })
})
