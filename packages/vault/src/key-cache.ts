export type KeyCacheSetParams = {
  keyID: string
  contentKey: Uint8Array
  keyVersion: number
  branchID: string
}

export const DEFAULT_UNLOCK_TTL = 15 * 60 * 1000

export type KeyCacheParams = {
  ttl?: number

  now?: () => number
}

export type KeyCache = {
  get(params: KeyCacheGetParams): { contentKey: Uint8Array; branchID: string } | null

  has(params: KeyCacheHasParams): boolean
  set(params: KeyCacheSetParams): void
  evictVersion(params: KeyCacheEvictVersionParams): void
  evict(keyID: string): void
  evictAll(): void
}

type CachedKey = {
  contentKey: Uint8Array
  branchID: string
  unlockedAt: number
}

export function createKeyCache(params: KeyCacheParams = {}): KeyCache {
  const ttl = params.ttl ?? DEFAULT_UNLOCK_TTL
  const now = params.now ?? Date.now
  const entries = new Map<string, Map<number, CachedKey>>()

  function evict(keyID: string): void {
    const versions = entries.get(keyID)

    if (versions == null) return

    for (const cached of versions.values()) cached.contentKey.fill(0)
    entries.delete(keyID)
  }

  function evictVersion(keyID: string, keyVersion: number): void {
    const versions = entries.get(keyID)
    const cached = versions?.get(keyVersion)

    if (cached == null) return

    cached.contentKey.fill(0)
    versions?.delete(keyVersion)

    if (versions?.size === 0) entries.delete(keyID)
  }

  function live(keyID: string, keyVersion: number): CachedKey | null {
    const cached = entries.get(keyID)?.get(keyVersion)

    if (cached == null) {
      return null
    }

    if (now() - cached.unlockedAt >= ttl) {
      evictVersion(keyID, keyVersion)

      return null
    }

    return cached
  }

  return {
    get({ keyID, keyVersion }) {
      const cached = live(keyID, keyVersion)

      if (cached == null) {
        return null
      }

      return { contentKey: cached.contentKey.slice(), branchID: cached.branchID }
    },

    has({ keyID, keyVersion }) {
      return live(keyID, keyVersion) != null
    },

    set({ keyID, contentKey, keyVersion, branchID }: KeyCacheSetParams) {
      evictVersion(keyID, keyVersion)

      const versions = entries.get(keyID) ?? new Map<number, CachedKey>()

      versions.set(keyVersion, {
        contentKey: contentKey.slice(),
        branchID,
        unlockedAt: now(),
      })

      entries.set(keyID, versions)
    },

    evict,
    evictVersion: ({ keyID, keyVersion }) => evictVersion(keyID, keyVersion),

    evictAll() {
      for (const keyID of [...entries.keys()]) {
        evict(keyID)
      }
    },
  }
}

export type KeyCacheGetParams = { keyID: string; keyVersion: number }

export type KeyCacheHasParams = { keyID: string; keyVersion: number }

export type KeyCacheEvictVersionParams = { keyID: string; keyVersion: number }
