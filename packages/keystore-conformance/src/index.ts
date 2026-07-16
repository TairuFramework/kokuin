import type { KeyStore, MutableKeyEntry } from '@kokuin/token'

/** A single conformance check. `run` throws on violation; resolving means the store conforms. */
export type ConformanceCase = {
  name: string
  run(): Promise<void>
}

export type KeyStoreConformanceHarness<PrivateKeyType> = {
  /** A store with no keys in it. Called once per case, so cases cannot leak into each other. */
  createStore(): KeyStore<PrivateKeyType> | Promise<KeyStore<PrivateKeyType>>
  /** Substrate-specific key equality — bytes, `CryptoKeyPair` identity, whatever applies. */
  isSameKey(a: PrivateKeyType, b: PrivateKeyType): boolean
  /**
   * Set for a **derived** backend (HD), where `getAsync` can always produce a key and so
   * never returns `null`. Skips the absent-means-null case; every other invariant still holds.
   */
  neverAbsent?: boolean
  /** Two keyIDs valid for this backend. Defaults to `['conformance-a', 'conformance-b']`. */
  keyIDs?: [string, string]
}

export type MutableKeyStoreConformanceHarness<PrivateKeyType> = Omit<
  KeyStoreConformanceHarness<PrivateKeyType>,
  'createStore'
> & {
  /** A store with no keys in it. Called once per case, so cases cannot leak into each other. */
  createStore():
    | KeyStore<PrivateKeyType, MutableKeyEntry<PrivateKeyType>>
    | Promise<KeyStore<PrivateKeyType, MutableKeyEntry<PrivateKeyType>>>
  /** A fresh key this backend would accept from `setAsync`. */
  createKey(): PrivateKeyType | Promise<PrivateKeyType>
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`KeyStore conformance: ${message}`)
  }
}

const DEFAULT_KEY_IDS: [string, string] = ['conformance-a', 'conformance-b']

/**
 * The invariants every {@link KeyStore} must hold, as runnable cases.
 *
 * Framework-agnostic by design — drive them from any runner:
 *
 * ```ts
 * for (const conformanceCase of keyStoreConformanceCases(harness)) {
 *   test(conformanceCase.name, () => conformanceCase.run())
 * }
 * ```
 */
export function keyStoreConformanceCases<PrivateKeyType>(
  harness: KeyStoreConformanceHarness<PrivateKeyType>,
): Array<ConformanceCase> {
  const [keyIDA, keyIDB] = harness.keyIDs ?? DEFAULT_KEY_IDS
  const store = () => Promise.resolve(harness.createStore())

  const cases: Array<ConformanceCase> = [
    {
      name: 'entry() round-trips the keyID',
      async run() {
        const entry = (await store()).entry(keyIDA)
        assert(
          entry.keyID === keyIDA,
          `entry(${JSON.stringify(keyIDA)}).keyID is ${JSON.stringify(entry.keyID)}`,
        )
      },
    },
    {
      name: 'entry() is cached — entry(x) === entry(x)',
      async run() {
        const created = await store()
        const first = created.entry(keyIDA)
        const second = created.entry(keyIDA)
        assert(
          first === second,
          'entry() returned a different object for the same keyID; per-entry concurrency state cannot work',
        )
      },
    },
    {
      name: 'provideAsync() then getAsync() returns the same key',
      async run() {
        const entry = (await store()).entry(keyIDA)
        const provided = await entry.provideAsync()
        const fetched = await entry.getAsync()
        assert(fetched != null, 'getAsync() returned null after provideAsync()')
        assert(
          harness.isSameKey(provided, fetched as PrivateKeyType),
          'getAsync() returned a different key than provideAsync() did',
        )
      },
    },
    {
      name: 'provideAsync() is idempotent across sequential calls',
      async run() {
        const entry = (await store()).entry(keyIDA)
        const first = await entry.provideAsync()
        const second = await entry.provideAsync()
        assert(harness.isSameKey(first, second), 'two sequential provideAsync() calls differ')
      },
    },
    {
      name: 'provideAsync() converges under concurrency',
      async run() {
        const entry = (await store()).entry(keyIDA)
        const results = await Promise.all([
          entry.provideAsync(),
          entry.provideAsync(),
          entry.provideAsync(),
          entry.provideAsync(),
        ])
        for (const result of results) {
          assert(
            harness.isSameKey(results[0], result),
            'concurrent provideAsync() calls resolved to different keys',
          )
        }
        const stored = await entry.getAsync()
        assert(stored != null, 'concurrent provideAsync() left no key stored')
        assert(
          harness.isSameKey(results[0], stored as PrivateKeyType),
          'concurrent provideAsync() returned a key that is not the one left in storage — a lost key',
        )
      },
    },
    {
      name: 'distinct keyIDs get distinct keys',
      async run() {
        const created = await store()
        const keyA = await created.entry(keyIDA).provideAsync()
        const keyB = await created.entry(keyIDB).provideAsync()
        assert(!harness.isSameKey(keyA, keyB), 'two different keyIDs resolved to the same key')
        const refetchedA = await created.entry(keyIDA).getAsync()
        assert(refetchedA != null, 'the first key vanished after providing the second')
        assert(
          harness.isSameKey(keyA, refetchedA as PrivateKeyType),
          'providing a second keyID overwrote the first keyID’s key',
        )
      },
    },
  ]

  if (harness.neverAbsent !== true) {
    cases.unshift({
      name: 'getAsync() returns null when absent',
      async run() {
        const result = await (await store()).entry(keyIDA).getAsync()
        assert(
          result === null,
          `getAsync() on an absent key returned ${String(result)}, expected null`,
        )
      },
    })
  }

  return cases
}

/** {@link keyStoreConformanceCases} plus the write/delete invariants of {@link MutableKeyEntry}. */
export function mutableKeyStoreConformanceCases<PrivateKeyType>(
  harness: MutableKeyStoreConformanceHarness<PrivateKeyType>,
): Array<ConformanceCase> {
  const [keyIDA] = harness.keyIDs ?? DEFAULT_KEY_IDS
  const store = () => Promise.resolve(harness.createStore())

  return [
    ...keyStoreConformanceCases(harness),
    {
      name: 'setAsync() then getAsync() round-trips the key',
      async run() {
        const entry = (await store()).entry(keyIDA)
        const key = await harness.createKey()
        await entry.setAsync(key)
        const fetched = await entry.getAsync()
        assert(fetched != null, 'getAsync() returned null after setAsync()')
        assert(
          harness.isSameKey(key, fetched as PrivateKeyType),
          'getAsync() did not return the key that was set',
        )
      },
    },
    {
      name: 'removeAsync() makes the key absent',
      async run() {
        const entry = (await store()).entry(keyIDA)
        await entry.provideAsync()
        await entry.removeAsync()
        const fetched = await entry.getAsync()
        assert(fetched === null, `getAsync() returned ${String(fetched)} after removeAsync()`)
      },
    },
    {
      name: 'removeAsync() is idempotent on an absent key',
      async run() {
        const entry = (await store()).entry(keyIDA)
        await entry.removeAsync()
        await entry.removeAsync()
      },
    },
    {
      name: 'provideAsync() after removeAsync() mints a fresh key',
      async run() {
        const entry = (await store()).entry(keyIDA)
        const first = await entry.provideAsync()
        await entry.removeAsync()
        const second = await entry.provideAsync()
        assert(
          !harness.isSameKey(first, second),
          'provideAsync() after removeAsync() returned the removed key — a stale cache',
        )
      },
    },
  ]
}
