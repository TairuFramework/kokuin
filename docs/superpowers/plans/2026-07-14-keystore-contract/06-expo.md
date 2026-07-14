## Task 8: expo — a real store class

`ExpoKeyStore` is an **object literal**, not a class. Its `entry()` caches nothing (`entry(x) !== entry(x)`, so the per-entry lock cannot work), takes an **undeclared second argument** the `KeyStore` type does not have, and `provideAsync` has no lock at all. It also lacks the prototype-pollution guard and has no sync `remove`.

No cross-process lock: a single app process makes it moot.

**Files:**
- Modify: `packages/expo/src/store.ts` (object literal → class)
- Modify: `packages/expo/src/entry.ts` (`MutableKeyEntry`, in-process lock, sync `remove`)
- Delete: `packages/expo/src/identity.ts`
- Modify: `packages/expo/src/index.ts`
- Create: `packages/expo/test/conformance.test.ts`
- Modify: `packages/expo/test/lib.test.ts`

**Interfaces:**
- Consumes: `MutableKeyEntry`, `KeyStore`, `mutableKeyStoreConformanceCases` from `@kokuin/token` (Task 1).
- Produces:
  - `ExpoKeyEntry implements MutableKeyEntry<Uint8Array>` — plus sync `get()` / `set()` / `provide()` / `remove()`.
  - `class ExpoKeyStore implements KeyStore<Uint8Array, ExpoKeyEntry>, IdentityProvider<FullIdentity>` with `static open(options?: StoreEntryOptions)`, `provideIdentity`, `provideIdentitySync`.
  - `provideFullIdentity` / `provideFullIdentityAsync` **removed**.

- [ ] **Step 1: Write the failing test**

Create `packages/expo/test/conformance.test.ts`. Mock `expo-secure-store` and `expo-crypto` (mirror the existing mocks in `lib.test.ts` — read it first and reuse its shape):

```ts
import { mutableKeyStoreConformanceCases } from '@kokuin/token'
import { beforeEach, describe, expect, test, vi } from 'vitest'

let secureStore: Record<string, string>

vi.mock('expo-secure-store', () => ({
  getItem: vi.fn((key: string) => secureStore[key] ?? null),
  getItemAsync: vi.fn(async (key: string) => secureStore[key] ?? null),
  setItem: vi.fn((key: string, value: string) => {
    secureStore[key] = value
  }),
  setItemAsync: vi.fn(async (key: string, value: string) => {
    secureStore[key] = value
  }),
  deleteItemAsync: vi.fn(async (key: string) => {
    delete secureStore[key]
  }),
}))

vi.mock('expo-crypto', () => ({
  getRandomBytes: vi.fn((size: number) => crypto.getRandomValues(new Uint8Array(size))),
  getRandomBytesAsync: vi.fn(async (size: number) => crypto.getRandomValues(new Uint8Array(size))),
}))

const { ExpoKeyStore } = await import('../src/store.js')

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

beforeEach(() => {
  secureStore = {}
})

describe('ExpoKeyStore conformance', () => {
  const cases = mutableKeyStoreConformanceCases({
    createStore: () => new ExpoKeyStore(),
    isSameKey: sameBytes,
    createKey: () => crypto.getRandomValues(new Uint8Array(32)),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('ExpoKeyStore', () => {
  test('entry() is cached, so the per-entry provideAsync lock can work', () => {
    const store = new ExpoKeyStore()
    expect(store.entry('user')).toBe(store.entry('user'))
  })

  test('entry() takes only a keyID — options move to construction', () => {
    expect(new ExpoKeyStore().entry.length).toBe(1)
  })

  test.each(['__proto__', 'constructor', 'prototype'])(
    'the prototype-pollution keyID %j behaves as an ordinary key',
    async (keyID) => {
      const store = new ExpoKeyStore()
      const entry = store.entry(keyID)
      expect(entry.keyID).toBe(keyID)
      expect(await entry.getAsync()).toBeNull()
      const key = await entry.provideAsync()
      expect(await entry.getAsync()).toEqual(key)
    },
  )

  test('provideIdentity returns a stable FullIdentity', async () => {
    const store = new ExpoKeyStore()
    const identity = await store.provideIdentity('user')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(store.provideIdentitySync('user').id).toBe(identity.id)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run from `packages/expo`: `pnpm exec vitest run test/conformance.test.ts` — expected: FAIL, `ExpoKeyStore is not a constructor`.

- [ ] **Step 3: Add the lock and sync remove to the entry**

In `packages/expo/src/entry.ts`: change the import to `MutableKeyEntry`, change the `implements` clause, add the in-process lock, and add the missing sync `remove()`:

```ts
import type { MutableKeyEntry } from '@kokuin/token'
```

```ts
export class ExpoKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #options?: StoreEntryOptions
  // Serializes provideAsync within this process. Expo runs a single app process, so there is
  // no cross-process race to guard — unlike node and electron.
  #provideLock: Promise<unknown> = Promise.resolve()
```

Replace `provideAsync` (lines 50-58) and add `remove` next to `removeAsync`:

```ts
  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => {
      const existing = await this.getAsync()
      if (existing != null) {
        return existing
      }
      const privateKey = await randomPrivateKeyAsync()
      await this.setAsync(privateKey)
      return privateKey
    })
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  remove(): void {
    SecureStore.deleteItemAsync(this.#keyID, this.#options)
  }
```

`expo-secure-store` exposes no sync delete, so `remove()` fires the async delete and does not await it. Document that:

```ts
  /**
   * Delete the key. `expo-secure-store` has no synchronous delete, so this starts the deletion
   * and returns immediately — use {@link removeAsync} when you need to know it completed.
   */
```

- [ ] **Step 4: Turn the store into a class**

Replace `packages/expo/src/store.ts`:

```ts
import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  createFullIdentity,
  type FullIdentity,
  type IdentityProvider,
  type KeyStore,
} from '@kokuin/token'
import { getLogger } from '@sozai/log'
import { withSpan, withSyncSpan } from '@sozai/otel'

import { ExpoKeyEntry, type StoreEntryOptions } from './entry.js'

const tracer = createTracer('keystore.expo')
const logger = getLogger(['kokuin', 'expo'])

export class ExpoKeyStore
  implements KeyStore<Uint8Array, ExpoKeyEntry>, IdentityProvider<FullIdentity>
{
  static #default?: ExpoKeyStore

  /** The process-wide store. `options` apply to every entry it creates. */
  static open(options?: StoreEntryOptions): ExpoKeyStore {
    ExpoKeyStore.#default ??= new ExpoKeyStore(options)
    return ExpoKeyStore.#default
  }

  #entries: Record<string, ExpoKeyEntry> = Object.create(null)
  #options?: StoreEntryOptions

  constructor(options?: StoreEntryOptions) {
    this.#options = options
  }

  /**
   * The entry for `keyID`, cached — `entry(x) === entry(x)`.
   *
   * The old object-literal store created a fresh entry per call, which silently defeated the
   * per-entry `provideAsync` lock, and took an undeclared second `options` argument that the
   * `KeyStore` type does not have. Options now belong to the store.
   */
  entry(keyID: string): ExpoKeyEntry {
    this.#entries[keyID] ??= new ExpoKeyEntry(keyID, this.#options)
    return this.#entries[keyID]
  }

  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
      async (span) => {
        const entry = this.entry(keyID)
        const existing = await entry.getAsync()
        const privateKey = existing ?? (await entry.provideAsync())
        const identity = createFullIdentity(privateKey)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, existing == null)
        if (existing == null) {
          logger.info('New identity generated: {did}', { did: identity.id })
        }
        return identity
      },
    )
  }

  /** {@link provideIdentity}, synchronously. Beyond the `IdentityProvider` contract. */
  provideIdentitySync(keyID: string): FullIdentity {
    return withSyncSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'expo' } },
      (span) => {
        const entry = this.entry(keyID)
        const existing = entry.get()
        const privateKey = existing ?? entry.provide()
        const identity = createFullIdentity(privateKey)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, existing == null)
        if (existing == null) {
          logger.info('New identity generated: {did}', { did: identity.id })
        }
        return identity
      },
    )
  }
}
```

- [ ] **Step 5: Delete `identity.ts` and update the index**

```bash
git rm packages/expo/src/identity.ts
```

`packages/expo/src/index.ts`:

```ts
/**
 * Key store for React Native.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/expo
 * ```
 *
 * @module expo-keystore
 */

export { ExpoKeyEntry, type StoreEntryOptions } from './entry.js'
export { ExpoKeyStore } from './store.js'
export { randomPrivateKey, randomPrivateKeyAsync } from './utils.js'
```

- [ ] **Step 6: Update `lib.test.ts`**

Replace `ExpoKeyStore.entry(id)` with `new ExpoKeyStore().entry(id)` (or `ExpoKeyStore.open().entry(id)`), and the free identity functions with `store.provideIdentity(id)` / `store.provideIdentitySync(id)`. Any call passing options as `entry(id, options)` moves the options to the constructor.

- [ ] **Step 7: Add the corrupt-credential cases**

Expo decodes base64 out of `expo-secure-store`, so it needs the same guard every decoding store does. Append to `packages/expo/test/conformance.test.ts`:

```ts
describe('corrupt credentials', () => {
  test('a non-base64 stored credential throws rather than yielding a bad key', async () => {
    secureStore.user = 'not!valid!base64!'
    await expect(new ExpoKeyStore().entry('user').getAsync()).rejects.toThrow()
  })

  test('a truncated key never becomes a silently wrong identity', async () => {
    secureStore.user = 'AAAAAAAAAAA=' // 8 bytes, not 32
    await expect(new ExpoKeyStore().provideIdentity('user')).rejects.toThrow()
  })
})
```

As in node: if the truncated-key case passes silently, that is a real finding about `createFullIdentity` accepting any length — raise it rather than weakening the test.

- [ ] **Step 8: Run tests and commit**

Run from `packages/expo`: `pnpm exec vitest run` and `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: PASS / clean.

```bash
git add packages/expo
git commit --no-verify -m "$(cat <<'EOF'
fix(expo)!: ExpoKeyStore becomes a class with a cached entry() and a lock

The object-literal store created a fresh entry per call, so entry(x) !== entry(x)
and the per-entry provideAsync lock could never work — and provideAsync had no
lock at all. entry() also took an undeclared second options argument the KeyStore
type does not have; options now belong to the store.

Adds the in-process provideAsync lock, the null-prototype entry cache, a sync
remove(), and ExpoKeyStore#provideIdentity replacing the free functions.
EOF
)"
```

---
