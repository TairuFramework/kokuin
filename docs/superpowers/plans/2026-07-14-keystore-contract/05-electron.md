## Task 6: electron — `Uint8Array` keys, `IdentityProvider`, prototype-pollution guard

Electron is the odd one out: `PrivateKeyType` is `string` (base64), so `decodePrivateKey` is threaded through `identity.ts` at four call sites. It also has the audit's **Critical #4** — two keyIDs colliding on one key — untested, and it lacks the prototype-pollution guard browser and node get from `Object.create(null)`.

The pollution bug is real and specific: `store.get('keys', {})` returns a plain `{}`-prototype object, so `keys['__proto__'] = encrypted` sets the *prototype* instead of creating an own property (the key is silently not stored), and `keys['constructor']` reads back `Object` — a function, not a string — which then goes to `decryptKey`.

**Files:**
- Modify: `packages/electron/src/types.ts` (null-prototype record)
- Modify: `packages/electron/src/entry.ts` (full rewrite — `Uint8Array`, `MutableKeyEntry`)
- Modify: `packages/electron/src/store.ts` (null-prototype keys, `provideIdentity`, absorb `identity.ts`)
- Delete: `packages/electron/src/identity.ts`
- Modify: `packages/electron/src/index.ts`
- Create: `packages/electron/test/conformance.test.ts`
- Modify: `packages/electron/test/lib.test.ts`

**Interfaces:**
- Consumes: `MutableKeyEntry`, `KeyStore`, `mutableKeyStoreConformanceCases` from `@kokuin/token` (Task 1).
- Produces:
  - `ElectronKeyEntry implements MutableKeyEntry<Uint8Array>` — plus sync `get()` / `set()` / `provide()` / `remove()`.
  - `ElectronKeyStore implements KeyStore<Uint8Array, ElectronKeyEntry>, IdentityProvider<FullIdentity>` with `provideIdentity` / `provideIdentitySync`.
  - `provideFullIdentity` / `provideFullIdentityAsync` **removed**.

- [ ] **Step 1: Write the failing test**

Create `packages/electron/test/conformance.test.ts`. Copy the `electron` and `electron-store` mocks from `lib.test.ts:1-33` verbatim (vitest mocks are per-module).

```ts
import { mutableKeyStoreConformanceCases } from '@kokuin/token'
import { beforeEach, describe, expect, test, vi } from 'vitest'

let encryptionAvailable = true
vi.mock('electron', () => ({
  safeStorage: {
    encryptString: vi.fn((str: string) => Buffer.from(str)),
    decryptString: vi.fn((buf: Buffer) => buf.toString()),
    isEncryptionAvailable: vi.fn(() => encryptionAvailable),
  },
}))

let storeData: Record<string, Record<string, string>>

vi.mock('electron-store', () => {
  class MockStore {
    name: string
    constructor(options: { name: string }) {
      this.name = options.name
    }
    get(key: string, defaultValue: Record<string, string> = {}) {
      return storeData[this.name]?.[key] != null
        ? JSON.parse(storeData[this.name][key])
        : defaultValue
    }
    set(key: string, value: unknown) {
      storeData[this.name] ??= {}
      storeData[this.name][key] = JSON.stringify(value)
    }
  }
  return { default: MockStore }
})

const { ElectronKeyStore } = await import('../src/store.js')

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

beforeEach(() => {
  storeData = {}
  encryptionAvailable = true
})

describe('ElectronKeyStore conformance', () => {
  let counter = 0
  const cases = mutableKeyStoreConformanceCases({
    createStore: () => new ElectronKeyStore(`conformance-${counter++}`),
    isSameKey: sameBytes,
    createKey: () => crypto.getRandomValues(new Uint8Array(32)),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('ElectronKeyStore adversarial input', () => {
  // The audit's Critical #4, never tested here until now.
  test('two keyIDs in one store get two distinct keys, and neither overwrites the other', async () => {
    const store = new ElectronKeyStore('two-keys')
    const alice = await store.entry('alice').provideAsync()
    const bob = await store.entry('bob').provideAsync()
    expect(alice).not.toEqual(bob)
    expect(await store.entry('alice').getAsync()).toEqual(alice)
    expect(await store.entry('bob').getAsync()).toEqual(bob)
  })

  test.each(['__proto__', 'constructor', 'prototype', 'toString'])(
    'the prototype-pollution keyID %j behaves as an ordinary key',
    async (keyID) => {
      const store = new ElectronKeyStore(`pollution-${keyID}`)
      const entry = store.entry(keyID)
      expect(entry.keyID).toBe(keyID)
      // Absent before it is provided — NOT a function inherited from Object.prototype.
      expect(await entry.getAsync()).toBeNull()

      const key = await entry.provideAsync()
      expect(key).toHaveLength(32)
      expect(await entry.getAsync()).toEqual(key)

      // And it did not corrupt the prototype of anything.
      expect(({} as Record<string, unknown>).polluted).toBeUndefined()
      expect(await store.entry('ordinary').getAsync()).toBeNull()
    },
  )

  test('a corrupt stored credential throws rather than yielding a bad key', async () => {
    const store = new ElectronKeyStore('corrupt')
    await store.entry('user').provideAsync()
    // Replace the ciphertext with something that is not valid base64.
    storeData.corrupt.keys = JSON.stringify({ user: 'not!valid!base64!' })
    const fresh = new ElectronKeyStore('corrupt')
    await expect(fresh.entry('user').getAsync()).rejects.toThrow()
  })
})

describe('ElectronKeyStore.provideIdentity', () => {
  test('returns a stable FullIdentity', async () => {
    const store = new ElectronKeyStore('identity')
    const first = await store.provideIdentity('user')
    expect(first.id).toMatch(/^did:key:z/)
    expect((await store.provideIdentity('user')).id).toBe(first.id)
    expect(store.provideIdentitySync('user').id).toBe(first.id)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run from `packages/electron`: `pnpm exec vitest run test/conformance.test.ts`

Expected: FAIL — keys are `string` not `Uint8Array` (so `sameBytes` and the length assertions fail), `provideIdentity` does not exist, and the `__proto__` / `constructor` cases fail against the plain-object storage.

- [ ] **Step 3: Make the storage record null-prototype**

Replace `packages/electron/src/types.ts`. A `Record<string, string>` read straight out of JSON carries `Object.prototype`, which is what makes `__proto__` and `constructor` dangerous as keyIDs.

```ts
/**
 * The persisted keyID → encrypted-key map.
 *
 * `getKeys` MUST return a **null-prototype** object. A plain `{}` inherits from
 * `Object.prototype`, so `keys['constructor']` reads back a function rather than `undefined`,
 * and `keys['__proto__'] = value` sets the prototype instead of creating an own property —
 * silently discarding the key. With a null prototype both behave as ordinary string keys.
 */
export type KeyStorage = {
  getKeys: () => Record<string, string>
  setKeys: (keys: Record<string, string>) => void
}
```

- [ ] **Step 4: Rewrite the entry around `Uint8Array`**

Replace `packages/electron/src/entry.ts`. Base64 encode/decode now lives *inside* the entry, so `PrivateKeyType` matches every other store and `decodePrivateKey` disappears from the identity path.

```ts
import type { MutableKeyEntry } from '@kokuin/token'
import { randomPrivateKey } from '@kokuin/token'
import { fromB64, toB64 } from '@sozai/codec'
import { safeStorage } from 'electron'

import type { KeyStorage } from './types.js'

/** Encrypt raw key bytes for storage: base64(safeStorage(base64(key))). */
function encryptKey(privateKey: Uint8Array): string {
  return toB64(safeStorage.encryptString(toB64(privateKey)))
}

function decryptKey(encrypted: string): Uint8Array {
  return fromB64(safeStorage.decryptString(Buffer.from(fromB64(encrypted))))
}

export class ElectronKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #key?: Uint8Array
  #storage: KeyStorage
  #allowInsecureStorage: boolean
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(
    storage: KeyStorage,
    keyID: string,
    key?: Uint8Array,
    allowInsecureStorage = false,
  ) {
    this.#keyID = keyID
    this.#key = key
    this.#storage = storage
    this.#allowInsecureStorage = allowInsecureStorage
  }

  #assertEncryptionAvailable(): void {
    if (!this.#allowInsecureStorage && !safeStorage.isEncryptionAvailable()) {
      throw new Error(
        'Electron safeStorage encryption is unavailable (e.g. Linux without a keyring); ' +
          'refusing to persist a plaintext-equivalent private key. ' +
          'Pass { allowInsecureStorage: true } to ElectronKeyStore.open to override.',
      )
    }
  }

  get keyID(): string {
    return this.#keyID
  }

  get(): Uint8Array | null {
    if (this.#key != null) {
      return this.#key
    }
    const encrypted = this.#storage.getKeys()[this.#keyID]
    if (encrypted == null) {
      return null
    }
    this.#key = decryptKey(encrypted)
    return this.#key
  }

  async getAsync(): Promise<Uint8Array | null> {
    return this.get()
  }

  set(privateKey: Uint8Array): void {
    this.#assertEncryptionAvailable()
    const keys = this.#storage.getKeys()
    keys[this.#keyID] = encryptKey(privateKey)
    this.#storage.setKeys(keys)
    this.#key = privateKey
  }

  async setAsync(privateKey: Uint8Array): Promise<void> {
    this.set(privateKey)
  }

  provide(): Uint8Array {
    const existing = this.get()
    if (existing != null) {
      return existing
    }
    const privateKey = randomPrivateKey()
    this.set(privateKey)
    return privateKey
  }

  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => this.provide())
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  remove(): void {
    const keys = this.#storage.getKeys()
    delete keys[this.#keyID]
    this.#storage.setKeys(keys)
    this.#key = undefined
  }

  async removeAsync(): Promise<void> {
    this.remove()
  }
}
```

Note `remove()` now mutates the null-prototype object with `delete` rather than the old rest-spread (`const { [id]: _, ...keys }`), which would have re-introduced an `Object.prototype`-backed object.

- [ ] **Step 5: Null-prototype storage + identity on the store**

Rewrite `packages/electron/src/store.ts`:

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
import Store from 'electron-store'

import { ElectronKeyEntry } from './entry.js'
import type { KeyStorage } from './types.js'

type StoreValues = { keys: Record<string, string> }

const tracer = createTracer('keystore.electron')
const logger = getLogger(['kokuin', 'electron'])

export type ElectronKeyStoreOptions = {
  allowInsecureStorage?: boolean
}

export class ElectronKeyStore
  implements KeyStore<Uint8Array, ElectronKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byName: Record<string, ElectronKeyStore> = Object.create(null)

  static open(name = 'keystore', options?: ElectronKeyStoreOptions): ElectronKeyStore {
    const cached = ElectronKeyStore.#byName[name]
    if (cached == null) {
      ElectronKeyStore.#byName[name] = new ElectronKeyStore(name, options)
      return ElectronKeyStore.#byName[name]
    }
    if (
      options?.allowInsecureStorage != null &&
      options.allowInsecureStorage !== cached.#allowInsecureStorage
    ) {
      throw new Error(
        `ElectronKeyStore.open('${name}') was already opened with allowInsecureStorage: ` +
          `${cached.#allowInsecureStorage}; cannot reopen with conflicting allowInsecureStorage: ` +
          `${options.allowInsecureStorage}.`,
      )
    }
    return cached
  }

  #entries: Record<string, ElectronKeyEntry> = Object.create(null)
  #storage: KeyStorage
  #allowInsecureStorage: boolean

  constructor(name: string, options?: ElectronKeyStoreOptions) {
    this.#allowInsecureStorage = options?.allowInsecureStorage ?? false
    const store = new Store<StoreValues>({
      name,
      schema: {
        keys: {
          type: 'object',
          properties: {
            key: { type: 'string' },
          },
        },
      },
      defaults: {
        keys: {},
      },
    })
    this.#storage = {
      // Copy onto a null prototype: the object electron-store hands back is JSON-derived and
      // inherits Object.prototype, which makes '__proto__' and 'constructor' hazardous keyIDs.
      getKeys: () => Object.assign(Object.create(null), store.get('keys', {})),
      setKeys: (keys) => store.set('keys', { ...keys }),
    }
  }

  entry(keyID: string): ElectronKeyEntry {
    this.#entries[keyID] ??= new ElectronKeyEntry(
      this.#storage,
      keyID,
      undefined,
      this.#allowInsecureStorage,
    )
    return this.#entries[keyID]
  }

  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'electron' } },
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
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'electron' } },
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

`setKeys` spreads back into a plain object because `electron-store` serializes to JSON; a null-prototype object round-trips through `JSON.stringify` identically, but the spread keeps the value it stores an ordinary one.

- [ ] **Step 6: Delete `identity.ts` and update the index**

```bash
git rm packages/electron/src/identity.ts
```

`packages/electron/src/index.ts`:

```ts
/**
 * Electron keystore.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/electron
 * ```
 *
 * @module electron-keystore
 */

export { ElectronKeyEntry } from './entry.js'
export { ElectronKeyStore, type ElectronKeyStoreOptions } from './store.js'
export type { KeyStorage } from './types.js'
```

- [ ] **Step 7: Update `lib.test.ts`**

In `packages/electron/test/lib.test.ts`: replace `provideFullIdentity(store, id)` → `store.provideIdentitySync(id)` and `await provideFullIdentityAsync(store, id)` → `await store.provideIdentity(id)`, and drop them from the import. Every assertion that expected a base64 **string** from `get`/`provide`/`set` now expects a `Uint8Array` — `expect(key).toHaveLength(32)` and `toEqual(otherBytes)` rather than string comparison.

- [ ] **Step 8: Run tests and commit**

Run from `packages/electron`:
- `pnpm exec vitest run` — expected: PASS.
- `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: clean.

```bash
git add packages/electron
git commit --no-verify -m "$(cat <<'EOF'
fix(electron)!: Uint8Array keys, IdentityProvider, prototype-pollution guard

- PrivateKeyType changes from base64 string to Uint8Array, matching every other
  store. Encoding moves inside the entry, deleting the decodePrivateKey calls
  threaded through identity.ts.
- provideFullIdentity/-Async are replaced by ElectronKeyStore#provideIdentity
  and #provideIdentitySync.
- The persisted key map is now null-prototype. It was JSON-derived and inherited
  Object.prototype, so keys['__proto__'] = value set the prototype instead of
  storing the key, and keys['constructor'] read back a function.
- Adds the "two keys in one store" test (audit Critical #4), never tested here.
EOF
)"
```

---

## Task 7: electron — opt-in cross-process lock via `lockPath`

`electron-store` is a plain JSON file, so two app instances race `provideAsync` exactly as two node processes do. Identical fix, and the conflict rule now covers both flags.

**Files:**
- Modify: `packages/electron/package.json` (dependency)
- Modify: `packages/electron/src/entry.ts` (lock-aware `provideAsync`, guard sync `provide`)
- Modify: `packages/electron/src/store.ts` (`lockPath` option + conflict rule)
- Create: `packages/electron/test/lock.test.ts`

**Interfaces:**
- Consumes: `withFileLock` from `@sozai/lock` (catalogued in Task 5).
- Produces: `ElectronKeyStoreOptions` gains `lockPath?: string`; `new ElectronKeyEntry(storage, keyID, key?, allowInsecureStorage?, lockPath?)`.

- [ ] **Step 1: Write the failing test**

Create `packages/electron/test/lock.test.ts` — same shape as `packages/node/test/lock.test.ts`. Copy the `electron` / `electron-store` mocks from `conformance.test.ts`, then:

```ts
describe('ElectronKeyStore lockPath', () => {
  test('provideAsync works with a lockPath set', async () => {
    const store = new ElectronKeyStore('lock-basic', { lockPath })
    expect(await store.entry('user').provideAsync()).toHaveLength(32)
  })

  test('concurrent provideAsync calls converge on one key', async () => {
    const store = new ElectronKeyStore('lock-concurrent', { lockPath })
    const entry = store.entry('user')
    const keys = await Promise.all([entry.provideAsync(), entry.provideAsync()])
    expect(keys[1]).toEqual(keys[0])
  })

  test('the sync provide() refuses to run under a lockPath', () => {
    const store = new ElectronKeyStore('lock-sync', { lockPath })
    expect(() => store.entry('user').provide()).toThrow(/lockPath/)
    expect(() => store.provideIdentitySync('user')).toThrow(/lockPath/)
  })

  test('no lockfile is left behind', async () => {
    const store = new ElectronKeyStore('lock-cleanup', { lockPath })
    await store.entry('user').provideAsync()
    const { existsSync } = await import('node:fs')
    expect(existsSync(lockPath)).toBe(false)
  })

  test('re-opening with a conflicting lockPath throws', () => {
    ElectronKeyStore.open('conflict', { lockPath })
    expect(() => ElectronKeyStore.open('conflict', { lockPath: `${lockPath}.other` })).toThrow(
      /lockPath/,
    )
  })
})
```

Use the same `beforeEach`/`afterEach` temp-directory setup as the node lock test (`mkdtemp` in `tmpdir()`, `rm` after).

- [ ] **Step 2: Run to verify it fails**

Run from `packages/electron`: `pnpm exec vitest run test/lock.test.ts` — expected: FAIL, `lockPath` is not a recognized option.

- [ ] **Step 3: Add the dependency**

In `packages/electron/package.json` `dependencies`, after `@sozai/codec`:

```json
    "@sozai/lock": "catalog:",
```

From the repo root: `pnpm install`

- [ ] **Step 4: Make the entry lock-aware**

In `packages/electron/src/entry.ts`, add `import { withFileLock } from '@sozai/lock'`, add a `#lockPath?: string` field taken as the fifth constructor argument, then replace `provide` and `provideAsync`:

```ts
  /**
   * The stored key, generating one if absent. Synchronous, and therefore **not** cross-process
   * safe. Throws when a `lockPath` is set rather than silently dropping the guarantee.
   */
  provide(): Uint8Array {
    if (this.#lockPath != null) {
      throw new Error(
        'ElectronKeyEntry.provide() cannot hold a cross-process lock: a file lock cannot be ' +
          'acquired synchronously. This store was opened with a lockPath — use provideAsync().',
      )
    }
    return this.#provideUnlocked()
  }

  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => {
      const lockPath = this.#lockPath
      if (lockPath == null) {
        return this.#provideUnlocked()
      }
      return await withFileLock(lockPath, async () => this.#provideUnlocked())
    })
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  /** Read-if-absent, generate, write. The caller owns exclusion. */
  #provideUnlocked(): Uint8Array {
    // Drop the in-memory cache: inside the lock we must see a peer's write, not our own
    // stale read. Without this the winner clobbers the peer's key.
    this.#key = undefined
    const existing = this.get()
    if (existing != null) {
      return existing
    }
    const privateKey = randomPrivateKey()
    this.set(privateKey)
    return privateKey
  }
```

- [ ] **Step 5: Thread `lockPath` through the store**

In `packages/electron/src/store.ts`, add `lockPath?: string` to `ElectronKeyStoreOptions` — reuse the JSDoc from `NodeKeyStoreOptions` (Task 5, Step 5) — add a `#lockPath?: string` field set in the constructor, pass it as the fifth argument to `new ElectronKeyEntry(...)` in `entry()`, and extend the `open` conflict check so it covers both flags:

```ts
    if (
      options?.allowInsecureStorage != null &&
      options.allowInsecureStorage !== cached.#allowInsecureStorage
    ) {
      throw new Error(
        `ElectronKeyStore.open('${name}') was already opened with allowInsecureStorage: ` +
          `${cached.#allowInsecureStorage}; cannot reopen with conflicting allowInsecureStorage: ` +
          `${options.allowInsecureStorage}.`,
      )
    }
    if (options?.lockPath != null && options.lockPath !== cached.#lockPath) {
      throw new Error(
        `ElectronKeyStore.open('${name}') was already opened with lockPath: ` +
          `${String(cached.#lockPath)}; cannot reopen with conflicting lockPath: ${options.lockPath}.`,
      )
    }
    return cached
```

- [ ] **Step 6: Run tests and commit**

Run from `packages/electron`: `pnpm exec vitest run` and `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: PASS / clean.

```bash
git add packages/electron pnpm-lock.yaml
git commit --no-verify -m "$(cat <<'EOF'
feat(electron): opt-in cross-process lock via lockPath

electron-store is a plain JSON file, so two app instances race provideAsync the
same way two node processes race the OS keychain, with the same silent key loss.
Same fix: a @sozai/lock file mutex around a critical section that re-reads inside
the lock.
EOF
)"
```

---

