# Keystore Correctness Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Stage:** planning
**Mode:** tasks
**Spec:** `docs/superpowers/specs/2026-07-07-keystore-correctness-fixes-design.md`

**Goal:** Fix six data-loss, concurrency, and safety bugs in the per-runtime keystores (`@kokuin/electron`, `@kokuin/browser`, `@kokuin/node`) that can irrecoverably destroy an identity.

**Architecture:** Each keystore package implements the `KeyEntry`/`KeyStore` contract from `@kokuin/token` over a runtime-specific backend (electron-store, IndexedDB, OS keyring). Fixes are localized to each package's `entry.ts`/`store.ts`; no contract change. Every fix is TDD — a regression test reproducing the bug lands first, then the minimal fix.

**Tech Stack:** TypeScript (ESM), vitest, biome, pnpm. `@napi-rs/keyring` (node), `electron-store` + `safeStorage` (electron), IndexedDB + SubtleCrypto (browser).

## Global Constraints

- `type` not `interface`; `Array<T>` not `T[]`; never `any`; capital `ID`/`HTTP`/`JWT`.
- ES `#fields`, never `private`/`readonly` on class members.
- Do NOT edit generated files (`lib/`). Source is `src/`, tests are `test/`.
- pnpm only. Run tests via `pnpm --filter <pkg> exec vitest run <file>` to bypass the local `rtk` shim.
- Tests must NOT import `@enkaku`/`@kumiai` (upward deps); `@sozai`/`@kokuin` deps OK.
- Commit after each task's tests pass.

---

### Task 1: Electron `set()` read-spread-write (Critical #4)

**Files:**
- Modify: `packages/electron/src/entry.ts:56-60` (`set()`)
- Test: `packages/electron/test/lib.test.ts` (add to `describe('ElectronKeyEntry')`)

**Interfaces:**
- Consumes: `KeyStorage` (`packages/electron/src/types.ts`) — `getKeys(): Record<string, string>`, `setKeys(keys): void`.
- Produces: no signature change; `set()` now merges rather than replaces.

- [ ] **Step 1: Write the failing test**

Add inside `describe('ElectronKeyEntry')` in `packages/electron/test/lib.test.ts`. Both entries must share ONE store (the existing `createEntry` helper builds a store per keyID, so open a shared store here):

```ts
test('set() preserves other keys in the same store', () => {
  const store = ElectronKeyStore.open('multi-key')
  const a = store.entry('key-a')
  const b = store.entry('key-b')
  a.set('secret-a')
  b.set('secret-b')
  expect(a.get()).toBe('secret-a')
  expect(b.get()).toBe('secret-b')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/electron exec vitest run test/lib.test.ts -t "preserves other keys"`
Expected: FAIL — `a.get()` returns `null` (the `b.set` wholesale write dropped `key-a`).

- [ ] **Step 3: Write minimal implementation**

Replace `set()` in `packages/electron/src/entry.ts`:

```ts
  set(key: string): void {
    const encrypted = encryptKey(key)
    const keys = this.#storage.getKeys()
    keys[this.#keyID] = encrypted
    this.#storage.setKeys(keys)
    this.#key = key
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @kokuin/electron exec vitest run test/lib.test.ts`
Expected: PASS (all existing tests still green).

- [ ] **Step 5: Commit**

```bash
git add packages/electron/src/entry.ts packages/electron/test/lib.test.ts
git commit -m "fix(electron): set() must not clobber other keys in the store"
```

---

### Task 2: Electron encryption-availability gate (High)

**Files:**
- Modify: `packages/electron/src/entry.ts` (add availability check to writes, add `allowInsecureStorage` field)
- Modify: `packages/electron/src/store.ts` (thread `allowInsecureStorage` from `open`/constructor into entries)
- Test: `packages/electron/test/lib.test.ts` (new `describe` block + extend the `electron` mock)

**Interfaces:**
- Consumes: `safeStorage.isEncryptionAvailable(): boolean` from `electron`.
- Produces:
  - `ElectronKeyStore.open(name?: string, options?: { allowInsecureStorage?: boolean }): ElectronKeyStore`
  - `new ElectronKeyEntry(storage: KeyStorage, keyID: string, key?: string, allowInsecureStorage?: boolean)`
  - Writes throw `Error` when `!isEncryptionAvailable()` and `allowInsecureStorage !== true`.

- [ ] **Step 1: Write the failing test**

First extend the `vi.mock('electron', ...)` at the top of `packages/electron/test/lib.test.ts` to expose a toggleable availability flag:

```ts
let encryptionAvailable = true
vi.mock('electron', () => ({
  safeStorage: {
    encryptString: vi.fn((str: string) => Buffer.from(str)),
    decryptString: vi.fn((buf: Buffer) => buf.toString()),
    isEncryptionAvailable: vi.fn(() => encryptionAvailable),
  },
}))
```

Add `encryptionAvailable = true` to the existing `beforeEach` so it resets. Then add a new describe block:

```ts
describe('ElectronKeyEntry encryption gate', () => {
  test('set() throws when encryption is unavailable', () => {
    encryptionAvailable = false
    const entry = ElectronKeyStore.open('gate-1').entry('k')
    expect(() => entry.set('secret')).toThrow(/encryption/i)
  })

  test('allowInsecureStorage bypasses the throw', () => {
    encryptionAvailable = false
    const entry = ElectronKeyStore.open('gate-2', { allowInsecureStorage: true }).entry('k')
    expect(() => entry.set('secret')).not.toThrow()
    expect(entry.get()).toBe('secret')
  })

  test('reads still work when encryption is unavailable', () => {
    const entry = ElectronKeyStore.open('gate-3').entry('k')
    entry.set('secret')
    encryptionAvailable = false
    expect(entry.get()).toBe('secret')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/electron exec vitest run test/lib.test.ts -t "encryption gate"`
Expected: FAIL — `set()` does not throw (no gate exists yet).

- [ ] **Step 3: Write minimal implementation**

In `packages/electron/src/entry.ts`, import `safeStorage` is already present. Add the field + constructor param + guard, and call the guard from `set` (which `provide` already routes through):

```ts
export class ElectronKeyEntry implements KeyEntry<string> {
  #keyID: string
  #key?: string
  #storage: KeyStorage
  #allowInsecureStorage: boolean

  constructor(storage: KeyStorage, keyID: string, key?: string, allowInsecureStorage = false) {
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
```

Add the guard as the first line of `set()`:

```ts
  set(key: string): void {
    this.#assertEncryptionAvailable()
    const encrypted = encryptKey(key)
    const keys = this.#storage.getKeys()
    keys[this.#keyID] = encrypted
    this.#storage.setKeys(keys)
    this.#key = key
  }
```

In `packages/electron/src/store.ts`, thread the option through:

```ts
  static open(name = 'keystore', options?: { allowInsecureStorage?: boolean }): ElectronKeyStore {
    if (ElectronKeyStore.#byName[name] == null) {
      ElectronKeyStore.#byName[name] = new ElectronKeyStore(name, options?.allowInsecureStorage ?? false)
    }
    return ElectronKeyStore.#byName[name]
  }

  #entries: Record<string, ElectronKeyEntry> = {}
  #storage: KeyStorage
  #allowInsecureStorage: boolean

  constructor(name: string, allowInsecureStorage = false) {
    this.#allowInsecureStorage = allowInsecureStorage
    // ...existing Store setup unchanged...
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
```

Note: keep the existing `Store<StoreValues>` construction inside the constructor exactly as-is; only add the `#allowInsecureStorage` assignment before it and the constructor param.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @kokuin/electron exec vitest run test/lib.test.ts`
Expected: PASS (all existing tests green — the default `isEncryptionAvailable` mock returns `true`).

- [ ] **Step 5: Commit**

```bash
git add packages/electron/src/entry.ts packages/electron/src/store.ts packages/electron/test/lib.test.ts
git commit -m "fix(electron): refuse to persist keys when safeStorage encryption is unavailable"
```

---

### Task 3: Browser `setAsync`/`removeAsync` resolve on commit (High)

**Files:**
- Modify: `packages/browser/src/entry.ts:28-34` (`setAsync`), `:46-52` (`removeAsync`)
- Test: `packages/browser/test/lib.test.ts` (upgrade `createMockGetStore` to model a transaction)

**Interfaces:**
- Consumes: `IDBObjectStore.transaction` (the `IDBTransaction` a store belongs to), with `oncomplete`/`onabort`/`onerror`.
- Produces: `setAsync`/`removeAsync` resolve on `transaction.oncomplete`, reject on `transaction.onabort`/`onerror`. No signature change.

- [ ] **Step 1: Write the failing test**

Upgrade `createMockGetStore` in `packages/browser/test/lib.test.ts` so each store carries a `transaction` whose `oncomplete` fires a microtask AFTER the request's `onsuccess`, and add an abort path. Replace the helper with:

```ts
function createMockGetStore(): {
  getStore: GetStore
  data: Map<string, unknown>
  abortNextWrite: () => void
} {
  const data = new Map<string, unknown>()
  let abortNext = false

  const getStore: GetStore = () => {
    const tx: Record<string, unknown> = {}
    const finish = (aborted: boolean) => {
      queueMicrotask(() => {
        if (aborted) (tx.onabort as (e: Event) => void)?.({} as Event)
        else (tx.oncomplete as (e: Event) => void)?.({} as Event)
      })
    }
    const store = {
      transaction: tx,
      get(key: string) {
        const result = data.get(key)
        const request: Record<string, unknown> = { result }
        queueMicrotask(() => (request.onsuccess as (e: Event) => void)?.({} as Event))
        finish(false)
        return request as unknown as IDBRequest
      },
      put(value: unknown, key: string) {
        const aborted = abortNext
        abortNext = false
        if (!aborted) data.set(key, value)
        const request: Record<string, unknown> = {}
        queueMicrotask(() => (request.onsuccess as (e: Event) => void)?.({} as Event))
        finish(aborted)
        return request as unknown as IDBRequest
      },
      delete(key: string) {
        data.delete(key)
        const request: Record<string, unknown> = {}
        queueMicrotask(() => (request.onsuccess as (e: Event) => void)?.({} as Event))
        finish(false)
        return request as unknown as IDBRequest
      },
    }
    tx.objectStore = () => store
    return store as unknown as IDBObjectStore
  }

  return { getStore, data, abortNextWrite: () => (abortNext = true) }
}
```

Add a test asserting a post-success abort rejects (the whole point — the old code would have resolved):

```ts
test('setAsync rejects when the transaction aborts after the request succeeds', async () => {
  const { getStore, data, abortNextWrite } = createMockGetStore()
  const entry = new BrowserKeyEntry('k', getStore)
  const keyPair = await randomKeyPair()
  abortNextWrite()
  await expect(entry.setAsync(keyPair)).rejects.toThrow()
  expect(data.has('k')).toBe(false)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/browser exec vitest run test/lib.test.ts -t "aborts after the request succeeds"`
Expected: FAIL — old `setAsync` resolves on `request.onsuccess`, so the promise resolves instead of rejecting.

- [ ] **Step 3: Write minimal implementation**

Rewrite `setAsync` and `removeAsync` in `packages/browser/src/entry.ts` to resolve on the transaction:

```ts
  setAsync(keyPair: CryptoKeyPair): Promise<void> {
    return new Promise((resolve, reject) => {
      const store = this.#getStore('readwrite')
      const request = store.put(keyPair, this.#keyID)
      request.onerror = () => reject(request.error)
      const tx = store.transaction
      tx.oncomplete = () => resolve()
      tx.onabort = () => reject(tx.error ?? new Error('Transaction aborted'))
      tx.onerror = () => reject(tx.error ?? new Error('Transaction failed'))
    })
  }

  removeAsync(): Promise<void> {
    return new Promise((resolve, reject) => {
      const store = this.#getStore('readwrite')
      const request = store.delete(this.#keyID)
      request.onerror = () => reject(request.error)
      const tx = store.transaction
      tx.oncomplete = () => resolve()
      tx.onabort = () => reject(tx.error ?? new Error('Transaction aborted'))
      tx.onerror = () => reject(tx.error ?? new Error('Transaction failed'))
    })
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @kokuin/browser exec vitest run test/lib.test.ts`
Expected: PASS (existing set/remove tests still green — `oncomplete` fires after `onsuccess`).

- [ ] **Step 5: Commit**

```bash
git add packages/browser/src/entry.ts packages/browser/test/lib.test.ts
git commit -m "fix(browser): resolve setAsync/removeAsync on transaction commit, not request success"
```

---

### Task 4: Browser `provideAsync` atomic get-else-put (High)

**Files:**
- Modify: `packages/browser/src/entry.ts:36-44` (`provideAsync`)
- Test: `packages/browser/test/lib.test.ts`

**Interfaces:**
- Consumes: `randomKeyPair()` from `packages/browser/src/utils.js`; the mock store from Task 3.
- Produces: `provideAsync` generates the keypair first, then a single `readwrite` transaction does get-else-put. No signature change.

- [ ] **Step 1: Write the failing test**

The deterministic property: if a value already exists when `provideAsync` reaches the store, it must return the existing value and NOT overwrite it (the discard-generated branch). Pre-seed the store:

```ts
test('provideAsync returns the pre-existing key and does not overwrite it', async () => {
  const { getStore, data } = createMockGetStore()
  const seeded = await randomKeyPair()
  data.set('k', seeded)
  const entry = new BrowserKeyEntry('k', getStore)
  const result = await entry.provideAsync()
  expect(result).toBe(seeded)
  expect(data.get('k')).toBe(seeded)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/browser exec vitest run test/lib.test.ts -t "does not overwrite"`
Expected: it may already pass on the trivial mock; if so, this test still locks the behavior in. The real regression it guards (two separate transactions) cannot be reproduced by the synchronous mock — note that in the commit body. Proceed to Step 3 regardless.

- [ ] **Step 3: Write minimal implementation**

Replace `provideAsync` in `packages/browser/src/entry.ts`. Generate first, then one transaction, using an explicit `get` request inside a `readwrite` store and putting only on miss:

```ts
  provideAsync(): Promise<CryptoKeyPair> {
    return randomKeyPair().then(
      (generated) =>
        new Promise<CryptoKeyPair>((resolve, reject) => {
          const store = this.#getStore('readwrite')
          const getRequest = store.get(this.#keyID)
          let result: CryptoKeyPair = generated
          getRequest.onerror = () => reject(getRequest.error)
          getRequest.onsuccess = () => {
            const existing = getRequest.result as CryptoKeyPair | undefined
            if (existing != null) {
              result = existing
            } else {
              store.put(generated, this.#keyID)
            }
          }
          const tx = store.transaction
          tx.oncomplete = () => resolve(result)
          tx.onabort = () => reject(tx.error ?? new Error('Transaction aborted'))
          tx.onerror = () => reject(tx.error ?? new Error('Transaction failed'))
        }),
    )
  }
```

Note for the implementer: because IDB serializes `readwrite` transactions on the same object store, two concurrent `provideAsync` calls run their get-else-put atomically — the second sees the first's write and returns it. This is the cross-tab-safe guarantee the design relies on; do not reintroduce a separate get transaction before the put.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @kokuin/browser exec vitest run test/lib.test.ts`
Expected: PASS (including the existing `provideAsync generates key when none exists` test).

- [ ] **Step 5: Commit**

```bash
git add packages/browser/src/entry.ts packages/browser/test/lib.test.ts
git commit -m "fix(browser): make provideAsync atomic via a single get-else-put transaction"
```

---

### Task 5: Node `provideAsync` in-process mutex (High)

**Files:**
- Modify: `packages/node/src/entry.ts` (add per-entry async mutex around `provideAsync`; document cross-process limit)
- Test: `packages/node/test/lib.test.ts`

**Interfaces:**
- Consumes: existing `getAsync`/`setAsync`/`randomPrivateKey`.
- Produces: `provideAsync` serialized per entry instance; concurrent calls resolve to the same key. No signature change. (Sync `provide()` is single-threaded already — unchanged.)

- [ ] **Step 1: Write the failing test**

The node mock keyring's async get/set resolve on microtasks, so two un-serialized `provideAsync` calls interleave and generate two different keys. Assert they agree:

```ts
test('concurrent provideAsync calls resolve to the same key', async () => {
  const entry = new NodeKeyEntry('svc', 'race')
  const [a, b, c] = await Promise.all([
    entry.provideAsync(),
    entry.provideAsync(),
    entry.provideAsync(),
  ])
  expect(a).toEqual(b)
  expect(b).toEqual(c)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/node exec vitest run test/lib.test.ts -t "same key"`
Expected: FAIL — the three calls each observe `null`, generate independently, and return different `Uint8Array`s.

- [ ] **Step 3: Write minimal implementation**

In `packages/node/src/entry.ts`, add a mutex field and wrap `provideAsync`. The mutex is a promise chain: each call awaits the previous one's completion before running its get-else-generate-set.

```ts
export class NodeKeyEntry implements KeyEntry<Uint8Array> {
  #async?: AsyncEntry
  #keyID: string
  #key?: Uint8Array
  #service: string
  #sync?: Entry
  // Serializes provideAsync within THIS process. A cross-process race on the OS
  // keyring remains possible: @napi-rs/keyring exposes no compare-and-set, so two
  // processes can still both observe null and generate. Not solvable here.
  #provideLock: Promise<unknown> = Promise.resolve()
```

Replace `provideAsync`:

```ts
  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => {
      const existing = await this.getAsync()
      if (existing != null) {
        return existing
      }
      const privateKey = randomPrivateKey()
      await this.setAsync(privateKey)
      return privateKey
    })
    // Keep the chain alive even if this call rejects, so a failure does not wedge the lock.
    this.#provideLock = run.catch(() => undefined)
    return run
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @kokuin/node exec vitest run test/lib.test.ts`
Expected: PASS (existing provideAsync tests green).

- [ ] **Step 5: Commit**

```bash
git add packages/node/src/entry.ts packages/node/test/lib.test.ts
git commit -m "fix(node): serialize provideAsync per entry to close the in-process check-then-set race"
```

---

### Task 6: Node `list()` lazy decode (Medium)

**Files:**
- Modify: `packages/node/src/store.ts:24-31` (`#toEntry`), `packages/node/src/entry.ts` (accept encoded string, decode lazily)
- Test: `packages/node/test/lib.test.ts`

**Interfaces:**
- Consumes: `Credential` (`{ account: string; password: string }`) from `@napi-rs/keyring`.
- Produces: `#toEntry` passes the raw encoded `password` to `NodeKeyEntry`; decode deferred to first `get()`/`getAsync()`. Constructor accepts an already-encoded string instead of a decoded `Uint8Array`.

- [ ] **Step 1: Write the failing test**

A corrupt (non-base64) credential must not abort `list()`; the good entry must still decode:

```ts
test('list() tolerates a corrupt credential and still returns the good one', () => {
  mockKeyring['good'] = toB64(new Uint8Array([1, 2, 3]))
  mockKeyring['corrupt'] = '!!!not-base64!!!'
  const store = NodeKeyStore.open('svc')
  const entries = store.list()
  expect(entries.map((e) => e.keyID).sort()).toEqual(['corrupt', 'good'])
  const good = entries.find((e) => e.keyID === 'good')
  expect(good?.get()).toEqual(new Uint8Array([1, 2, 3]))
})
```

Add `toB64` to the existing `@sozai/codec` import at the top of the test file if not present:

```ts
import { toB64 } from '@sozai/codec'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @kokuin/node exec vitest run test/lib.test.ts -t "tolerates a corrupt credential"`
Expected: FAIL — `#toEntry` runs `fromB64('!!!not-base64!!!')` eagerly during `list()`, throwing before the array is returned.

- [ ] **Step 3: Write minimal implementation**

Change `NodeKeyEntry`'s constructor to take the encoded string and decode on demand. In `packages/node/src/entry.ts`:

```ts
  #encoded?: string

  constructor(service: string, keyID: string, encoded?: string) {
    this.#service = service
    this.#keyID = keyID
    this.#encoded = encoded
  }
```

Decode from `#encoded` on first access in both `get()` and `getAsync()` before hitting the keyring. Update `get()`:

```ts
  get(): Uint8Array | null {
    if (this.#key != null) {
      return this.#key
    }
    if (this.#encoded != null) {
      this.#key = fromB64(this.#encoded)
      this.#encoded = undefined
      return this.#key
    }
    const encoded = this.#syncEntry.getPassword()
    if (encoded == null) {
      return null
    }
    this.#key = fromB64(encoded)
    return this.#key
  }
```

And `getAsync()`:

```ts
  async getAsync(): Promise<Uint8Array | null> {
    if (this.#key != null) {
      return this.#key
    }
    if (this.#encoded != null) {
      this.#key = fromB64(this.#encoded)
      this.#encoded = undefined
      return this.#key
    }
    const encoded = await this.#asyncEntry.getPassword()
    if (encoded == null) {
      return null
    }
    this.#key = fromB64(encoded)
    return this.#key
  }
```

In `packages/node/src/store.ts`, stop decoding in `#toEntry` and drop the now-unused `fromB64` import:

```ts
  #toEntry(credential: Credential): NodeKeyEntry {
    this.#entries[credential.account] ??= new NodeKeyEntry(
      this.#service,
      credential.account,
      credential.password,
    )
    return this.#entries[credential.account]
  }
```

Remove `fromB64` from the `@sozai/codec` import in `store.ts` (it is no longer referenced there).

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @kokuin/node exec vitest run test/lib.test.ts`
Expected: PASS (existing node tests green; `set()`/`get()` roundtrip unaffected).

- [ ] **Step 5: Commit**

```bash
git add packages/node/src/entry.ts packages/node/src/store.ts packages/node/test/lib.test.ts
git commit -m "fix(node): defer credential decode to first get so one corrupt entry can't break list()"
```

---

### Task 7: Prototype-safe caches across all three packages (Medium)

**Files:**
- Modify: `packages/node/src/store.ts` (`#byService`, `#entries`)
- Modify: `packages/browser/src/store.ts` (`#byName`, `#entries`)
- Modify: `packages/electron/src/store.ts` (`#byName`, `#entries`)
- Test: one test per package's `test/lib.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: every cache object is `Object.create(null)`, so caller strings like `'constructor'`/`'__proto__'` cannot collide with prototype members. No signature change.

- [ ] **Step 1: Write the failing tests**

Node — add to `describe('NodeKeyStore')` (create it if absent):

```ts
test('entry("constructor") returns a real entry, not a prototype member', () => {
  const store = NodeKeyStore.open('proto-svc')
  const entry = store.entry('constructor')
  expect(entry).toBeInstanceOf(NodeKeyEntry)
  expect(entry.keyID).toBe('constructor')
})
```

Browser — add to `describe('BrowserKeyStore')` (uses the same mock IDB `open` as existing store tests; if store tests are fully mocked out, place this on a directly constructed store via the existing pattern in the file):

```ts
test('entry("constructor") returns a real entry, not a prototype member', () => {
  const store = new BrowserKeyStore(makeMockDb())
  const entry = store.entry('constructor')
  expect(entry).toBeInstanceOf(BrowserKeyEntry)
  expect(entry.keyID).toBe('constructor')
})
```

If `BrowserKeyStore`/`makeMockDb` are not already imported/available in the test file, use the file's existing store-construction helper instead; the assertion (real entry, not `Object`) is the point.

Electron — add to `describe('ElectronKeyStore')`:

```ts
test('entry("constructor") returns a real entry, not a prototype member', () => {
  const store = ElectronKeyStore.open('proto-electron')
  const entry = store.entry('constructor')
  expect(entry.keyID).toBe('constructor')
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run each:
```
pnpm --filter @kokuin/node exec vitest run test/lib.test.ts -t "prototype member"
pnpm --filter @kokuin/browser exec vitest run test/lib.test.ts -t "prototype member"
pnpm --filter @kokuin/electron exec vitest run test/lib.test.ts -t "prototype member"
```
Expected: FAIL — `#entries['constructor'] ??= …` sees the prototype's `constructor` (a function, non-nullish), never assigns, and returns it; `.keyID` is `undefined` / not the expected entry.

- [ ] **Step 3: Write minimal implementation**

In each `store.ts`, initialize both caches with `Object.create(null)`:

Node (`packages/node/src/store.ts`):
```ts
  static #byService: Record<string, NodeKeyStore> = Object.create(null)
  // ...
  #entries: Record<string, NodeKeyEntry> = Object.create(null)
```

Browser (`packages/browser/src/store.ts`):
```ts
  static #byName: Record<string, Promise<BrowserKeyStore>> = Object.create(null)
  // ...
  #entries: Record<string, BrowserKeyEntry> = Object.create(null)
```

Electron (`packages/electron/src/store.ts`):
```ts
  static #byName: Record<string, ElectronKeyStore> = Object.create(null)
  // ...
  #entries: Record<string, ElectronKeyEntry> = Object.create(null)
```

- [ ] **Step 4: Run tests to verify they pass**

Run the full suite per package:
```
pnpm --filter @kokuin/node exec vitest run test/lib.test.ts
pnpm --filter @kokuin/browser exec vitest run test/lib.test.ts
pnpm --filter @kokuin/electron exec vitest run test/lib.test.ts
```
Expected: PASS for all three.

- [ ] **Step 5: Commit**

```bash
git add packages/node/src/store.ts packages/browser/src/store.ts packages/electron/src/store.ts \
  packages/node/test/lib.test.ts packages/browser/test/lib.test.ts packages/electron/test/lib.test.ts
git commit -m "fix(keystore): use null-prototype caches so caller strings can't hit Object members"
```

---

## Final verification

- [ ] **Run all three package test suites + biome**

```bash
pnpm --filter @kokuin/electron exec vitest run
pnpm --filter @kokuin/browser exec vitest run
pnpm --filter @kokuin/node exec vitest run
pnpm exec biome check packages/electron packages/browser packages/node
```
Expected: all tests PASS; biome reports no errors.
