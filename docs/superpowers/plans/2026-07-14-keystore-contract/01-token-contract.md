## Task 1: token — the faceted storage contract and its conformance suite

The contract is only worth having if it is executable. This task ships both: the types, and a framework-agnostic suite that decides whether a backend honors them. Every later backend task consumes `keyStoreConformanceCases`.

**Files:**
- Modify: `packages/token/src/keystore.ts` (full rewrite, currently 14 lines)
- Create: `packages/token/src/conformance.ts`
- Modify: `packages/token/src/index.ts:72` (the `keystore.js` export line)
- Create: `packages/token/test/conformance.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type KeyEntry<PrivateKeyType> = { readonly keyID: string; getAsync(): Promise<PrivateKeyType | null>; provideAsync(): Promise<PrivateKeyType> }`
  - `type MutableKeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType> & { setAsync(privateKey: PrivateKeyType): Promise<void>; removeAsync(): Promise<void> }`
  - `type KeyStore<PrivateKeyType, EntryType extends KeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType>> = { entry(keyID: string): EntryType }`
  - `type KeyStoreConformanceHarness<PrivateKeyType>` — `{ createStore, isSameKey, neverAbsent?, keyIDs? }`
  - `type ConformanceCase = { name: string; run(): Promise<void> }`
  - `function keyStoreConformanceCases<T>(harness: KeyStoreConformanceHarness<T>): Array<ConformanceCase>`
  - `function mutableKeyStoreConformanceCases<T>(harness: MutableKeyStoreConformanceHarness<T>): Array<ConformanceCase>`

- [ ] **Step 1: Write the failing test**

Create `packages/token/test/conformance.test.ts`. It defines a correct in-memory reference store, runs the suite against it, and — critically — defines a *broken* store and asserts the suite rejects it. A conformance suite that cannot fail is decoration.

```ts
import { describe, expect, test } from 'vitest'

import {
  type ConformanceCase,
  keyStoreConformanceCases,
  mutableKeyStoreConformanceCases,
} from '../src/conformance.js'
import type { KeyStore, MutableKeyEntry } from '../src/keystore.js'

// --- A correct reference implementation ---

class MemoryKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #keys: Map<string, Uint8Array>
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor(keyID: string, keys: Map<string, Uint8Array>) {
    this.#keyID = keyID
    this.#keys = keys
  }

  get keyID(): string {
    return this.#keyID
  }

  async getAsync(): Promise<Uint8Array | null> {
    return this.#keys.get(this.#keyID) ?? null
  }

  async setAsync(privateKey: Uint8Array): Promise<void> {
    this.#keys.set(this.#keyID, privateKey)
  }

  provideAsync(): Promise<Uint8Array> {
    const run = this.#provideLock.then(async () => {
      const existing = await this.getAsync()
      if (existing != null) {
        return existing
      }
      const privateKey = crypto.getRandomValues(new Uint8Array(32))
      await this.setAsync(privateKey)
      return privateKey
    })
    this.#provideLock = run.catch(() => undefined)
    return run
  }

  async removeAsync(): Promise<void> {
    this.#keys.delete(this.#keyID)
  }
}

class MemoryKeyStore implements KeyStore<Uint8Array, MemoryKeyEntry> {
  #entries: Record<string, MemoryKeyEntry> = Object.create(null)
  #keys = new Map<string, Uint8Array>()

  entry(keyID: string): MemoryKeyEntry {
    this.#entries[keyID] ??= new MemoryKeyEntry(keyID, this.#keys)
    return this.#entries[keyID]
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

// --- Broken implementations the suite MUST reject ---

/** Returns the wrong keyID — the deterministic package's real bug. */
class WrongKeyIDStore extends MemoryKeyStore {
  entry(keyID: string): MemoryKeyEntry {
    return super.entry(`prefixed/${keyID}`)
  }
}

/** Every keyID shares one key — the electron "two keys in one store" bug, inverted. */
class SharedKeyStore implements KeyStore<Uint8Array, MemoryKeyEntry> {
  #keys = new Map<string, Uint8Array>()
  entry(keyID: string): MemoryKeyEntry {
    return new MemoryKeyEntry(keyID, this.#keys) // no cache AND one shared slot
  }
}

/** No lock: concurrent provideAsync generates two keys and loses one. */
class RacyKeyEntry extends MemoryKeyEntry {
  async provideAsync(): Promise<Uint8Array> {
    const existing = await this.getAsync()
    if (existing != null) {
      return existing
    }
    await new Promise((resolve) => setTimeout(resolve, 0)) // widen the window
    const privateKey = crypto.getRandomValues(new Uint8Array(32))
    await this.setAsync(privateKey)
    return privateKey
  }
}

class RacyKeyStore implements KeyStore<Uint8Array, RacyKeyEntry> {
  #entries: Record<string, RacyKeyEntry> = Object.create(null)
  #keys = new Map<string, Uint8Array>()
  entry(keyID: string): RacyKeyEntry {
    this.#entries[keyID] ??= new RacyKeyEntry(keyID, this.#keys)
    return this.#entries[keyID]
  }
}

async function runAll(cases: Array<ConformanceCase>): Promise<void> {
  for (const testCase of cases) {
    await testCase.run()
  }
}

describe('conformance suite', () => {
  test('a correct store passes every case', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new MemoryKeyStore(),
      isSameKey: sameBytes,
    })
    expect(cases.length).toBeGreaterThan(0)
    await runAll(cases)
  })

  test('a correct mutable store passes every mutable case', async () => {
    const cases = mutableKeyStoreConformanceCases({
      createStore: () => new MemoryKeyStore(),
      isSameKey: sameBytes,
      createKey: () => crypto.getRandomValues(new Uint8Array(32)),
    })
    expect(cases.length).toBeGreaterThan(0)
    await runAll(cases)
  })

  test('rejects a store whose entry() does not round-trip the keyID', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new WrongKeyIDStore(),
      isSameKey: sameBytes,
    })
    await expect(runAll(cases)).rejects.toThrow(/keyID/)
  })

  test('rejects a store where distinct keyIDs collide on one key', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new SharedKeyStore(),
      isSameKey: sameBytes,
    })
    await expect(runAll(cases)).rejects.toThrow()
  })

  test('rejects a store whose provideAsync races', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new RacyKeyStore(),
      isSameKey: sameBytes,
    })
    await expect(runAll(cases)).rejects.toThrow(/concurrent/i)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run from `packages/token`: `pnpm exec vitest run test/conformance.test.ts`

Expected: FAIL — `Failed to resolve import "../src/conformance.js"`.

- [ ] **Step 3: Rewrite the contract**

Replace `packages/token/src/keystore.ts` entirely. `setAsync` / `removeAsync` move out of `KeyEntry` into `MutableKeyEntry`, so a derived backend simply does not have them rather than throwing from them.

```ts
/**
 * A single key slot in a {@link KeyStore}, identified by `keyID`.
 *
 * This is the **read/provide** facet — the floor every backend can honor, including ones
 * that derive keys rather than store them (HD) or never expose key material at all.
 * A backend that can also write and delete implements {@link MutableKeyEntry}.
 *
 * ## Invariants
 *
 * Enforced by `keyStoreConformanceCases`. A backend that cannot satisfy these does not
 * implement this type — it exposes a different surface instead.
 *
 * 1. **keyID round-trips.** `store.entry(x).keyID === x`, always.
 * 2. **Absent means `null`.** {@link getAsync} resolves `null` when no key exists. Never
 *    `undefined`, never a throw. A *derived* backend may never return `null` at all —
 *    it can always produce a key — and that is contract-legal.
 * 3. **{@link provideAsync} is idempotent under concurrency.** Two concurrent calls on one
 *    keyID resolve to the *same* key. Never two keys; never a key that is generated,
 *    returned to a caller, and then overwritten by a racer.
 */
export type KeyEntry<PrivateKeyType> = {
  /** The keyID this entry was created for. Identical to the string passed to `entry()`. */
  readonly keyID: string
  /** The stored key, or `null` when none exists. Never `undefined`; never throws for absence. */
  getAsync(): Promise<PrivateKeyType | null>
  /**
   * The stored key, generating and persisting one if absent.
   *
   * Idempotent under concurrency: racing callers converge on a single key. Backends that
   * share storage across processes need a cross-process lock to hold this (see `lockPath`
   * on `NodeKeyStore` / `ElectronKeyStore`); an in-process promise chain is not enough.
   */
  provideAsync(): Promise<PrivateKeyType>
}

/**
 * A {@link KeyEntry} on a backend that can also **write and delete** key material.
 *
 * HD and ledger backends deliberately do NOT implement this: an HD key is derived (there is
 * nothing to set, and removing it does not stop it being derivable), and a ledger key never
 * leaves the device. Previously they "conformed" by throwing from `setAsync` and silently
 * no-op'ing `removeAsync` — the type now says what the substrate can do, so there is nothing
 * to throw from.
 */
export type MutableKeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType> & {
  /** Persist `privateKey` under this entry's keyID, replacing any existing key. */
  setAsync(privateKey: PrivateKeyType): Promise<void>
  /** Delete this entry's key. Idempotent — removing an absent key resolves, it does not throw. */
  removeAsync(): Promise<void>
}

/**
 * A keyed collection of {@link KeyEntry}s.
 *
 * Parameterized by entry type, so a writable backend is `KeyStore<T, MutableKeyEntry<T>>`
 * and a derived one is `KeyStore<T, KeyEntry<T>>`. No separate mutable store type is needed.
 *
 * Most consumers should NOT be generic over this — they should be generic over
 * `IdentityProvider`, which is what "give me an identity for this keyID" actually needs.
 * `KeyStore` is the *storage* contract, useful to backend authors and to the conformance
 * suite. A backend whose key never leaves the device (ledger) implements `IdentityProvider`
 * and neither storage type; that is the contract working, not a gap.
 */
export type KeyStore<
  PrivateKeyType,
  EntryType extends KeyEntry<PrivateKeyType> = KeyEntry<PrivateKeyType>,
> = {
  /**
   * The entry for `keyID`.
   *
   * Must be **cached**: `store.entry(x) === store.entry(x)`. Entries carry per-entry
   * concurrency state (the `provideAsync` lock), so handing out a fresh entry per call
   * silently defeats it.
   */
  entry(keyID: string): EntryType
}
```

- [ ] **Step 4: Write the conformance suite**

Create `packages/token/src/conformance.ts`. It imports **no test framework** — each case is a plain async function that throws on violation. That is what lets vitest (here), node:test (e2e), or any third-party backend's runner drive it.

```ts
import type { KeyEntry, KeyStore, MutableKeyEntry } from './keystore.js'

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

export type MutableKeyStoreConformanceHarness<PrivateKeyType> =
  KeyStoreConformanceHarness<PrivateKeyType> & {
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
        assert(
          created.entry(keyIDA) === created.entry(keyIDA),
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
```

- [ ] **Step 5: Export from the package index**

In `packages/token/src/index.ts`, replace the single `keystore.js` export line (currently line 72, `export type { KeyEntry, KeyStore } from './keystore.js'`) with both modules. Keep the file's alphabetical-by-module ordering: `conformance.js` sorts before `did.js`, so insert it after the `cache.js` block.

Add after the `cache.js` export block:

```ts
export {
  type ConformanceCase,
  keyStoreConformanceCases,
  type KeyStoreConformanceHarness,
  mutableKeyStoreConformanceCases,
  type MutableKeyStoreConformanceHarness,
} from './conformance.js'
```

And replace the `keystore.js` line with:

```ts
export type { KeyEntry, KeyStore, MutableKeyEntry } from './keystore.js'
```

- [ ] **Step 6: Run the tests**

Run from `packages/token`:
- `pnpm exec vitest run test/conformance.test.ts` — expected: PASS (5 tests).
- `pnpm exec vitest run` — expected: PASS. Nothing else in `token` imports `keystore.ts`, so removing `setAsync`/`removeAsync` from `KeyEntry` breaks nothing here. It **will** break the five backends; they are fixed in Tasks 3–11 and are not built by this command.
- `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: clean.

- [ ] **Step 7: Commit**

The repo-wide `build:types` in the pre-commit hook will now fail on the backends, which still `implements KeyEntry` with `setAsync`/`removeAsync`. That is expected and is fixed by Tasks 3–11. Use `--no-verify` for this one commit, and note it in the message.

```bash
git add packages/token/src/keystore.ts packages/token/src/conformance.ts packages/token/src/index.ts packages/token/test/conformance.test.ts
git commit --no-verify -m "$(cat <<'EOF'
feat(token)!: faceted KeyEntry/MutableKeyEntry contract + conformance suite

Splits the write/delete facet out of KeyEntry so derived (HD) and
identity-only (ledger) backends stop "conforming" by throwing and no-op'ing.
Adds a framework-agnostic conformance suite pinning the invariants.

Backends do not compile until they are migrated (Tasks 3-11), so this commit
skips the repo-wide build:types hook.
EOF
)"
```

---

