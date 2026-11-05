import type { KeyStore, MutableKeyEntry } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import {
  type ConformanceCase,
  keyStoreConformanceCases,
  mutableKeyStoreConformanceCases,
} from '../src/index.js'

type MemoryKeyEntryParams = { keyID: string; keys: Map<string, Uint8Array> }
type CollidingKeyEntryParams = { keyID: string; keys: Map<string, Uint8Array>; slot: string }

// --- A correct reference implementation ---

class MemoryKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #keys: Map<string, Uint8Array>
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor({ keyID, keys }: MemoryKeyEntryParams) {
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
    this.#entries[keyID] ??= new MemoryKeyEntry({ keyID, keys: this.#keys })
    return this.#entries[keyID]
  }
}

function sameBytes({ a, b }: { a: Uint8Array; b: Uint8Array }): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

// --- Broken implementations the suite MUST reject ---

/** Returns the wrong keyID — the deterministic package's real bug. */
class WrongKeyIDStore extends MemoryKeyStore {
  entry(keyID: string): MemoryKeyEntry {
    return super.entry(`prefixed/${keyID}`)
  }
}

/**
 * Reports the correct keyID and caches entries correctly, but every entry reads and
 * writes the same underlying slot — the electron "two keys in one store" bug.
 */
class CollidingKeyEntry implements MutableKeyEntry<Uint8Array> {
  #keyID: string
  #keys: Map<string, Uint8Array>
  #slot: string
  #provideLock: Promise<unknown> = Promise.resolve()

  constructor({ keyID, keys, slot }: CollidingKeyEntryParams) {
    this.#keyID = keyID
    this.#keys = keys
    this.#slot = slot
  }

  get keyID(): string {
    return this.#keyID
  }

  async getAsync(): Promise<Uint8Array | null> {
    return this.#keys.get(this.#slot) ?? null
  }

  async setAsync(privateKey: Uint8Array): Promise<void> {
    this.#keys.set(this.#slot, privateKey)
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
    this.#keys.delete(this.#slot)
  }
}

class CollidingKeyStore implements KeyStore<Uint8Array, CollidingKeyEntry> {
  #entries: Record<string, CollidingKeyEntry> = Object.create(null)
  #keys = new Map<string, Uint8Array>()
  entry(keyID: string): CollidingKeyEntry {
    this.#entries[keyID] ??= new CollidingKeyEntry({
      keyID,
      keys: this.#keys,
      slot: 'shared-slot',
    })
    return this.#entries[keyID]
  }
}

/** Fresh entry object on every call — per-entry concurrency state (the provide lock) cannot survive. */
class UncachedEntryStore implements KeyStore<Uint8Array, MemoryKeyEntry> {
  #keys = new Map<string, Uint8Array>()
  entry(keyID: string): MemoryKeyEntry {
    return new MemoryKeyEntry({ keyID, keys: this.#keys })
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
    this.#entries[keyID] ??= new RacyKeyEntry({ keyID, keys: this.#keys })
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
      isSameKey: ({ a, b }) => sameBytes({ a, b }),
    })
    expect(cases.length).toBeGreaterThan(0)
    await runAll(cases)
  })

  test('a correct mutable store passes every mutable case', async () => {
    const cases = mutableKeyStoreConformanceCases({
      createStore: () => new MemoryKeyStore(),
      isSameKey: ({ a, b }) => sameBytes({ a, b }),
      createKey: () => crypto.getRandomValues(new Uint8Array(32)),
    })
    expect(cases.length).toBeGreaterThan(0)
    await runAll(cases)
  })

  test('rejects a store whose entry() does not round-trip the keyID', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new WrongKeyIDStore(),
      isSameKey: ({ a, b }) => sameBytes({ a, b }),
    })
    await expect(runAll(cases)).rejects.toThrow(/keyID/)
  })

  test('rejects a store where distinct keyIDs collide on one key', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new CollidingKeyStore(),
      isSameKey: ({ a, b }) => sameBytes({ a, b }),
    })
    await expect(runAll(cases)).rejects.toThrow(/same key|vanished/)
  })

  test('rejects a store whose entry() is not cached', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new UncachedEntryStore(),
      isSameKey: ({ a, b }) => sameBytes({ a, b }),
    })
    await expect(runAll(cases)).rejects.toThrow(/cached|different object/)
  })

  test('rejects a store whose provideAsync races', async () => {
    const cases = keyStoreConformanceCases({
      createStore: () => new RacyKeyStore(),
      isSameKey: ({ a, b }) => sameBytes({ a, b }),
    })
    await expect(runAll(cases)).rejects.toThrow(/concurrent/i)
  })
})
