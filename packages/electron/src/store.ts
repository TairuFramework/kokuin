import type { KeyStore } from '@kokuin/token'
import Store from 'electron-store'

import { ElectronKeyEntry } from './entry.js'
import type { KeyStorage } from './types.js'

type StoreValues = { keys: Record<string, string> }

export class ElectronKeyStore implements KeyStore<string, ElectronKeyEntry> {
  static #byName: Record<string, ElectronKeyStore> = Object.create(null)

  static open(name = 'keystore', options?: { allowInsecureStorage?: boolean }): ElectronKeyStore {
    if (ElectronKeyStore.#byName[name] == null) {
      ElectronKeyStore.#byName[name] = new ElectronKeyStore(
        name,
        options?.allowInsecureStorage ?? false,
      )
    }
    return ElectronKeyStore.#byName[name]
  }

  #entries: Record<string, ElectronKeyEntry> = Object.create(null)
  #storage: KeyStorage
  #allowInsecureStorage: boolean

  constructor(name: string, allowInsecureStorage = false) {
    this.#allowInsecureStorage = allowInsecureStorage
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
      getKeys: () => store.get('keys', {}),
      setKeys: (keys) => store.set('keys', keys),
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
}
