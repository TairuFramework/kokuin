import type { KeyEntry } from '@kokuin/token'

import { randomKeyPair } from './utils.js'

export type GetStore = (mode?: IDBTransactionMode) => IDBObjectStore

export class BrowserKeyEntry implements KeyEntry<CryptoKeyPair> {
  #getStore: GetStore
  #keyID: string

  constructor(keyID: string, getStore: GetStore) {
    this.#getStore = getStore
    this.#keyID = keyID
  }

  get keyID(): string {
    return this.#keyID
  }

  getAsync(): Promise<CryptoKeyPair | null> {
    return new Promise((resolve, reject) => {
      const request = this.#getStore().get(this.#keyID)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => resolve(request.result ?? null)
    })
  }

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
}
