import type { MutableKeyEntry } from '@kokuin/token'

import { generateKeyRecord, type StoredKeyRecord } from './utils.js'

export type GetStore = (mode?: IDBTransactionMode) => IDBObjectStore

export type BrowserKeyEntryParams = {
  keyID: string
  getStore: GetStore
}

export class BrowserKeyEntry implements MutableKeyEntry<StoredKeyRecord> {
  #getStore: GetStore
  #keyID: string

  constructor(params: BrowserKeyEntryParams) {
    this.#getStore = params.getStore
    this.#keyID = params.keyID
  }

  get keyID(): string {
    return this.#keyID
  }

  getAsync(): Promise<StoredKeyRecord | null> {
    return new Promise((resolve, reject) => {
      const request = this.#getStore().get(this.#keyID)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => resolve(request.result ?? null)
    })
  }

  setAsync(record: StoredKeyRecord): Promise<void> {
    return new Promise((resolve, reject) => {
      const store = this.#getStore('readwrite')
      const request = store.put(record, this.#keyID)
      request.onerror = () => reject(request.error)
      const tx = store.transaction
      tx.oncomplete = () => resolve()
      tx.onabort = () => reject(tx.error ?? new Error('Transaction aborted'))
      tx.onerror = () => reject(tx.error ?? new Error('Transaction failed'))
    })
  }

  provideAsync(): Promise<StoredKeyRecord> {
    return generateKeyRecord().then(
      (generated) =>
        new Promise<StoredKeyRecord>((resolve, reject) => {
          const store = this.#getStore('readwrite')
          const getRequest = store.get(this.#keyID)
          let result: StoredKeyRecord = generated
          getRequest.onerror = () => reject(getRequest.error)
          getRequest.onsuccess = () => {
            const existing = getRequest.result as StoredKeyRecord | undefined
            if (existing != null) {
              // A stored record ALWAYS wins over the freshly generated one — including a
              // legacy ES256 record. Overwriting it would change the identity's DID.
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
