import type { EncryptEntryResult, VaultEntryMetadata, WrapResult } from '@kokuin/vault'

export type KeyAddress = { ownerDID: string; keyID: string }
export type EntryAddress = { ownerDID: string; entryID: string }
export type WrappingAddress = { ownerDID: string; wrappingID: string }
export type KeyRow = KeyAddress & { suite: number; version: number; state: 'active' | 'retired' }
export type EntryMetadata = VaultEntryMetadata
export type WrappingRow = KeyAddress &
  WrapResult &
  WrappingAddress & {
    keyVersion: number
    recipientDID: string | null
    provenance: string
  }
export type EntryRow = KeyAddress &
  EntryAddress &
  EntryMetadata &
  EncryptEntryResult & {
    keyVersion: number
    hlc: string
    provenance: string
  }
export type EntryFilter = KeyAddress & Partial<EntryMetadata>
export type UpdateEntryResult = 'updated' | 'absent' | 'superseded'
export type VaultStoreAPI = {
  isTransaction: boolean
  transaction<Result>(fn: (store: VaultStoreAPI) => Promise<Result>): Promise<Result>
  /** Declare the complete key set before authoritative reads. Requires a transaction. */
  lockKeyRows(addresses: ReadonlyArray<KeyAddress>): Promise<void>
  lockKeyRow(address: KeyAddress): Promise<void>
  putKey(row: KeyRow): Promise<void>
  getKey(address: KeyAddress): Promise<KeyRow | undefined>
  listKeys(ownerDID: string): Promise<Array<KeyRow>>
  setKeyState(row: KeyAddress & Pick<KeyRow, 'state'>): Promise<void>
  setKeyVersion(row: KeyAddress & Pick<KeyRow, 'version'>): Promise<void>
  deleteKey(address: KeyAddress): Promise<void>
  putWrapping(row: WrappingRow): Promise<void>
  getWrapping(address: WrappingAddress): Promise<WrappingRow | undefined>
  listWrappings(address: KeyAddress & { keyVersion?: number }): Promise<Array<WrappingRow>>
  deleteWrapping(address: WrappingAddress): Promise<void>
  deleteWrappingsBelowVersion(address: KeyAddress & { keyVersion: number }): Promise<void>
  putEntry(row: EntryRow): Promise<void>
  /** Stores caller-encrypted bytes. Does nothing if the observed source disappears or changes key. */
  moveEntry(row: EntryRow): Promise<void>
  updateEntryIfPresent(row: EntryRow): Promise<'updated' | 'absent'>
  updateEntryIfUnchanged(row: EntryRow & { expectedHLC: string }): Promise<UpdateEntryResult>
  getEntry(address: EntryAddress): Promise<EntryRow | undefined>
  getEntryWithProvenance(address: EntryAddress): Promise<EntryRow | undefined>
  listEntryOwners(entryID: string): Promise<Array<string>>
  listEntries(filter: EntryFilter): Promise<Array<EntryRow>>
  deleteEntry(address: EntryAddress): Promise<void>
  getMaxEntryHLC(): Promise<string | null>
}
