import type { Adapter } from '@hozon/adapter'
import {
  type Kysely,
  type Selectable,
  type StoreContext,
  type StoreProvider,
  sql,
  withKeyLock,
  withKeyLocks,
  withStoreTransaction,
} from '@hozon/db'

import { claimMode, VaultModeConflict, vaultDatabases } from './record-context.js'
import { getVaultRecordsStore } from './record-definition.js'
import type { VaultRecordsTables } from './record-tables.js'
import type {
  VaultEntryTable,
  VaultKeyTable,
  VaultStoreTables,
  VaultWrappingTable,
} from './tables.js'
import type {
  EntryAddress,
  EntryRow,
  KeyAddress,
  KeyRow,
  UpdateEntryResult,
  VaultStoreAPI,
  WrappingRow,
} from './types.js'

const databases = new WeakMap<VaultStoreAPI, Kysely<VaultStoreTables>>()

async function transactionDatabase(provider: StoreProvider): Promise<Kysely<VaultStoreTables>> {
  const store = (await provider.getStore('vault')) as VaultStoreAPI
  const db = databases.get(store)

  if (db == null) throw new Error('Vault store database is unavailable')

  return db
}

// The vault record lock's key is already framed as [owner, keyID]. Keep that identity intact.
function lockTuple(address: KeyAddress): Array<string> {
  return [JSON.stringify([address.ownerDID, address.keyID])]
}

function decodeJSON<Value>(value: Value | string): Value {
  return typeof value === 'string' ? (JSON.parse(value) as Value) : value
}

function keyRow(row: Selectable<VaultKeyTable>): KeyRow {
  return {
    ownerDID: row.owner_did,
    keyID: row.key_id,
    suite: row.suite,
    version: row.version,
    state: row.state,
  }
}

function entryRow(row: Selectable<VaultEntryTable>): EntryRow {
  return {
    ownerDID: row.owner_did,
    entryID: row.entry_id,
    keyID: row.key_id,
    keyVersion: row.key_version,
    kind: row.kind,
    label: row.label,
    attributes: decodeJSON(row.attributes),
    iv: Uint8Array.from(row.iv),
    ciphertext: Uint8Array.from(row.ciphertext),
    hlc: row.hlc,
    provenance: row.provenance,
  }
}

function wrappingRow(row: Selectable<VaultWrappingTable>): WrappingRow {
  return {
    ownerDID: row.owner_did,
    wrappingID: row.wrapping_id,
    keyID: row.key_id,
    keyVersion: row.key_version,
    descriptors: decodeJSON(row.descriptors),
    descriptorDigest: row.descriptor_digest,
    iv: Uint8Array.from(row.iv),
    wrappedKey: Uint8Array.from(row.wrapped_key),
    recipientDID: row.recipient_did,
    provenance: row.provenance,
  }
}

export function createVaultStore(
  db: Kysely<VaultStoreTables>,
  adapter: Adapter,
  context: StoreContext,
): VaultStoreAPI {
  const read = <Result>(
    fn: (trx: Kysely<VaultStoreTables>) => Promise<Result>,
  ): Promise<Result> => {
    return withStoreTransaction(db, fn)
  }
  const locked = async <Result>(
    addresses: ReadonlyArray<KeyAddress>,
    fn: (trx: Kysely<VaultStoreTables>) => Promise<Result>,
  ): Promise<Result> => {
    const run = async (provider: StoreProvider): Promise<Result> => {
      return withStoreTransaction(await transactionDatabase(provider), fn)
    }
    const address = addresses[0]

    if (addresses.length === 1 && address != null) {
      return withKeyLock(context.provider, 'vault_keys', lockTuple(address), run)
    }

    return withKeyLocks(context.provider, 'vault_keys', addresses.map(lockTuple), run)
  }
  const localMode = async (
    trx: Kysely<VaultStoreTables>,
    type: 'vault.key' | 'vault.entry' | 'vault.wrapping',
    owner: string,
    id: string,
  ): Promise<void> => {
    const table =
      type === 'vault.key'
        ? 'vault_keys'
        : type === 'vault.entry'
          ? 'vault_entries'
          : 'vault_wrappings'
    const column =
      type === 'vault.key' ? 'key_id' : type === 'vault.entry' ? 'entry_id' : 'wrapping_id'
    const row = await trx
      .selectFrom(table)
      .select('mode')
      .where('owner_did', '=', owner)
      .where(column, '=', id)
      .executeTakeFirst()

    if (row?.mode === 'replicated') throw new VaultModeConflict()

    if (context.provider.hasStore('vault-records')) {
      await getVaultRecordsStore(context.provider)
      await claimMode(trx as Kysely<VaultRecordsTables>, { type, owner, id }, 'local')
    }
  }
  const selectEntry = (trx: Kysely<VaultStoreTables>, address: EntryAddress) => {
    return trx
      .selectFrom('vault_entries')
      .selectAll()
      .where('owner_did', '=', address.ownerDID)
      .where('entry_id', '=', address.entryID)
  }
  const entryValues = (row: EntryRow) => {
    return {
      owner_did: row.ownerDID,
      entry_id: row.entryID,
      key_id: row.keyID,
      key_version: row.keyVersion,
      kind: row.kind,
      label: row.label,
      attributes: adapter.encodeJSON(row.attributes) as Record<string, string>,
      iv: adapter.encodeBinary(row.iv) as Uint8Array,
      ciphertext: adapter.encodeBinary(row.ciphertext) as Uint8Array,
      hlc: row.hlc,
      provenance: row.provenance,
    }
  }
  const updateEntry = async (row: EntryRow, expectedHLC?: string): Promise<UpdateEntryResult> => {
    return locked([row], async (trx) => {
      await localMode(trx, 'vault.entry', row.ownerDID, row.entryID)

      let update = trx
        .updateTable('vault_entries')
        .set(entryValues(row))
        .where('owner_did', '=', row.ownerDID)
        .where('entry_id', '=', row.entryID)
        .where('key_id', '=', row.keyID)

      if (expectedHLC !== undefined) update = update.where('hlc', '=', expectedHLC)

      const result = await update.executeTakeFirst()

      if (result.numUpdatedRows > 0n) return 'updated'

      if (expectedHLC !== undefined) {
        const existing = await selectEntry(trx, row)
          .where('key_id', '=', row.keyID)
          .executeTakeFirst()

        if (existing != null && existing.hlc !== expectedHLC) return 'superseded'
      }

      return 'absent'
    })
  }
  const api: VaultStoreAPI = {
    isTransaction: db.isTransaction,
    async transaction(fn) {
      return context.provider.withTransaction(async (tx) => {
        const store = (await tx.getStore('vault')) as VaultStoreAPI

        return withStoreTransaction(await transactionDatabase(tx), async () => fn(store))
      })
    },
    async lockKeyRow(address) {
      if (!context.provider.isTransactionBound) throw new Error('Key locks require a transaction')

      await locked([address], async () => {})
    },
    async lockKeyRows(addresses) {
      if (!context.provider.isTransactionBound) throw new Error('Key locks require a transaction')

      await locked(addresses, async () => {})
    },
    async putKey(row) {
      await locked([row], async (trx) => {
        await localMode(trx, 'vault.key', row.ownerDID, row.keyID)

        const values = {
          owner_did: row.ownerDID,
          key_id: row.keyID,
          suite: row.suite,
          version: row.version,
          state: row.state,
        }

        await trx
          .insertInto('vault_keys')
          .values(values)
          .onConflict((oc) => {
            return oc
              .columns(['owner_did', 'key_id'])
              .doUpdateSet({ suite: row.suite, version: row.version, state: row.state })
              .where('vault_keys.version', '<=', row.version)
          })
          .execute()
      })
    },
    async getKey(address) {
      return read(async (trx) => {
        const row = await trx
          .selectFrom('vault_keys')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .executeTakeFirst()

        return row == null ? undefined : keyRow(row)
      })
    },
    async listKeys(ownerDID) {
      return read(async (trx) => {
        const rows = await trx
          .selectFrom('vault_keys')
          .selectAll()
          .where('owner_did', '=', ownerDID)
          .orderBy('key_id')
          .execute()

        return rows.map(keyRow)
      })
    },
    async setKeyState(row) {
      await locked([row], async (trx) => {
        await localMode(trx, 'vault.key', row.ownerDID, row.keyID)
        await trx
          .updateTable('vault_keys')
          .set({ state: row.state })
          .where('owner_did', '=', row.ownerDID)
          .where('key_id', '=', row.keyID)
          .execute()
      })
    },
    async setKeyVersion(row) {
      await locked([row], async (trx) => {
        await localMode(trx, 'vault.key', row.ownerDID, row.keyID)
        await trx
          .updateTable('vault_keys')
          .set({ version: row.version })
          .where('owner_did', '=', row.ownerDID)
          .where('key_id', '=', row.keyID)
          .where('version', '<=', row.version)
          .execute()
      })
    },
    async deleteKey(address) {
      await locked([address], async (trx) => {
        await localMode(trx, 'vault.key', address.ownerDID, address.keyID)
        await trx
          .deleteFrom('vault_keys')
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .execute()
      })
    },
    async putWrapping(row) {
      await locked([row], async (trx) => {
        await localMode(trx, 'vault.wrapping', row.ownerDID, row.wrappingID)

        const existing = await trx
          .selectFrom('vault_wrappings')
          .select('key_id')
          .where('owner_did', '=', row.ownerDID)
          .where('wrapping_id', '=', row.wrappingID)
          .executeTakeFirst()

        if (existing != null && existing.key_id !== row.keyID)
          throw new Error('Wrapping belongs to another key')

        const values = {
          owner_did: row.ownerDID,
          wrapping_id: row.wrappingID,
          key_id: row.keyID,
          key_version: row.keyVersion,
          descriptors: adapter.encodeJSON(row.descriptors) as WrappingRow['descriptors'],
          descriptor_digest: row.descriptorDigest,
          iv: adapter.encodeBinary(row.iv) as Uint8Array,
          wrapped_key: adapter.encodeBinary(row.wrappedKey) as Uint8Array,
          recipient_did: row.recipientDID,
          provenance: row.provenance,
        }
        const result = await trx
          .insertInto('vault_wrappings')
          .values(values)
          .onConflict((oc) => {
            return oc
              .columns(['owner_did', 'wrapping_id'])
              .doUpdateSet(values)
              .where('vault_wrappings.key_id', '=', row.keyID)
          })
          .executeTakeFirst()

        if (result.numInsertedOrUpdatedRows === 0n)
          throw new Error('Wrapping belongs to another key')
      })
    },
    async getWrapping(address) {
      return read(async (trx) => {
        const row = await trx
          .selectFrom('vault_wrappings')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('wrapping_id', '=', address.wrappingID)
          .executeTakeFirst()

        return row == null ? undefined : wrappingRow(row)
      })
    },
    async listWrappings(address) {
      return read(async (trx) => {
        let query = trx
          .selectFrom('vault_wrappings')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)

        if (address.keyVersion !== undefined)
          query = query.where('key_version', '=', address.keyVersion)

        return (await query.orderBy('wrapping_id').execute()).map(wrappingRow)
      })
    },
    async deleteWrapping(address) {
      // Discover the key before locking, then qualify deletion so a changed association survives.
      const row = await api.getWrapping(address)

      if (row == null) return

      await locked([row], async (trx) => {
        await localMode(trx, 'vault.wrapping', row.ownerDID, row.wrappingID)
        await trx
          .deleteFrom('vault_wrappings')
          .where('owner_did', '=', row.ownerDID)
          .where('wrapping_id', '=', row.wrappingID)
          .where('key_id', '=', row.keyID)
          .execute()
      })
    },
    async deleteWrappingsBelowVersion(address) {
      await locked([address], async (trx) => {
        const rows = await trx
          .selectFrom('vault_wrappings')
          .selectAll()
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .where('key_version', '<', address.keyVersion)
          .execute()

        for (const row of rows)
          await localMode(trx, 'vault.wrapping', row.owner_did, row.wrapping_id)

        await trx
          .deleteFrom('vault_wrappings')
          .where('owner_did', '=', address.ownerDID)
          .where('key_id', '=', address.keyID)
          .where('key_version', '<', address.keyVersion)
          .execute()
      })
    },
    async putEntry(row) {
      await locked([row], async (trx) => {
        await localMode(trx, 'vault.entry', row.ownerDID, row.entryID)

        const existing = await selectEntry(trx, row).executeTakeFirst()

        if (existing != null && existing.key_id !== row.keyID)
          throw new Error('Entry belongs to another key')

        const result = await trx
          .insertInto('vault_entries')
          .values(entryValues(row))
          .onConflict((oc) => {
            return oc
              .columns(['owner_did', 'entry_id'])
              .doUpdateSet(entryValues(row))
              .where('vault_entries.key_id', '=', row.keyID)
          })
          .executeTakeFirst()

        if (result.numInsertedOrUpdatedRows === 0n) throw new Error('Entry belongs to another key')
      })
    },
    async moveEntry(row) {
      const source = await api.getEntry(row)

      if (source == null) return

      await locked([source, row], async (trx) => {
        await localMode(trx, 'vault.entry', row.ownerDID, row.entryID)
        // UPDATE-only plus the source predicate prevents resurrection and stale reassociation.
        await trx
          .updateTable('vault_entries')
          .set(entryValues(row))
          .where('owner_did', '=', row.ownerDID)
          .where('entry_id', '=', row.entryID)
          .where('key_id', '=', source.keyID)
          .execute()
      })
    },
    async updateEntryIfPresent(row) {
      return (await updateEntry(row)) as 'updated' | 'absent'
    },
    async updateEntryIfUnchanged(row) {
      return updateEntry(row, row.expectedHLC)
    },
    async getEntry(address) {
      return read(async (trx) => {
        const row = await selectEntry(trx, address).executeTakeFirst()

        return row == null ? undefined : entryRow(row)
      })
    },
    async getEntryWithProvenance(address) {
      return api.getEntry(address)
    },
    async listEntryOwners(entryID) {
      return read(async (trx) => {
        const rows = await trx
          .selectFrom('vault_entries')
          .select('owner_did')
          .where('entry_id', '=', entryID)
          .orderBy('owner_did')
          .execute()

        return rows.map((row) => row.owner_did)
      })
    },
    async listEntries(filter) {
      return read(async (trx) => {
        let query = trx
          .selectFrom('vault_entries')
          .selectAll()
          .where('owner_did', '=', filter.ownerDID)
          .where('key_id', '=', filter.keyID)

        if (filter.kind !== undefined) query = query.where('kind', '=', filter.kind)

        if (filter.label !== undefined) query = query.where('label', '=', filter.label)

        if (filter.attributes !== undefined) {
          // One JSON bind handles arbitrary attribute sets without dynamic paths or bind growth.
          const attributes = JSON.stringify(filter.attributes)
          const column = sql.ref('vault_entries.attributes')

          query = query.where(
            adapter.kind === 'postgres'
              ? sql<boolean>`${column} @> ${attributes}::text::jsonb`
              : sql<boolean>`not exists (
                select 1 from json_each(${attributes}) as wanted
                where not exists (
                  select 1 from json_each(${column}) as held
                  where held.key = wanted.key and held.type = 'text' and held.value = wanted.value
                )
              )`,
          )
        }

        return (await query.orderBy('entry_id').execute()).map(entryRow)
      })
    },
    async deleteEntry(address) {
      const row = await api.getEntry(address)

      if (row == null) return

      await locked([row], async (trx) => {
        await localMode(trx, 'vault.entry', row.ownerDID, row.entryID)
        await trx
          .deleteFrom('vault_entries')
          .where('owner_did', '=', row.ownerDID)
          .where('entry_id', '=', row.entryID)
          .where('key_id', '=', row.keyID)
          .execute()
      })
    },
    async getMaxEntryHLC() {
      return read(async (trx) => {
        const row = await trx
          .selectFrom('vault_entries')
          .select((eb) => eb.fn.max('hlc').as('max_hlc'))
          .executeTakeFirst()

        return row?.max_hlc ?? null
      })
    },
  }

  vaultDatabases.set(api, { db: db as Kysely<VaultRecordsTables>, adapter, context })
  databases.set(api, db)

  return api
}
