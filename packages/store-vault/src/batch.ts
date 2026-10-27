import type { Insertable, Kysely } from '@hozon/db'
import { chunk } from '@hozon/db'

import type { VaultKeyBranchTable, VaultRecordsTables } from './record-tables.js'
import type { VaultEntryTable, VaultStoreTables, VaultWrappingTable } from './tables.js'

/**
 * Bound parameters allowed in one statement. Well under SQLite's oldest default limit (999) and
 * Postgres's (65535), and the cap the store's own reads keep to.
 */
export const PARAMETER_BUDGET = 500

/** Splits `items` so no statement binds more than `PARAMETER_BUDGET` parameters. */
export function statementChunks<Item>(
  items: Iterable<Item>,
  parametersPerItem: number,
): Array<Array<Item>> {
  return chunk(items, Math.max(1, Math.floor(PARAMETER_BUDGET / parametersPerItem)))
}

export type WrappingValues = Insertable<Omit<VaultWrappingTable, 'mode'>>

export type EntryValues = Insertable<Omit<VaultEntryTable, 'mode'>>

export type WrappingKey = { owner_did: string; wrapping_id: string }

export type EntryKey = { owner_did: string; entry_id: string }

export type DecisionKey = { type: string; owner: string; id: string }

/** Parameters each row binds. */
export const WRAPPING_COLUMNS = 10

export const ENTRY_COLUMNS = 11

export const DECISION_COLUMNS = 6

export const KEY_BRANCH_COLUMNS = 6

/**
 * One multi-row upsert. A row whose stored wrapping belongs to another key is left alone and
 * not counted, as the single-row upsert does.
 */
export function upsertWrappings(db: Kysely<VaultStoreTables>, rows: Array<WrappingValues>) {
  return db
    .insertInto('vault_wrappings')
    .values(rows)
    .onConflict((oc) => {
      return oc
        .columns(['owner_did', 'wrapping_id'])
        .doUpdateSet((eb) => {
          return {
            key_id: eb.ref('excluded.key_id'),
            key_version: eb.ref('excluded.key_version'),
            descriptors: eb.ref('excluded.descriptors'),
            descriptor_digest: eb.ref('excluded.descriptor_digest'),
            iv: eb.ref('excluded.iv'),
            wrapped_key: eb.ref('excluded.wrapped_key'),
            recipient_did: eb.ref('excluded.recipient_did'),
            provenance: eb.ref('excluded.provenance'),
          }
        })
        .where((eb) => eb('vault_wrappings.key_id', '=', eb.ref('excluded.key_id')))
    })
}

/** As `upsertWrappings`, for entries. */
export function upsertEntries(db: Kysely<VaultStoreTables>, rows: Array<EntryValues>) {
  return db
    .insertInto('vault_entries')
    .values(rows)
    .onConflict((oc) => {
      return oc
        .columns(['owner_did', 'entry_id'])
        .doUpdateSet((eb) => {
          return {
            key_id: eb.ref('excluded.key_id'),
            key_version: eb.ref('excluded.key_version'),
            kind: eb.ref('excluded.kind'),
            label: eb.ref('excluded.label'),
            attributes: eb.ref('excluded.attributes'),
            iv: eb.ref('excluded.iv'),
            ciphertext: eb.ref('excluded.ciphertext'),
            hlc: eb.ref('excluded.hlc'),
            provenance: eb.ref('excluded.provenance'),
          }
        })
        .where((eb) => eb('vault_entries.key_id', '=', eb.ref('excluded.key_id')))
    })
}

export function selectWrappings(db: Kysely<VaultStoreTables>, keys: Array<WrappingKey>) {
  return db
    .selectFrom('vault_wrappings')
    .selectAll()
    .where((eb) => {
      return eb.or(
        keys.map((key) => {
          return eb.and([
            eb('owner_did', '=', key.owner_did),
            eb('wrapping_id', '=', key.wrapping_id),
          ])
        }),
      )
    })
}

export function selectEntries(db: Kysely<VaultStoreTables>, keys: Array<EntryKey>) {
  return db
    .selectFrom('vault_entries')
    .selectAll()
    .where((eb) => {
      return eb.or(
        keys.map((key) => {
          return eb.and([eb('owner_did', '=', key.owner_did), eb('entry_id', '=', key.entry_id)])
        }),
      )
    })
}

/** Deletes each wrapping only while it still belongs to the named key. */
export function deleteWrappingRows(
  db: Kysely<VaultStoreTables>,
  rows: Array<WrappingKey & { key_id: string }>,
) {
  return db.deleteFrom('vault_wrappings').where((eb) => {
    return eb.or(
      rows.map((row) => {
        return eb.and([
          eb('owner_did', '=', row.owner_did),
          eb('wrapping_id', '=', row.wrapping_id),
          eb('key_id', '=', row.key_id),
        ])
      }),
    )
  })
}

/** Deletes each entry only while it still belongs to the named key. */
export function deleteEntryRows(
  db: Kysely<VaultStoreTables>,
  rows: Array<EntryKey & { key_id: string }>,
) {
  return db.deleteFrom('vault_entries').where((eb) => {
    return eb.or(
      rows.map((row) => {
        return eb.and([
          eb('owner_did', '=', row.owner_did),
          eb('entry_id', '=', row.entry_id),
          eb('key_id', '=', row.key_id),
        ])
      }),
    )
  })
}

export function insertDecisionClaims(
  db: Kysely<VaultRecordsTables>,
  keys: Array<DecisionKey>,
  mode: 'local' | 'replicated',
) {
  return db
    .insertInto('vault_decisions')
    .values(
      keys.map((key) => {
        return { ...key, mode, content_digest: null, decision_hlc: null }
      }),
    )
    .onConflict((oc) => oc.columns(['type', 'owner', 'id']).doNothing())
}

export function selectDecisionModes(db: Kysely<VaultRecordsTables>, keys: Array<DecisionKey>) {
  return db
    .selectFrom('vault_decisions')
    .select(['type', 'owner', 'id', 'mode'])
    .where((eb) => {
      return eb.or(
        keys.map((key) => {
          return eb.and([
            eb('type', '=', key.type),
            eb('owner', '=', key.owner),
            eb('id', '=', key.id),
          ])
        }),
      )
    })
}

/**
 * Claims a record key for replicated mode and records its decision, in one statement. A key held
 * in local mode is left alone and counts no row.
 */
export function upsertReplicatedDecision(
  db: Kysely<VaultRecordsTables>,
  decision: DecisionKey & { content_digest: string; decision_hlc: string },
) {
  return db
    .insertInto('vault_decisions')
    .values({ ...decision, mode: 'replicated' })
    .onConflict((oc) => {
      return oc
        .columns(['type', 'owner', 'id'])
        .doUpdateSet({
          content_digest: decision.content_digest,
          decision_hlc: decision.decision_hlc,
        })
        .where('vault_decisions.mode', '=', 'replicated')
    })
}

/** One multi-row upsert of key-branch projection rows. A record ID moves to its new key. */
export function upsertKeyBranches(
  db: Kysely<VaultRecordsTables>,
  rows: Array<VaultKeyBranchTable>,
) {
  return db
    .insertInto('vault_key_branches')
    .values(rows)
    .onConflict((oc) => {
      return oc.columns(['owner_did', 'record_id']).doUpdateSet((eb) => {
        return {
          key_id: eb.ref('excluded.key_id'),
          key_version: eb.ref('excluded.key_version'),
          branch_id: eb.ref('excluded.branch_id'),
          op_jwt: eb.ref('excluded.op_jwt'),
        }
      })
    })
}
