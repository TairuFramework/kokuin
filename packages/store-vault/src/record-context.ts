import type { Adapter } from '@hozon/adapter'
import type { Kysely, StoreContext } from '@hozon/db'
import { recordKeyText } from '@kokuin/records'

import type { DecisionKey } from './batch.js'
import {
  DECISION_COLUMNS,
  insertDecisionClaims,
  selectDecisionModes,
  statementChunks,
} from './batch.js'
import type { VaultRecordsTables } from './record-tables.js'
import { settleAll } from './settle.js'
import type { VaultStoreAPI } from './types.js'

export type VaultDatabase = {
  db: Kysely<VaultRecordsTables>
  adapter: Adapter
  context: StoreContext
}

export const vaultDatabases = new WeakMap<VaultStoreAPI, VaultDatabase>()

export class VaultModeConflict extends Error {
  constructor() {
    super('The record belongs to another vault storage mode')
    this.name = 'VaultModeConflict'
  }
}

export class VaultWriteConflict extends Error {
  constructor() {
    super('Vault write preconditions no longer hold')
    this.name = 'VaultWriteConflict'
  }
}

export async function claimMode(
  db: Kysely<VaultRecordsTables>,
  key: { type: string; owner: string; id: string },
  mode: 'local' | 'replicated',
): Promise<void> {
  await claimModes(db, [key], mode)
}

/** Claims every key for `mode`, in one insert and one read per statement chunk. */
export async function claimModes(
  db: Kysely<VaultRecordsTables>,
  keys: ReadonlyArray<DecisionKey>,
  mode: 'local' | 'replicated',
): Promise<void> {
  const unique = [...new Map(keys.map((key) => [recordKeyText(key), key])).values()]

  if (unique.length === 0) return

  const parts = statementChunks(unique, DECISION_COLUMNS)

  await settleAll(parts.map((part) => insertDecisionClaims(db, part, mode).execute()))

  const stored = (
    await settleAll(parts.map((part) => selectDecisionModes(db, part).execute()))
  ).flat()

  if (stored.length !== unique.length || stored.some((row) => row.mode !== mode))
    throw new VaultModeConflict()
}
