import type { Adapter } from '@hozon/adapter'
import type { Kysely, StoreContext } from '@hozon/db'

import type { VaultRecordsTables } from './record-tables.js'
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
  await db
    .insertInto('vault_decisions')
    .values({
      type: key.type,
      owner: key.owner,
      id: key.id,
      mode,
      content_digest: null,
      decision_hlc: null,
    })
    .onConflict((oc) => oc.columns(['type', 'owner', 'id']).doNothing())
    .execute()

  const stored = await db
    .selectFrom('vault_decisions')
    .select('mode')
    .where('type', '=', key.type)
    .where('owner', '=', key.owner)
    .where('id', '=', key.id)
    .executeTakeFirstOrThrow()

  if (stored.mode !== mode) throw new VaultModeConflict()
}
