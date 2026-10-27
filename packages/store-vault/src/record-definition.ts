import type { Kysely, Migration, MigrationContext, StoreDefinition, StoreProvider } from '@hozon/db'
import { withStoreTransaction } from '@hozon/db'

import type { VaultDatabase } from './record-context.js'
import type { VaultRecordsTables } from './record-tables.js'

export const VAULT_RECORDS_STORE = 'vault-records'

function migrations(ctx: MigrationContext): Record<string, Migration> {
  const t = ctx.types
  const p = ctx.tablePrefix

  return {
    '0-init': {
      async up(db: Kysely<VaultRecordsTables>) {
        await db.schema
          .createTable('vault_record_domain')
          .addColumn('singleton', 'integer', (c) => c.primaryKey())
          .addColumn('op_kind', t.text, (c) => c.notNull())
          .execute()

        await db.schema
          .createTable('vault_decisions')
          .addColumn('type', t.text, (c) => c.notNull())
          .addColumn('owner', t.text, (c) => c.notNull())
          .addColumn('id', t.text, (c) => c.notNull())
          .addColumn('mode', t.text, (c) => c.notNull())
          .addColumn('content_digest', t.text)
          .addColumn('decision_hlc', t.text)
          .addPrimaryKeyConstraint(`${p}_vault_decisions_pkey`, ['type', 'owner', 'id'])
          .execute()

        for (const table of ['vault_records', 'vault_entry_candidates'] as const) {
          let builder = db.schema
            .createTable(table)
            .addColumn('type', t.text, (c) => c.notNull())
            .addColumn('owner', t.text, (c) => c.notNull())
            .addColumn('id', t.text, (c) => c.notNull())
            .addColumn('hlc', t.text, (c) => c.notNull())
            .addColumn('op_jwt', t.text, (c) => c.notNull())
            .addColumn('op_hash', t.text, (c) => c.notNull())
            .addColumn('payload', t.binary)
            .addColumn('payload_digest', t.text)
            .addColumn('deleted', 'integer', (c) => c.notNull())
            .addColumn('meta', t.json, (c) => c.notNull())

          if (table === 'vault_entry_candidates') {
            builder = builder
              .addColumn('key_id', t.text, (c) => c.notNull())
              .addColumn('key_version', 'integer', (c) => c.notNull())
              .addColumn('branch_id', t.text, (c) => c.notNull())
          }

          await builder
            .addPrimaryKeyConstraint(`${p}_${table}_pkey`, ['type', 'owner', 'id', 'op_hash'])
            .execute()
        }

        await db.schema
          .createIndex(`${p}_vault_candidates_key_idx`)
          .on('vault_entry_candidates')
          .columns(['owner', 'key_id', 'key_version'])
          .execute()

        await db.schema
          .createTable('vault_key_branches')
          .addColumn('owner_did', t.text, (c) => c.notNull())
          .addColumn('key_id', t.text, (c) => c.notNull())
          .addColumn('key_version', 'integer', (c) => c.notNull())
          .addColumn('record_id', t.text, (c) => c.notNull())
          .addColumn('branch_id', t.text, (c) => c.notNull())
          .addColumn('op_jwt', t.text, (c) => c.notNull())
          .addPrimaryKeyConstraint(`${p}_vault_branches_pkey`, ['owner_did', 'record_id'])
          .execute()

        await db.schema
          .createIndex(`${p}_vault_branches_key_idx`)
          .on('vault_key_branches')
          .columns(['owner_did', 'key_id', 'key_version'])
          .execute()

        await db.schema
          .createTable('vault_revocations')
          .addColumn('owner_did', t.text, (c) => c.notNull())
          .addColumn('key_id', t.text, (c) => c.notNull())
          .addColumn('recipient_did', t.text, (c) => c.notNull())
          .addPrimaryKeyConstraint(`${p}_vault_revocations_pkey`, [
            'owner_did',
            'key_id',
            'recipient_did',
          ])
          .execute()
      },
      async down(db: Kysely<VaultRecordsTables>) {
        for (const table of [
          'vault_revocations',
          'vault_key_branches',
          'vault_entry_candidates',
          'vault_records',
          'vault_decisions',
          'vault_record_domain',
        ] as const)
          await db.schema.dropTable(table).execute()
      },
    },
  }
}

/** Register separately to keep local-only databases free of replicated state. */
export const vaultRecordsStoreDefinition: StoreDefinition<VaultRecordsTables, VaultDatabase> = {
  name: VAULT_RECORDS_STORE,
  dependsOn: ['vault'],
  migrations,
  createAPI: (db, adapter, context) => ({ db, adapter, context }),
}

export async function getVaultRecordsStore(
  provider: StoreProvider,
  opKind?: string,
): Promise<VaultDatabase> {
  if (opKind !== undefined) {
    if (typeof opKind !== 'string' || opKind.length === 0)
      throw new TypeError('An explicit operation kind is required')

    if (provider.isTransactionBound)
      throw new Error('Initialise the vault operation kind outside caller transactions')
  }

  const storage = (await provider.getStore(VAULT_RECORDS_STORE)) as VaultDatabase

  if (opKind !== undefined) {
    // Bind without vault key locks, before any caller transaction can apply records.
    await withStoreTransaction(storage.db, async (db) => {
      await db
        .insertInto('vault_record_domain')
        .values({ singleton: 1, op_kind: opKind })
        .onConflict((oc) => oc.column('singleton').doNothing())
        .execute()

      const row = await db.selectFrom('vault_record_domain').selectAll().executeTakeFirstOrThrow()

      if (row.op_kind !== opKind)
        throw new TypeError('Vault records store belongs to another operation kind')
    })
  }

  return storage
}
