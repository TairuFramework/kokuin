import { type Expression, type Kysely, type Migration, type MigrationContext, sql } from '@hozon/db'

import type { VaultStoreTables } from './tables.js'

export function getVaultMigrations(ctx: MigrationContext): Record<string, Migration> {
  const t = ctx.types
  const p = ctx.tablePrefix
  const hlcColumn = <
    Column extends {
      notNull(): Column
      modifyFront(modifier: Expression<unknown>): Column
    },
  >(
    column: Column,
  ): Column => {
    const required = column.notNull()

    return ctx.kind === 'postgres' ? required.modifyFront(sql`collate "C"`) : required
  }

  return {
    '0-init': {
      async up(db: Kysely<VaultStoreTables>) {
        await db.schema
          .createTable('vault_keys')
          .addColumn('owner_did', t.text, (c) => c.notNull())
          .addColumn('key_id', t.text, (c) => c.notNull())
          .addColumn('suite', 'integer', (c) => c.notNull())
          .addColumn('version', 'integer', (c) => c.notNull())
          .addColumn('state', t.text, (c) => c.notNull())
          .addColumn('mode', t.text, (c) => c.notNull().defaultTo('local'))
          .addPrimaryKeyConstraint(`${p}_vault_keys_pkey`, ['owner_did', 'key_id'])
          .execute()

        await db.schema
          .createTable('vault_wrappings')
          .addColumn('owner_did', t.text, (c) => c.notNull())
          .addColumn('wrapping_id', t.text, (c) => c.notNull())
          .addColumn('key_id', t.text, (c) => c.notNull())
          .addColumn('key_version', 'integer', (c) => c.notNull())
          .addColumn('descriptors', t.json, (c) => c.notNull())
          .addColumn('descriptor_digest', t.text, (c) => c.notNull())
          .addColumn('iv', t.binary, (c) => c.notNull())
          .addColumn('wrapped_key', t.binary, (c) => c.notNull())
          .addColumn('recipient_did', t.text)
          .addColumn('provenance', t.text, (c) => c.notNull())
          .addColumn('mode', t.text, (c) => c.notNull().defaultTo('local'))
          .addPrimaryKeyConstraint(`${p}_vault_wrappings_pkey`, ['owner_did', 'wrapping_id'])
          .execute()

        await db.schema
          .createIndex(`${p}_vault_wrappings_key_idx`)
          .on('vault_wrappings')
          .columns(['owner_did', 'key_id', 'key_version'])
          .execute()

        await db.schema
          .createTable('vault_entries')
          .addColumn('owner_did', t.text, (c) => c.notNull())
          .addColumn('entry_id', t.text, (c) => c.notNull())
          .addColumn('key_id', t.text, (c) => c.notNull())
          .addColumn('key_version', 'integer', (c) => c.notNull())
          .addColumn('kind', t.text, (c) => c.notNull())
          .addColumn('label', t.text, (c) => c.notNull())
          .addColumn('attributes', t.json, (c) => c.notNull())
          .addColumn('iv', t.binary, (c) => c.notNull())
          .addColumn('ciphertext', t.binary, (c) => c.notNull())
          .addColumn('hlc', t.text, hlcColumn)
          .addColumn('provenance', t.text, (c) => c.notNull())
          .addColumn('mode', t.text, (c) => c.notNull().defaultTo('local'))
          .addPrimaryKeyConstraint(`${p}_vault_entries_pkey`, ['owner_did', 'entry_id'])
          .execute()

        for (const column of ['kind', 'label'] as const) {
          await db.schema
            .createIndex(`${p}_vault_entries_${column}_idx`)
            .on('vault_entries')
            .columns(['owner_did', 'key_id', column])
            .execute()
        }

        await db.schema
          .createIndex(`${p}_vault_entries_id_idx`)
          .on('vault_entries')
          .column('entry_id')
          .execute()

        await db.schema
          .createIndex(`${p}_vault_entries_hlc_idx`)
          .on('vault_entries')
          .column('hlc')
          .execute()

        if (ctx.kind === 'postgres') {
          await db.schema
            .createIndex(`${p}_vault_entries_attributes_idx`)
            .on('vault_entries')
            .using('gin')
            .column('attributes')
            .execute()
        }
      },
      async down(db: Kysely<VaultStoreTables>) {
        await db.schema.dropTable('vault_entries').execute()
        await db.schema.dropTable('vault_wrappings').execute()
        await db.schema.dropTable('vault_keys').execute()
      },
    },
  }
}
