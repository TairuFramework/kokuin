import type { Kysely, Migration, MigrationContext } from '@hozon/db'

import type { ControllerStoreTables } from './tables.js'

export function getControllerMigrations(ctx: MigrationContext): Record<string, Migration> {
  const t = ctx.types
  const now = ctx.functions.now

  const init: Migration = {
    async up(db: Kysely<ControllerStoreTables>) {
      // One row per controller DID; `log` holds the signed event array verbatim.
      await db.schema
        .createTable('controller_logs')
        .ifNotExists()
        .addColumn('did', t.text, (col) => col.notNull())
        .addColumn('log', t.json, (col) => col.notNull())
        .addColumn('created_at', t.timestamp, (col) => col.defaultTo(now).notNull())
        .addColumn('updated_at', t.timestamp)
        .addPrimaryKeyConstraint(`${ctx.tablePrefix}_controller_logs_pkey`, ['did'])
        .execute()
    },

    async down(db: Kysely<ControllerStoreTables>) {
      await db.schema.dropTable('controller_logs').ifExists().execute()
    },
  }

  return { '0-init': init }
}
