import { type Expression, type Kysely, type Migration, type MigrationContext, sql } from '@hozon/db'

import type { DelegationStoreTables } from './tables.js'

export function getDelegationMigrations(ctx: MigrationContext): Record<string, Migration> {
  const t = ctx.types
  const now = ctx.functions.now
  const p = ctx.tablePrefix

  // SQL `>` and JS `<=` must agree on `hlc` order. SQLite's default collation is
  // byte-wise, but a Postgres default collation can be locale-sensitive.
  // Typed structurally: `@hozon/db` does not re-export kysely's `ColumnDefinitionBuilder`.
  const hlcColumn = <C extends { notNull(): C; modifyFront(modifier: Expression<unknown>): C }>(
    col: C,
  ): C => {
    const notNull = col.notNull()
    return ctx.kind === 'postgres' ? notNull.modifyFront(sql`collate "C"`) : notNull
  }

  const init: Migration = {
    async up(db: Kysely<DelegationStoreTables>) {
      await db.schema
        .createTable('delegation_tokens')
        .ifNotExists()
        .addColumn('jti', t.text, (col) => col.notNull())
        .addColumn('grantor', t.text, (col) => col.notNull())
        .addColumn('audience', t.text, (col) => col.notNull())
        .addColumn('token', t.text, (col) => col.notNull())
        .addColumn('resource', t.text, (col) => col.notNull())
        .addColumn('act', t.text, (col) => col.notNull())
        // Capability expiry, a numeric unix-seconds claim mirrored from the
        // token for indexed validity filtering. bigint, not int32: a 32-bit
        // seconds column ceilings at 2038. The adapter's int8 parser reads it
        // back as a JS number, so the row type stays `number`.
        .addColumn('exp', t.bigint, (col) => col.notNull())
        .addColumn('hlc', t.text, hlcColumn)
        .addColumn('created_at', t.timestamp, (col) => col.defaultTo(now).notNull())
        .addColumn('updated_at', t.timestamp)
        .addPrimaryKeyConstraint(`${p}_delegation_tokens_pkey`, ['grantor', 'audience', 'resource'])
        .execute()

      await db.schema
        .createIndex(`${p}_delegation_tokens_grantor_audience_idx`)
        .ifNotExists()
        .on('delegation_tokens')
        .columns(['grantor', 'audience'])
        .execute()

      // Held tokens are read by audience with an expiry filter on a hot path.
      await db.schema
        .createIndex(`${p}_delegation_tokens_audience_exp_idx`)
        .ifNotExists()
        .on('delegation_tokens')
        .columns(['audience', 'exp'])
        .execute()

      // Revocation lookup keys on `jti`, which is not part of the composite PK
      // `(grantor, audience, resource)`.
      await db.schema
        .createIndex(`${p}_delegation_tokens_jti_idx`)
        .ifNotExists()
        .on('delegation_tokens')
        .column('jti')
        .execute()

      // `verified_at` doubles as the verified flag (NULL = pending cross-check
      // against the cap's iss) and a forensic timestamp. `cap_exp` is set when
      // verification matches a known cap, and drives the expired-revocation purge.
      //
      // Keyed by `(jti, revoker_did)`, not `jti` alone: one row per `jti` cannot
      // represent two revokers naming the same capability, so the LWW upsert
      // would let any group member's higher-HLC broadcast overwrite the
      // grantor's row. Each author owns its own row and can only displace itself.
      await db.schema
        .createTable('revoked_capabilities')
        .ifNotExists()
        .addColumn('jti', t.text, (col) => col.notNull())
        .addColumn('revoker_did', t.text, (col) => col.notNull())
        // Unix seconds, bigint for the same 2038 reason as `exp` above.
        .addColumn('revoked_iat', t.bigint, (col) => col.notNull())
        .addColumn('revocation_token', t.text, (col) => col.notNull())
        .addColumn('verified_at', t.bigint)
        .addColumn('cap_exp', t.bigint)
        .addColumn('hlc', t.text, hlcColumn)
        .addColumn('created_at', t.timestamp, (col) => col.defaultTo(now).notNull())
        .addColumn('updated_at', t.timestamp)
        .addPrimaryKeyConstraint(`${p}_revoked_capabilities_pkey`, ['jti', 'revoker_did'])
        .execute()

      // Serves the expired-revocation purge predicate. `jti` leads the primary
      // key, so per-issuer lookups need no index of their own.
      await db.schema
        .createIndex(`${p}_revoked_capabilities_verified_cap_exp_idx`)
        .ifNotExists()
        .on('revoked_capabilities')
        .columns(['verified_at', 'cap_exp'])
        .execute()
    },

    async down(db: Kysely<DelegationStoreTables>) {
      await db.schema.dropTable('revoked_capabilities').ifExists().execute()
      await db.schema.dropTable('delegation_tokens').ifExists().execute()
    },
  }

  return { '0-init': init }
}
