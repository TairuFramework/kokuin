import type { Kysely, StoreDefinition } from '@hozon/db'

export type RawDB = Kysely<Record<string, Record<string, unknown>>>

/** A migration-free store exposing the database's Kysely instance, for catalog queries. */
export const rawStore: StoreDefinition<unknown, RawDB> = {
  name: 'raw',
  migrations: {},
  createAPI: (db) => db as RawDB,
}
