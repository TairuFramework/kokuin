import type { Kysely, StoreDefinition } from '@hozon/db'

// biome-ignore lint/suspicious/noExplicitAny: raw access to tables created by the stores.
export type RawDB = Kysely<any>

/** A migration-free store exposing the database's Kysely instance, for catalog queries. */
export const rawStore: StoreDefinition<unknown, RawDB> = {
  name: 'raw',
  migrations: {},
  createAPI: (db) => db as RawDB,
}
