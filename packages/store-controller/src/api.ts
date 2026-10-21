import type { Adapter } from '@hozon/adapter'
import { type Kysely, withStoreTransaction } from '@hozon/db'
import type { ControllerLog, LogStore, SignedEvent } from '@kokuin/controller'

import type { ControllerStoreTables } from './tables.js'

// Typed against `@kokuin/controller`'s `LogStore` so a drift in that interface
// surfaces here as a type error rather than at a call site.
export type ControllerStoreAPI = LogStore & {
  /** Last explicit store write, including a locally seeded controller log. */
  getObservedAt(did: string): Promise<Date | undefined>
}

// ParseJSONResultsPlugin usually parses the JSON column back to an object, but a
// value can still arrive as a string (adapter/driver dependent). Handle both. A
// row written before the log split into chain and epoch events is a bare event
// array: it is that chain, with no epoch events.
function decodeLog(value: unknown): ControllerLog {
  const parsed = (typeof value === 'string' ? JSON.parse(value) : value) as
    | ControllerLog
    | Array<SignedEvent>
  return Array.isArray(parsed) ? { chain: parsed, events: [] } : parsed
}

export function createControllerStore(
  db: Kysely<ControllerStoreTables>,
  adapter: Adapter,
): ControllerStoreAPI {
  const api: ControllerStoreAPI = {
    async get(did: string): Promise<ControllerLog | undefined> {
      const row = await db
        .selectFrom('controller_logs')
        .select('log')
        .where('did', '=', did)
        .executeTakeFirst()
      return row == null ? undefined : decodeLog(row.log)
    },

    async getObservedAt(did: string): Promise<Date | undefined> {
      const row = await db
        .selectFrom('controller_logs')
        .select(['created_at', 'updated_at'])
        .where('did', '=', did)
        .executeTakeFirst()
      if (row == null) return undefined
      return adapter.decodeTimestamp(row.updated_at ?? row.created_at)
    },

    // Writes whatever `update` returns: arbitration lives in the resolver
    // (`authoritativeLog`), never here. A caller ingesting an UNTRUSTED log (e.g.
    // one pulled from a peer) must build the update from `authoritativeLog` —
    // this store will not refuse a truncated or forked log on its own, so
    // writing peer bytes directly would bypass the anti-truncation guarantee.
    // The read and the upsert share a store transaction, which joins an
    // enclosing one.
    async merge(
      did: string,
      update: (current: ControllerLog | undefined) => Promise<ControllerLog>,
    ): Promise<ControllerLog> {
      return await withStoreTransaction(db, async (trx) => {
        const row = await trx
          .selectFrom('controller_logs')
          .select('log')
          .where('did', '=', did)
          .executeTakeFirst()
        const next = await update(row == null ? undefined : decodeLog(row.log))
        const encoded = adapter.encodeJSON(next) as ControllerLog
        const observedAt = adapter.encodeTimestamp(new Date()) as number
        await trx
          .insertInto('controller_logs')
          .values({ did, log: encoded, updated_at: observedAt })
          .onConflict((oc) =>
            oc.column('did').doUpdateSet((eb) => ({
              log: eb.ref('excluded.log'),
              updated_at: observedAt,
            })),
          )
          .execute()
        return next
      })
    },
  }

  return api
}
