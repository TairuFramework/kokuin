import type { Adapter } from '@hozon/adapter'
import { type Kysely, withStoreTransaction } from '@hozon/db'
import {
  type ControllerLog,
  isControllerLog,
  type LogStore,
  type SignedEvent,
} from '@kokuin/controller'

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
// array: it is that chain, with no epoch events. Anything else is not a log and
// is no memory, as the resolver treats a stored value of that shape.
function decodeLog(value: unknown): ControllerLog | undefined {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value
  if (Array.isArray(parsed)) {
    return { chain: parsed as Array<SignedEvent>, events: [] }
  }
  return isControllerLog(parsed) ? parsed : undefined
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
    // The read and the write share a store transaction, which joins an enclosing
    // one. Postgres locks the row on read (`for update`), so a concurrent merge
    // waits and then reads this one's result. A DID with no row has nothing to
    // lock: both merges would see none, so the insert is made `do nothing` and a
    // lost race (no row inserted) re-reads, now locking the row the winner wrote.
    // SQLite has one writer at a time and no row locks.
    async merge(
      did: string,
      update: (current: ControllerLog | undefined) => Promise<ControllerLog>,
    ): Promise<ControllerLog> {
      return await withStoreTransaction(db, async (trx) => {
        const lock = adapter.kind === 'postgres'
        const write = async (next: ControllerLog): Promise<void> => {
          await trx
            .insertInto('controller_logs')
            .values({
              did,
              log: adapter.encodeJSON(next) as ControllerLog,
              updated_at: adapter.encodeTimestamp(new Date()) as number,
            })
            .onConflict((oc) =>
              oc.column('did').doUpdateSet((eb) => ({
                log: eb.ref('excluded.log'),
                updated_at: eb.ref('excluded.updated_at'),
              })),
            )
            .execute()
        }

        let query = trx.selectFrom('controller_logs').select('log').where('did', '=', did)
        if (lock) query = query.forUpdate()
        const row = await query.executeTakeFirst()
        if (row != null || !lock) {
          const next = await update(row == null ? undefined : decodeLog(row.log))
          await write(next)
          return next
        }

        const first = await update(undefined)
        const inserted = await trx
          .insertInto('controller_logs')
          .values({
            did,
            log: adapter.encodeJSON(first) as ControllerLog,
            updated_at: adapter.encodeTimestamp(new Date()) as number,
          })
          .onConflict((oc) => oc.column('did').doNothing())
          .executeTakeFirst()
        if (Number(inserted.numInsertedOrUpdatedRows ?? 0) > 0) return first

        const current = await query.executeTakeFirst()
        const next = await update(current == null ? undefined : decodeLog(current.log))
        await write(next)
        return next
      })
    },
  }

  return api
}
