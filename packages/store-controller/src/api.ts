import type { Adapter } from '@hozon/adapter'
import { type Kysely, type StoreContext, withKeyLock } from '@hozon/db'
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

const storeDatabases = new WeakMap<ControllerStoreAPI, Kysely<ControllerStoreTables>>()

// ParseJSONResultsPlugin usually parses the JSON column back to an object, but a
// value can still arrive as a string (adapter/driver dependent). Handle both. A
// row written before the log split into chain and epoch events is a bare event
// array: it is that chain, with no epoch events. Anything else is not a log and
// is no memory, as the resolver treats a stored value of that shape -- a string
// that does not parse included: throwing would refuse every later `get` and
// `merge` for the DID, where no memory costs one round of the guarantee and the
// next merge replaces the row.
function decodeLog(value: unknown): ControllerLog | undefined {
  let parsed: unknown = value
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value)
    } catch {
      return undefined
    }
  }
  if (Array.isArray(parsed)) {
    return { chain: parsed as Array<SignedEvent>, events: [] }
  }
  return isControllerLog(parsed) ? parsed : undefined
}

export function createControllerStore(
  db: Kysely<ControllerStoreTables>,
  adapter: Adapter,
  context: StoreContext,
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

    // Writes whatever `update` returns, unless it hands back `current` itself:
    // that is "nothing changed" (see `LogStore.merge`), and the row -- written
    // or not, legacy shape or not -- is left alone. Arbitration lives in the resolver
    // (`authoritativeLog`), never here. A caller ingesting an UNTRUSTED log (e.g.
    // one pulled from a peer) must build the update from `authoritativeLog` —
    // this store will not refuse a truncated or forked log on its own, and the
    // resolver does not re-verify the current epoch's stored events. Writing
    // peer bytes directly would bypass the anti-truncation guarantee AND let a
    // forged event of the current epoch be applied as authentic.
    // The key lock serialises merges even within one transaction, including a
    // DID with no row. Postgres also locks the row on read and re-reads after a
    // lost insert race against a writer that does not hold the key lock.
    async merge(
      did: string,
      update: (current: ControllerLog | undefined) => Promise<ControllerLog>,
    ): Promise<ControllerLog> {
      return await withKeyLock(context.provider, 'controller_logs', [did], async (tx) => {
        // Resolve through the locked provider so standalone calls use its new transaction.
        const store = (await tx.getStore('controller')) as ControllerStoreAPI
        const trx = storeDatabases.get(store)
        if (trx == null) throw new Error('Controller store database is unavailable')
        const lock = adapter.kind === 'postgres'
        const values = (next: ControllerLog) => ({
          did,
          log: adapter.encodeJSON(next) as ControllerLog,
          updated_at: adapter.encodeTimestamp(new Date()) as number,
        })
        const write = async (next: ControllerLog): Promise<void> => {
          await trx
            .insertInto('controller_logs')
            .values(values(next))
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
          const current = row == null ? undefined : decodeLog(row.log)
          const next = await update(current)
          if (next !== current) await write(next)
          return next
        }

        const first = await update(undefined)
        const inserted = await trx
          .insertInto('controller_logs')
          .values(values(first))
          .onConflict((oc) => oc.column('did').doNothing())
          .executeTakeFirst()
        if (Number(inserted.numInsertedOrUpdatedRows ?? 0) > 0) return first

        const raced = await query.executeTakeFirst()
        const current = raced == null ? undefined : decodeLog(raced.log)
        const next = await update(current)
        if (next !== current) await write(next)
        return next
      })
    },
  }

  storeDatabases.set(api, db)
  return api
}
