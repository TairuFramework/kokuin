import type { Adapter } from '@hozon/adapter'
import type { LogStore, SignedEvent } from '@kokuin/controller'
import type { Kysely } from 'kysely'

import type { ControllerStoreTables } from './tables.js'

// Typed against `@kokuin/controller`'s `LogStore` so a drift in that interface
// surfaces here as a type error rather than at a call site.
export type ControllerStoreAPI = LogStore & {
  /** Last explicit store write, including a locally seeded controller log. */
  getObservedAt(did: string): Promise<Date | undefined>
}

// ParseJSONResultsPlugin usually parses the JSON column back to an object, but a
// value can still arrive as a string (adapter/driver dependent). Handle both.
function decodeLog(value: unknown): Array<SignedEvent> {
  return (typeof value === 'string' ? JSON.parse(value) : value) as Array<SignedEvent>
}

export function createControllerStore(
  db: Kysely<ControllerStoreTables>,
  adapter: Adapter,
): ControllerStoreAPI {
  const api: ControllerStoreAPI = {
    async get(did: string): Promise<Array<SignedEvent> | undefined> {
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

    // Plain last-writer-wins: `set` is called only after the log has folded, so
    // arbitration lives in the resolver, never here. See `@kokuin/controller`.
    // A caller ingesting an UNTRUSTED log (e.g. one pulled from a peer) must run
    // it through the resolver's `authoritativeStates`/`history` guard first — this
    // store will not refuse a truncated or forked log on its own, so a direct
    // `set` of peer bytes would bypass the anti-truncation guarantee.
    async set(did: string, log: Array<SignedEvent>): Promise<void> {
      const encoded = adapter.encodeJSON(log) as Array<SignedEvent>
      const observedAt = adapter.encodeTimestamp(new Date()) as number
      await db
        .insertInto('controller_logs')
        .values({ did, log: encoded, updated_at: observedAt })
        .onConflict((oc) =>
          oc.column('did').doUpdateSet((eb) => ({
            log: eb.ref('excluded.log'),
            updated_at: observedAt,
          })),
        )
        .execute()
    },
  }

  return api
}
