// Parameter audit: every statement binds a fixed, small count (at most 12) -- no `IN` lists
// built from input and no multi-row values -- so none nears the 500-parameter limit.
import type { Adapter } from '@hozon/adapter'
import { type Kysely, type StoreContext, sql, withKeyLock, withStoreTransaction } from '@hozon/db'
import { normalizeDID } from '@kokuin/token'

import type {
  DelegationStoreTables,
  DelegationToken,
  HeldRevocation,
  InsertDelegationToken,
  InsertRevokedCapability,
  RevokedCapability,
} from './tables.js'

/**
 * Purge parameters. `graceSeconds` defaults to `REVOCATION_GC_VERIFIED_GRACE_SECONDS` and must be
 * a non-negative safe integer, otherwise the purge throws `RangeError`.
 */
export type PurgeParams = {
  graceSeconds?: number
  /** Evaluation time in Unix seconds; defaults to the system clock. */
  atTime?: number
}

/** SQL aggregate of held rows. `bytes` counts UTF-8 bytes (SQLite uses its database encoding). */
export type HeldTokenStats = { count: number; bytes: number }

export type HeldTokenPageOversized = { jti: string; bytes: number }

export type HeldTokenPage = {
  tokens: Array<DelegationToken>
  next: string | null
  oversized?: HeldTokenPageOversized
}

/** Maximum token rows materialised by one held-token page. */
export const MAX_HELD_TOKEN_PAGE_SIZE = 1_000

export type DelegationStoreAPI = {
  /**
   * Serialised last-writer-wins arbitration per `(grantor, audience, resource)`.
   * Losing and replaced JTIs remain superseded for revocation. Returns whether active content changed.
   */
  addDelegationToken(token: DelegationStoreAPIAddDelegationTokenParams): Promise<boolean>
  getDelegationTokens(params: {
    grantor: string
    audience: string
  }): Promise<Array<DelegationToken>>
  getHeldTokens(params: { audience: string; atTime: number }): Promise<Array<DelegationToken>>
  /** SQL-only preflight. Separate reads are not a snapshot of concurrent writes. */
  getHeldTokenStats(params: { audience: string; atTime: number }): Promise<HeldTokenStats>
  /**
   * Keyset page in `(grantor, resource, jti)` order within the normalised audience.
   * `limit` must be an integer from 1 to MAX_HELD_TOKEN_PAGE_SIZE, otherwise throws RangeError.
   * `after` is an opaque cursor from `next`. Keep audience and atTime unchanged between pages.
   * Concurrent inserts before the cursor are omitted. Use snapshot isolation in a caller
   * transaction for consistent reads.
   * Optional `maxBytes` must be a positive safe integer, otherwise throws RangeError.
   * SQL bounds the longest ordered prefix by token bytes, using the stats byte expression.
   * An oversized first row returns no bodies and `oversized`. `next` stays `after ?? null`.
   * Retry with a larger allowance or stop on `oversized`, even when `next` is null.
   */
  getHeldTokenPage(params: {
    audience: string
    atTime: number
    after?: string
    limit: number
    maxBytes?: number
  }): Promise<HeldTokenPage>
  listIssuedTokens(grantor: string): Promise<Array<DelegationToken>>
  /** Live superseded grants without any revocation by their grantor, including pending claims. */
  listUnrevokedSupersededTokens(params: {
    grantor: string
    audience: string
    resource: string
    atTime: number
  }): Promise<Array<DelegationToken>>
  getDelegationTokenByGrantorJTI(params: {
    jti: string
    grantor: string
  }): Promise<DelegationToken | null>
  listDelegationTokensByJTI(jti: string): Promise<Array<DelegationToken>>
  removeDelegationToken(params: { jti: string }): Promise<boolean>

  /**
   * Last-writer-wins upsert keyed by `(jti, revoker_did)`. A `revoked_iat` beyond
   * `(atTime ?? now) + MAX_REVOCATION_FUTURE_DRIFT_SECONDS` is floored to that bound.
   * `atTime` is Unix seconds and defaults to the system clock. Returns whether the stored row changed. The result is an approximate change signal for emission gating: the
   * pre-read takes no lock, so two concurrent writers can both see `true`.
   *
   * A row written verified (`verified_at` set) with `cap_exp: null` is never purged: the expired
   * purge needs a `cap_exp` and the pending purge only takes unverified rows. Pass `cap_exp` with
   * `verified_at`, or verify through `markRevocationVerified`, which requires it.
   */
  addRevocation(input: InsertRevokedCapability & { atTime?: number }): Promise<boolean>
  getRevocationByIssuer(
    params: DelegationStoreAPIGetRevocationByIssuerParams,
  ): Promise<RevokedCapability | null>
  listRevocations(jti: string): Promise<Array<RevokedCapability>>
  /**
   * Diagnostic only -- **not** an authorization read. The `verified_at IS NOT NULL` predicate is
   * the inverse of the enforcement rule: a co-member holds no copy of the capability, so its
   * genuine revocation stays pending forever and this answers `false` for it. Authorization must
   * read the issuer's row whatever its verification state.
   */
  isRevokedBy(params: DelegationStoreAPIIsRevokedByParams): Promise<boolean>
  getHeldRevocations(params: { audience: string }): Promise<Array<HeldRevocation>>
  markRevocationVerified(params: DelegationStoreAPIMarkRevocationVerifiedParams): Promise<boolean>
  getPendingRevocationByIssuer(
    params: DelegationStoreAPIGetPendingRevocationByIssuerParams,
  ): Promise<RevokedCapability | null>
  deletePendingRevocationsFromOtherIssuers(
    params: DelegationStoreAPIDeletePendingRevocationsFromOtherIssuersParams,
  ): Promise<number>
  /**
   * Deletes verified rows whose `cap_exp` is more than the grace in the past. A single
   * time-predicate `DELETE`: atomic, idempotent, and safe alongside writes. Nothing calls it
   * implicitly -- schedule it.
   *
   * Verified rows with a null `cap_exp` are never deleted (see `addRevocation`).
   *
   * Consumer contracts:
   * - The grace must cover the consumer's `clockTolerance`. A capability is still accepted up to
   *   `cap_exp + clockTolerance`, and its revocation must outlive that: `graceSeconds: 0` deletes
   *   the revocation once `cap_exp` passes, so a tolerated, revoked capability is honoured again.
   * - Run it outside a caller transaction. On Postgres a failure inside one aborts it.
   * - A local clock running ahead deletes rows early. The default grace absorbs ordinary skew.
   */
  purgeExpiredRevocations(params?: PurgeParams): Promise<number>
  /**
   * Deletes pending rows once `now > revoked_iat + MAX_CAP_TTL_SECONDS + grace`, where the stored
   * `revoked_iat` is already floored to `write time + MAX_REVOCATION_FUTURE_DRIFT_SECONDS`. A
   * single time-predicate `DELETE`: atomic, idempotent, and safe alongside writes. Nothing calls
   * it implicitly -- schedule it.
   *
   * The store never sees the revoked capability, so deletion is safe only while the consumer
   * enforces, on mint and on receive:
   * - `cap.exp - cap.iat <= MAX_CAP_TTL_SECONDS`, with `iat` required;
   * - `cap.iat <= now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS`.
   *
   * The default grace covers that drift, the floor and the consumer's clock tolerance.
   * Otherwise a revoked capability can outlive its revocation and be honoured again.
   *
   * Further consumer contracts:
   * - Run it outside a caller transaction. On Postgres a failure inside one aborts it.
   * - A local clock running ahead deletes rows early. The default grace absorbs ordinary skew.
   */
  purgeDeadPendingRevocations(params?: PurgeParams): Promise<number>
}

/**
 * Longest lifetime (`exp - iat`, seconds) a capability may carry -- 30 days.
 *
 * This is a retention bound, not a policy preference. A co-member holds no copy
 * of the capability a revocation names, so the pending-revocation purge can only
 * bound the row's useful life from the revocation itself:
 * `cap.exp ≤ cap.iat + MAX_CAP_TTL_SECONDS ≤ revoked_iat + MAX_CAP_TTL_SECONDS`.
 * That holds only while every *accepted* capability respects the limit, so the
 * consumer enforces it on receive as well as on mint.
 */
export const MAX_CAP_TTL_SECONDS = 2_592_000

/**
 * Verified revocations remain queryable this long past the capability's
 * expiry -- enough for audit lookbacks before the row is pruned. Pending rows
 * reuse it as the margin past `revoked_iat + MAX_CAP_TTL_SECONDS`, so both
 * kinds age out on the same policy.
 */
export const REVOCATION_GC_VERIFIED_GRACE_SECONDS = 86_400 * 30

/**
 * How far ahead of the local clock a revocation's `iat` may sit before it is
 * floored on write -- one hour.
 *
 * A pending row's retention is computed from `revoked_iat`, and `revoked_iat`
 * comes off a broadcast any co-member can sign, so an unbounded stamp buys an
 * immortal row. Floored rather than rejected: dropping a genuine revocation is
 * the failure this store exists to prevent, and a grantor with real clock skew
 * must not lose its record.
 */
export const MAX_REVOCATION_FUTURE_DRIFT_SECONDS = 3_600

function now(): number {
  return Date.now()
}

function nowSeconds(): number {
  return Math.floor(now() / 1000)
}

// A negative grace deletes revocations of still-valid capabilities, un-revoking
// them. A fractional or oversized one breaks the bigint comparison on Postgres.
function resolveGraceSeconds(params?: PurgeParams): number {
  const grace = params?.graceSeconds ?? REVOCATION_GC_VERIFIED_GRACE_SECONDS
  if (!(Number.isSafeInteger(grace) && grace >= 0)) {
    throw new RangeError(`graceSeconds must be a non-negative safe integer, got ${grace}`)
  }
  return grace
}

const storeDatabases = new WeakMap<DelegationStoreAPI, Kysely<DelegationStoreTables>>()

// One identity reaches this store in two spellings: a `did:peer:4` signer
// embeds its long form as the `iss` of its first token to a given audience and
// its short form thereafter, while `identity.id` and `sub` are always short. So
// the DID a capability presents at check time and the DID its revocation was
// filed under are genuinely different strings for the same peer, with no
// attacker involved. Every DID crossing this boundary -- written or compared --
// is folded through `normalizeDID`, because a raw equality here silently
// returns "not revoked".
export type CreateDelegationStoreParams = {
  db: Kysely<DelegationStoreTables>
  adapter: Adapter
  context: StoreContext
}

export function createDelegationStore({
  context,
  adapter,
  db,
}: CreateDelegationStoreParams): DelegationStoreAPI {
  // The join carries the author predicate for two reasons. It is an
  // authorization filter -- only the grantor's own claim may withhold a token
  // from the audience holding it. It also keeps the result one row per token:
  // `(jti, revoker_did)` is the revocation key, so pinning `revoker_did` to the
  // token's grantor makes the fan-out at most 1. A duplicate would break a
  // multi-hop delegation chain outright.
  function heldTokens(params: { audience: string; atTime: number }) {
    return (
      db
        .selectFrom('delegation_tokens')
        .leftJoin('revoked_capabilities', (join) => {
          return join
            .onRef('revoked_capabilities.jti', '=', 'delegation_tokens.jti')
            .onRef('revoked_capabilities.revoker_did', '=', 'delegation_tokens.grantor')
        })
        .where('audience', '=', normalizeDID(params.audience))
        .where('delegation_tokens.superseded', '=', 0)
        .where('exp', '>=', params.atTime)
        // Pending revocations (verified_at IS NULL) are not binding until the
        // cap-arrival cross-check verifies them, so they don't filter tokens.
        .where((eb) => {
          return eb.or([
            eb('revoked_capabilities.jti', 'is', null),
            eb('revoked_capabilities.verified_at', 'is', null),
          ])
        })
    )
  }

  function heldTokensAfter(params: { audience: string; atTime: number }, after?: string) {
    const query = heldTokens(params)
    if (after === undefined) return query
    let key: unknown
    try {
      key = JSON.parse(after)
    } catch (cause) {
      throw new RangeError('Invalid held-token cursor', { cause })
    }
    if (
      !Array.isArray(key) ||
      key.length !== 3 ||
      !key.every((value) => typeof value === 'string')
    ) {
      throw new RangeError('Invalid held-token cursor')
    }
    const [grantor, resource, jti] = key as [string, string, string]
    return query.where((eb) =>
      eb.or([
        eb('delegation_tokens.grantor', '>', grantor),
        eb.and([
          eb('delegation_tokens.grantor', '=', grantor),
          eb('delegation_tokens.resource', '>', resource),
        ]),
        eb.and([
          eb('delegation_tokens.grantor', '=', grantor),
          eb('delegation_tokens.resource', '=', resource),
          eb('delegation_tokens.jti', '>', jti),
        ]),
      ]),
    )
  }

  function tokenBytes() {
    const token = sql.ref('delegation_tokens.token')
    return adapter.kind === 'postgres'
      ? sql<number | string>`octet_length(convert_to(${token}, 'UTF8'))`
      : sql<number | string>`length(cast(${token} as blob))`
  }

  const api: DelegationStoreAPI = {
    // Lock before reading so arbitration preserves history even on one ambient transaction.
    async addDelegationToken(token: DelegationStoreAPIAddDelegationTokenParams): Promise<boolean> {
      const grantor = normalizeDID(token.grantor)
      const audience = normalizeDID(token.audience)
      const key = { grantor, audience, resource: token.resource }
      return await withKeyLock(
        context.provider,
        'delegation_tokens',
        [grantor, audience, token.resource],
        async (tx) => {
          // Standalone calls resolve the database belonging to the lock's new transaction.
          const store = (await tx.getStore('delegation')) as DelegationStoreAPI
          const trx = storeDatabases.get(store)
          if (trx == null) throw new Error('Delegation store database is unavailable')
          const existing = await trx
            .selectFrom('delegation_tokens')
            .select(['jti', 'token', 'act', 'exp', 'hlc'])
            .where('grantor', '=', grantor)
            .where('audience', '=', audience)
            .where('resource', '=', token.resource)
            .where('superseded', '=', 0)
            .executeTakeFirst()
          if (existing != null && token.hlc <= existing.hlc) {
            // A losing JTI may already have been delivered and must remain revocable.
            await trx
              .insertInto('delegation_tokens')
              .values({
                ...key,
                jti: token.jti,
                token: token.token,
                act: token.act,
                exp: token.exp,
                hlc: token.hlc,
                superseded: 1,
              })
              .onConflict((oc) => {
                return oc.columns(['grantor', 'audience', 'resource', 'jti']).doNothing()
              })
              .execute()
            return false
          }

          if (existing != null && existing.jti !== token.jti) {
            await trx
              .updateTable('delegation_tokens')
              .set({
                superseded: 1,
                updated_at: adapter.encodeTimestamp(
                  new Date(token.atTime == null ? now() : token.atTime * 1000),
                ) as number,
              })
              .where('grantor', '=', grantor)
              .where('audience', '=', audience)
              .where('resource', '=', token.resource)
              .where('superseded', '=', 0)
              .execute()
          }

          await trx
            .insertInto('delegation_tokens')
            .values({
              ...key,
              jti: token.jti,
              token: token.token,
              act: token.act,
              exp: token.exp,
              hlc: token.hlc,
              superseded: 0,
            })
            .onConflict((oc) => {
              return oc.columns(['grantor', 'audience', 'resource', 'jti']).doUpdateSet((eb) => {
                return {
                  token: eb.ref('excluded.token'),
                  act: eb.ref('excluded.act'),
                  exp: eb.ref('excluded.exp'),
                  hlc: eb.ref('excluded.hlc'),
                  superseded: 0,
                  updated_at: adapter.encodeTimestamp(
                    new Date(token.atTime == null ? now() : token.atTime * 1000),
                  ) as number,
                }
              })
            })
            .execute()

          return (
            existing == null ||
            existing.jti !== token.jti ||
            existing.token !== token.token ||
            existing.act !== token.act ||
            existing.exp !== token.exp
          )
        },
      )
    },

    async getDelegationTokens(params: {
      grantor: string
      audience: string
    }): Promise<Array<DelegationToken>> {
      return await db
        .selectFrom('delegation_tokens')
        .selectAll()
        .where('grantor', '=', normalizeDID(params.grantor))
        .where('audience', '=', normalizeDID(params.audience))
        .where('delegation_tokens.superseded', '=', 0)
        .execute()
    },

    async getHeldTokens(params) {
      return await heldTokens(params).selectAll('delegation_tokens').execute()
    },

    async getHeldTokenStats(params) {
      const length = tokenBytes()
      const row = await heldTokens(params)
        .select((eb) => [
          eb.fn.countAll().as('count'),
          sql<number | string>`coalesce(sum(${length}), 0)`.as('bytes'),
        ])
        .executeTakeFirstOrThrow()
      const count = Number(row.count)
      const bytes = Number(row.bytes)
      // Never silently underestimate a resource preflight through numeric rounding.
      if (!Number.isSafeInteger(count) || !Number.isSafeInteger(bytes)) {
        throw new RangeError('Held-token statistics exceed the safe integer range')
      }
      return { count, bytes }
    },

    async getHeldTokenPage(params) {
      if (
        !Number.isInteger(params.limit) ||
        params.limit < 1 ||
        params.limit > MAX_HELD_TOKEN_PAGE_SIZE
      ) {
        throw new RangeError(`limit must be an integer from 1 to ${MAX_HELD_TOKEN_PAGE_SIZE}`)
      }
      const { maxBytes } = params
      if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes <= 0)) {
        throw new RangeError('maxBytes must be a positive safe integer')
      }
      if (maxBytes !== undefined) {
        // The limited candidate set contains only keys and lengths. Window totals and the
        // body join share one statement snapshot, including concurrent replacements/inserts.
        const candidates = heldTokensAfter(params, params.after)
          .select([
            'delegation_tokens.grantor',
            'delegation_tokens.audience',
            'delegation_tokens.resource',
            'delegation_tokens.jti',
            tokenBytes().as('bytes'),
          ])
          .orderBy('delegation_tokens.grantor')
          .orderBy('delegation_tokens.resource')
          .orderBy('delegation_tokens.jti')
          .limit(params.limit)
        const rows = await db
          .with('held_candidates', () => candidates)
          .with('held_running', (qb) =>
            qb
              .selectFrom('held_candidates')
              .selectAll()
              .select([
                sql<
                  number | string
                >`sum(bytes) over (order by grantor, resource, jti rows unbounded preceding)`.as(
                  'total',
                ),
                sql<number>`row_number() over (order by grantor, resource, jti)`.as('position'),
              ]),
          )
          .selectFrom('held_running')
          .leftJoin('delegation_tokens', (join) =>
            join
              .onRef('delegation_tokens.grantor', '=', 'held_running.grantor')
              .onRef('delegation_tokens.audience', '=', 'held_running.audience')
              .onRef('delegation_tokens.resource', '=', 'held_running.resource')
              .onRef('delegation_tokens.jti', '=', 'held_running.jti')
              // Rejected keys cannot join a body, even for the oversized metadata row.
              .on('held_running.total', '<=', maxBytes),
          )
          .selectAll('delegation_tokens')
          .select(['held_running.jti as candidate_jti', 'held_running.bytes'])
          .where((eb) =>
            eb.or([
              eb('held_running.total', '<=', maxBytes),
              eb('held_running.position', '=', sql.lit(1)),
            ]),
          )
          .orderBy('held_running.grantor')
          .orderBy('held_running.resource')
          .orderBy('held_running.jti')
          .execute()
        const first = rows[0]
        if (first == null) return { tokens: [], next: null }
        if (first.jti == null) {
          return {
            tokens: [],
            next: params.after ?? null,
            oversized: { jti: first.candidate_jti, bytes: Number(first.bytes) },
          }
        }
        const tokens = rows.map(
          ({ candidate_jti: _key, bytes: _bytes, ...token }) =>
            // The join either provides a complete row or only the first oversized marker.
            token as DelegationToken,
        )
        const last = rows.at(-1) ?? first
        const cursor = JSON.stringify([last.grantor, last.resource, last.jti])
        const more = await heldTokensAfter(params, cursor)
          .select('delegation_tokens.jti')
          .limit(1)
          .executeTakeFirst()
        return { tokens, next: more == null ? null : cursor }
      }
      const tokens = await heldTokensAfter(params, params.after)
        .selectAll('delegation_tokens')
        .orderBy('delegation_tokens.grantor')
        .orderBy('delegation_tokens.resource')
        .orderBy('delegation_tokens.jti')
        .limit(params.limit)
        .execute()
      const last = tokens.at(-1)
      if (last == null || tokens.length < params.limit) return { tokens, next: null }
      const cursor = JSON.stringify([last.grantor, last.resource, last.jti])
      // Probe only a key, never an extra potentially oversized token string.
      const more = await heldTokensAfter(params, cursor)
        .select('delegation_tokens.jti')
        .limit(1)
        .executeTakeFirst()
      return { tokens, next: more == null ? null : cursor }
    },

    async listIssuedTokens(grantor: string): Promise<Array<DelegationToken>> {
      return await db
        .selectFrom('delegation_tokens')
        .selectAll()
        .where('grantor', '=', normalizeDID(grantor))
        .where('superseded', '=', 0)
        .execute()
    },

    async listUnrevokedSupersededTokens(params): Promise<Array<DelegationToken>> {
      const grantor = normalizeDID(params.grantor)
      return await db
        .selectFrom('delegation_tokens')
        .leftJoin('revoked_capabilities', (join) => {
          return join
            .onRef('revoked_capabilities.jti', '=', 'delegation_tokens.jti')
            .onRef('revoked_capabilities.revoker_did', '=', 'delegation_tokens.grantor')
        })
        .selectAll('delegation_tokens')
        .where('delegation_tokens.grantor', '=', grantor)
        .where('audience', '=', normalizeDID(params.audience))
        .where('resource', '=', params.resource)
        .where('delegation_tokens.superseded', '=', 1)
        .where('exp', '>=', params.atTime)
        .where('revoked_capabilities.jti', 'is', null)
        .orderBy('delegation_tokens.hlc')
        .orderBy('delegation_tokens.jti')
        .execute()
    },

    // `jti` is picked by whoever minted the capability and the grant travels to
    // the whole group, so any co-member can mint one reusing a `jti` it saw. It
    // names a row only inside a single grantor's namespace, and even there it is
    // not a key. A grantor that reused one `jti` across two of its own grants
    // leaves no representable answer, so this throws rather than pick.
    async getDelegationTokenByGrantorJTI(params: {
      jti: string
      grantor: string
    }): Promise<DelegationToken | null> {
      const grantor = normalizeDID(params.grantor)
      const rows = await db
        .selectFrom('delegation_tokens')
        .selectAll()
        .where('jti', '=', params.jti)
        .where('grantor', '=', grantor)
        .limit(2)
        .execute()
      if (rows.length > 1) {
        throw new Error(
          `Ambiguous delegation token: grantor ${grantor} holds more than one row for jti ${params.jti}`,
        )
      }
      return rows[0] ?? null
    },

    // Every grantor's row for one `jti`. For diagnostics and for absence
    // assertions across grantors -- an authorization decision needs
    // `getDelegationTokenByGrantorJTI`, since any row here may be a co-member's.
    async listDelegationTokensByJTI(jti: string): Promise<Array<DelegationToken>> {
      return await db
        .selectFrom('delegation_tokens')
        .selectAll()
        .where('jti', '=', jti)
        .orderBy('grantor')
        .execute()
    },

    async removeDelegationToken(params: { jti: string }): Promise<boolean> {
      const result = await db
        .deleteFrom('delegation_tokens')
        .where('jti', '=', params.jti)
        .executeTakeFirst()
      return (result.numDeletedRows ?? 0n) > 0n
    },

    // Same LWW arbitration as `addDelegationToken`. Both the pre-read and the
    // conflict target are scoped to `(jti, revoker_did)`: several revokers may
    // name the same `jti`, and each may only arbitrate against its own row.
    async addRevocation(input: InsertRevokedCapability & { atTime?: number }): Promise<boolean> {
      const revokerDID = normalizeDID(input.revoker_did)
      // `revoked_iat` comes from a signed broadcast, and on a pending row no
      // issuer has been matched yet -- so any co-member could name a `jti` with a
      // far-future stamp and outlive every purge. Floored, not rejected: the
      // record still binds, only its retention is bounded.
      const revokedIat = Math.min(
        input.revoked_iat,
        (input.atTime ?? nowSeconds()) + MAX_REVOCATION_FUTURE_DRIFT_SECONDS,
      )
      const verifiedAt = input.verified_at ?? null
      const capExp = input.cap_exp ?? null
      return await withStoreTransaction(db, async (trx) => {
        const existing = await trx
          .selectFrom('revoked_capabilities')
          .select(['revoked_iat', 'revocation_token', 'verified_at', 'cap_exp', 'hlc'])
          .where('jti', '=', input.jti)
          .where('revoker_did', '=', revokerDID)
          .executeTakeFirst()

        await trx
          .insertInto('revoked_capabilities')
          .values({
            jti: input.jti,
            revoker_did: revokerDID,
            revoked_iat: revokedIat,
            revocation_token: input.revocation_token,
            verified_at: verifiedAt,
            cap_exp: capExp,
            hlc: input.hlc,
          })
          .onConflict((oc) => {
            return oc
              .columns(['jti', 'revoker_did'])
              .doUpdateSet((eb) => {
                return {
                  revoked_iat: eb.ref('excluded.revoked_iat'),
                  revocation_token: eb.ref('excluded.revocation_token'),
                  verified_at: eb.ref('excluded.verified_at'),
                  cap_exp: eb.ref('excluded.cap_exp'),
                  hlc: eb.ref('excluded.hlc'),
                  updated_at: adapter.encodeTimestamp(
                    new Date(input.atTime == null ? now() : input.atTime * 1000),
                  ) as number,
                }
              })
              .where((eb) => eb('excluded.hlc', '>', eb.ref('revoked_capabilities.hlc')))
          })
          .execute()

        if (existing == null) {
          return true
        }
        if (input.hlc <= existing.hlc) {
          return false
        }
        // Compares the floored stamp, so an identical re-broadcast is a no-op.
        return (
          existing.revoked_iat !== revokedIat ||
          existing.revocation_token !== input.revocation_token ||
          existing.verified_at !== verifiedAt ||
          existing.cap_exp !== capExp
        )
      })
    },

    // `jti` alone does not identify a row: several revokers may name the same
    // capability and only the one signed by its issuer binds.
    async getRevocationByIssuer({ jti, issuer }): Promise<RevokedCapability | null> {
      const row = await db
        .selectFrom('revoked_capabilities')
        .selectAll()
        .where('jti', '=', jti)
        .where('revoker_did', '=', normalizeDID(issuer))
        .executeTakeFirst()
      return row ?? null
    },

    // Every author's claim about one `jti`. For diagnostics and absence
    // assertions -- an enforcement decision needs `getRevocationByIssuer`.
    async listRevocations(jti: string): Promise<Array<RevokedCapability>> {
      return await db
        .selectFrom('revoked_capabilities')
        .selectAll()
        .where('jti', '=', jti)
        .orderBy('revoker_did')
        .execute()
    },

    async isRevokedBy({ jti, issuer }): Promise<boolean> {
      const row = await db
        .selectFrom('revoked_capabilities')
        .select('jti')
        .where('jti', '=', jti)
        .where('revoker_did', '=', normalizeDID(issuer))
        .where('verified_at', 'is not', null)
        .executeTakeFirst()
      return row != null
    },

    // Explicit column list because both tables share column names (`jti`, `hlc`,
    // `created_at`, `updated_at`). The INNER JOIN drops verified revocations
    // whose cap is not held locally, and `revoker_did = grantor` drops a
    // co-member's row for the same `jti`, which revokes nothing.
    async getHeldRevocations(params: { audience: string }): Promise<Array<HeldRevocation>> {
      const rows = await db
        .selectFrom('revoked_capabilities')
        .innerJoin('delegation_tokens', (join) => {
          return join
            .onRef('delegation_tokens.jti', '=', 'revoked_capabilities.jti')
            .onRef('delegation_tokens.grantor', '=', 'revoked_capabilities.revoker_did')
        })
        .select([
          'revoked_capabilities.jti as jti',
          'delegation_tokens.grantor as grantor',
          'delegation_tokens.audience as audience',
          'revoked_capabilities.revoker_did as revoker_did',
          'revoked_capabilities.revoked_iat as revoked_iat',
          'revoked_capabilities.verified_at as verified_at',
          'revoked_capabilities.cap_exp as cap_exp',
        ])
        .where('revoked_capabilities.verified_at', 'is not', null)
        .where('delegation_tokens.audience', '=', normalizeDID(params.audience))
        .execute()
      return rows.map((row) => {
        return {
          jti: row.jti,
          grantor: row.grantor,
          audience: row.audience,
          revoker_did: row.revoker_did,
          revoked_iat: row.revoked_iat,
          // Non-null by the WHERE above.
          verified_at: row.verified_at as number,
          cap_exp: row.cap_exp,
        }
      })
    },

    // Promotion is an authorization decision about one author's claim: the
    // arriving capability proves only that its own issuer's record is genuine.
    async markRevocationVerified({ jti, issuer, cap_exp, verified_at, atTime }): Promise<boolean> {
      const result = await db
        .updateTable('revoked_capabilities')
        .set({
          verified_at: verified_at ?? atTime ?? nowSeconds(),
          cap_exp,
          updated_at: adapter.encodeTimestamp(
            new Date(atTime == null ? now() : atTime * 1000),
          ) as number,
        })
        .where('jti', '=', jti)
        .where('revoker_did', '=', normalizeDID(issuer))
        .where('verified_at', 'is', null)
        .executeTakeFirst()
      return (result.numUpdatedRows ?? 0n) > 0n
    },

    async getPendingRevocationByIssuer({ jti, issuer }): Promise<RevokedCapability | null> {
      const row = await db
        .selectFrom('revoked_capabilities')
        .selectAll()
        .where('jti', '=', jti)
        .where('revoker_did', '=', normalizeDID(issuer))
        .where('verified_at', 'is', null)
        .executeTakeFirst()
      return row ?? null
    },

    // The inverse scoping of `markRevocationVerified`: what that promotes this
    // discards, so together they settle every pending row for the `jti`.
    async deletePendingRevocationsFromOtherIssuers({ jti, issuer }): Promise<number> {
      const result = await db
        .deleteFrom('revoked_capabilities')
        .where('jti', '=', jti)
        .where('revoker_did', '!=', normalizeDID(issuer))
        .where('verified_at', 'is', null)
        .executeTakeFirst()
      return Number(result.numDeletedRows ?? 0n)
    },

    // `cap_exp` is plain integer seconds, so the cutoff stays in integer space on
    // both back-ends. Pending rows have `cap_exp` NULL and are excluded.
    async purgeExpiredRevocations(params?: PurgeParams): Promise<number> {
      const cutoff = (params?.atTime ?? nowSeconds()) - resolveGraceSeconds(params)
      const result = await db
        .deleteFrom('revoked_capabilities')
        .where('verified_at', 'is not', null)
        .where('cap_exp', 'is not', null)
        .where('cap_exp', '<', cutoff)
        .executeTakeFirst()
      return Number(result.numDeletedRows ?? 0n)
    },

    // Keyed off `revoked_iat` rather than `created_at`: the capability was live
    // when revoked, so `cap.exp ≤ revoked_iat + MAX_CAP_TTL_SECONDS`. It is a
    // bigint of unix seconds, not an adapter-encoded timestamp, so the cutoff
    // must not go through `adapter.encodeTimestamp`.
    async purgeDeadPendingRevocations(params?: PurgeParams): Promise<number> {
      const cutoff =
        (params?.atTime ?? nowSeconds()) - MAX_CAP_TTL_SECONDS - resolveGraceSeconds(params)
      const result = await db
        .deleteFrom('revoked_capabilities')
        .where('verified_at', 'is', null)
        .where('revoked_iat', '<', cutoff)
        .executeTakeFirst()
      return Number(result.numDeletedRows ?? 0n)
    },
  }

  storeDatabases.set(api, db)
  return api
}

export type DelegationStoreAPIGetRevocationByIssuerParams = { jti: string; issuer: string }

export type DelegationStoreAPIIsRevokedByParams = { jti: string; issuer: string }

export type DelegationStoreAPIMarkRevocationVerifiedParams = {
  jti: string
  issuer: string
  cap_exp: number
  verified_at?: number
  /** Verification time in Unix seconds, used when verified_at is omitted. */
  atTime?: number
}

export type DelegationStoreAPIGetPendingRevocationByIssuerParams = { jti: string; issuer: string }

export type DelegationStoreAPIDeletePendingRevocationsFromOtherIssuersParams = {
  jti: string
  issuer: string
}

/** Store write time in Unix seconds. Fractional seconds preserve the caller clock. */
export type DelegationStoreAPIAddDelegationTokenParams = InsertDelegationToken & { atTime?: number }
