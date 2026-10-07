// Parameter audit: every statement binds a fixed, small count (at most 9) -- no `IN` lists
// built from input and no multi-row values -- so none nears the 500-parameter limit.
import type { Adapter } from '@hozon/adapter'
import { withStoreTransaction } from '@hozon/db'
import { normalizeDID } from '@kokuin/token'
import type { Kysely } from 'kysely'

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
export type PurgeParams = { graceSeconds?: number }

export type DelegationStoreAPI = {
  /**
   * Last-writer-wins upsert keyed by `(grantor, audience, resource)`. Returns whether the stored
   * row changed. The result is an approximate change signal for emission gating: the pre-read
   * takes no lock, so two concurrent writers can both see `true`.
   */
  addDelegationToken(token: InsertDelegationToken): Promise<boolean>
  getDelegationTokens(params: {
    grantor: string
    audience: string
  }): Promise<Array<DelegationToken>>
  getHeldTokens(params: { audience: string; atTime: number }): Promise<Array<DelegationToken>>
  listIssuedTokens(grantor: string): Promise<Array<DelegationToken>>
  getDelegationTokenByGrantorJTI(params: {
    jti: string
    grantor: string
  }): Promise<DelegationToken | null>
  listDelegationTokensByJTI(jti: string): Promise<Array<DelegationToken>>
  removeDelegationToken(params: { jti: string }): Promise<boolean>

  /**
   * Last-writer-wins upsert keyed by `(jti, revoker_did)`. A `revoked_iat` beyond
   * `now + MAX_REVOCATION_FUTURE_DRIFT_SECONDS` is floored to that bound. Returns whether the
   * stored row changed. The result is an approximate change signal for emission gating: the
   * pre-read takes no lock, so two concurrent writers can both see `true`.
   *
   * A row written verified (`verified_at` set) with `cap_exp: null` is never purged: the expired
   * purge needs a `cap_exp` and the pending purge only takes unverified rows. Pass `cap_exp` with
   * `verified_at`, or verify through `markRevocationVerified`, which requires it.
   */
  addRevocation(input: InsertRevokedCapability): Promise<boolean>
  getRevocationByIssuer(jti: string, issuer: string): Promise<RevokedCapability | null>
  listRevocations(jti: string): Promise<Array<RevokedCapability>>
  /**
   * Diagnostic only -- **not** an authorization read. The `verified_at IS NOT NULL` predicate is
   * the inverse of the enforcement rule: a co-member holds no copy of the capability, so its
   * genuine revocation stays pending forever and this answers `false` for it. Authorization must
   * read the issuer's row whatever its verification state.
   */
  isRevokedBy(jti: string, issuer: string): Promise<boolean>
  getHeldRevocations(params: { audience: string }): Promise<Array<HeldRevocation>>
  markRevocationVerified(
    jti: string,
    issuer: string,
    params: { cap_exp: number; verified_at?: number },
  ): Promise<boolean>
  getPendingRevocationByIssuer(jti: string, issuer: string): Promise<RevokedCapability | null>
  deletePendingRevocationsFromOtherIssuers(jti: string, issuer: string): Promise<number>
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

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
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

// One identity reaches this store in two spellings: a `did:peer:4` signer
// embeds its long form as the `iss` of its first token to a given audience and
// its short form thereafter, while `identity.id` and `sub` are always short. So
// the DID a capability presents at check time and the DID its revocation was
// filed under are genuinely different strings for the same peer, with no
// attacker involved. Every DID crossing this boundary -- written or compared --
// is folded through `normalizeDID`, because a raw equality here silently
// returns "not revoked".
export function createDelegationStore(
  db: Kysely<DelegationStoreTables>,
  adapter: Adapter,
): DelegationStoreAPI {
  const api: DelegationStoreAPI = {
    // LWW arbitration on `hlc`: SQL `>` decides the upsert, JS `<=` the change
    // signal. Both are byte-wise (see the migration's collation), so they agree.
    // The pre-read and upsert share a store transaction, which joins an enclosing
    // one. That does not lock the pre-read, so the result stays approximate.
    async addDelegationToken(token: InsertDelegationToken): Promise<boolean> {
      const grantor = normalizeDID(token.grantor)
      const audience = normalizeDID(token.audience)
      return await withStoreTransaction(db, async (trx) => {
        const existing = await trx
          .selectFrom('delegation_tokens')
          .select(['jti', 'token', 'act', 'exp', 'hlc'])
          .where('grantor', '=', grantor)
          .where('audience', '=', audience)
          .where('resource', '=', token.resource)
          .executeTakeFirst()

        await trx
          .insertInto('delegation_tokens')
          .values({
            jti: token.jti,
            grantor,
            audience,
            token: token.token,
            resource: token.resource,
            act: token.act,
            exp: token.exp,
            hlc: token.hlc,
          })
          .onConflict((oc) =>
            oc
              .columns(['grantor', 'audience', 'resource'])
              .doUpdateSet((eb) => ({
                jti: eb.ref('excluded.jti'),
                token: eb.ref('excluded.token'),
                act: eb.ref('excluded.act'),
                exp: eb.ref('excluded.exp'),
                hlc: eb.ref('excluded.hlc'),
                updated_at: adapter.encodeTimestamp(new Date()) as number,
              }))
              .where((eb) => eb('excluded.hlc', '>', eb.ref('delegation_tokens.hlc'))),
          )
          .execute()

        if (existing == null) {
          return true
        }
        if (token.hlc <= existing.hlc) {
          // LWW lost: the stored row is unchanged.
          return false
        }
        // LWW won: report a change only if content differs, so an identical
        // re-broadcast with a newer hlc is a no-op for consumers.
        return (
          existing.jti !== token.jti ||
          existing.token !== token.token ||
          existing.act !== token.act ||
          existing.exp !== token.exp
        )
      })
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
        .execute()
    },

    // The join carries the author predicate for two reasons. It is an
    // authorization filter -- only the grantor's own claim may withhold a token
    // from the audience holding it. It also keeps the result one row per token:
    // `(jti, revoker_did)` is the revocation key, so pinning `revoker_did` to the
    // token's grantor makes the fan-out at most 1. A duplicate would break a
    // multi-hop delegation chain outright.
    async getHeldTokens(params: {
      audience: string
      atTime: number
    }): Promise<Array<DelegationToken>> {
      return await db
        .selectFrom('delegation_tokens')
        .leftJoin('revoked_capabilities', (join) =>
          join
            .onRef('revoked_capabilities.jti', '=', 'delegation_tokens.jti')
            .onRef('revoked_capabilities.revoker_did', '=', 'delegation_tokens.grantor'),
        )
        .selectAll('delegation_tokens')
        .where('audience', '=', normalizeDID(params.audience))
        .where('exp', '>', params.atTime)
        // Pending revocations (verified_at IS NULL) are not binding until the
        // cap-arrival cross-check verifies them, so they don't filter tokens.
        .where((eb) =>
          eb.or([
            eb('revoked_capabilities.jti', 'is', null),
            eb('revoked_capabilities.verified_at', 'is', null),
          ]),
        )
        .execute()
    },

    async listIssuedTokens(grantor: string): Promise<Array<DelegationToken>> {
      return await db
        .selectFrom('delegation_tokens')
        .selectAll()
        .where('grantor', '=', normalizeDID(grantor))
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
    async addRevocation(input: InsertRevokedCapability): Promise<boolean> {
      const revokerDID = normalizeDID(input.revoker_did)
      // `revoked_iat` comes from a signed broadcast, and on a pending row no
      // issuer has been matched yet -- so any co-member could name a `jti` with a
      // far-future stamp and outlive every purge. Floored, not rejected: the
      // record still binds, only its retention is bounded.
      const revokedIat = Math.min(
        input.revoked_iat,
        nowSeconds() + MAX_REVOCATION_FUTURE_DRIFT_SECONDS,
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
          .onConflict((oc) =>
            oc
              .columns(['jti', 'revoker_did'])
              .doUpdateSet((eb) => ({
                revoked_iat: eb.ref('excluded.revoked_iat'),
                revocation_token: eb.ref('excluded.revocation_token'),
                verified_at: eb.ref('excluded.verified_at'),
                cap_exp: eb.ref('excluded.cap_exp'),
                hlc: eb.ref('excluded.hlc'),
                updated_at: adapter.encodeTimestamp(new Date()) as number,
              }))
              .where((eb) => eb('excluded.hlc', '>', eb.ref('revoked_capabilities.hlc'))),
          )
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
    async getRevocationByIssuer(jti: string, issuer: string): Promise<RevokedCapability | null> {
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

    async isRevokedBy(jti: string, issuer: string): Promise<boolean> {
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
        .innerJoin('delegation_tokens', (join) =>
          join
            .onRef('delegation_tokens.jti', '=', 'revoked_capabilities.jti')
            .onRef('delegation_tokens.grantor', '=', 'revoked_capabilities.revoker_did'),
        )
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
      return rows.map((row) => ({
        jti: row.jti,
        grantor: row.grantor,
        audience: row.audience,
        revoker_did: row.revoker_did,
        revoked_iat: row.revoked_iat,
        // Non-null by the WHERE above.
        verified_at: row.verified_at as number,
        cap_exp: row.cap_exp,
      }))
    },

    // Promotion is an authorization decision about one author's claim: the
    // arriving capability proves only that its own issuer's record is genuine.
    async markRevocationVerified(
      jti: string,
      issuer: string,
      params: { cap_exp: number; verified_at?: number },
    ): Promise<boolean> {
      const result = await db
        .updateTable('revoked_capabilities')
        .set({
          verified_at: params.verified_at ?? nowSeconds(),
          cap_exp: params.cap_exp,
          updated_at: adapter.encodeTimestamp(new Date()) as number,
        })
        .where('jti', '=', jti)
        .where('revoker_did', '=', normalizeDID(issuer))
        .where('verified_at', 'is', null)
        .executeTakeFirst()
      return (result.numUpdatedRows ?? 0n) > 0n
    },

    async getPendingRevocationByIssuer(
      jti: string,
      issuer: string,
    ): Promise<RevokedCapability | null> {
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
    async deletePendingRevocationsFromOtherIssuers(jti: string, issuer: string): Promise<number> {
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
      const cutoff = nowSeconds() - resolveGraceSeconds(params)
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
      const cutoff = nowSeconds() - MAX_CAP_TTL_SECONDS - resolveGraceSeconds(params)
      const result = await db
        .deleteFrom('revoked_capabilities')
        .where('verified_at', 'is', null)
        .where('revoked_iat', '<', cutoff)
        .executeTakeFirst()
      return Number(result.numDeletedRows ?? 0n)
    },
  }

  return api
}
