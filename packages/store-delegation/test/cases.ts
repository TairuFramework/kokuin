import type { Adapter } from '@hozon/adapter'
import { HozonDB, TablePrefixPlugin } from '@hozon/db'
import { createCapability, createRevocationRecord } from '@kokuin/capability'
import { createIdentity, stringifyToken } from '@kokuin/token'
import { Kysely, type QueryExecutorProvider, sql } from 'kysely'
import { type Migration, Migrator } from 'kysely/migration'
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest'

import {
  createDelegationStore,
  type DelegationStoreAPI,
  type DelegationStoreTables,
  delegationStoreDefinition,
  getDelegationStore,
  type InsertDelegationToken,
  type InsertRevokedCapability,
  MAX_CAP_TTL_SECONDS,
  MAX_REVOCATION_FUTURE_DRIFT_SECONDS,
  REVOCATION_GC_VERIFIED_GRACE_SECONDS,
} from '../src/index.js'
import { getDelegationMigrations } from '../src/migrations.js'

export type StoreHarness = {
  name: string
  createAdapter(): Promise<Adapter>
  cleanup(): Promise<void>
}

/** Index names of a physical table. Kysely has no dialect-agnostic catalog query. */
export async function indexNames(
  db: QueryExecutorProvider,
  kind: 'sqlite' | 'postgres',
  table: string,
): Promise<Array<string>> {
  const query =
    kind === 'sqlite'
      ? sql<{ name: string }>`select name from sqlite_master
        where type = 'index' and tbl_name = ${sql.lit(table)}`
      : sql<{ name: string }>`select indexname as name from pg_indexes
        where tablename = ${sql.lit(table)}`
  const { rows } = await query.execute(db)
  return rows.map((row) => row.name)
}

// The store compares `hlc` as a byte-wise string, so tests use zero-padded
// counters where lexical order matches logical order.
function hlc(counter: number): string {
  return counter.toString().padStart(12, '0')
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

function delegationToken(overrides: Partial<InsertDelegationToken> = {}): InsertDelegationToken {
  return {
    jti: 'jti-1',
    grantor: 'did:key:grantor',
    audience: 'did:key:audience',
    token: 'signed-token-1',
    resource: 'doc:1',
    act: 'write',
    // Past the int32 second ceiling (2^31-1 ≈ 2038): a value the `exp` column
    // must hold as bigint. On an int32 column this overflows on Postgres.
    exp: 5_000_000_000,
    hlc: hlc(1),
    ...overrides,
  }
}

// A `did:peer:4` identity is the only DID with two spellings: `identity.id` is
// the short form a row is filed under, `longForm` is what the signer embeds as
// `iss` on a first token to a given audience. Both come out of the mint path.
async function peer4Identity() {
  const identity = await createIdentity({
    keys: [{ purpose: 'sig', alg: 'EdDSA' }],
    didMethod: 'peer:4',
  })
  // Not vacuous: the two spellings really are different strings.
  expect(identity.longForm).not.toBe(identity.id)
  return identity
}

// The author `revocation()` attributes a row to. Reads name it explicitly: a
// `jti` identifies several rows, one per revoker.
const REVOKER = 'did:key:revoker'

function revocation(overrides: Partial<InsertRevokedCapability> = {}): InsertRevokedCapability {
  return {
    jti: 'jti-1',
    revoker_did: REVOKER,
    revoked_iat: 1_700_000_000,
    revocation_token: 'signed-revocation-1',
    verified_at: null,
    cap_exp: null,
    hlc: hlc(1),
    ...overrides,
  }
}

// Fixed-width stamps equal in time and counter, so only the node ID decides.
function stamp(nodeID: string): string {
  return `2026-01-01T00:00:00.000Z:000000000001:${nodeID}`
}

const TIE_BREAK_PAIRS: Array<[string, string]> = [
  ['B', 'a'],
  ['node-9', 'node-10'],
]

/**
 * Registers the delegation store conformance tests. Call inside a `describe`.
 * Every physical name is derived from `options.tablePrefix`, and the cases run
 * on any adapter.
 */
export function delegationStoreCases(
  harness: StoreHarness,
  options: { tablePrefix?: string } = {},
): void {
  const { tablePrefix } = options
  const prefix = tablePrefix ?? 'hozon'

  afterAll(async () => {
    await harness.cleanup()
  })

  describe('store', () => {
    let db: HozonDB
    let store: DelegationStoreAPI

    beforeAll(async () => {
      db = new HozonDB({ adapter: await harness.createAdapter(), tablePrefix })
      db.register(delegationStoreDefinition)
      store = await getDelegationStore(db)
    }, 60_000)

    afterAll(async () => {
      vi.useRealTimers()
      await db?.close()
    })

    test('addDelegationToken inserts a fresh row and reports changed', async () => {
      const changed = await store.addDelegationToken(
        delegationToken({ grantor: 'did:key:g-fresh', audience: 'did:key:a-fresh' }),
      )
      expect(changed).toBe(true)

      const rows = await store.getDelegationTokens({
        grantor: 'did:key:g-fresh',
        audience: 'did:key:a-fresh',
      })
      expect(rows).toHaveLength(1)
      expect(rows[0]?.token).toBe('signed-token-1')
      expect(rows[0]?.resource).toBe('doc:1')
    })

    test('addDelegationToken LWW: newer HLC with changed content wins, older loses', async () => {
      const base = {
        grantor: 'did:key:g-lww',
        audience: 'did:key:a-lww',
        resource: 'doc:lww',
      }
      await store.addDelegationToken(delegationToken({ ...base, token: 'v1', hlc: hlc(5) }))

      // Older HLC is rejected: no update, reports unchanged.
      const older = await store.addDelegationToken(
        delegationToken({ ...base, token: 'v-old', hlc: hlc(4) }),
      )
      expect(older).toBe(false)
      let rows = await store.getDelegationTokens({ grantor: base.grantor, audience: base.audience })
      expect(rows).toHaveLength(1)
      expect(rows[0]?.token).toBe('v1')

      // Newer HLC with different content wins and overwrites in place.
      const newer = await store.addDelegationToken(
        delegationToken({ ...base, token: 'v2', hlc: hlc(6) }),
      )
      expect(newer).toBe(true)
      rows = await store.getDelegationTokens({ grantor: base.grantor, audience: base.audience })
      expect(rows).toHaveLength(1)
      expect(rows[0]?.token).toBe('v2')
    })

    test('getDelegationTokenByGrantorJTI returns the named grantor’s token or null', async () => {
      await store.addDelegationToken(
        delegationToken({ jti: 'jti-by-jti', grantor: 'did:key:g-jti', audience: 'did:key:a-jti' }),
      )
      const found = await store.getDelegationTokenByGrantorJTI({
        jti: 'jti-by-jti',
        grantor: 'did:key:g-jti',
      })
      expect(found?.grantor).toBe('did:key:g-jti')
      // A post-2038 expiry round-trips exactly, confirming the bigint column.
      expect(found?.exp).toBe(5_000_000_000)
      expect(
        await store.getDelegationTokenByGrantorJTI({
          jti: 'jti-missing',
          grantor: 'did:key:g-jti',
        }),
      ).toBeNull()
    })

    // A `jti` is namespaced by its grantor, so a co-member reusing one names a
    // different capability. Neither grantor may answer for the other's row.
    test('getDelegationTokenByGrantorJTI does not answer for a colliding grantor', async () => {
      const jti = 'jti-collision'
      await store.addDelegationToken(
        delegationToken({ jti, grantor: 'did:key:g-collide-a', audience: 'did:key:a-collide' }),
      )
      await store.addDelegationToken(
        delegationToken({ jti, grantor: 'did:key:g-collide-b', audience: 'did:key:a-collide' }),
      )

      expect(
        (await store.getDelegationTokenByGrantorJTI({ jti, grantor: 'did:key:g-collide-a' }))
          ?.grantor,
      ).toBe('did:key:g-collide-a')
      expect(
        (await store.getDelegationTokenByGrantorJTI({ jti, grantor: 'did:key:g-collide-b' }))
          ?.grantor,
      ).toBe('did:key:g-collide-b')
      expect(
        await store.getDelegationTokenByGrantorJTI({ jti, grantor: 'did:key:g-collide-c' }),
      ).toBeNull()
      expect((await store.listDelegationTokensByJTI(jti)).map((row) => row.grantor)).toEqual([
        'did:key:g-collide-a',
        'did:key:g-collide-b',
      ])
    })

    // One grantor reusing a `jti` across two of its own grants leaves the scoped
    // read with no answer to give; picking one would be true of some grant.
    test('getDelegationTokenByGrantorJTI throws when one grantor holds two rows for a jti', async () => {
      const jti = 'jti-ambiguous'
      const grantor = 'did:key:g-ambiguous'
      await store.addDelegationToken(
        delegationToken({ jti, grantor, audience: 'did:key:a-ambiguous', resource: 'doc:one' }),
      )
      await store.addDelegationToken(
        delegationToken({ jti, grantor, audience: 'did:key:a-ambiguous', resource: 'doc:two' }),
      )

      await expect(store.getDelegationTokenByGrantorJTI({ jti, grantor })).rejects.toThrow(
        /Ambiguous delegation token/,
      )
    })

    test('listDelegationTokensByJTI returns an empty list for an unknown jti', async () => {
      expect(await store.listDelegationTokensByJTI('jti-nobody-has')).toEqual([])
    })

    test('getHeldTokens excludes expired tokens', async () => {
      const audience = 'did:key:a-exp'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-live',
          grantor: 'did:key:g-live',
          audience,
          resource: 'doc:live',
          exp: 5_000,
        }),
      )
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-dead',
          grantor: 'did:key:g-dead',
          audience,
          resource: 'doc:dead',
          exp: 1_000,
        }),
      )
      const held = await store.getHeldTokens({ audience, atTime: 3_000 })
      expect(held.map((t) => t.jti)).toEqual(['jti-live'])
    })

    test('getHeldTokens excludes verified-revoked but keeps pending-revoked', async () => {
      const audience = 'did:key:a-rev'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-verified-rev',
          grantor: 'did:key:g1',
          audience,
          resource: 'doc:a',
          exp: 2_000_000_000,
        }),
      )
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-pending-rev',
          grantor: 'did:key:g2',
          audience,
          resource: 'doc:b',
          exp: 2_000_000_000,
        }),
      )
      // Verified revocation removes its token from held. Authored by the cap's
      // own grantor — only that author's claim withholds a token.
      await store.addRevocation(
        revocation({
          jti: 'jti-verified-rev',
          revoker_did: 'did:key:g1',
          verified_at: 1_700_000_001,
          cap_exp: 2_000_000_000,
        }),
      )
      // Pending revocation (verified_at NULL) does not filter yet.
      await store.addRevocation(
        revocation({ jti: 'jti-pending-rev', revoker_did: 'did:key:g2', verified_at: null }),
      )

      const held = await store.getHeldTokens({ audience, atTime: 1_000 })
      expect(held.map((t) => t.jti).sort()).toEqual(['jti-pending-rev'])
    })

    // The auto-attach source. A capability's `jti` travels to every group member,
    // so a co-member can file a revocation under it; only the grantor's own claim
    // may withhold the token from the delegate that holds it.
    test('getHeldTokens keeps a token revoked by someone other than its grantor', async () => {
      const audience = 'did:key:a-forged-rev'
      const grantor = 'did:key:g-forged-rev'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-forged-rev',
          grantor,
          audience,
          resource: 'doc:forged-rev',
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-forged-rev',
          revoker_did: 'did:key:x-forged-rev',
          verified_at: 1_700_000_040,
          cap_exp: 2_000_000_000,
        }),
      )
      expect((await store.getHeldTokens({ audience, atTime: 1_000 })).map((t) => t.jti)).toEqual([
        'jti-forged-rev',
      ])

      // The grantor's own row does withhold it — so the token surviving above is
      // the author predicate, not the join failing to match at all.
      await store.addRevocation(
        revocation({
          jti: 'jti-forged-rev',
          revoker_did: grantor,
          verified_at: 1_700_000_041,
          cap_exp: 2_000_000_000,
        }),
      )
      expect(await store.getHeldTokens({ audience, atTime: 1_000 })).toEqual([])
    })

    // The join fans out over revocation rows, and several authors may name one
    // `jti`. A repeated token would be handed to the capability chain twice.
    test('getHeldTokens returns one row per token however many authors name its jti', async () => {
      const audience = 'did:key:a-dup-rev'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-dup-rev',
          grantor: 'did:key:g-dup-rev',
          audience,
          resource: 'doc:dup-rev',
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({ jti: 'jti-dup-rev', revoker_did: 'did:key:x1-dup-rev', verified_at: null }),
      )
      await store.addRevocation(
        revocation({ jti: 'jti-dup-rev', revoker_did: 'did:key:x2-dup-rev', verified_at: null }),
      )

      const held = await store.getHeldTokens({ audience, atTime: 1_000 })
      expect(held.map((t) => t.jti)).toEqual(['jti-dup-rev'])
    })

    test('addRevocation + isRevokedBy reflects verification state', async () => {
      // Pending revocation is not yet binding.
      await store.addRevocation(revocation({ jti: 'jti-isrevoked', verified_at: null }))
      expect(await store.isRevokedBy('jti-isrevoked', REVOKER)).toBe(false)

      // Verified revocation is binding.
      await store.addRevocation(
        revocation({
          jti: 'jti-isrevoked',
          verified_at: 1_700_000_002,
          cap_exp: 3_000,
          hlc: hlc(2),
        }),
      )
      expect(await store.isRevokedBy('jti-isrevoked', REVOKER)).toBe(true)
    })

    test('markRevocationVerified promotes a pending revocation', async () => {
      await store.addRevocation(revocation({ jti: 'jti-mark', verified_at: null }))
      expect(await store.isRevokedBy('jti-mark', REVOKER)).toBe(false)

      const marked = await store.markRevocationVerified('jti-mark', REVOKER, {
        cap_exp: 4_000,
        verified_at: 1_700_000_003,
      })
      expect(marked).toBe(true)
      expect(await store.isRevokedBy('jti-mark', REVOKER)).toBe(true)

      const row = await store.getRevocationByIssuer('jti-mark', REVOKER)
      expect(row?.verified_at).toBe(1_700_000_003)
      expect(row?.cap_exp).toBe(4_000)

      // A second mark is a no-op: the guard only promotes still-pending rows.
      expect(
        await store.markRevocationVerified('jti-mark', REVOKER, {
          cap_exp: 9_999,
          verified_at: 1_700_000_004,
        }),
      ).toBe(false)
    })

    // The capability that arrives proves its own issuer's record genuine and
    // says nothing about anyone else's.
    test('markRevocationVerified leaves another author’s pending row alone', async () => {
      const jti = 'jti-mark-scoped'
      const other = 'did:key:x-mark-scoped'
      await store.addRevocation(revocation({ jti, verified_at: null }))
      await store.addRevocation(revocation({ jti, revoker_did: other, verified_at: null }))

      expect(
        await store.markRevocationVerified(jti, REVOKER, {
          cap_exp: 4_000,
          verified_at: 1_700_000_003,
        }),
      ).toBe(true)
      expect(await store.isRevokedBy(jti, REVOKER)).toBe(true)
      expect(await store.isRevokedBy(jti, other)).toBe(false)
      expect((await store.getRevocationByIssuer(jti, other))?.verified_at).toBeNull()
    })

    test('getPendingRevocationByIssuer answers for the author it names', async () => {
      const jti = 'jti-pending-by-issuer'
      const other = 'did:key:x-pending-by-issuer'
      await store.addRevocation(
        revocation({ jti, revoker_did: other, revocation_token: 'other-token', verified_at: null }),
      )
      await store.addRevocation(
        revocation({ jti, revocation_token: 'mine-token', verified_at: null }),
      )

      expect((await store.getPendingRevocationByIssuer(jti, REVOKER))?.revocation_token).toBe(
        'mine-token',
      )
      expect((await store.getPendingRevocationByIssuer(jti, other))?.revocation_token).toBe(
        'other-token',
      )
      expect(await store.getPendingRevocationByIssuer(jti, 'did:key:absent')).toBeNull()

      // A verified row is not pending, whoever authored it.
      await store.markRevocationVerified(jti, REVOKER, { cap_exp: 4_000 })
      expect(await store.getPendingRevocationByIssuer(jti, REVOKER)).toBeNull()
    })

    test('getHeldRevocations joins verified revocations to locally held caps', async () => {
      const audience = 'did:key:a-held-rev'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-held-rev',
          grantor: 'did:key:g-held-rev',
          audience,
          resource: 'doc:held-rev',
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-held-rev',
          revoker_did: 'did:key:g-held-rev',
          verified_at: 1_700_000_005,
          cap_exp: 2_000_000_000,
        }),
      )
      const held = await store.getHeldRevocations({ audience })
      expect(held).toHaveLength(1)
      expect(held[0]).toMatchObject({
        jti: 'jti-held-rev',
        grantor: 'did:key:g-held-rev',
        audience,
        revoker_did: 'did:key:g-held-rev',
        verified_at: 1_700_000_005,
      })

      // Pending revocations are excluded from held revocations.
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-held-pending',
          grantor: 'did:key:g-held-pending',
          audience,
          resource: 'doc:held-pending',
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-held-pending',
          revoker_did: 'did:key:g-held-pending',
          verified_at: null,
        }),
      )
      const stillOne = await store.getHeldRevocations({ audience })
      expect(stillOne.map((r) => r.jti)).toEqual(['jti-held-rev'])
    })

    test('purgeExpiredRevocations deletes verified rows whose cap has expired past grace', async () => {
      // Drain any verified-and-expired rows left by earlier tests so this sweep's
      // delete count reflects only the rows added here.
      await store.purgeExpiredRevocations({ graceSeconds: 0 })

      // Verified revocation with a long-expired cap (epoch seconds in the past).
      await store.addRevocation(
        revocation({ jti: 'jti-purge-old', verified_at: 1_700_000_006, cap_exp: 1_000 }),
      )
      // Verified revocation whose cap is far in the future — must survive.
      await store.addRevocation(
        revocation({ jti: 'jti-purge-keep', verified_at: 1_700_000_007, cap_exp: 2_000_000_000 }),
      )
      // Pending revocation (cap_exp NULL) — must survive the expired-cap sweep.
      await store.addRevocation(revocation({ jti: 'jti-purge-pending', verified_at: null }))

      const deleted = await store.purgeExpiredRevocations({ graceSeconds: 0 })
      expect(deleted).toBe(1)
      expect(await store.getRevocationByIssuer('jti-purge-old', REVOKER)).toBeNull()
      expect(await store.getRevocationByIssuer('jti-purge-keep', REVOKER)).not.toBeNull()
      expect(await store.getRevocationByIssuer('jti-purge-pending', REVOKER)).not.toBeNull()
    })

    test('getHeldTokens excludes tokens addressed to a different audience', async () => {
      const mine = 'did:key:a-iso-mine'
      const theirs = 'did:key:a-iso-theirs'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-iso-mine',
          grantor: 'did:key:g-iso',
          audience: mine,
          resource: 'doc:iso-mine',
          exp: 2_000_000_000,
        }),
      )
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-iso-theirs',
          grantor: 'did:key:g-iso',
          audience: theirs,
          resource: 'doc:iso-theirs',
          exp: 2_000_000_000,
        }),
      )
      // The auto-attach scoping guard: a held-token lookup for one audience never
      // surfaces a cap addressed to another.
      const held = await store.getHeldTokens({ audience: mine, atTime: 1_000 })
      expect(held.map((t) => t.jti)).toEqual(['jti-iso-mine'])
    })

    test('getHeldRevocations excludes a verified revocation whose cap is held by another audience', async () => {
      const other = 'did:key:a-held-cross-owner'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-held-cross',
          grantor: 'did:key:g-held-cross',
          audience: other,
          resource: 'doc:held-cross',
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-held-cross',
          revoker_did: 'did:key:g-held-cross',
          verified_at: 1_700_000_010,
          cap_exp: 2_000_000_000,
        }),
      )
      // The row does surface for the audience that holds the cap — so the empty
      // result below is the audience filter, not some other exclusion.
      expect((await store.getHeldRevocations({ audience: other })).map((r) => r.jti)).toEqual([
        'jti-held-cross',
      ])
      // Querying a different audience must not see the revocation for the cap the
      // other audience holds.
      const held = await store.getHeldRevocations({ audience: 'did:key:a-held-cross-absent' })
      expect(held).toEqual([])
    })

    test('getHeldRevocations drops a verified revocation with no matching held cap', async () => {
      // A verified revocation with no local delegation-token row — the INNER JOIN
      // drops it.
      await store.addRevocation(revocation({ jti: 'jti-orphan-rev', verified_at: 1_700_000_011 }))
      const held = await store.getHeldRevocations({ audience: 'did:key:a-orphan-rev' })
      expect(held.map((r) => r.jti)).not.toContain('jti-orphan-rev')
    })

    // A listing that matched on `jti` alone would report a held capability as
    // revoked because someone other than its grantor said so.
    test('getHeldRevocations ignores a row whose revoker is not the cap grantor', async () => {
      const audience = 'did:key:a-held-forged'
      const grantor = 'did:key:g-held-forged'
      await store.addDelegationToken(
        delegationToken({
          jti: 'jti-held-forged',
          grantor,
          audience,
          resource: 'doc:held-forged',
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-held-forged',
          revoker_did: 'did:key:x-held-forged',
          verified_at: 1_700_000_012,
          cap_exp: 2_000_000_000,
        }),
      )
      expect(await store.getHeldRevocations({ audience })).toEqual([])

      // The grantor's own row for the same jti is reported — the exclusion above
      // is the revoker mismatch, not the join failing outright.
      await store.addRevocation(
        revocation({
          jti: 'jti-held-forged',
          revoker_did: grantor,
          verified_at: 1_700_000_013,
          cap_exp: 2_000_000_000,
        }),
      )
      const held = await store.getHeldRevocations({ audience })
      expect(held).toHaveLength(1)
      expect(held[0]).toMatchObject({ jti: 'jti-held-forged', revoker_did: grantor })
    })

    // `grantor` and `revoker_did` are written by different paths and a peer:4
    // identity has two spellings: a root capability may name its own long form as
    // `sub` (only `normalizeDID(sub) === normalizeDID(signer)` is required). The
    // join is a DID-to-DID compare across those two columns, so it has to see one
    // spelling whichever way the revoker arrives.
    test.each([
      ['short', (identity: { id: string; longForm: string }) => identity.id],
      ['long', (identity: { id: string; longForm: string }) => identity.longForm],
    ])('getHeldRevocations joins a long-form grantor to a %s-form revoker', async (form, pick) => {
      const grantor = await peer4Identity()
      // Distinct per case: the store outlives a single test, and a shared audience
      // would make the second run read the first run's row as a second held one.
      const audience = `did:key:a-held-peer4-${form}`
      const jti = `jti-held-peer4-${form}`
      const cap = await createCapability(grantor, {
        sub: grantor.longForm,
        aud: audience,
        act: 'document/write',
        res: `doc:held-peer4-${form}`,
        iat: 1_700_000_020,
        exp: 2_000_000_000,
        jti,
      })
      const record = await createRevocationRecord(grantor, jti)
      const revokerDID = pick(grantor)
      expect(cap.payload.sub).toBe(grantor.longForm)

      await store.addDelegationToken(
        delegationToken({
          jti,
          grantor: cap.payload.sub,
          audience: cap.payload.aud,
          resource: `doc:held-peer4-${form}`,
          exp: 2_000_000_000,
        }),
      )
      await store.addRevocation(
        revocation({
          jti,
          revoker_did: revokerDID,
          revocation_token: stringifyToken(record),
          verified_at: 1_700_000_021,
          cap_exp: 2_000_000_000,
        }),
      )

      const held = await store.getHeldRevocations({ audience })
      expect(held).toHaveLength(1)
      expect(held[0]).toMatchObject({
        jti,
        grantor: grantor.id,
        revoker_did: grantor.id,
        verified_at: 1_700_000_021,
      })
    })

    // The three enforcement-critical reads, each driven with the issuer's long
    // form against a row filed under its short form — the split every peer:4
    // signer produces on its own, with no attacker. `markRevocationVerified` and
    // `getPendingRevocationByIssuer` miss the genuine row under a raw equality;
    // `deletePendingRevocationsFromOtherIssuers` is worse than a miss, since a raw
    // `!=` is true of the issuer's *own* row and carries it off with the forgery.

    test('getPendingRevocationByIssuer folds a long-form issuer onto its own row', async () => {
      const grantor = await peer4Identity()
      const jti = 'jti-peer4-pending-read'
      const other = 'did:key:x-peer4-pending-read'
      await store.addRevocation(
        revocation({ jti, revoker_did: other, revocation_token: 'foreign', verified_at: null }),
      )
      await store.addRevocation(
        revocation({
          jti,
          revoker_did: grantor.id,
          revocation_token: 'genuine',
          verified_at: null,
        }),
      )

      expect(
        (await store.getPendingRevocationByIssuer(jti, grantor.longForm))?.revocation_token,
      ).toBe('genuine')
      // The long form does not answer for anyone else, so the hit above is the
      // fold rather than the predicate having gone missing.
      expect(
        await store.getPendingRevocationByIssuer(jti, 'did:key:y-peer4-pending-read'),
      ).toBeNull()
    })

    test('deletePendingRevocationsFromOtherIssuers spares a long-form issuer’s own row', async () => {
      const grantor = await peer4Identity()
      const jti = 'jti-peer4-delete-scope'
      const other = 'did:key:x-peer4-delete-scope'
      await store.addRevocation(revocation({ jti, revoker_did: other, verified_at: null }))
      await store.addRevocation(revocation({ jti, revoker_did: grantor.id, verified_at: null }))

      expect(await store.deletePendingRevocationsFromOtherIssuers(jti, grantor.longForm)).toBe(1)
      expect(await store.getRevocationByIssuer(jti, other)).toBeNull()
      expect(await store.getRevocationByIssuer(jti, grantor.id)).not.toBeNull()
    })

    test('markRevocationVerified promotes under a long-form issuer', async () => {
      const grantor = await peer4Identity()
      const jti = 'jti-peer4-mark'
      await store.addRevocation(
        revocation({ jti, revoker_did: grantor.id, verified_at: null, hlc: hlc(1) }),
      )

      expect(
        await store.markRevocationVerified(jti, grantor.longForm, {
          cap_exp: 2_000_000_000,
          verified_at: 1_700_000_050,
        }),
      ).toBe(true)
      expect((await store.getRevocationByIssuer(jti, grantor.id))?.verified_at).toBe(1_700_000_050)
      expect(await store.isRevokedBy(jti, grantor.longForm)).toBe(true)
    })

    test('deletePendingRevocationsFromOtherIssuers spares a verified row', async () => {
      const jti = 'jti-del-verified'
      const other = 'did:key:x-del-verified'
      await store.addRevocation(
        revocation({ jti, revoker_did: other, verified_at: 1_700_000_020, cap_exp: 2_000_000_000 }),
      )
      // Only pending rows are deletable — a verified (binding) row survives.
      expect(await store.deletePendingRevocationsFromOtherIssuers(jti, REVOKER)).toBe(0)
      const row = await store.getRevocationByIssuer(jti, other)
      expect(row).not.toBeNull()
      expect(row?.verified_at).toBe(1_700_000_020)
    })

    // The counterweight to `markRevocationVerified`: what the arriving capability
    // cannot vouch for, it also must not carry away.
    test('deletePendingRevocationsFromOtherIssuers keeps the named issuer’s pending row', async () => {
      const jti = 'jti-del-pending'
      const other = 'did:key:x-del-pending'
      await store.addRevocation(revocation({ jti, revoker_did: other, verified_at: null }))
      await store.addRevocation(revocation({ jti, verified_at: null }))

      expect(await store.deletePendingRevocationsFromOtherIssuers(jti, REVOKER)).toBe(1)
      expect(await store.getRevocationByIssuer(jti, other)).toBeNull()
      expect(await store.getRevocationByIssuer(jti, REVOKER)).not.toBeNull()
    })

    // All three boundaries under one sweep call, so a predicate that deleted (or
    // spared) unconditionally fails whichever way it is wrong.
    test('purgeDeadPendingRevocations retains a pending row until the capability lifetime plus grace', async () => {
      const nowSec = nowSeconds()
      await store.addRevocation(
        revocation({ jti: 'jti-pending-past-7d', revoked_iat: nowSec - 86_400 * 8 }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-pending-past-ttl',
          revoked_iat: nowSec - MAX_CAP_TTL_SECONDS - 86_400,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-pending-past-ttl-grace',
          revoked_iat: nowSec - MAX_CAP_TTL_SECONDS - REVOCATION_GC_VERIFIED_GRACE_SECONDS - 60,
        }),
      )

      await store.purgeDeadPendingRevocations({
        graceSeconds: REVOCATION_GC_VERIFIED_GRACE_SECONDS,
      })

      // Past a seven-day age but still inside the window in which a capability
      // revoked at `revoked_iat` can be presented.
      expect(await store.getRevocationByIssuer('jti-pending-past-7d', REVOKER)).not.toBeNull()
      expect(await store.getRevocationByIssuer('jti-pending-past-ttl', REVOKER)).not.toBeNull()
      // Past `revoked_iat + MAX_CAP_TTL_SECONDS + grace`: no capability the
      // receiver would accept can still name it.
      expect(await store.getRevocationByIssuer('jti-pending-past-ttl-grace', REVOKER)).toBeNull()
    })

    test('purgeDeadPendingRevocations spares a verified row of the same age', async () => {
      const nowSec = nowSeconds()
      const deadIat = nowSec - MAX_CAP_TTL_SECONDS - REVOCATION_GC_VERIFIED_GRACE_SECONDS - 60
      await store.addRevocation(revocation({ jti: 'jti-purge-pending-twin', revoked_iat: deadIat }))
      await store.addRevocation(
        revocation({
          jti: 'jti-purge-survivor-verified',
          revoked_iat: deadIat,
          verified_at: nowSec - 100,
          cap_exp: nowSec + 100_000,
        }),
      )

      await store.purgeDeadPendingRevocations({
        graceSeconds: REVOCATION_GC_VERIFIED_GRACE_SECONDS,
      })

      // The rows differ in one column. Verified rows prune on `cap_exp` instead.
      expect(await store.getRevocationByIssuer('jti-purge-pending-twin', REVOKER)).toBeNull()
      expect(
        await store.getRevocationByIssuer('jti-purge-survivor-verified', REVOKER),
      ).not.toBeNull()
    })

    // Retention is computed from a column an unverified broadcast supplies, so
    // an unbounded `iat` would buy an immortal row.
    test('addRevocation floors a far-future revoked_iat so the row stays reclaimable', async () => {
      const nowSec = nowSeconds()
      const jti = 'jti-future-iat'
      const futureIat = nowSec + 86_400 * 100
      // The bound is `now + drift`, so a second ticking between the two stores
      // re-floors to a genuinely different value and the re-store below would
      // report `changed` for a reason that is not the defect. Pinned throughout.
      vi.useFakeTimers({ toFake: ['Date'] })
      try {
        vi.setSystemTime(nowSec * 1000)
        await store.addRevocation(revocation({ jti, revoked_iat: futureIat }))

        // Pinned to the bound from both sides: floored to `now` instead would cost
        // a grantor an hour fast its stamp, and is not what bounds retention.
        const row = await store.getRevocationByIssuer(jti, REVOKER)
        if (row == null) throw new Error('expected the revocation row')
        expect(row.revoked_iat).toBe(nowSec + MAX_REVOCATION_FUTURE_DRIFT_SECONDS)

        // The change-detection compare reads the *floored* stamp, so an identical
        // re-broadcast is a no-op. Comparing the raw claim instead reports
        // `changed` on every arrival.
        const again = await store.addRevocation(
          revocation({ jti, revoked_iat: futureIat, hlc: hlc(2) }),
        )
        expect(again).toBe(false)
        // The re-store won the LWW race, so `false` came from the content compare
        // rather than the HLC arbiter short-circuiting ahead of it.
        const after = await store.getRevocationByIssuer(jti, REVOKER)
        expect(after?.hlc).toBe(hlc(2))
        expect(after?.revoked_iat).toBe(row.revoked_iat)

        // One second past the floored row's retention. The unfloored stamp would
        // have survived this sweep by 100 days.
        vi.setSystemTime(
          (row.revoked_iat + MAX_CAP_TTL_SECONDS + REVOCATION_GC_VERIFIED_GRACE_SECONDS + 1) * 1000,
        )
        await store.purgeDeadPendingRevocations({
          graceSeconds: REVOCATION_GC_VERIFIED_GRACE_SECONDS,
        })
        expect(await store.getRevocationByIssuer(jti, REVOKER)).toBeNull()
      } finally {
        vi.useRealTimers()
      }
    })

    test('addRevocation LWW: a stale older-HLC re-store does not un-revoke a verified row', async () => {
      const jti = 'jti-lww-rev'
      await store.addRevocation(
        revocation({ jti, verified_at: 1_700_000_030, cap_exp: 2_000_000_000, hlc: hlc(5) }),
      )
      expect(await store.isRevokedBy(jti, REVOKER)).toBe(true)

      // A replayed older-HLC pending broadcast must not clobber the binding row.
      const changed = await store.addRevocation(
        revocation({ jti, verified_at: null, cap_exp: null, hlc: hlc(4) }),
      )
      expect(changed).toBe(false)
      const row = await store.getRevocationByIssuer(jti, REVOKER)
      expect(row?.verified_at).toBe(1_700_000_030)
      expect(await store.isRevokedBy(jti, REVOKER)).toBe(true)
    })

    test('removeDelegationToken removes a stored token by jti and reports true', async () => {
      await store.addDelegationToken(
        delegationToken({ jti: 'jti-remove', grantor: 'did:key:g-remove' }),
      )
      expect(await store.listDelegationTokensByJTI('jti-remove')).toHaveLength(1)

      expect(await store.removeDelegationToken({ jti: 'jti-remove' })).toBe(true)
      expect(await store.listDelegationTokensByJTI('jti-remove')).toEqual([])
    })

    test('removeDelegationToken reports false for an absent jti', async () => {
      expect(await store.removeDelegationToken({ jti: 'jti-never-existed' })).toBe(false)
    })

    test('removeDelegationToken leaves an unrelated token intact', async () => {
      await store.addDelegationToken(
        delegationToken({ jti: 'jti-keep-a', grantor: 'did:key:g-a', resource: 'doc:a' }),
      )
      await store.addDelegationToken(
        delegationToken({ jti: 'jti-keep-b', grantor: 'did:key:g-b', resource: 'doc:b' }),
      )

      expect(await store.removeDelegationToken({ jti: 'jti-keep-a' })).toBe(true)
      expect(await store.listDelegationTokensByJTI('jti-keep-a')).toEqual([])
      expect(await store.listDelegationTokensByJTI('jti-keep-b')).toHaveLength(1)
    })

    test('purges default the grace', async () => {
      // Drain rows earlier tests left purgeable at any grace, so the counts below
      // are this test's rows only.
      await store.purgeExpiredRevocations({ graceSeconds: 0 })
      await store.purgeDeadPendingRevocations({ graceSeconds: 0 })

      const nowSec = nowSeconds()
      const grace = REVOCATION_GC_VERIFIED_GRACE_SECONDS
      await store.addRevocation(
        revocation({
          jti: 'jti-default-verified-dead',
          verified_at: nowSec,
          cap_exp: nowSec - grace - 1,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-default-verified-kept',
          verified_at: nowSec,
          cap_exp: nowSec - grace + 60,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-default-pending-dead',
          revoked_iat: nowSec - MAX_CAP_TTL_SECONDS - grace - 1,
        }),
      )
      await store.addRevocation(
        revocation({
          jti: 'jti-default-pending-kept',
          revoked_iat: nowSec - MAX_CAP_TTL_SECONDS - grace + 60,
        }),
      )

      const expired = await store.purgeExpiredRevocations()
      expect(typeof expired).toBe('number')
      expect(expired).toBe(1)
      expect(await store.getRevocationByIssuer('jti-default-verified-dead', REVOKER)).toBeNull()
      expect(await store.getRevocationByIssuer('jti-default-verified-kept', REVOKER)).not.toBeNull()

      const pending = await store.purgeDeadPendingRevocations()
      expect(typeof pending).toBe('number')
      expect(pending).toBe(1)
      expect(await store.getRevocationByIssuer('jti-default-pending-dead', REVOKER)).toBeNull()
      expect(await store.getRevocationByIssuer('jti-default-pending-kept', REVOKER)).not.toBeNull()
    })

    test('pending purge boundary', async () => {
      const jti = 'jti-pending-boundary'
      const revokedIat = nowSeconds()
      await store.addRevocation(revocation({ jti, revoked_iat: revokedIat }))
      const boundary = revokedIat + MAX_CAP_TTL_SECONDS + REVOCATION_GC_VERIFIED_GRACE_SECONDS

      vi.useFakeTimers({ toFake: ['Date'] })
      try {
        vi.setSystemTime(boundary * 1000)
        await store.purgeDeadPendingRevocations()
        expect(await store.getRevocationByIssuer(jti, REVOKER)).not.toBeNull()

        vi.setSystemTime((boundary + 1) * 1000)
        await store.purgeDeadPendingRevocations()
        expect(await store.getRevocationByIssuer(jti, REVOKER)).toBeNull()
      } finally {
        vi.useRealTimers()
      }
    })

    test('future revoked_iat is floored on write', async () => {
      const jti = 'jti-future-floor'
      const nowSec = nowSeconds()
      vi.useFakeTimers({ toFake: ['Date'] })
      try {
        vi.setSystemTime(nowSec * 1000)
        await store.addRevocation(
          revocation({ jti, revoked_iat: nowSec + 10 * MAX_REVOCATION_FUTURE_DRIFT_SECONDS }),
        )
        const row = await store.getRevocationByIssuer(jti, REVOKER)
        if (row == null) throw new Error('expected the revocation row')
        expect(row.revoked_iat).toBeLessThanOrEqual(nowSec + MAX_REVOCATION_FUTURE_DRIFT_SECONDS)

        vi.setSystemTime(
          (row.revoked_iat + MAX_CAP_TTL_SECONDS + REVOCATION_GC_VERIFIED_GRACE_SECONDS + 1) * 1000,
        )
        await store.purgeDeadPendingRevocations()
        expect(await store.getRevocationByIssuer(jti, REVOKER)).toBeNull()
      } finally {
        vi.useRealTimers()
      }
    })

    test('writes join an enclosing transaction', async () => {
      const token = delegationToken({
        jti: 'jti-tx',
        grantor: 'did:key:g-tx',
        audience: 'did:key:a-tx',
      })
      const failure = new Error('roll back')
      await expect(
        db.withTransaction(async (tx) => {
          const txStore = await getDelegationStore(tx)
          // A nested `.transaction()` inside the store would reject here.
          expect(await txStore.addDelegationToken(token)).toBe(true)
          expect(await txStore.addRevocation(revocation({ jti: 'jti-tx' }))).toBe(true)
          throw failure
        }),
      ).rejects.toBe(failure)

      expect(
        await store.getDelegationTokens({ grantor: 'did:key:g-tx', audience: 'did:key:a-tx' }),
      ).toEqual([])
      expect(await store.listRevocations('jti-tx')).toEqual([])
    })

    test('no implicit purge on insert', async () => {
      const jti = 'jti-no-implicit-purge'
      await store.addRevocation(revocation({ jti, verified_at: 1_700_000_060, cap_exp: 1_000 }))
      for (let i = 0; i < 300; i++) {
        await store.addDelegationToken(
          delegationToken({
            jti: `jti-implicit-${i}`,
            grantor: 'did:key:g-implicit',
            audience: 'did:key:a-implicit',
            resource: `doc:implicit-${i}`,
          }),
        )
      }
      expect(await store.getRevocationByIssuer(jti, REVOKER)).not.toBeNull()
    })

    test.each(TIE_BREAK_PAIRS)(
      'hlc tie-break agrees between SQL and JS (%s vs %s)',
      async (first, second) => {
        const [lower, higher] = stamp(first) < stamp(second) ? [first, second] : [second, first]
        const key = `${lower}-${higher}`

        // Lower then higher: the higher overwrites.
        const ascending = { grantor: `did:key:g-asc-${key}`, audience: 'did:key:a-tie' }
        await store.addDelegationToken(
          delegationToken({ ...ascending, token: 'lower', hlc: stamp(lower) }),
        )
        expect(
          await store.addDelegationToken(
            delegationToken({ ...ascending, token: 'higher', hlc: stamp(higher) }),
          ),
        ).toBe(true)
        const ascRows = await store.getDelegationTokens(ascending)
        expect(ascRows.map((row) => [row.token, row.hlc])).toEqual([['higher', stamp(higher)]])

        // Higher then lower on a fresh key: SQL keeps the higher, JS reports the loss.
        const descending = { grantor: `did:key:g-desc-${key}`, audience: 'did:key:a-tie' }
        await store.addDelegationToken(
          delegationToken({ ...descending, token: 'higher', hlc: stamp(higher) }),
        )
        expect(
          await store.addDelegationToken(
            delegationToken({ ...descending, token: 'lower', hlc: stamp(lower) }),
          ),
        ).toBe(false)
        const descRows = await store.getDelegationTokens(descending)
        expect(descRows.map((row) => [row.token, row.hlc])).toEqual([['higher', stamp(higher)]])

        // The revocation table carries the same arbiter on its own column.
        const jti = `jti-tie-${key}`
        await store.addRevocation(
          revocation({ jti, revocation_token: 'higher', hlc: stamp(higher) }),
        )
        expect(
          await store.addRevocation(
            revocation({ jti, revocation_token: 'lower', hlc: stamp(lower) }),
          ),
        ).toBe(false)
        const rev = await store.getRevocationByIssuer(jti, REVOKER)
        expect([rev?.revocation_token, rev?.hlc]).toEqual(['higher', stamp(higher)])
      },
    )
  })

  // `0-init` runs through the migrator on a raw Kysely rather than through
  // HozonDB, so the schema these cases assert against is the one the migration
  // produces and not one a store factory could have repaired.
  describe('migrated schema', () => {
    let adapter: Adapter
    let raw: Kysely<DelegationStoreTables>
    let db: Kysely<DelegationStoreTables>
    let store: DelegationStoreAPI

    beforeAll(async () => {
      adapter = await harness.createAdapter()
      raw = new Kysely<DelegationStoreTables>({ dialect: adapter.dialect })
      // The migrator's bookkeeping tables carry physical names, so only the
      // migrations themselves see the prefix plugin, as in HozonDB.
      const plugin = new TablePrefixPlugin(prefix)
      const migrations = getDelegationMigrations({
        tablePrefix: prefix,
        kind: adapter.kind,
        types: adapter.types,
        functions: adapter.functions,
      })
      const prefixed: Record<string, Migration> = Object.fromEntries(
        Object.entries(migrations).map(([name, migration]) => [
          name,
          { up: (kysely) => migration.up(kysely.withPlugin(plugin)) },
        ]),
      )

      const applied = await new Migrator({
        db: raw,
        provider: { getMigrations: () => Promise.resolve(prefixed) },
        migrationTableName: `${prefix}_delegation_migration`,
        migrationLockTableName: `${prefix}_delegation_migration_lock`,
      }).migrateToLatest()
      if (applied.error != null) {
        throw applied.error
      }

      db = raw.withPlugin(plugin)
      store = createDelegationStore(db, adapter)
    }, 120_000)

    afterAll(async () => {
      await raw?.destroy()
    })

    async function countRevocations(): Promise<number> {
      const row = await db
        .selectFrom('revoked_capabilities')
        .select((eb) => eb.fn.countAll().as('count'))
        .executeTakeFirstOrThrow()
      return Number(row.count)
    }

    test('the secondary indexes are created under prefixed names', async () => {
      expect(await indexNames(raw, adapter.kind, `${prefix}_delegation_tokens`)).toEqual(
        expect.arrayContaining([
          `${prefix}_delegation_tokens_grantor_audience_idx`,
          `${prefix}_delegation_tokens_audience_exp_idx`,
          `${prefix}_delegation_tokens_jti_idx`,
        ]),
      )
      expect(await indexNames(raw, adapter.kind, `${prefix}_revoked_capabilities`)).toContain(
        `${prefix}_revoked_capabilities_verified_cap_exp_idx`,
      )
    })

    // What the composite key buys, and the only assertion here that fails
    // against a `jti`-only primary key: under one row per `jti` the second
    // `addRevocation` is an upsert on the same row, so the forgery displaces the
    // grantor's and the read returns a single forged row.
    test('a forged higher-HLC revocation from another revoker inserts alongside', async () => {
      const jti = 'jti-two-revokers'
      const grantor = 'did:key:g-two'
      const forger = 'did:key:x-two'

      expect(
        await store.addRevocation(
          revocation({
            jti,
            revoker_did: grantor,
            revocation_token: 'grantor-token',
            verified_at: 1_700_000_600,
            cap_exp: 5_000_000_000,
            hlc: hlc(5),
          }),
        ),
      ).toBe(true)
      expect(
        await store.addRevocation(
          revocation({
            jti,
            revoker_did: forger,
            revocation_token: 'forged-token',
            verified_at: null,
            hlc: hlc(9),
          }),
        ),
      ).toBe(true)

      const rows = await db
        .selectFrom('revoked_capabilities')
        .selectAll()
        .where('jti', '=', jti)
        .orderBy('revoker_did')
        .execute()
      expect(
        rows.map((row) => ({
          revoker_did: row.revoker_did,
          revocation_token: row.revocation_token,
          verified_at: row.verified_at,
          hlc: row.hlc,
        })),
      ).toEqual([
        {
          revoker_did: grantor,
          revocation_token: 'grantor-token',
          verified_at: 1_700_000_600,
          hlc: hlc(5),
        },
        { revoker_did: forger, revocation_token: 'forged-token', verified_at: null, hlc: hlc(9) },
      ])
    })

    test('same-author LWW still arbitrates in place', async () => {
      const jti = 'jti-same-author-lww'
      const revoker = 'did:key:g-lww-author'
      const other = 'did:key:x-lww-author'

      await store.addRevocation(
        revocation({ jti, revoker_did: revoker, revocation_token: 'v1', hlc: hlc(5) }),
      )
      // A co-member's much newer row must not be mistaken for this author's own
      // history by the `changed` pre-read.
      await store.addRevocation(
        revocation({ jti, revoker_did: other, revocation_token: 'other', hlc: hlc(99) }),
      )

      expect(
        await store.addRevocation(
          revocation({ jti, revoker_did: revoker, revocation_token: 'v0', hlc: hlc(4) }),
        ),
      ).toBe(false)
      expect(
        await store.addRevocation(
          revocation({ jti, revoker_did: revoker, revocation_token: 'v2', hlc: hlc(6) }),
        ),
      ).toBe(true)

      const mine = await db
        .selectFrom('revoked_capabilities')
        .selectAll()
        .where('jti', '=', jti)
        .where('revoker_did', '=', revoker)
        .execute()
      expect(mine).toHaveLength(1)
      expect(mine[0]?.revocation_token).toBe('v2')
      expect(mine[0]?.hlc).toBe(hlc(6))
    })

    // Both rows are reachable and each read answers for exactly the author it
    // names — the ambiguity a `jti`-only read used to resolve arbitrarily (and
    // adapter-dependently) is now not expressible.
    test('each author’s row is reachable by name once two rows share a jti', async () => {
      const jti = 'jti-ambiguous-read'
      const first = 'did:key:b-ambiguous'
      const second = 'did:key:a-ambiguous'
      await store.addRevocation(
        revocation({ jti, revoker_did: first, revocation_token: 'first-token', hlc: hlc(1) }),
      )
      await store.addRevocation(
        revocation({ jti, revoker_did: second, revocation_token: 'second-token', hlc: hlc(2) }),
      )

      expect((await store.listRevocations(jti)).map((row) => row.revoker_did)).toEqual([
        second,
        first,
      ])
      expect((await store.getRevocationByIssuer(jti, first))?.revocation_token).toBe('first-token')
      expect((await store.getRevocationByIssuer(jti, second))?.revocation_token).toBe(
        'second-token',
      )
      // A third party's absence is not answered by either stored row.
      expect(await store.getRevocationByIssuer(jti, 'did:key:c-ambiguous')).toBeNull()
    })

    test.each([
      -1,
      0.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 1,
    ])('graceSeconds guard rejects %s', async (graceSeconds) => {
      // Rows a negative grace would reach, so a missing guard changes the count.
      const nowSec = nowSeconds()
      await store.addRevocation(
        revocation({
          jti: 'jti-guard-verified',
          verified_at: nowSec,
          cap_exp: nowSec - 60,
        }),
      )
      await store.addRevocation(
        revocation({ jti: 'jti-guard-pending', revoked_iat: nowSec - MAX_CAP_TTL_SECONDS - 60 }),
      )
      const before = await countRevocations()

      await expect(store.purgeExpiredRevocations({ graceSeconds })).rejects.toThrow(RangeError)
      await expect(store.purgeDeadPendingRevocations({ graceSeconds })).rejects.toThrow(RangeError)
      expect(await countRevocations()).toBe(before)
    })
  })
}
