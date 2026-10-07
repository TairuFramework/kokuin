import { HozonDB } from '@hozon/db'
import { NodeSQLiteAdapter } from '@hozon/node-sqlite'
import {
  type CapabilityPayload,
  checkCapability,
  createCapability,
  createRevocationRecord,
} from '@kokuin/capability'
import {
  createControllerIdentity,
  createControllerResolver,
  createInception,
  createRevoke,
  createRotate,
  didFromInception,
  keyTarget,
  type SignedEvent,
} from '@kokuin/controller'
import {
  randomIdentity as createIdentity,
  createIdentity as createPeer4Identity,
  createSigningIdentityForDID,
  type MethodRegistry,
  normalizeDID,
  type SigningIdentity,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'vitest'

import {
  createDelegationRevocationBackend,
  createDelegationRevocationChecker,
  type DelegationStoreAPI,
  delegationStoreDefinition,
  getDelegationStore,
  type InsertRevokedCapability,
  VerifiedRevocationError,
} from '../src/index.js'

const HLC = '2026-01-02T00:00:00.000Z:00000000:node-a'

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

function revocation(overrides: Partial<InsertRevokedCapability> = {}): InsertRevokedCapability {
  return {
    jti: 'jti-1',
    revoker_did: 'did:key:revoker',
    revoked_iat: 1_700_000_000,
    revocation_token: 'signed-revocation-1',
    verified_at: null,
    cap_exp: null,
    hlc: HLC,
    ...overrides,
  }
}

async function openStore(): Promise<{ db: HozonDB; store: DelegationStoreAPI }> {
  const db = new HozonDB({ adapter: new NodeSQLiteAdapter({ database: ':memory:' }) })
  db.register(delegationStoreDefinition)
  return { db, store: await getDelegationStore(db) }
}

async function capability(grantor: SigningIdentity, jti: string) {
  const iat = nowSeconds()
  return await createCapability(grantor, {
    sub: grantor.id,
    aud: 'did:key:z6MkAudience',
    act: 'document/write',
    res: '*',
    iat,
    exp: iat + 3600,
    jti,
  })
}

describe('createDelegationRevocationChecker (SQLite)', () => {
  let db: HozonDB
  let store: DelegationStoreAPI

  beforeAll(async () => {
    ;({ db, store } = await openStore())
  })

  afterAll(async () => {
    await db?.close()
  })

  async function storeRevocation(params: {
    revoker: SigningIdentity
    jti: string
    verified_at: number | null
  }) {
    const record = await createRevocationRecord(params.revoker, params.jti)
    await store.addRevocation(
      revocation({
        jti: params.jti,
        revoker_did: params.revoker.id,
        revocation_token: stringifyToken(record),
        verified_at: params.verified_at,
        cap_exp: params.verified_at == null ? null : 1_800_000_000,
      }),
    )
  }

  test('a verified revocation from the capability grantor revokes', async () => {
    const grantor = createIdentity()
    const jti = 'jti-verified'
    await storeRevocation({ revoker: grantor, jti, verified_at: 1_700_000_100 })

    const check = createDelegationRevocationChecker(store)
    const cap = await capability(grantor, jti)
    await expect(check(cap, stringifyToken(cap))).rejects.toThrow(`Token revoked: ${jti}`)
  })

  // The row a co-member holds for someone else's capability is pending: it
  // arrived with no local grant to cross-check against. It still names the
  // grantor as its signer, so it must bind -- the issuer match is what makes
  // that safe, not `verified_at`.
  test('a pending revocation from the capability grantor still revokes', async () => {
    const grantor = createIdentity()
    const jti = 'jti-pending'
    await storeRevocation({ revoker: grantor, jti, verified_at: null })
    expect((await store.getRevocationByIssuer(jti, grantor.id))?.verified_at).toBeNull()

    const check = createDelegationRevocationChecker(store)
    const cap = await capability(grantor, jti)
    await expect(check(cap, stringifyToken(cap))).rejects.toThrow(`Token revoked: ${jti}`)
  })

  // The counterweight: dropping the `verified_at` gate must not let any group
  // member revoke a capability they did not issue.
  test('a pending revocation from a non-grantor does not revoke', async () => {
    const grantor = createIdentity()
    const forger = createIdentity()
    const jti = 'jti-pending-forged'
    await storeRevocation({ revoker: forger, jti, verified_at: null })
    // Not vacuous: the row is there and is what the checker rejects.
    expect(await store.getRevocationByIssuer(jti, forger.id)).not.toBeNull()

    const check = createDelegationRevocationChecker(store)
    const cap = await capability(grantor, jti)
    await expect(check(cap, stringifyToken(cap))).resolves.toBeUndefined()
  })

  // A did:peer:4 signer embeds its LONG form as the `iss` of its first token to
  // a given audience, while `identity.id` -- what the revoker files the row
  // under -- is always the short form. Both spellings come out of the mint path,
  // so the capability presented at check time and the row its revocation was
  // stored under name the same grantor with different strings, with no attacker
  // involved. A raw equality in the lookup misses and the revoked capability is
  // admitted.
  //
  // The record is signed long-form rather than through `createRevocationRecord`
  // because that helper emits the short form as `iss` (its claims carry no
  // `aud`), and this checker is given no DID cache, so a short-form peer:4
  // issuer resolves nowhere.
  test('a revocation binds when the capability presents the grantor’s long form', async () => {
    const grantor = await createPeer4Identity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const jti = 'jti-peer4-form-skew'
    const record = await grantor.signToken(
      { jti, rev: true, iat: nowSeconds() },
      { embedLongForm: true },
    )
    // What a revoker files: its own `identity.id`.
    await store.addRevocation(
      revocation({
        jti,
        revoker_did: grantor.id,
        revocation_token: stringifyToken(record),
        verified_at: 1_700_000_100,
        cap_exp: 1_800_000_000,
      }),
    )
    const cap = await capability(grantor, jti)
    // Not vacuous: the capability really does present a different string for
    // the grantor than the row was filed under.
    expect(cap.payload.iss).toBe(grantor.longForm)
    expect(cap.payload.iss).not.toBe(grantor.id)

    const check = createDelegationRevocationChecker(store)
    await expect(
      checkCapability(
        { act: 'document/write', res: '*' },
        { iss: 'did:key:z6MkAudience', sub: grantor.id, cap: [stringifyToken(cap)] },
        { verifyToken: check },
      ),
    ).rejects.toThrow(`Token revoked: ${jti}`)
  })

  test('a corrupt stored record revokes nothing', async () => {
    const grantor = createIdentity()
    const jti = 'jti-corrupt'
    await store.addRevocation(
      revocation({
        jti,
        revoker_did: grantor.id,
        revocation_token: 'not-a-token',
        verified_at: 1_700_000_100,
        cap_exp: 1_800_000_000,
      }),
    )

    const check = createDelegationRevocationChecker(store)
    const cap = await capability(grantor, jti)
    await expect(check(cap, stringifyToken(cap))).resolves.toBeUndefined()
  })

  test('an unknown jti revokes nothing and writes no row', async () => {
    const grantor = createIdentity()
    const jti = 'jti-unknown'

    const check = createDelegationRevocationChecker(store)
    const cap = await capability(grantor, jti)
    await expect(check(cap, stringifyToken(cap))).resolves.toBeUndefined()
    // The no-op `add` could only ever write under an author this test does not
    // choose, so the no-write claim has to hold across every author.
    expect(await store.listRevocations(jti)).toEqual([])
  })
})

describe('createDelegationRevocationChecker with a controller issuer', () => {
  let db: HozonDB
  let store: DelegationStoreAPI

  beforeEach(async () => {
    ;({ db, store } = await openStore())
  })

  afterEach(async () => {
    await db.close()
  })

  const registry = (did: string, log: Array<SignedEvent>): MethodRegistry => [
    createControllerResolver({ loadLog: async (asked) => (asked === did ? log : undefined) }),
  ]

  async function fileRecord(params: { jti: string; revokerDID: string; token: string }) {
    const now = nowSeconds()
    await store.addRevocation({
      jti: params.jti,
      revoker_did: params.revokerDID,
      revoked_iat: now,
      revocation_token: params.token,
      verified_at: now,
      cap_exp: now + 3600,
      hlc: HLC,
    })
  }

  test.each(['SQLITE_BUSY: controller log lookup', 'Invalid signature'])(
    'controller lookup fault (%s) while checking a stored revocation rejects',
    async (message) => {
      const seed = new Uint8Array(32).fill(61)
      const icp = createInception(seed, 0)
      const issuer = didFromInception(icp.event)
      const identity = createControllerIdentity({ seed, profile: 0, log: [icp] })
      const goodResolver = createControllerResolver({ loadLog: async () => [icp] })
      const jti = 'revocation-controller-fault'
      const now = nowSeconds()
      const cap = await createCapability(identity, {
        sub: issuer,
        aud: 'did:key:z6MkAudience',
        act: 'document/write',
        res: '*',
        jti,
        iat: now,
        exp: now + 3600,
      })
      const capRaw = stringifyToken(cap)
      const verified = await verifyToken<CapabilityPayload>(capRaw, {
        methods: [goodResolver],
        historic: true,
      })
      const record = await createRevocationRecord(identity, jti)
      await fileRecord({ jti, revokerDID: issuer, token: stringifyToken(record) })
      const failure = new Error(message)
      const faultResolver = {
        ...goodResolver,
        resolve: async () => {
          throw failure
        },
        resolveHistoric: async () => {
          throw failure
        },
      }

      await expect(
        createDelegationRevocationChecker(store, { methods: [faultResolver] })(verified, capRaw),
      ).rejects.toBe(failure)
    },
  )

  // Capability's checker returns normally here (the record claims another
  // issuer), so only the recorded fault keeps it from reading "not revoked".
  // Capability's checker returns normally here: the record's `iss` carries a
  // fragment, so it does not match the token's issuer. The resolver call is
  // still about the token's own issuer, so only the recorded fault keeps it
  // from reading "not revoked".
  test('an own-issuer resolver fault rejects even when the checker returns normally', async () => {
    const seed = new Uint8Array(32).fill(63)
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const issuer = createControllerIdentity({ seed, profile: 0, log: [icp] })
    const jti = 'jti-fault-own-issuer'
    const fragmented = createSigningIdentityForDID(
      `${did}#key-1` as typeof did,
      createIdentity().privateKey,
    )
    const record = await fragmented.signToken({ jti, rev: true, iat: nowSeconds() })
    await fileRecord({ jti, revokerDID: did, token: stringifyToken(record) })
    const failure = new Error('SQLITE_BUSY: controller log lookup')
    const faultResolver = {
      ...createControllerResolver({ loadLog: async () => [icp] }),
      resolveHistoric: async () => {
        throw failure
      },
    }
    const cap = await capability(issuer, jti)

    await expect(
      createDelegationRevocationChecker(store, { methods: [faultResolver] }).verdict(
        cap,
        stringifyToken(cap),
      ),
    ).rejects.toBe(failure)
  })

  // A record naming another issuer cannot revoke this capability, so failing
  // to resolve that issuer hides nothing. Rejecting would let a planted record
  // deny the check.
  test('an unresolvable foreign issuer in the row revokes nothing', async () => {
    const seed = new Uint8Array(32).fill(64)
    const icp = createInception(seed, 0)
    const foreign = createControllerIdentity({ seed, profile: 0, log: [icp] })
    const grantor = createIdentity()
    const jti = 'jti-foreign-unresolvable'
    const record = await createRevocationRecord(foreign, jti)
    await fileRecord({ jti, revokerDID: grantor.id, token: stringifyToken(record) })
    // Knows no log at all, so resolving the foreign DID throws `Unknown DID`.
    const resolver = createControllerResolver({ loadLog: async () => undefined })
    const cap = await capability(grantor, jti)

    await expect(
      createDelegationRevocationChecker(store, { methods: [resolver] }).verdict(
        cap,
        stringifyToken(cap),
      ),
    ).resolves.toBe(false)
  })

  test('a store fault rejects with the fault', async () => {
    const issuer = createIdentity()
    const failure = new Error('SQLITE_BUSY: revocation lookup')
    const faulty: DelegationStoreAPI = {
      ...store,
      getRevocationByIssuer: async () => {
        throw failure
      },
    }
    const cap = await capability(issuer, 'jti-store-fault')

    await expect(
      createDelegationRevocationChecker(faulty).verdict(cap, stringifyToken(cap)),
    ).rejects.toBe(failure)
  })

  // A routine rotate must not resurrect what the issuer revoked under its
  // earlier key: the record is past-minted and verifies historically.
  test('rotated issuer: a revocation signed before a rotate still revokes', async () => {
    const seed = new Uint8Array(32).fill(71)
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rotate = createRotate({ seed, profile: 0, did, prior: icp.event })
    const beforeRotate = createControllerIdentity({ seed, profile: 0, log: [icp] })
    const jti = 'jti-rotated'
    const record = await createRevocationRecord(beforeRotate, jti)
    await fileRecord({ jti, revokerDID: did, token: stringifyToken(record) })
    const cap = await capability(beforeRotate, jti)

    const check = createDelegationRevocationChecker(store, {
      methods: registry(did, [icp, rotate]),
    })
    await expect(check(cap, stringifyToken(cap))).rejects.toBeInstanceOf(VerifiedRevocationError)
  })

  // Denying a leaked key must not undo the revocations that key signed.
  test('denied key: a revocation signed by a since-denied key still revokes', async () => {
    const seed = new Uint8Array(32).fill(53)
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const rotate = createRotate({ seed, profile: 0, did, prior: icp.event })
    const leaked = icp.event.k[0]
    if (leaked === undefined) throw new Error('expected inception key')
    const revoked: Array<SignedEvent> = [
      icp,
      rotate,
      createRevoke({
        seed,
        profile: 0,
        did,
        prior: rotate.event,
        target: keyTarget(leaked),
        keyPosition: { gen: 0, seq: 1 },
      }),
    ]
    const thief = createControllerIdentity({ seed, profile: 0, log: [icp] })
    const owner = createControllerIdentity({ seed, profile: 0, log: revoked })
    const jti = 'jti-denied-key'
    const record = await createRevocationRecord(thief, jti)
    await fileRecord({ jti, revokerDID: did, token: stringifyToken(record) })
    const cap = await capability(owner, jti)

    const check = createDelegationRevocationChecker(store, { methods: registry(did, revoked) })
    await expect(check(cap, stringifyToken(cap))).rejects.toBeInstanceOf(VerifiedRevocationError)
  })

  // Anyone can name an unpublished key, so "no such key" is an answer, not a
  // fault: it must neither revoke nor reject.
  test('a record naming a key the issuer never published revokes nothing', async () => {
    const seed = new Uint8Array(32).fill(81)
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const issuer = createControllerIdentity({ seed, profile: 0, log: [icp] })
    const unpublished = createInception(new Uint8Array(32).fill(82), 0).event.k[0]
    if (unpublished === undefined) throw new Error('expected inception key')
    const forger = createSigningIdentityForDID(did, createIdentity().privateKey)
    const jti = 'jti-unpublished-kid'
    const record = await forger.signToken(
      { jti, rev: true, iat: nowSeconds() },
      { header: { kid: keyTarget(unpublished) } },
    )
    await fileRecord({ jti, revokerDID: did, token: stringifyToken(record) })
    const cap = await capability(issuer, jti)

    const check = createDelegationRevocationChecker(store, { methods: registry(did, [icp]) })
    await expect(check.verdict(cap, stringifyToken(cap))).resolves.toBe(false)
  })

  test('never-published key: a record from an unrelated identity revokes nothing', async () => {
    const seed = new Uint8Array(32).fill(91)
    const icp = createInception(seed, 0)
    const did = didFromInception(icp.event)
    const issuer = createControllerIdentity({ seed, profile: 0, log: [icp] })
    const jti = 'jti-never-published'
    const record = await createRevocationRecord(createIdentity(), jti)
    // Filed under the issuer's DID, so the lookup does return it.
    await fileRecord({ jti, revokerDID: did, token: stringifyToken(record) })
    const cap = await capability(issuer, jti)

    const check = createDelegationRevocationChecker(store, { methods: registry(did, [icp]) })
    await expect(check.verdict(cap, stringifyToken(cap))).resolves.toBe(false)
  })

  // Decodes, but the payload is `null`: no issuer, so no evidence.
  test('a stored record with a null payload is not evidence', async () => {
    const issuer = createIdentity()
    const jti = 'jti-null-payload'
    const b64u = (json: string) => Buffer.from(json).toString('base64url')
    await fileRecord({ jti, revokerDID: issuer.id, token: `${b64u('{}')}.${b64u('null')}.x` })
    const cap = await capability(issuer, jti)
    // The backend drops it itself, independent of capability's own guard.
    expect(await createDelegationRevocationBackend(store).get(jti, issuer.id)).toBeUndefined()

    const verdict = createDelegationRevocationChecker(store).verdict(cap, stringifyToken(cap))
    await expect(verdict).resolves.toBe(false)
  })

  test('a record signed by another issuer does not revoke the row’s issuer', async () => {
    const x = createIdentity()
    const y = createIdentity()
    const jti = 'jti-cross-issuer'
    const record = await createRevocationRecord(y, jti)
    await fileRecord({ jti, revokerDID: x.id, token: stringifyToken(record) })
    // Not vacuous: the row is filed under X and holds Y's record.
    expect((await store.getRevocationByIssuer(jti, x.id))?.revocation_token).toBe(
      stringifyToken(record),
    )
    const cap = await capability(x, jti)

    const verdict = createDelegationRevocationChecker(store).verdict(cap, stringifyToken(cap))
    await expect(verdict).resolves.toBe(false)
  })

  test('the backend scopes records by issuer', async () => {
    const a = await createPeer4Identity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const b = createIdentity()
    const jti = 'jti-scoped'
    const recordA = await createRevocationRecord(a, jti)
    const recordB = await createRevocationRecord(b, jti)
    await fileRecord({ jti, revokerDID: a.id, token: stringifyToken(recordA) })
    await fileRecord({ jti, revokerDID: b.id, token: stringifyToken(recordB) })

    const backend = createDelegationRevocationBackend(store)
    const found = await backend.get(jti, normalizeDID(a.longForm))
    expect(found && stringifyToken(found)).toBe(stringifyToken(recordA))
    expect(await backend.get(jti, 'did:key:unknown')).toBeUndefined()
  })
})
