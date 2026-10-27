import { recordClaimDigest, verifySignedRecord } from '@kokuin/records'
import { createIdentity, randomIdentity } from '@kokuin/token'
import {
  getSuite,
  InvalidVaultFactors,
  VAULT_OP_KIND,
  VaultSecretRejected,
  VaultTampered,
} from '@kokuin/vault'
import { createRuntime } from '@sozai/runtime'
import { afterEach, describe, expect, test, vi } from 'vitest'

import type { CredentialAuthorityRequest, VaultCoordinatorParams } from '../src/index.js'
import { createVaultCoordinator, VaultNotAuthorized, VaultWriteConflict } from '../src/index.js'
import type { StoreHarness } from './cases.js'
import { openVaultTestDB, stamp } from './cases.js'

export function coordinatorCases(harness: StoreHarness): void {
  describe(`vault coordinators (${harness.name})`, () => {
    const bytes = (text: string) => new TextEncoder().encode(text)
    const text = (value: Uint8Array) => new TextDecoder().decode(value)
    const metadata = { kind: 'blob', label: 'State', attributes: { app: 'test' } }
    const databases: Array<Awaited<ReturnType<typeof openVaultTestDB>>> = []
    let counter = 1000
    const nowMS = () => Date.parse('2026-10-01T01:00:00.000Z')
    const runtime = createRuntime()
    const cost = { m: 8, t: 1, p: 1 }

    async function signedOps(f: Awaited<ReturnType<typeof fixture>>, types: Array<string>) {
      const decisions = await f.manager.records.adapter.list(types)
      return Promise.all(
        decisions
          .flatMap((decision) => decision.copies)
          .map(async (record) => {
            const op = await verifySignedRecord(record, VAULT_OP_KIND)
            if (op === null) throw new Error('Invalid signed record')
            return { record, op }
          }),
      )
    }

    const currentEvidence = { delegation: 'current administrator' }
    const previousEvidence = { delegation: 'previous administrator' }

    function administrator(f: Awaited<ReturnType<typeof fixture>>) {
      if (f.params.mode !== 'replicated') throw new Error('Expected replicated mode')
      const signer = randomIdentity()
      return createVaultCoordinator({ ...f.params, signer, principal: signer.id })
    }

    test('grantSignsSuppliedConsumerEvidence', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id, consumer: previousEvidence })
      const recipientDID = randomIdentity().id
      await administrator(f).grant({ ...key, recipientDID, consumer: currentEvidence })
      const supplied = (await signedOps(f, ['vault.wrapping'])).filter(
        ({ op }) => op.claim.meta.recipient === recipientDID,
      )
      expect(supplied).toHaveLength(1)
      expect(supplied[0]?.op.claim.meta.consumer).toEqual(currentEvidence)
      expect(supplied[0]?.op.issuer).not.toBe(f.identity.id)
    })

    test('rotationSignsSuppliedConsumerEvidenceOnKeyAndBranch', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id, consumer: previousEvidence })
      const entry = await f.manager.putEntry({
        ...key,
        entryID: 'independent-evidence',
        ...metadata,
        plaintext: bytes('preserved'),
        consumer: previousEvidence,
      })
      const inherited = await f.manager.putEntry({
        ...key,
        entryID: 'inherited-evidence',
        ...metadata,
        plaintext: bytes('also preserved'),
        consumer: previousEvidence,
      })
      const replacement = { entry: 'replacement evidence' }
      await administrator(f).rotate({
        ...key,
        excludedRecipients: [randomIdentity().id],
        consumer: currentEvidence,
        reissue: [{ ...entry, action: 'preserve', consumer: replacement }],
      })
      const output = await signedOps(f, [
        'vault.key',
        'vault.key-branch',
        'vault.wrapping',
        'vault.revocation',
      ])
      const current = output.filter(
        ({ op }) =>
          op.claim.meta.version === 2 ||
          op.claim.meta.keyVersion === 2 ||
          op.claim.type === 'vault.revocation',
      )
      expect(current.map(({ op }) => op.claim.type).sort()).toEqual(
        ['vault.key', 'vault.key-branch', 'vault.wrapping', 'vault.revocation'].sort(),
      )
      for (const { op } of current) {
        expect(op.claim.meta.consumer).toEqual(currentEvidence)
        expect(op.issuer).not.toBe(f.identity.id)
      }
      const entries = await signedOps(f, ['vault.entry'])
      expect(
        entries.find(({ record }) => record.id === entry.entryID)?.op.claim.meta.consumer,
      ).toEqual(replacement)
      expect(
        entries.find(({ record }) => record.id === inherited.entryID)?.op.claim.meta.consumer,
      ).toEqual(previousEvidence)
      expect(text(await f.manager.readEntry(entry))).toBe('preserved')
    })

    test('repairForkSignsSuppliedConsumerEvidence', async () => {
      const a = await fixture('replicated')
      const b = await fixture('replicated', a.identity)
      const key = await a.manager.createKey({ ownerDID: a.identity.id, consumer: previousEvidence })
      const types = ['vault.key', 'vault.key-branch', 'vault.wrapping']
      await b.manager.records.apply(
        (await a.manager.records.adapter.list(types)).flatMap((d) => d.copies),
      )
      await a.manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
      await b.manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
      await a.manager.records.apply(
        (await b.manager.records.adapter.list(types)).flatMap((d) => d.copies),
      )
      expect(
        await administrator(a).repairFork({
          ...key,
          excludedRecipients: [randomIdentity().id],
          reissue: [],
          consumer: currentEvidence,
        }),
      ).toEqual({ status: 'rotated', version: 3 })
      const current = (await signedOps(a, ['vault.key', 'vault.key-branch'])).filter(
        ({ op }) => op.claim.meta.version === 3 || op.claim.meta.keyVersion === 3,
      )
      expect(current).toHaveLength(2)
      for (const { op } of current) expect(op.claim.meta.consumer).toEqual(currentEvidence)
    })

    test('unsetConsumerKeepsInheritedEvidence', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id, consumer: previousEvidence })
      await f.manager.rotate({ ...key, excludedRecipients: [], reissue: [], consumer: undefined })
      const current = (
        await signedOps(f, ['vault.key', 'vault.key-branch', 'vault.wrapping'])
      ).filter(({ op }) => op.claim.meta.version === 2 || op.claim.meta.keyVersion === 2)
      expect(current).toHaveLength(3)
      for (const { op } of current) expect(op.claim.meta.consumer).toEqual(previousEvidence)
      const recipientDID = randomIdentity().id
      await f.manager.grant({ ...key, recipientDID })
      expect(
        (await signedOps(f, ['vault.wrapping'])).find(
          ({ op }) => op.claim.meta.recipient === recipientDID,
        )?.op.claim.meta.consumer,
      ).toBeNull()
    })

    test('nullConsumerClearsEvidence', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id, consumer: previousEvidence })
      await f.manager.rotate({ ...key, excludedRecipients: [], reissue: [], consumer: null })
      const current = (
        await signedOps(f, ['vault.key', 'vault.key-branch', 'vault.wrapping'])
      ).filter(({ op }) => op.claim.meta.version === 2 || op.claim.meta.keyVersion === 2)
      expect(current).toHaveLength(3)
      for (const { op } of current) expect(op.claim.meta.consumer).toBeNull()
    })

    test.each(['metadata', 'authority'] as const)(
      'suppliedConsumerRefusalPreventsWrites (%s)',
      async (refusal) => {
        const f = await fixture('replicated')
        const key = await f.manager.createKey({ ownerDID: f.identity.id })
        if (f.params.mode !== 'replicated') throw new Error('Expected replicated mode')
        const seen: Array<unknown> = []
        const authority = {
          authorize: vi.fn(async (request: CredentialAuthorityRequest) => {
            if (request.source === 'local') return true
            seen.push(request.op.claim.meta.consumer)
            return refusal !== 'authority' || request.op.claim.meta.consumer === null
          }),
        }
        const validateConsumerMetadata = vi.fn(async (consumer: unknown) => {
          seen.push(consumer)
          return refusal !== 'metadata' || consumer === null
        })
        const manager = createVaultCoordinator({
          ...f.params,
          authority,
          records: { ...f.params.records, validateConsumerMetadata },
        })
        const types = ['vault.key', 'vault.key-branch', 'vault.wrapping', 'vault.revocation']
        const before = await f.manager.records.adapter.list(types)
        const wrappings = await f.store.listWrappings(key)
        const queryStart = f.queries.length
        await expect(
          manager.grant({
            ...key,
            recipientDID: randomIdentity().id,
            consumer: currentEvidence,
          }),
        ).rejects.toThrow()
        expect(seen).toContainEqual(currentEvidence)
        expect(
          f.queries
            .slice(queryStart)
            .filter(
              ({ sql }) => /^\s*(insert|update|delete)\b/i.test(sql) && !/WHERE 1 = 0$/.test(sql),
            ),
        ).toEqual([])
        expect(await f.manager.records.adapter.list(types)).toEqual(before)
        expect(await f.store.listWrappings(key)).toEqual(wrappings)
      },
    )

    test.each([
      'setKeyState',
      'deleteKey',
      'addFactor',
      'removeFactor',
      'updateEntry',
      'updateEntryIfPresent',
      'updateEntryIfUnchanged',
      'deleteEntry',
      'reKeyEntry',
    ] as const)('mutationSignsCurrentConsumerEvidence (%s)', async (operation) => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id, consumer: previousEvidence })
      const entry = await f.manager.putEntry({
        ...key,
        entryID: 'evidence',
        ...metadata,
        plaintext: bytes('old'),
        consumer: previousEvidence,
      })
      const manager = administrator(f)
      const call = { ...key, ...entry, consumer: currentEvidence }
      if (operation === 'setKeyState') await manager.setKeyState({ ...call, state: 'retired' })
      else if (operation === 'deleteKey') await manager.deleteKey(call)
      else if (operation === 'addFactor')
        await manager.addFactor({
          ...call,
          factor: { kind: 'pin', input: bytes('pin'), cost },
        })
      else if (operation === 'removeFactor') {
        await f.manager.addFactor({ ...key, factor: { kind: 'pin', input: bytes('pin'), cost } })
        await manager.removeFactor({ ...call, inputs: { pin: bytes('pin') }, kind: 'pin' })
      } else if (operation === 'deleteEntry') await manager.deleteEntry(call)
      else if (operation === 'reKeyEntry') {
        const target = await f.manager.createKey({ ownerDID: f.identity.id })
        await manager.reKeyEntry({ ...call, toKeyID: target.keyID })
      } else if (operation === 'updateEntryIfUnchanged') {
        const row = await f.store.getEntry(entry)
        if (row === undefined) throw new Error('Missing entry')
        await manager.updateEntryIfUnchanged({
          ...call,
          plaintext: bytes('new'),
          expectedHLC: row.hlc,
        })
      } else await manager[operation]({ ...call, plaintext: bytes('new') })
      const type =
        operation === 'setKeyState' || operation === 'deleteKey'
          ? 'vault.key'
          : operation === 'addFactor' || operation === 'removeFactor'
            ? 'vault.wrapping'
            : 'vault.entry'
      const signed = (await signedOps(f, [type])).filter(({ op }) => op.issuer !== f.identity.id)
      expect(signed.length).toBeGreaterThan(0)
      for (const { op } of signed) expect(op.claim.meta.consumer).toEqual(currentEvidence)
      if (type === 'vault.wrapping') expect(signed).toHaveLength(2)
    })

    test('replicated reads refuse replayed ciphertext beneath a newer signed entry decision', async () => {
      const { sql } = await import('@hozon/db')
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const entry = await f.manager.putEntry({
        ...key,
        entryID: 'replay',
        plaintext: bytes('old'),
        ...metadata,
      })
      const old = await f.store.getEntry(entry)
      if (!old) throw new Error('missing entry')
      await f.manager.updateEntry({ ...entry, plaintext: bytes('new') })
      expect(text(await f.manager.readEntry(entry))).toBe('new')
      await sql`update ${sql.table('vault_entries')} set iv = ${old.iv}, ciphertext = ${old.ciphertext} where entry_id = ${entry.entryID}`.execute(
        f.raw,
      )
      await expect(f.manager.readEntry(entry)).rejects.toBeInstanceOf(VaultTampered)
    })

    test('repair restores readable projections after concurrent preservation rotations', async () => {
      const a = await fixture('replicated')
      const b = await fixture('replicated', a.identity)
      const key = await a.manager.createKey({ ownerDID: a.identity.id })
      const entry = await a.manager.putEntry({
        ...key,
        entryID: 'preserved',
        plaintext: bytes('same'),
        ...metadata,
      })
      const types = [
        'vault.key',
        'vault.key-branch',
        'vault.wrapping',
        'vault.entry',
        'vault.revocation',
      ]
      await b.manager.records.apply(
        (await a.manager.records.adapter.list(types)).flatMap((d) => d.copies),
      )
      await a.manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
      await b.manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
      const left = (await a.manager.records.listKeyBranches({ ...key, keyVersion: 2 }))[0]
      const right = (await b.manager.records.listKeyBranches({ ...key, keyVersion: 2 }))[0]
      if (!left || !right) throw new Error('missing branches')
      const [winner, loser] =
        recordClaimDigest(left.introducingOp.claim) > recordClaimDigest(right.introducingOp.claim)
          ? [a, b]
          : [b, a]
      const selected = (
        await loser.manager.records.adapter.get({
          type: 'vault.entry',
          owner: key.ownerDID,
          id: entry.entryID,
        })
      )?.copies[0]
      if (!selected) throw new Error('missing entry record')
      await winner.manager.records.apply(
        (await loser.manager.records.adapter.list(types)).flatMap((d) => d.copies),
      )
      // Entry and key decisions have independent digest winners. Force the unreadable projection.
      await winner.manager.records.adapter.transaction(async (tx) => {
        await tx.putCopy(selected)
      })
      await expect(winner.manager.readEntry(entry)).rejects.toMatchObject({
        name: 'VaultSupersededBranch',
      })
      expect(
        await winner.manager.repairFork({ ...key, excludedRecipients: [], reissue: [] }),
      ).toEqual({
        status: 'rotated',
        version: 3,
      })
      expect(text(await winner.manager.readEntry(entry))).toBe('same')
    })

    for (const mode of ['local', 'replicated'] as const) {
      for (const sourceVersion of [undefined, 1]) {
        test(`foreign secret rotation refuses by default without writes (${mode}, source=${sourceVersion})`, async () => {
          const f = await fixture(mode)
          const recipient = randomIdentity()
          const key = await f.manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [
              [{ kind: 'did', recipientDID: f.identity.id }],
              [
                { kind: 'did', recipientDID: recipient.id },
                { kind: 'passphrase', input: bytes('recovery'), cost },
              ],
            ],
          })
          const before = await f.store.listWrappings(key)
          const foreign = before.find((w) => w.descriptors.length === 2)
          const offset = f.queries.length
          await expect(
            f.manager.rotate({
              ...key,
              sourceVersion,
              excludedRecipients: [],
              reissue: [],
              inputs: { passphrase: bytes('recovery') },
            }),
          ).rejects.toMatchObject({
            name: 'VaultSecretUnverifiable',
            wrappingID: foreign?.wrappingID,
            recipientDID: recipient.id,
            factorKinds: ['did', 'passphrase'],
          })
          expect(
            f.queries.slice(offset).filter((q) => {
              // Hozon acquires SQLite's write lock with a zero-row DELETE.
              return /^(insert|update|delete) /i.test(q.sql) && !q.sql.endsWith(' WHERE 1 = 0')
            }),
          ).toEqual([])
          expect((await f.store.getKey(key))?.version).toBe(1)
          expect(await f.store.listWrappings(key)).toEqual(before)
        })

        test.each(['owner-secret', 'foreign-did', 'foreign-secret'] as const)(
          `rotation retains %s access (${mode}, source=${sourceVersion})`,
          async (scenario) => {
            const f = await fixture(mode)
            const recipient = scenario === 'owner-secret' ? f.identity : randomIdentity()
            const key = await f.manager.createKey({
              ownerDID: f.identity.id,
              wrappings: [
                [{ kind: 'did', recipientDID: f.identity.id }],
                [
                  { kind: 'did', recipientDID: recipient.id },
                  ...(scenario === 'foreign-did'
                    ? []
                    : [{ kind: 'passphrase' as const, input: bytes('recovery'), cost }]),
                ],
              ],
            })
            const entry = await f.manager.putEntry({
              ...key,
              entryID: 'retained',
              ...metadata,
              plaintext: bytes('preserved'),
            })
            expect(
              await f.manager.rotate({
                ...key,
                sourceVersion,
                excludedRecipients: [],
                reissue: [],
                inputs: { passphrase: bytes('recovery') },
                trustUnverifiableSecrets: scenario === 'foreign-secret',
              }),
            ).toBe(2)
            expect(await f.store.listWrappings({ ...key, keyVersion: 2 })).toHaveLength(2)
            const reader = createVaultCoordinator({
              ...f.params,
              identity: recipient,
              principal: recipient.id,
            })
            expect(
              text(await reader.readEntry({ ...entry, inputs: { passphrase: bytes('recovery') } })),
            ).toBe('preserved')
          },
        )
      }

      test.each(['own-did', 'secret-only', 'missing-foreign'] as const)(
        `trusting foreign secrets still refuses %s input (${mode})`,
        async (scenario) => {
          const f = await fixture(mode)
          const recipient = randomIdentity()
          const key = await f.manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [
              [{ kind: 'did', recipientDID: f.identity.id }],
              [
                { kind: 'did', recipientDID: recipient.id },
                { kind: 'passphrase', input: bytes('recovery'), cost },
              ],
              ...(scenario === 'missing-foreign'
                ? []
                : [
                    [
                      ...(scenario === 'own-did'
                        ? [{ kind: 'did' as const, recipientDID: f.identity.id }]
                        : []),
                      { kind: 'passphrase' as const, input: bytes('recovery'), cost },
                    ],
                  ]),
            ],
          })
          const before = await f.store.listWrappings(key)
          const offset = f.queries.length
          await expect(
            f.manager.rotate({
              ...key,
              excludedRecipients: [],
              reissue: [],
              trustUnverifiableSecrets: true,
              inputs: scenario === 'missing-foreign' ? {} : { passphrase: bytes('wrong') },
            }),
          ).rejects.toMatchObject({
            name:
              scenario === 'missing-foreign' ? 'VaultSecretUnverifiable' : 'VaultSecretRejected',
          })
          expect(
            f.queries.slice(offset).filter((q) => {
              // Hozon acquires SQLite's write lock with a zero-row DELETE.
              return /^(insert|update|delete) /i.test(q.sql) && !q.sql.endsWith(' WHERE 1 = 0')
            }),
          ).toEqual([])
          expect((await f.store.getKey(key))?.version).toBe(1)
          expect(await f.store.listWrappings(key)).toEqual(before)
        },
      )

      test(`excluded foreign secret needs no input and is not retained (${mode})`, async () => {
        const f = await fixture(mode)
        const recipient = randomIdentity()
        const key = await f.manager.createKey({
          ownerDID: f.identity.id,
          wrappings: [
            [{ kind: 'did', recipientDID: f.identity.id }],
            [
              { kind: 'did', recipientDID: recipient.id },
              { kind: 'passphrase', input: bytes('recovery'), cost },
            ],
          ],
        })
        await f.manager.rotate({
          ...key,
          excludedRecipients: [recipient.id],
          reissue: [],
          trustUnverifiableSecrets: true,
        })
        if (mode === 'replicated') {
          await f.manager.rotate({
            ...key,
            sourceVersion: 1,
            excludedRecipients: [],
            reissue: [],
            trustUnverifiableSecrets: true,
          })
        }
        const version = mode === 'replicated' ? 3 : 2
        const retained = await f.store.listWrappings({ ...key, keyVersion: version })
        expect(retained).toHaveLength(1)
        expect(retained[0]?.descriptors).toMatchObject([
          { kind: 'did', params: { recipient: f.identity.id } },
        ])
      })
    }

    test('foreign secret fork repair stays pending until explicitly trusted', async () => {
      const a = await fixture('replicated')
      const b = await fixture('replicated', a.identity)
      const recipient = randomIdentity()
      const key = await a.manager.createKey({
        ownerDID: a.identity.id,
        wrappings: [
          [{ kind: 'did', recipientDID: a.identity.id }],
          [
            { kind: 'did', recipientDID: recipient.id },
            { kind: 'passphrase', input: bytes('recovery'), cost },
          ],
        ],
      })
      const entry = await a.manager.putEntry({
        ...key,
        entryID: 'forked',
        ...metadata,
        plaintext: bytes('preserved'),
      })
      const types = [
        'vault.key',
        'vault.key-branch',
        'vault.wrapping',
        'vault.entry',
        'vault.revocation',
      ]
      await b.manager.records.apply(
        (await a.manager.records.adapter.list(types)).flatMap((d) => d.copies),
      )
      const request = {
        ...key,
        excludedRecipients: [],
        reissue: [],
        inputs: { passphrase: bytes('recovery') },
        trustUnverifiableSecrets: true,
      }
      await a.manager.rotate(request)
      await b.manager.rotate(request)
      await a.manager.records.apply(
        (await b.manager.records.adapter.list(types)).flatMap((d) => d.copies),
      )
      // A replacement makes repair necessary regardless of branch digest order.
      const repair = {
        ...request,
        reissue: [
          { entryID: entry.entryID, action: 'replace' as const, plaintext: bytes('repaired') },
        ],
      }
      const before = await a.manager.records.adapter.list(types)
      expect(
        await a.manager.repairFork({ ...repair, trustUnverifiableSecrets: false }),
      ).toMatchObject({
        status: 'pending',
        reason: 'secret-unverifiable',
        wrapping: { recipientDID: recipient.id, factorKinds: ['did', 'passphrase'] },
      })
      expect(await a.manager.records.adapter.list(types)).toEqual(before)
      expect((await a.store.getKey(key))?.version).toBe(2)
      expect(await a.manager.repairFork({ ...repair, inputs: {} })).toMatchObject({
        status: 'pending',
      })
      expect(await a.manager.records.adapter.list(types)).toEqual(before)
      expect(await a.manager.repairFork(repair)).toEqual({ status: 'rotated', version: 3 })
      const reader = createVaultCoordinator({
        ...a.params,
        identity: recipient,
        principal: recipient.id,
      })
      expect(text(await reader.readEntry({ ...entry, inputs: request.inputs }))).toBe('repaired')
    }, 30_000)

    for (const mode of ['local', 'replicated'] as const) {
      test(`factor edits restore recipient metadata when only the DID remains (${mode})`, async () => {
        const f = await fixture(mode)
        const pin = bytes('pin')
        const key = await f.manager.createKey({
          ownerDID: f.identity.id,
          wrappings: [
            [
              { kind: 'did', recipientDID: f.identity.id },
              { kind: 'pin', input: pin, cost },
            ],
          ],
        })
        await f.manager.removeFactor({ ...key, inputs: { pin }, kind: 'pin' })
        expect((await f.store.listWrappings(key))[0]?.recipientDID).toBe(f.identity.id)
      })

      test(`owner lockAll preserves another owner's cached and in-flight keys (${mode})`, async () => {
        const f = await fixture(mode)
        const owner = randomIdentity().id
        const own = await f.manager.createKey({ ownerDID: f.identity.id })
        const ownPending = await f.manager.createKey({ ownerDID: f.identity.id })
        const other = await f.manager.createKey({ ownerDID: owner })
        const pending = await f.manager.createKey({ ownerDID: owner })
        await f.manager.unlock(own)
        await f.manager.unlock(other)
        const unwrap = getSuite(1).unwrap.bind(getSuite(1))
        let release = () => {}
        const gate = new Promise<void>((resolve) => {
          release = resolve
        })
        let reached = 0
        vi.spyOn(getSuite(1), 'unwrap').mockImplementation(async (p) => {
          reached += 1
          await gate
          return unwrap(p)
        })
        const opening = f.manager.openKey(pending)
        const ownOpening = f.manager.openKey(ownPending)
        await vi.waitFor(() => expect(reached).toBe(2))
        await f.manager.lockAll(f.identity.id)
        release()
        ;(await opening).contentKey.fill(0)
        ;(await ownOpening).contentKey.fill(0)
        expect(await f.manager.status(own)).not.toMatchObject({ state: 'unlocked' })
        expect(await f.manager.status(ownPending)).not.toMatchObject({ state: 'unlocked' })
        expect(await f.manager.status(other)).toEqual({ state: 'unlocked' })
        expect(await f.manager.status(pending)).toEqual({ state: 'unlocked' })
      })

      test(`factor edits keep passphrase-only access through an unrelated DID exclusion (${mode})`, async () => {
        const f = await fixture(mode)
        const passphrase = bytes('phrase')
        const key = await f.manager.createKey({ ownerDID: f.identity.id })
        await f.manager.addFactor({
          ...key,
          factor: { kind: 'passphrase', input: passphrase, cost },
        })
        await f.manager.removeFactor({ ...key, inputs: { passphrase }, kind: 'did' })
        await f.manager.rotate({
          ...key,
          inputs: { passphrase },
          excludedRecipients: [f.identity.id],
          reissue: [],
        })
        const current = await f.store.listWrappings({ ...key, keyVersion: 2 })
        expect(current).toHaveLength(1)
        expect(current[0]?.recipientDID).toBeNull()
        const reader = createVaultCoordinator({
          ...f.params,
          principal: randomIdentity().id,
          identity: null,
        })
        const opened = await reader.openKey({ ...key, inputs: { passphrase } })
        expect(opened.version).toBe(2)
        opened.contentKey.fill(0)
      })
    }

    afterEach(async () => {
      vi.restoreAllMocks()
      for (const opened of databases.splice(0)) await opened.db.close()
      await harness.cleanup()
    })

    async function fixture(mode: 'local' | 'replicated', identity = randomIdentity()) {
      const opened = await openVaultTestDB(harness, mode === 'replicated')
      databases.push(opened)
      const calls: Array<CredentialAuthorityRequest> = []
      let refuse = false
      const authority = {
        authorize: vi.fn(async (request: CredentialAuthorityRequest) => {
          calls.push(request)
          return !refuse
        }),
      }
      const params: VaultCoordinatorParams = {
        store: opened.store,
        principal: identity.id,
        identity,
        runtime,
        authority,
        nextHLC: async () => stamp(++counter),
        ...(mode === 'replicated'
          ? {
              mode: 'replicated',
              signer: identity,
              records: {
                opKind: VAULT_OP_KIND,
                nowMS,
                maxDriftMS: 60_000,
                validateConsumerMetadata: async () => true,
              },
            }
          : { mode: 'local' }),
      }
      const manager = createVaultCoordinator(params)
      return {
        ...opened,
        manager,
        params,
        calls,
        deny: () => {
          refuse = true
        },
        identity,
      }
    }

    for (const mode of ['local', 'replicated'] as const)
      describe(`vault coordinator (${mode})`, () => {
        test('creates, opens, caches private clones and lists public metadata without writing on reads', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [[{ kind: 'did', recipientDID: f.identity.id }]],
          })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'grant:opaque',
            plaintext: bytes('secret'),
            ...metadata,
          })
          f.queries.length = 0
          f.calls.length = 0
          const first = await f.manager.openKey(key)
          first.contentKey.fill(0)
          expect((await f.manager.openKey(key)).contentKey.some((v) => v !== 0)).toBe(true)
          expect(text(await f.manager.readEntry(entry))).toBe('secret')
          expect(await f.manager.getEntry(entry)).toMatchObject(metadata)
          expect(await f.manager.listEntries({ ...key, attributes: { app: 'test' } })).toHaveLength(
            1,
          )
          expect(await f.manager.listKeys(f.identity.id)).toHaveLength(1)
          expect(f.calls.length).toBeGreaterThanOrEqual(6)
          expect(f.calls.every((call) => call.verb === 'read')).toBe(true)
          expect(f.queries.filter((q) => !/^(select|begin|commit)/i.test(q.sql))).toEqual([])
          if (mode === 'local') expect(f.db.hasStore('vault-records')).toBe(false)
        })

        test('every public operation asks authority and refusal writes nothing even with a warm key', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('secret'),
            ...metadata,
          })
          const row = await f.store.getEntry(entry)
          if (!row) throw new Error('missing entry')
          const operations = [
            ['read', () => f.manager.openKey(key)],
            ['read', () => f.manager.unlock(key)],
            ['read', () => f.manager.lock(key)],
            ['read', () => f.manager.lockAll(key.ownerDID)],
            ['read', () => f.manager.readEntry(entry)],
            ['read', () => f.manager.getEntry(entry)],
            ['read', () => f.manager.listEntries(key)],
            ['read', () => f.manager.listKeys(key.ownerDID)],
            ['read', () => f.manager.status(key)],
            ['administer', () => f.manager.createKey({ ownerDID: key.ownerDID })],
            [
              'administer',
              () =>
                f.manager.putEntry({ ...key, entryID: 'new', plaintext: bytes('x'), ...metadata }),
            ],
            ['administer', () => f.manager.updateEntry({ ...entry, plaintext: bytes('x') })],
            [
              'administer',
              () => f.manager.updateEntryIfPresent({ ...entry, plaintext: bytes('x') }),
            ],
            [
              'administer',
              () =>
                f.manager.updateEntryIfUnchanged({
                  ...entry,
                  plaintext: bytes('x'),
                  expectedHLC: row.hlc,
                }),
            ],
            ['administer', () => f.manager.deleteEntry(entry)],
            ['administer', () => f.manager.deleteKey(key)],
            ['administer', () => f.manager.reendorse({ ...key, records: [] })],
            ['administer', () => f.manager.setKeyState({ ...key, state: 'retired' })],
            ['administer', () => f.manager.grant({ ...key, recipientDID: randomIdentity().id })],
            [
              'administer',
              () =>
                f.manager.addFactor({
                  ...key,
                  factor: { kind: 'passphrase', input: bytes('p'), cost },
                }),
            ],
            ['administer', () => f.manager.removeFactor({ ...key, kind: 'did' })],
            [
              'administer',
              () => f.manager.rotate({ ...key, excludedRecipients: [f.identity.id], reissue: [] }),
            ],
            [
              'administer',
              () => f.manager.repairFork({ ...key, excludedRecipients: [], reissue: [] }),
            ],
            ['administer', () => f.manager.reKeyEntry({ ...entry, toKeyID: key.keyID })],
          ] as const
          f.deny()
          for (const [verb, operation] of operations) {
            f.calls.length = 0
            f.queries.length = 0
            await expect(operation()).rejects.toBeInstanceOf(VaultNotAuthorized)
            expect(f.calls[0]?.verb).toBe(verb)
            expect(f.queries.filter((q) => /^(insert|update|delete)/i.test(q.sql))).toEqual([])
          }
          expect(await f.store.getEntry(entry)).toEqual(row)
        })

        test('ordered factors distinguish missing input, wrong secret and authenticated descriptor tampering', async () => {
          const f = await fixture(mode)
          const pin = bytes('1234')
          const key = await f.manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [
              [
                { kind: 'did', recipientDID: f.identity.id },
                { kind: 'pin', input: pin, cost },
              ],
            ],
          })
          await expect(f.manager.openKey(key)).rejects.toMatchObject({ name: 'VaultKeyLocked' })
          await expect(
            f.manager.openKey({ ...key, inputs: { pin: bytes('wrong') } }),
          ).rejects.toBeInstanceOf(VaultSecretRejected)
          await f.manager.openKey({ ...key, inputs: { pin } })
          await expect(
            f.manager.openKey({ ...key, inputs: { pin: bytes('wrong') } }),
          ).rejects.toBeInstanceOf(VaultSecretRejected)
          await f.manager.lock(key)
          const original = f.store.listWrappings.bind(f.store)
          vi.spyOn(f.store, 'listWrappings').mockImplementation(async (address) =>
            (await original(address)).map((row) => ({
              ...row,
              descriptors: [...row.descriptors].reverse(),
            })),
          )
          await expect(f.manager.openKey({ ...key, inputs: { pin } })).rejects.toBeInstanceOf(
            mode === 'replicated' ? VaultTampered : VaultSecretRejected,
          )
        })

        test('factor edits are atomic and removing every factor is refused', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          await expect(f.manager.removeFactor({ ...key, kind: 'did' })).rejects.toBeInstanceOf(
            InvalidVaultFactors,
          )
          await f.manager.addFactor({ ...key, factor: { kind: 'pin', input: bytes('1234'), cost } })
          await f.manager.lock(key)
          await expect(f.manager.openKey(key)).rejects.toMatchObject({ name: 'VaultKeyLocked' })
          await f.manager.removeFactor({ ...key, kind: 'pin', inputs: { pin: bytes('1234') } })
          await f.manager.lock(key)
          expect((await f.manager.openKey(key)).version).toBe(1)
        })

        test('rotation excludes exactly named recipients and re-encrypts generic entries', async () => {
          const f = await fixture(mode)
          const dropped = randomIdentity()
          const kept = randomIdentity()
          const key = await f.manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [f.identity, dropped, kept].map((id) => [
              { kind: 'did', recipientDID: id.id },
            ]),
          })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'grant:uninterpreted',
            plaintext: bytes('kept'),
            ...metadata,
          })
          const before = await f.store.getEntry(entry)
          expect(
            await f.manager.rotate({ ...key, excludedRecipients: [dropped.id], reissue: [] }),
          ).toBe(2)
          expect(
            (await f.store.listWrappings({ ...key, keyVersion: 2 }))
              .map((w) => w.recipientDID)
              .sort(),
          ).toEqual([f.identity.id, kept.id].sort())
          expect(
            (await f.store.listWrappings(key)).some((w) => w.recipientDID === dropped.id),
          ).toBe(false)
          const after = await f.store.getEntry(entry)
          expect(after?.keyVersion).toBe(2)
          expect(after?.ciphertext).not.toEqual(before?.ciphertext)
          expect(text(await f.manager.readEntry(entry))).toBe('kept')
          if (mode === 'replicated') {
            const record = await f.manager.records.adapter.get({
              type: 'vault.entry',
              owner: key.ownerDID,
              id: entry.entryID,
            })
            const op =
              record?.copies[0] && (await verifySignedRecord(record.copies[0], VAULT_OP_KIND))
            expect(op?.claim.meta.contentHLC).toBe(before?.hlc)
            expect(await f.manager.records.listRevocations(key)).toEqual([dropped.id])
          }
        })

        test('explicit reissue instructions replace, skip and delete precisely the selected entries', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          for (const entryID of ['replace', 'skip', 'delete', 'preserve'])
            await f.manager.putEntry({ ...key, entryID, plaintext: bytes(entryID), ...metadata })
          const skipped = await f.store.getEntry({ ownerDID: key.ownerDID, entryID: 'skip' })
          await f.manager.rotate({
            ...key,
            excludedRecipients: [],
            reissue: [
              {
                entryID: 'replace',
                action: 'replace',
                plaintext: bytes('replacement'),
                contentHLC: stamp(++counter),
                consumer: { opaque: 'new' },
              },
              { entryID: 'skip', action: 'skip' },
              { entryID: 'delete', action: 'delete', contentHLC: stamp(++counter) },
            ],
          })
          expect(
            text(await f.manager.readEntry({ ownerDID: key.ownerDID, entryID: 'replace' })),
          ).toBe('replacement')
          expect(await f.store.getEntry({ ownerDID: key.ownerDID, entryID: 'skip' })).toEqual(
            skipped,
          )
          expect(
            await f.store.getEntry({ ownerDID: key.ownerDID, entryID: 'delete' }),
          ).toBeUndefined()
          expect(
            text(await f.manager.readEntry({ ownerDID: key.ownerDID, entryID: 'preserve' })),
          ).toBe('preserve')
          await expect(
            f.manager.rotate({
              ...key,
              excludedRecipients: [],
              reissue: [{ entryID: 'unknown', action: 'skip' }],
            }),
          ).rejects.toThrow()
          expect((await f.store.getKey(key))?.version).toBe(2)
        })

        test('entry CAS never resurrects and movement re-encrypts under both authorised keys', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const target = await f.manager.createKey({ ownerDID: f.identity.id })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('one'),
            ...metadata,
          })
          const row = await f.store.getEntry(entry)
          if (!row) throw new Error('missing entry')
          expect(
            await f.manager.updateEntryIfUnchanged({
              ...entry,
              expectedHLC: row.hlc,
              plaintext: bytes('two'),
            }),
          ).toBe('updated')
          expect(
            await f.manager.updateEntryIfUnchanged({
              ...entry,
              expectedHLC: row.hlc,
              plaintext: bytes('lost'),
            }),
          ).toBe('superseded')
          f.calls.length = 0
          await f.manager.reKeyEntry({ ...entry, toKeyID: target.keyID })
          expect(
            f.calls
              .filter((c) => c.source === 'local' && c.verb === 'administer')
              .map((c) => (c.source === 'local' ? c.keyID : undefined)),
          ).toEqual(expect.arrayContaining([key.keyID, target.keyID]))
          expect((await f.store.getEntry(entry))?.keyID).toBe(target.keyID)
          expect(text(await f.manager.readEntry(entry))).toBe('two')
          await f.manager.deleteEntry(entry)
          expect(
            await f.manager.updateEntryIfPresent({ ...entry, plaintext: bytes('resurrected') }),
          ).toBe('absent')
        })

        test('rotation rollback preserves all ciphertext and zeroes temporary plaintext on failure', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('secret'),
            ...metadata,
          })
          const before = await f.store.getEntry(entry)
          const suite = getSuite(1)
          const decrypt = suite.decryptEntry.bind(suite)
          const buffers: Array<Uint8Array> = []
          vi.spyOn(suite, 'decryptEntry').mockImplementation((p) => {
            const result = decrypt(p)
            buffers.push(result)
            return result
          })
          vi.spyOn(suite, 'encryptEntry').mockImplementation(() => {
            throw new Error('injected')
          })
          await expect(
            f.manager.rotate({ ...key, excludedRecipients: [], reissue: [] }),
          ).rejects.toThrow('injected')
          expect((await f.store.getKey(key))?.version).toBe(1)
          expect(await f.store.getEntry(entry)).toEqual(before)
          expect(buffers.length).toBeGreaterThan(0)
          expect(buffers.every((b) => b.every((v) => v === 0))).toBe(true)
        })

        test('a lock during open suppresses cache warming and concurrent input-free opens share unwrap', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const unwrap = getSuite(1).unwrap.bind(getSuite(1))
          let release = () => {}
          const gate = new Promise<void>((resolve) => {
            release = resolve
          })
          const spy = vi.spyOn(getSuite(1), 'unwrap').mockImplementation(async (p) => {
            await gate
            return unwrap(p)
          })
          const opens = Promise.all([f.manager.openKey(key), f.manager.openKey(key)])
          await vi.waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
          await f.manager.lock(key)
          release()
          const results = await opens
          expect(results[0]?.contentKey).toEqual(results[1]?.contentKey)
          expect(results[0]?.contentKey).not.toBe(results[1]?.contentKey)
          expect(await f.manager.status(key)).not.toMatchObject({ state: 'unlocked' })
        })
      })

    test('replicated writes enter apply, admission refusal rolls back the whole key creation', async () => {
      const f = await fixture('replicated')
      f.params.authority.authorize = vi.fn(
        async (r) => !(r.source === 'record' && r.recordKey.type === 'vault.wrapping'),
      )
      await expect(f.manager.createKey({ ownerDID: f.identity.id })).rejects.toThrow()
      expect(await f.store.listKeys(f.identity.id)).toEqual([])
      expect(await f.manager.records.adapter.list(['vault.key', 'vault.key-branch'])).toEqual([])
    })

    test('replicated repair uses proven branches and retained losing entries, preserving newer tombstones', async () => {
      const a = await fixture('replicated')
      const b = await fixture('replicated', a.identity)
      const key = await a.manager.createKey({ ownerDID: a.identity.id })
      await b.manager.records.apply(
        (
          await a.manager.records.adapter.list([
            'vault.key',
            'vault.key-branch',
            'vault.wrapping',
            'vault.entry',
            'vault.revocation',
          ])
        ).flatMap((d) => d.copies),
      )
      await a.manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
      await b.manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
      const branches = [a, b]
      const keys = await Promise.all(
        branches.map(
          async (f) => (await f.manager.records.listKeyBranches({ ...key, keyVersion: 2 }))[0],
        ),
      )
      const [firstBranch, secondBranch] = keys
      if (firstBranch === undefined || secondBranch === undefined) throw new Error('Missing branch')
      const [loser, winner] =
        recordClaimDigest(firstBranch.introducingOp.claim) <
        recordClaimDigest(secondBranch.introducingOp.claim)
          ? [a, b]
          : [b, a]
      await loser.manager.putEntry({
        ...key,
        entryID: 'loser-only',
        plaintext: bytes('survives'),
        ...metadata,
      })
      await winner.manager.putEntry({
        ...key,
        entryID: 'deleted',
        plaintext: bytes('old'),
        ...metadata,
      })
      await loser.manager.putEntry({
        ...key,
        entryID: 'deleted',
        plaintext: bytes('new'),
        ...metadata,
      })
      await loser.manager.deleteEntry({ ownerDID: key.ownerDID, entryID: 'deleted' })
      await a.manager.records.apply(
        (
          await b.manager.records.adapter.list([
            'vault.key',
            'vault.key-branch',
            'vault.wrapping',
            'vault.entry',
            'vault.revocation',
          ])
        ).flatMap((d) => d.copies),
      )
      await b.manager.records.apply(
        (
          await a.manager.records.adapter.list([
            'vault.key',
            'vault.key-branch',
            'vault.wrapping',
            'vault.entry',
            'vault.revocation',
          ])
        ).flatMap((d) => d.copies),
      )
      await expect(
        a.manager.readEntry({ ownerDID: key.ownerDID, entryID: 'loser-only' }),
      ).rejects.toMatchObject({ name: 'VaultSupersededBranch' })
      expect(await a.manager.repairFork({ ...key, excludedRecipients: [], reissue: [] })).toEqual({
        status: 'rotated',
        version: 3,
      })
      expect(
        text(await a.manager.readEntry({ ownerDID: key.ownerDID, entryID: 'loser-only' })),
      ).toBe('survives')
      expect(await a.store.getEntry({ ownerDID: key.ownerDID, entryID: 'deleted' })).toBeUndefined()
      expect(await a.manager.repairFork({ ...key, excludedRecipients: [], reissue: [] })).toEqual({
        status: 'not-needed',
      })
    })

    test('re-endorsement preserves the exact named claim and signs as the supplied effective member through apply', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const original = (
        await f.manager.records.adapter.get({
          type: 'vault.key',
          owner: key.ownerDID,
          id: key.keyID,
        })
      )?.copies[0]
      if (original === undefined) throw new Error('Missing key')
      const survivor = await createIdentity({
        keys: [
          { purpose: 'sig', alg: 'EdDSA' },
          { purpose: 'kem', alg: 'X25519' },
        ],
      })
      if (f.params.mode !== 'replicated') throw new Error('wrong mode')
      const manager = createVaultCoordinator({
        ...f.params,
        signer: survivor,
        principal: survivor.id,
      })
      await manager.reendorse({ ...key, records: [original] })
      const copies = (await manager.records.adapter.get(original))?.copies
      if (copies === undefined) throw new Error('Missing endorsed record')
      expect(copies).toHaveLength(2)
      const ops = await Promise.all(copies.map((r) => verifySignedRecord(r, VAULT_OP_KIND)))
      expect(ops.map((o) => o?.issuer)).toContain(survivor.id)
      expect(
        new Set(ops.map((o) => (o === null ? 'invalid' : recordClaimDigest(o.claim)))).size,
      ).toBe(1)
      f.deny()
      await expect(manager.reendorse({ ...key, records: [original] })).rejects.toBeInstanceOf(
        VaultNotAuthorized,
      )
    })

    test('signed write CAS refuses a stale rotation and retains the current ciphertext', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const record = (
        await f.manager.records.adapter.get({
          type: 'vault.key',
          owner: key.ownerDID,
          id: key.keyID,
        })
      )?.copies[0]
      if (record === undefined) throw new Error('missing key')
      await expect(
        f.manager.records.write({
          records: [record],
          preconditions: { key: { ...key, expectedVersion: 99 } },
        }),
      ).rejects.toBeInstanceOf(VaultWriteConflict)
    })

    for (const mode of ['local', 'replicated'] as const)
      describe(`coordinator transaction guarantees (${mode})`, () => {
        test('coordinator writes join the enclosing host transaction and never cache rolled-back key material', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('initial'),
            ...metadata,
          })
          const before = await f.store.getEntry(entry)
          await expect(
            f.db.withTransaction(async (provider) => {
              const { getVaultStore } = await import('../src/index.js')
              const txStore = await getVaultStore(provider)
              const manager = createVaultCoordinator({ ...f.params, store: txStore })
              await manager.rotate({ ...key, excludedRecipients: [], reissue: [] })
              throw new Error('host rollback')
            }),
          ).rejects.toThrow('host rollback')
          expect(await f.store.getEntry(entry)).toEqual(before)
          expect((await f.store.getKey(key))?.version).toBe(1)
          expect(text(await f.manager.readEntry(entry))).toBe('initial')
        })

        test('rotation and entry writes serialize for their complete critical sections in one host transaction', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('initial'),
            ...metadata,
          })
          await f.db.withTransaction(async (provider) => {
            const { getVaultStore } = await import('../src/index.js')
            const store = await getVaultStore(provider)
            const rotating = createVaultCoordinator({ ...f.params, store })
            const writer = createVaultCoordinator({ ...f.params, store })
            const wrap = getSuite(1).wrap.bind(getSuite(1))
            let release = () => {}
            let reached = false
            const gate = new Promise<void>((resolve) => {
              release = resolve
            })
            const spy = vi.spyOn(getSuite(1), 'wrap').mockImplementation(async (p) => {
              reached = true
              await gate
              return wrap(p)
            })
            const rotation = rotating.rotate({ ...key, excludedRecipients: [], reissue: [] })
            await vi.waitFor(() => expect(reached).toBe(true))
            let settled = false
            const write = writer
              .updateEntry({ ...entry, plaintext: bytes('latest') })
              .finally(() => {
                settled = true
              })
            await new Promise((resolve) => setTimeout(resolve, 40))
            expect(settled, 'writer must wait for the complete rotation critical section').toBe(
              false,
            )
            release()
            try {
              expect(await rotation).toBe(2)
              await write
            } finally {
              spy.mockRestore()
            }
          })
          expect((await f.store.getEntry(entry))?.keyVersion).toBe(2)
          expect(text(await f.manager.readEntry(entry))).toBe('latest')
        })

        test('a missing rotation secret leaves all versions and bytes unchanged', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [
              [
                { kind: 'did', recipientDID: f.identity.id },
                { kind: 'pin', input: bytes('pin'), cost },
              ],
            ],
          })
          const row = (await f.store.listWrappings(key))[0]
          await expect(
            f.manager.rotate({ ...key, excludedRecipients: [], reissue: [] }),
          ).rejects.toThrow()
          expect((await f.store.getKey(key))?.version).toBe(1)
          expect((await f.store.listWrappings(key))[0]).toEqual(row)
        })

        test('two concurrent entry CAS requests have exactly one winner', async () => {
          const f = await fixture(mode)
          const key = await f.manager.createKey({ ownerDID: f.identity.id })
          const entry = await f.manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('one'),
            ...metadata,
          })
          const row = await f.store.getEntry(entry)
          if (!row) throw new Error('missing entry')
          const outcomes = await Promise.all(
            ['a', 'b'].map((value) =>
              f.manager.updateEntryIfUnchanged({
                ...entry,
                expectedHLC: row.hlc,
                plaintext: bytes(value),
              }),
            ),
          )
          expect(outcomes.sort()).toEqual(['superseded', 'updated'])
        })

        test('unlock throttles rejected PIN attempts before deriving another secret', async () => {
          const f = await fixture(mode)
          const manager = createVaultCoordinator({
            ...f.params,
            pinThrottle: { freeAttempts: 1, baseDelay: 1000, now: () => 100 },
          })
          const key = await manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [
              [
                { kind: 'did', recipientDID: f.identity.id },
                { kind: 'pin', input: bytes('pin'), cost },
              ],
            ],
          })
          const spy = vi.spyOn(getSuite(1), 'unwrap')
          await expect(
            manager.unlock({ ...key, inputs: { pin: bytes('bad') } }),
          ).rejects.toMatchObject({ name: 'VaultPinRejected' })
          const calls = spy.mock.calls.length
          await expect(
            manager.unlock({ ...key, inputs: { pin: bytes('bad') } }),
          ).rejects.toMatchObject({ name: 'VaultPinRejected' })
          expect(spy).toHaveBeenCalledTimes(calls)
        })
      })

    test('replicated retirement never silently reports a refused same-version activation as successful', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      await f.manager.setKeyState({ ...key, state: 'retired' })
      await expect(f.manager.setKeyState({ ...key, state: 'active' })).rejects.toBeInstanceOf(
        VaultWriteConflict,
      )
      expect((await f.store.getKey(key))?.state).toBe('retired')
    })

    test('re-endorsement includes consumer-named key tombstones after physical projection deletion', async () => {
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      await f.manager.deleteKey(key)
      const tombstone = (
        await f.manager.records.adapter.get({
          type: 'vault.key',
          owner: key.ownerDID,
          id: key.keyID,
        })
      )?.copies[0]
      if (!tombstone) throw new Error('missing tombstone')
      const survivor = randomIdentity()
      if (f.params.mode !== 'replicated') throw new Error('wrong mode')
      const manager = createVaultCoordinator({
        ...f.params,
        signer: survivor,
        principal: survivor.id,
      })
      await manager.reendorse({ ...key, records: [tombstone] })
      expect((await manager.records.adapter.get(tombstone))?.copies).toHaveLength(2)
      expect(await f.store.getKey(key)).toBeUndefined()
    })

    for (const mode of ['local', 'replicated'] as const)
      test(`default long-form recipients, metadata filtering and TTL survive restart (${mode})`, async () => {
        const identity = await createIdentity({
          didMethod: 'peer:4',
          keys: [
            { purpose: 'sig', alg: 'EdDSA' },
            { purpose: 'kem', alg: 'X25519' },
          ],
        })
        const f = await fixture(mode, identity)
        let now = 0
        const manager = createVaultCoordinator({ ...f.params, cache: { ttl: 10, now: () => now } })
        const key = await manager.createKey({ ownerDID: identity.id })
        const row = (await f.store.listWrappings(key))[0]
        expect(row?.descriptors[0]?.params.recipient).toBe(identity.longForm)
        const entry = await manager.putEntry({
          ...key,
          entryID: 'peer',
          plaintext: bytes('peer state'),
          ...metadata,
        })
        expect(await manager.status(key)).toMatchObject({ state: 'unlocked' })
        now = 10
        expect(await manager.status(key)).toMatchObject({ state: 'available' })
        expect(text(await createVaultCoordinator(f.params).readEntry(entry))).toBe('peer state')
        expect(await manager.listEntries({ ...key, kind: 'wrong' })).toEqual([])
      })

    test('local status reports an unsupported suite as unopenable', async () => {
      const f = await fixture('local')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      await f.store.putKey({ ...key, version: 1, suite: 99, state: 'active' })
      expect(await f.manager.status(key)).toEqual({ state: 'unopenable' })
    })

    for (const mode of ['local', 'replicated'] as const)
      describe(`mutation opening and PIN checks (${mode})`, () => {
        test.each(['grant', 'addFactor', 'removeFactor'] as const)(
          '%s refuses a historical version without damaging the current wrapping',
          async (method) => {
            const f = await fixture(mode)
            const pin = bytes('pin')
            const key = await f.manager.createKey({
              ownerDID: f.identity.id,
              wrappings: [
                [
                  { kind: 'did', recipientDID: f.identity.id },
                  { kind: 'pin', input: pin, cost },
                ],
              ],
            })
            const entry = await f.manager.putEntry({
              ...key,
              entryID: 'e',
              plaintext: bytes('current'),
              inputs: { pin },
              ...metadata,
            })
            await f.manager.rotate({ ...key, inputs: { pin }, excludedRecipients: [], reissue: [] })
            const before = await f.store.listWrappings(key)
            const request = { ...key, atVersion: 1, inputs: { pin } }
            const action =
              method === 'grant'
                ? f.manager.grant({ ...request, recipientDID: randomIdentity().id })
                : method === 'addFactor'
                  ? f.manager.addFactor({
                      ...request,
                      factor: { kind: 'passphrase', input: bytes('phrase'), cost },
                    })
                  : f.manager.removeFactor({ ...request, kind: 'pin' })
            await expect(action).rejects.toBeInstanceOf(VaultWriteConflict)
            expect(await f.store.listWrappings(key)).toEqual(before)
            expect(text(await f.manager.readEntry({ ...entry, inputs: { pin } }))).toBe('current')
          },
        )

        test('PIN lockout covers open, read and every shared mutation opening path', async () => {
          const f = await fixture(mode)
          const manager = createVaultCoordinator({
            ...f.params,
            pinThrottle: { freeAttempts: 1, baseDelay: 1000, now: () => 100 },
          })
          const pin = bytes('pin')
          const key = await manager.createKey({
            ownerDID: f.identity.id,
            wrappings: [
              [
                { kind: 'did', recipientDID: f.identity.id },
                { kind: 'pin', input: pin, cost },
              ],
            ],
          })
          const entry = await manager.putEntry({
            ...key,
            entryID: 'e',
            plaintext: bytes('secret'),
            inputs: { pin },
            ...metadata,
          })
          await manager.lock(key)
          await expect(
            manager.unlock({ ...key, inputs: { pin: bytes('wrong') } }),
          ).rejects.toMatchObject({ name: 'VaultPinRejected' })
          const spy = vi.spyOn(getSuite(1), 'unwrap')
          const inputs = { pin: bytes('wrong') }
          for (const operation of [
            () => manager.openKey({ ...key, inputs }),
            () => manager.readEntry({ ...entry, inputs }),
            () => manager.rotate({ ...key, inputs, excludedRecipients: [], reissue: [] }),
            () => manager.grant({ ...key, inputs, recipientDID: randomIdentity().id }),
            () => manager.removeFactor({ ...key, inputs, kind: 'pin' }),
          ])
            await expect(operation()).rejects.toMatchObject({ name: 'VaultPinRejected' })
          expect(spy).not.toHaveBeenCalled()
        })
      })

    test('replicated rotation refuses tampered projection recipients before signing new key material', async () => {
      const { sql } = await import('@hozon/db')
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const wrapping = (await f.store.listWrappings(key))[0]
      if (!wrapping) throw new Error('missing wrapping')
      const attacker = randomIdentity()
      const descriptors = wrapping.descriptors.map((d) => ({
        ...d,
        params: { ...d.params, recipient: attacker.id },
      }))
      await sql`update ${sql.table('vault_wrappings')} set descriptors = ${JSON.stringify(descriptors)} where wrapping_id = ${wrapping.wrappingID}`.execute(
        f.raw,
      )
      f.queries.length = 0
      await expect(
        f.manager.rotate({ ...key, excludedRecipients: [], reissue: [] }),
      ).rejects.toBeInstanceOf(VaultTampered)
      expect((await f.store.getKey(key))?.version).toBe(1)
      expect(
        f.queries.filter(
          (q) => /^(insert|update|delete)/i.test(q.sql) && !/where 1 = 0/i.test(q.sql),
        ),
      ).toEqual([])
    })

    test('replicated rotation refuses unauthenticated public entry metadata instead of re-signing it', async () => {
      const { sql } = await import('@hozon/db')
      const f = await fixture('replicated')
      const key = await f.manager.createKey({ ownerDID: f.identity.id })
      const entry = await f.manager.putEntry({
        ...key,
        entryID: 'e',
        plaintext: bytes('secret'),
        ...metadata,
      })
      await sql`update ${sql.table('vault_entries')} set label = ${'forged'} where entry_id = ${entry.entryID}`.execute(
        f.raw,
      )
      await expect(
        f.manager.rotate({ ...key, excludedRecipients: [], reissue: [] }),
      ).rejects.toBeInstanceOf(VaultTampered)
      expect((await f.store.getKey(key))?.version).toBe(1)
    })
  })
}
