import { createIdentity, normalizeDID, randomIdentity, type SigningIdentity } from '@kokuin/token'
import { blake3 } from '@noble/hashes/blake3.js'
import { fromUTF, toB64U } from '@sozai/codec'
import { HLC } from '@sozai/hlc'
import { describe, expect, test } from 'vitest'

import {
  filterVisibleRecords,
  type MergePolicy,
  RANGE_LEAF_THRESHOLD,
  type RangeBounds,
  type RangeLeaf,
  type RecordClaim,
  type RecordStoreAdapter,
  type RecordTypeDefinition,
  rangeLeaf,
  recordPayloadDigest,
  type SignedRecord,
  signRecordOp,
  splitRange,
  summarizeRange,
  type VisibilityContext,
  type VisibilityRule,
  verifyHolderProof,
  verifySignedRecord,
  visibilityRules,
  visibleTo,
} from '../src/index.js'
import { decisionOf } from './decision-fixture.js'

const KEY = 'credential.key'
const BRANCH = 'credential.key-branch'
const WRAPPING = 'credential.wrapping'
const ENTRY = 'credential.entry'
const MANIFEST = 'credential.manifest'
const REVOCATION = 'credential.revocation'
const SHARED = 'test.shared'

const LWW: MergePolicy = { kind: 'lww' }

function rowKey(type: string, owner: string, id: string): string {
  return JSON.stringify([type, owner, id])
}

/** A store that counts writes, so a test can prove a proof is never stored. */
function memoryStore(initial: ReadonlyArray<SignedRecord> = []) {
  const rows = new Map(
    initial.map((record) => [rowKey(record.type, record.owner, record.id), record]),
  )
  const writes: Array<SignedRecord> = []
  const store: RecordStoreAdapter = {
    transaction: async (fn) => await fn(store),
    get: async (key) => {
      const record = rows.get(rowKey(key.type, key.owner, key.id))
      return record?.owner === key.owner ? decisionOf(record) : null
    },
    list: async (types) =>
      [...rows.values()].filter((record) => types.includes(record.type)).map(decisionOf),
    putCopy: async (record) => {
      writes.push(record)
      rows.set(rowKey(record.type, record.owner, record.id), record)
    },
    pruneCopy: async () => {},
  }
  return { store, writes }
}

let tick = 0

/** The op hash a record op is addressed by, framed as the op module frames it. */
function opHashOf(opJWT: string): string {
  return toB64U(blake3(fromUTF(`${opJWT.length}:${opJWT}`), { dkLen: 32 }))
}

async function makeRecord(
  signer: SigningIdentity,
  type: string,
  id: string,
  meta: Record<string, unknown>,
  options: { owner?: string; deleted?: boolean } = {},
): Promise<SignedRecord> {
  const payload = options.deleted === true ? null : new Uint8Array([1, tick % 256])
  const claim: RecordClaim = {
    type,
    id,
    owner: options.owner ?? normalizeDID(signer.id),
    hlc: HLC.serialize({ wallTime: Date.now(), counter: tick++, nodeID: signer.id }),
    payloadDigest: recordPayloadDigest(payload),
    deleted: payload === null,
    meta,
  }
  return {
    type,
    id,
    owner: claim.owner,
    hlc: claim.hlc,
    payload,
    ...(await signRecordOp(signer, claim)),
  }
}

/** A wrapping needs the key branch at its own version, as the credential types will. */
function wrappingDefinition(owner: string): RecordTypeDefinition {
  return {
    type: WRAPPING,
    policy: LWW,
    dependsOn: [],
    authorize: async (op) => op.issuer === owner && op.claim.owner === owner,
    dependencies: (_record, op) => {
      const { keyID, keyVersion } = op.claim.meta
      return [
        {
          type: BRANCH,
          owner: op.claim.owner,
          id: `${String(keyID)}:${String(keyVersion)}`,
          satisfiedBy: (stored) => stored.claim.meta.keyVersion === keyVersion,
        },
      ]
    },
  }
}

type World = {
  owner: SigningIdentity
  ownerDID: string
  b: SigningIdentity
  c: SigningIdentity
  bDID: string
  cDID: string
}

function world(): World {
  const owner = randomIdentity()
  const b = randomIdentity()
  const c = randomIdentity()
  return {
    owner,
    ownerDID: normalizeDID(owner.id),
    b,
    c,
    bDID: normalizeDID(b.id),
    cDID: normalizeDID(c.id),
  }
}

function contextFor(
  w: World,
  requester: { peerDID: string; controllerDID?: string | null },
  options: {
    store: RecordStoreAdapter
    proofs?: ReadonlyArray<SignedRecord>
    current?: Record<string, number>
    currentByOwner?: Record<string, Record<string, number>>
    groups?: Record<string, ReadonlyArray<string>>
    definition?: RecordTypeDefinition
  },
): VisibilityContext {
  const wrapping = options.definition ?? wrappingDefinition(w.ownerDID)
  const current = options.current ?? { 'key-1': 3, 'key-2': 3 }
  return {
    requester: { peerDID: requester.peerDID, controllerDID: requester.controllerDID ?? null },
    proofs: options.proofs ?? [],
    store: options.store,
    // The same authorizer apply runs, as a responder binds it.
    authorizeProof: async (record, stored) => {
      const op = await verifySignedRecord(record)
      return (
        op !== null &&
        (await wrapping.authorize(op, {
          record,
          stored,
          store: options.store,
          resolveController: async () => null,
          verifyCapability: async () => false,
        }))
      )
    },
    // Key ids are scoped by owner: `current` is the world owner's, `currentByOwner` any other.
    currentKeyVersion: async (owner, keyID) =>
      (owner === w.ownerDID ? current : (options.currentByOwner?.[owner] ?? {}))[keyID] ?? null,
    isGroupMember: async (groupID, did) => (options.groups?.[groupID] ?? []).includes(did),
    holderTypes: new Map([[WRAPPING, wrapping]]),
  }
}

/** Key, branch and entries for one key at one version, all written by the owner. */
async function keyRecords(w: World, keyID: string, version: number) {
  return {
    key: await makeRecord(w.owner, KEY, keyID, { keyID, version }),
    branch: await makeRecord(w.owner, BRANCH, `${keyID}:${version}`, {
      keyID,
      keyVersion: version,
    }),
    entries: [
      await makeRecord(w.owner, ENTRY, `${keyID}-entry-1`, { keyID, keyVersion: version }),
      await makeRecord(w.owner, ENTRY, `${keyID}-entry-2`, { keyID, keyVersion: version }),
    ],
  }
}

async function wrappingFor(w: World, keyID: string, version: number, recipient: string) {
  return await makeRecord(w.owner, WRAPPING, `${keyID}:${recipient}`, {
    keyID,
    keyVersion: version,
    recipient,
  })
}

const RULES: Record<string, ReadonlyArray<VisibilityRule>> = {
  [KEY]: ['ownerDevices', 'keyHolder'],
  [BRANCH]: ['keyHolder'],
  [WRAPPING]: ['recipient', 'ownerDevices'],
  [ENTRY]: ['keyHolder'],
  [MANIFEST]: ['recipient'],
  [REVOCATION]: ['keyHolder'],
}

function typesWithVisibility(): Map<string, RecordTypeDefinition> {
  const types = new Map<string, RecordTypeDefinition>()
  for (const [type, rules] of Object.entries(RULES)) {
    types.set(type, {
      type,
      policy: LWW,
      dependsOn: [],
      authorize: async () => true,
      dependencies: () => [],
      visibleTo: visibilityRules(rules),
    })
  }
  return types
}

async function visibleIDs(records: ReadonlyArray<SignedRecord>, ctx: VisibilityContext) {
  const visible = await filterVisibleRecords(records, typesWithVisibility(), ctx)
  return visible.map((record) => `${record.type}/${record.id}`).sort()
}

function ids(records: ReadonlyArray<SignedRecord>): Array<string> {
  return records.map((record) => `${record.type}/${record.id}`).sort()
}

test('a proof below the responder current key version earns no entries', async () => {
  const signer = randomIdentity()
  const requester = randomIdentity()
  const owner = normalizeDID(signer.id)
  const make = async (type: string, id: string, meta: Record<string, unknown>) => {
    const payload = new Uint8Array([1])
    const claim: RecordClaim = {
      type,
      id,
      owner,
      hlc: HLC.serialize({ wallTime: Date.now(), counter: 0, nodeID: signer.id }),
      payloadDigest: recordPayloadDigest(payload),
      deleted: false,
      meta,
    }
    return { type, id, owner, hlc: claim.hlc, payload, ...(await signRecordOp(signer, claim)) }
  }
  const proof = await make('credential.wrapping', 'wrap-1', {
    keyID: 'key-1',
    keyVersion: 2,
    recipient: normalizeDID(requester.id),
  })
  const entry = await make('credential.entry', 'entry-1', {
    keyID: 'key-1',
    keyVersion: 3,
  })
  const store: RecordStoreAdapter = {
    transaction: async (fn) => await fn(store),
    get: async () => null,
    list: async () => [],
    putCopy: async () => {},
    pruneCopy: async () => {},
  }
  const ctx: VisibilityContext = {
    requester: { peerDID: requester.id, controllerDID: null },
    proofs: [proof],
    store,
    authorizeProof: async () => true,
    currentKeyVersion: async () => 3,
    isGroupMember: async () => false,
    holderTypes: new Map([
      [
        'credential.wrapping',
        {
          type: 'credential.wrapping',
          policy: { kind: 'lww' },
          dependsOn: [],
          authorize: async () => true,
          dependencies: () => [],
        },
      ],
    ]),
  }
  expect(await verifyHolderProof(proof, ctx)).toBe(false)
  expect(await visibleTo(entry, ['keyHolder'], ctx)).toBe(false)
  // The same proof at the current version earns the entry: the version alone refused it.
  const current = await make('credential.wrapping', 'wrap-1', {
    keyID: 'key-1',
    keyVersion: 3,
    recipient: normalizeDID(requester.id),
  })
  const currentCtx: VisibilityContext = { ...ctx, proofs: [current] }
  expect(await verifyHolderProof(current, currentCtx)).toBe(true)
  expect(await visibleTo(entry, ['keyHolder'], currentCtx)).toBe(true)
})

describe('ownerDevices', () => {
  test('the owner device and a device acting for the owner see the owner rows', async () => {
    const w = world()
    const { store } = memoryStore()
    const key = await makeRecord(w.owner, KEY, 'key-1', { keyID: 'key-1', version: 3 })
    expect(
      await visibleTo(key, ['ownerDevices'], contextFor(w, { peerDID: w.owner.id }, { store })),
    ).toBe(true)
    const delegated = contextFor(w, { peerDID: w.b.id, controllerDID: w.ownerDID }, { store })
    expect(await visibleTo(key, ['ownerDevices'], delegated)).toBe(true)
    const other = contextFor(w, { peerDID: w.b.id, controllerDID: w.cDID }, { store })
    expect(await visibleTo(key, ['ownerDevices'], other)).toBe(false)
  })
})

describe('recipient', () => {
  test('a recipient sees only its own wrapping and manifest', async () => {
    const w = world()
    const bWrapping = await wrappingFor(w, 'key-1', 3, w.bDID)
    const cWrapping = await wrappingFor(w, 'key-1', 3, w.cDID)
    const bManifest = await makeRecord(w.owner, MANIFEST, `manifest:${w.bDID}`, {
      recipient: w.bDID,
    })
    const cManifest = await makeRecord(w.owner, MANIFEST, `manifest:${w.cDID}`, {
      recipient: w.cDID,
    })
    const { store } = memoryStore()
    const ctx = contextFor(w, { peerDID: w.b.id }, { store })
    expect(await visibleIDs([bWrapping, cWrapping, bManifest, cManifest], ctx)).toEqual(
      ids([bWrapping, bManifest]),
    )
  })
})

describe('keyHolder', () => {
  test('a requester the responder holds a current wrapping for sees the key and its entries', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const two = await keyRecords(w, 'key-2', 3)
    const bWrapping = await wrappingFor(w, 'key-1', 3, w.bDID)
    const stored = [one.key, one.branch, ...one.entries, two.key, two.branch, ...two.entries]
    const { store } = memoryStore([...stored, bWrapping])
    const forB = contextFor(w, { peerDID: w.b.id }, { store })
    expect(await visibleIDs(stored, forB)).toEqual(ids([one.key, one.branch, ...one.entries]))
    const forC = contextFor(w, { peerDID: w.c.id }, { store })
    expect(await visibleIDs(stored, forC)).toEqual([])
  })

  test('a valid self-addressed proof stands in for a wrapping the responder lacks', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const two = await keyRecords(w, 'key-2', 3)
    const bWrapping = await wrappingFor(w, 'key-1', 3, w.bDID)
    const stored = [one.key, one.branch, ...one.entries, two.key, two.branch, ...two.entries]
    const { store, writes } = memoryStore(stored)
    const ctx = contextFor(w, { peerDID: w.b.id }, { store, proofs: [bWrapping] })
    expect(await verifyHolderProof(bWrapping, ctx)).toBe(true)
    expect(await visibleIDs(stored, ctx)).toEqual(ids([one.key, one.branch, ...one.entries]))
    expect(writes).toEqual([])
  })

  test('a peer:4 recipient binds in either spelling', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const { store } = memoryStore([one.branch])
    const peer4 = await createIdentity({
      didMethod: 'peer:4',
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
    })
    expect(peer4.longForm).not.toBe(peer4.id)
    const longRecipient = await wrappingFor(w, 'key-1', 3, peer4.longForm)
    const shortRecipient = await wrappingFor(w, 'key-1', 3, peer4.id)
    const shortSession = contextFor(w, { peerDID: peer4.id }, { store })
    const longSession = contextFor(w, { peerDID: peer4.longForm }, { store })
    expect(await verifyHolderProof(longRecipient, shortSession)).toBe(true)
    expect(await verifyHolderProof(shortRecipient, longSession)).toBe(true)
    expect(await visibleTo(longRecipient, ['recipient'], shortSession)).toBe(true)
    expect(await visibleTo(shortRecipient, ['recipient'], longSession)).toBe(true)
  })

  describe('a proof earns nothing when', () => {
    async function setup() {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const { store } = memoryStore([one.key, one.branch, ...one.entries])
      return { w, one, store }
    }

    async function expectRejected(
      proof: SignedRecord,
      ctx: VisibilityContext,
      entry: SignedRecord,
    ): Promise<void> {
      expect(await verifyHolderProof(proof, ctx)).toBe(false)
      expect(await visibleTo(entry, ['keyHolder'], ctx)).toBe(false)
    }

    test('it is forged', async () => {
      const { w, one, store } = await setup()
      const genuine = await wrappingFor(w, 'key-1', 3, w.bDID)
      const [header, body] = genuine.opJWT.split('.')
      const other = await wrappingFor(w, 'key-1', 3, w.cDID)
      const signature = other.opJWT.split('.')[2]
      // B's claim under a signature made over C's, with an op hash that matches the token.
      const opJWT = `${header}.${body}.${signature}`
      const forged = { ...genuine, opJWT, opHash: opHashOf(opJWT) }
      // Even an authorizer that accepts anything does not rescue a bad signature.
      const ctx: VisibilityContext = {
        ...contextFor(w, { peerDID: w.b.id }, { store, proofs: [forged] }),
        authorizeProof: async () => true,
      }
      await expectRejected(forged, ctx, one.entries[0] as SignedRecord)
    })

    test('its payload does not match the signed digest', async () => {
      const { w, one, store } = await setup()
      const genuine = await wrappingFor(w, 'key-1', 3, w.bDID)
      const swapped = { ...genuine, payload: new Uint8Array([9, 9, 9]) }
      await expectRejected(
        swapped,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [swapped] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('the type authorizer refuses its issuer', async () => {
      const { w, one, store } = await setup()
      // Signed by B itself, claiming the owner's authority it does not have.
      const selfIssued = await makeRecord(
        w.b,
        WRAPPING,
        `key-1:${w.bDID}`,
        { keyID: 'key-1', keyVersion: 3, recipient: w.bDID },
        { owner: w.bDID },
      )
      await expectRejected(
        selfIssued,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [selfIssued] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('it is addressed to C but presented by B', async () => {
      const { w, one, store } = await setup()
      const cWrapping = await wrappingFor(w, 'key-1', 3, w.cDID)
      await expectRejected(
        cWrapping,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [cWrapping] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('it is for another key', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const two = await keyRecords(w, 'key-2', 3)
      const { store } = memoryStore([one.key, one.branch, ...one.entries, two.branch])
      const keyTwo = await wrappingFor(w, 'key-2', 3, w.bDID)
      const ctx = contextFor(w, { peerDID: w.b.id }, { store, proofs: [keyTwo] })
      // Valid for key-2, and still earns nothing for key-1.
      expect(await verifyHolderProof(keyTwo, ctx)).toBe(true)
      expect(await visibleTo(one.entries[0] as SignedRecord, ['keyHolder'], ctx)).toBe(false)
      expect(await visibleTo(one.key, ['keyHolder'], ctx)).toBe(false)
    })

    test('it is older than the responder current key version', async () => {
      const w = world()
      const v2 = await keyRecords(w, 'key-1', 2)
      const one = await keyRecords(w, 'key-1', 3)
      const { store } = memoryStore([v2.branch, one.branch, ...one.entries])
      const old = await wrappingFor(w, 'key-1', 2, w.bDID)
      await expectRejected(
        old,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [old] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('the responder holds no current version for the key', async () => {
      const { w, one, store } = await setup()
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      const ctx = contextFor(w, { peerDID: w.b.id }, { store, proofs: [proof], current: {} })
      await expectRejected(proof, ctx, one.entries[0] as SignedRecord)
    })

    test('it is tombstoned', async () => {
      const { w, one, store } = await setup()
      const tombstone = await makeRecord(
        w.owner,
        WRAPPING,
        `key-1:${w.bDID}`,
        { keyID: 'key-1', keyVersion: 3, recipient: w.bDID },
        { deleted: true },
      )
      await expectRejected(
        tombstone,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [tombstone] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('its key-branch dependency is missing', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const { store } = memoryStore([one.key, ...one.entries])
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      await expectRejected(
        proof,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [proof] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('its key-branch dependency is at another version', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      // A branch row under the version-3 id that signs for version 2.
      const misfiled = await makeRecord(w.owner, BRANCH, 'key-1:3', {
        keyID: 'key-1',
        keyVersion: 2,
      })
      const { store } = memoryStore([one.key, misfiled, ...one.entries])
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      await expectRejected(
        proof,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [proof] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('it is a record of a type that does not prove holding', async () => {
      const { w, one, store } = await setup()
      // A revocation names a key and a recipient too, and must never count as a wrapping.
      const revocation = await makeRecord(w.owner, REVOCATION, `key-1:${w.bDID}`, {
        keyID: 'key-1',
        keyVersion: 3,
        recipient: w.bDID,
      })
      await expectRejected(
        revocation,
        contextFor(w, { peerDID: w.b.id }, { store, proofs: [revocation] }),
        one.entries[0] as SignedRecord,
      )
    })

    test('it is hostile garbage, without throwing', async () => {
      const { w, one, store } = await setup()
      const genuine = await wrappingFor(w, 'key-1', 3, w.bDID)
      const hostile: Array<SignedRecord> = [
        { ...genuine, opJWT: 'not-a-token' },
        { ...genuine, opJWT: '' },
        { ...genuine, id: 'other' },
        await makeRecord(w.owner, WRAPPING, 'bad-recipient', {
          keyID: 'key-1',
          keyVersion: 3,
          recipient: 'not a did',
        }),
        await makeRecord(w.owner, WRAPPING, 'bad-version', {
          keyID: 'key-1',
          keyVersion: '3',
          recipient: w.bDID,
        }),
        await makeRecord(w.owner, WRAPPING, 'bad-key', {
          keyID: 1,
          keyVersion: 3,
          recipient: w.bDID,
        }),
        await makeRecord(w.owner, WRAPPING, 'no-meta', {}),
      ]
      const ctx = contextFor(w, { peerDID: w.b.id }, { store, proofs: hostile })
      for (const proof of hostile) {
        expect(await verifyHolderProof(proof, ctx)).toBe(false)
      }
      expect(await visibleTo(one.entries[0] as SignedRecord, ['keyHolder'], ctx)).toBe(false)
    })

    test('the authorizer throws', async () => {
      const { w, one, store } = await setup()
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      const ctx: VisibilityContext = {
        ...contextFor(w, { peerDID: w.b.id }, { store, proofs: [proof] }),
        authorizeProof: async () => {
          throw new Error('resolver refused a hostile DID')
        },
      }
      await expectRejected(proof, ctx, one.entries[0] as SignedRecord)
    })
  })

  describe('with a permissive authorizer and no dependencies, a proof still earns nothing when', () => {
    /** Only the proof checks themselves stand between the requester and the entries. */
    async function bareContext(w: World, proofs: ReadonlyArray<SignedRecord>) {
      const { store } = memoryStore()
      const bare: RecordTypeDefinition = {
        ...wrappingDefinition(w.ownerDID),
        dependencies: () => [],
      }
      return {
        ...contextFor(w, { peerDID: w.b.id }, { store, proofs }),
        authorizeProof: async () => true,
        holderTypes: new Map([[WRAPPING, bare]]),
      }
    }

    test('its indexed fields do not match its op', async () => {
      const w = world()
      const genuine = await wrappingFor(w, 'key-1', 3, w.bDID)
      const moved = { ...genuine, id: 'other' }
      const ctx = await bareContext(w, [moved])
      expect(await verifyHolderProof(genuine, ctx)).toBe(true)
      expect(await verifyHolderProof(moved, ctx)).toBe(false)
    })

    test('its key version is not a number', async () => {
      const w = world()
      const spelled = await wrappingFor(w, 'key-1', 3, w.bDID)
      const asString = await makeRecord(w.owner, WRAPPING, 'as-string', {
        keyID: 'key-1',
        keyVersion: '3',
        recipient: w.bDID,
      })
      const missing = await makeRecord(w.owner, WRAPPING, 'missing', {
        keyID: 'key-1',
        recipient: w.bDID,
      })
      const ctx = await bareContext(w, [asString, missing])
      expect(await verifyHolderProof(spelled, ctx)).toBe(true)
      expect(await verifyHolderProof(asString, ctx)).toBe(false)
      expect(await verifyHolderProof(missing, ctx)).toBe(false)
    })
  })

  describe('a holding is bound to the record owner and the stored row', () => {
    /** Owner binding as a real authorizer does it: any op whose owner is its signer. */
    function permissive(w: World): RecordTypeDefinition {
      return {
        ...wrappingDefinition(w.ownerDID),
        authorize: async (op) => op.issuer === op.claim.owner,
      }
    }

    test('a wrapping B signed for itself earns nothing for the owner records', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const { store } = memoryStore([one.key, one.branch, ...one.entries])
      const selfSigned = await makeRecord(
        w.b,
        WRAPPING,
        `key-1:${w.bDID}:self`,
        { keyID: 'key-1', keyVersion: 3, recipient: w.bDID },
        { owner: w.bDID },
      )
      const ownBranch = await makeRecord(
        w.b,
        BRANCH,
        'key-1:3',
        { keyVersion: 3 },
        { owner: w.bDID },
      )
      await store.putCopy(ownBranch)
      const ctx = contextFor(
        w,
        { peerDID: w.b.id },
        {
          store,
          proofs: [selfSigned],
          definition: permissive(w),
          // Even a responder that knows B's own key-1 at the same version.
          currentByOwner: { [w.bDID]: { 'key-1': 3 } },
        },
      )
      // A well-formed holding of B's own key-1, which is not the owner's key-1.
      expect(await verifyHolderProof(selfSigned, ctx)).toBe(true)
      expect(await visibleTo(one.entries[0] as SignedRecord, ['keyHolder'], ctx)).toBe(false)
      expect(await visibleTo(one.key, ['keyHolder'], ctx)).toBe(false)
    })

    test('a proof under a stored row of another owner earns nothing', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const stored = await wrappingFor(w, 'key-1', 3, w.cDID)
      const { store } = memoryStore([one.branch, stored])
      const takeover = await makeRecord(
        w.b,
        WRAPPING,
        stored.id,
        { keyID: 'key-1', keyVersion: 3, recipient: w.bDID },
        { owner: w.bDID },
      )
      const ctx = contextFor(
        w,
        { peerDID: w.b.id },
        { store, proofs: [takeover], definition: permissive(w) },
      )
      expect(await verifyHolderProof(takeover, ctx)).toBe(false)
    })

    test('a proof whose stored row is a tombstone earns nothing, even when newer', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const tombstone = await makeRecord(
        w.owner,
        WRAPPING,
        `key-1:${w.bDID}`,
        { keyID: 'key-1', keyVersion: 3, recipient: w.bDID },
        { deleted: true },
      )
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      const { store } = memoryStore([one.branch, ...one.entries, tombstone])
      const ctx = contextFor(
        w,
        { peerDID: w.b.id },
        { store, proofs: [proof], definition: permissive(w) },
      )
      expect(await verifyHolderProof(proof, ctx)).toBe(false)
      expect(await visibleTo(one.entries[0] as SignedRecord, ['keyHolder'], ctx)).toBe(false)
    })

    test('a proof older than the stored row earns nothing', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      const newer = await wrappingFor(w, 'key-1', 3, w.bDID)
      const { store } = memoryStore([one.branch, newer])
      const ctx = contextFor(
        w,
        { peerDID: w.b.id },
        { store, proofs: [proof], definition: permissive(w) },
      )
      expect(await verifyHolderProof(proof, ctx)).toBe(false)
      expect(await verifyHolderProof(newer, ctx)).toBe(true)
    })

    test('a forked proof loses by content digest even when its op hash is greater', async () => {
      const w = world()
      const base = await wrappingFor(w, 'key-1', 3, w.bDID)
      const verified = await verifySignedRecord(base)
      if (verified === null) throw new Error('Signed wrapping did not verify')
      const copies: Array<{ record: SignedRecord; digest: string }> = []
      for (let value = 0; value < 12; value++) {
        const payload = new Uint8Array([value])
        const claim = { ...verified.claim, payloadDigest: recordPayloadDigest(payload) }
        const record = { ...base, payload, ...(await signRecordOp(w.owner, claim)) }
        copies.push({ record, digest: decisionOf(record).contentDigest })
      }
      const opposed = copies.flatMap((proof) =>
        copies
          .filter(
            (stored) => proof.digest < stored.digest && proof.record.opHash > stored.record.opHash,
          )
          .map((stored) => ({ proof: proof.record, stored: stored.record })),
      )[0]
      if (opposed === undefined) throw new Error('No opposed digest and op-hash pair')
      const { store } = memoryStore([opposed.stored])
      const definition: RecordTypeDefinition = {
        ...wrappingDefinition(w.ownerDID),
        policy: { kind: 'monotonic', version: () => [3] },
        onEqual: () => 'fork',
        dependencies: () => [],
      }
      const ctx = {
        ...contextFor(w, { peerDID: w.b.id }, { store, definition }),
        authorizeProof: async () => true,
      }
      expect(await verifyHolderProof(opposed.proof, ctx)).toBe(false)
      expect(await verifyHolderProof(opposed.stored, ctx)).toBe(true)
    })

    test('a legitimate proof still earns, whether the responder holds it or is behind', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const older = await wrappingFor(w, 'key-1', 3, w.bDID)
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      for (const held of [proof, older]) {
        const { store } = memoryStore([one.key, one.branch, ...one.entries, held])
        const ctx = contextFor(
          w,
          { peerDID: w.b.id },
          { store, proofs: [proof], definition: permissive(w) },
        )
        expect(await verifyHolderProof(proof, ctx)).toBe(true)
        expect(await visibleTo(one.entries[0] as SignedRecord, ['keyHolder'], ctx)).toBe(true)
      }
    })

    test('the authorizer sees the stored row, not a first write', async () => {
      const w = world()
      const one = await keyRecords(w, 'key-1', 3)
      const older = await wrappingFor(w, 'key-1', 3, w.bDID)
      const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
      const { store } = memoryStore([one.branch, older])
      const seen: Array<SignedRecord | null> = []
      const ctx: VisibilityContext = {
        ...contextFor(w, { peerDID: w.b.id }, { store, proofs: [proof] }),
        authorizeProof: async (_record, stored) => {
          seen.push(stored)
          return true
        },
      }
      expect(await verifyHolderProof(proof, ctx)).toBe(true)
      expect(seen.map((record) => record?.opHash)).toEqual([older.opHash])
    })
  })

  test('a key version must be a non-negative safe integer', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const { store } = memoryStore([one.branch])
    const bare: RecordTypeDefinition = { ...wrappingDefinition(w.ownerDID), dependencies: () => [] }
    const proofAt = async (keyVersion: number) =>
      await makeRecord(w.owner, WRAPPING, `at-${keyVersion}`, {
        keyID: 'key-1',
        keyVersion,
        recipient: w.bDID,
      })
    const valid = await proofAt(3)
    const ctx = contextFor(w, { peerDID: w.b.id }, { store, proofs: [valid], definition: bare })
    expect(await verifyHolderProof(valid, ctx)).toBe(true)
    for (const keyVersion of [3.5, 1e300]) {
      expect(await verifyHolderProof(await proofAt(keyVersion), ctx)).toBe(false)
    }
    // A guarded record whose own key version is malformed is visible to no holder.
    const entryAt = async (keyVersion: number) =>
      await makeRecord(w.owner, ENTRY, `entry-${keyVersion}`, { keyID: 'key-1', keyVersion })
    expect(await visibleTo(await entryAt(3), ['keyHolder'], ctx)).toBe(true)
    for (const keyVersion of [3.5, 1e300, -1]) {
      expect(await visibleTo(await entryAt(keyVersion), ['keyHolder'], ctx)).toBe(false)
    }
  })

  test('a current key version is read for the owner of the key, not the key id alone', async () => {
    const w = world()
    const other = randomIdentity()
    const otherDID = normalizeDID(other.id)
    // Both owners name a key `key-1`; the world owner's is at version 2, the other's at 5.
    const ownerEntry = await makeRecord(w.owner, ENTRY, 'owner-entry', {
      keyID: 'key-1',
      keyVersion: 2,
    })
    const otherEntry = await makeRecord(other, ENTRY, 'other-entry', {
      keyID: 'key-1',
      keyVersion: 5,
    })
    const ownerProof = await makeRecord(w.owner, WRAPPING, 'owner-wrap', {
      keyID: 'key-1',
      keyVersion: 2,
      recipient: w.bDID,
    })
    const otherProof = await makeRecord(other, WRAPPING, 'other-wrap', {
      keyID: 'key-1',
      keyVersion: 2,
      recipient: w.bDID,
    })
    const { store } = memoryStore([ownerEntry, otherEntry])
    const bare: RecordTypeDefinition = {
      ...wrappingDefinition(w.ownerDID),
      authorize: async (op) => op.issuer === op.claim.owner,
      dependencies: () => [],
    }
    const ctx = contextFor(
      w,
      { peerDID: w.b.id },
      {
        store,
        proofs: [ownerProof, otherProof],
        current: { 'key-1': 2 },
        currentByOwner: { [otherDID]: { 'key-1': 5 } },
        definition: bare,
      },
    )
    expect(await verifyHolderProof(ownerProof, ctx)).toBe(true)
    expect(await verifyHolderProof(otherProof, ctx)).toBe(false)
    expect(await visibleTo(ownerEntry, ['keyHolder'], ctx)).toBe(true)
    expect(await visibleTo(otherEntry, ['keyHolder'], ctx)).toBe(false)
  })

  test('a responder with no holder types admits no key holder', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const proof = await wrappingFor(w, 'key-1', 3, w.bDID)
    const { store } = memoryStore([one.branch, proof])
    const ctx: VisibilityContext = {
      ...contextFor(w, { peerDID: w.b.id }, { store, proofs: [proof] }),
      holderTypes: new Map(),
    }
    expect(await verifyHolderProof(proof, ctx)).toBe(false)
    expect(await visibleTo(one.entries[0] as SignedRecord, ['keyHolder'], ctx)).toBe(false)
  })
})

describe('sharedWith', () => {
  test('a named DID, the controller it acts for, or a named group member is a share target', async () => {
    const w = world()
    const controller = normalizeDID(randomIdentity().id)
    const toB = await makeRecord(w.owner, SHARED, 'to-b', { sharedWith: [w.bDID] })
    const toController = await makeRecord(w.owner, SHARED, 'to-controller', {
      sharedWith: [controller],
    })
    const toGroup = await makeRecord(w.owner, SHARED, 'to-group', { sharedWithGroups: ['g1'] })
    const toOther = await makeRecord(w.owner, SHARED, 'to-other', {
      sharedWith: [w.cDID],
      sharedWithGroups: ['g2'],
    })
    // Fields of the wrong shape: a bare DID where a list belongs, a number as a group id.
    const bareDID = await makeRecord(w.owner, SHARED, 'bare-did', { sharedWith: w.bDID })
    const numericGroup = await makeRecord(w.owner, SHARED, 'numeric-group', {
      sharedWithGroups: [1],
    })
    const { store } = memoryStore()
    const ctx = contextFor(
      w,
      { peerDID: w.b.id, controllerDID: controller },
      { store, groups: { g1: [w.bDID], g2: [w.cDID], '1': [w.bDID] } },
    )
    const results = await Promise.all(
      [toB, toController, toGroup, toOther, bareDID, numericGroup].map((record) =>
        visibleTo(record, ['sharedWith'], ctx),
      ),
    )
    expect(results).toEqual([true, true, true, false, false, false])
  })
})

describe('owner offline', () => {
  test('B obtains the key and entries from C, and neither receives the other wrapping', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const bWrapping = await wrappingFor(w, 'key-1', 3, w.bDID)
    const cWrapping = await wrappingFor(w, 'key-1', 3, w.cDID)

    // C, a co-recipient, holds its own wrapping and never B's.
    const cHolds = [one.key, one.branch, ...one.entries, cWrapping]
    const atC = memoryStore(cHolds)
    const bAsksC = contextFor(w, { peerDID: w.b.id }, { store: atC.store, proofs: [bWrapping] })
    const toB = await filterVisibleRecords(cHolds, typesWithVisibility(), bAsksC)
    expect(ids(toB)).toEqual(ids([one.key, one.branch, ...one.entries]))
    expect(toB.map((record) => record.opHash)).not.toContain(bWrapping.opHash)
    expect(atC.writes).toEqual([])

    // B, answering C in turn, holds its own wrapping and never serves it to C.
    const bHolds = [one.key, one.branch, ...one.entries, bWrapping]
    const atB = memoryStore(bHolds)
    const cAsksB = contextFor(w, { peerDID: w.c.id }, { store: atB.store, proofs: [cWrapping] })
    const toC = await filterVisibleRecords(bHolds, typesWithVisibility(), cAsksB)
    expect(ids(toC)).toEqual(ids([one.key, one.branch, ...one.entries]))
    expect(atB.writes).toEqual([])
  })

  test('an owner device holding every wrapping serves each recipient only its own', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const bWrapping = await wrappingFor(w, 'key-1', 3, w.bDID)
    const cWrapping = await wrappingFor(w, 'key-1', 3, w.cDID)
    const held = [one.key, one.branch, ...one.entries, bWrapping, cWrapping]
    const { store } = memoryStore(held)
    const toC = await filterVisibleRecords(
      held,
      typesWithVisibility(),
      contextFor(w, { peerDID: w.c.id }, { store }),
    )
    expect(ids(toC)).toEqual(ids([one.key, one.branch, ...one.entries, cWrapping]))
  })

  test('a revoked B with its old proof receives no current entries', async () => {
    const w = world()
    const v3 = await keyRecords(w, 'key-1', 3)
    const v4 = await keyRecords(w, 'key-1', 4)
    const oldB = await wrappingFor(w, 'key-1', 3, w.bDID)
    const cWrapping = await wrappingFor(w, 'key-1', 4, w.cDID)
    // C rotated past B to version 4; the version-3 branch is still stored.
    const cHolds = [v4.key, v3.branch, v4.branch, ...v4.entries, cWrapping]
    const { store } = memoryStore(cHolds)
    const ctx = contextFor(
      w,
      { peerDID: w.b.id },
      { store, proofs: [oldB], current: { 'key-1': 4 } },
    )
    expect(await verifyHolderProof(oldB, ctx)).toBe(false)
    expect(await filterVisibleRecords(cHolds, typesWithVisibility(), ctx)).toEqual([])
    // Nor does an old wrapping for B still sitting in the responder's own store.
    const stale = memoryStore([...cHolds, oldB])
    const fromStore = contextFor(
      w,
      { peerDID: w.b.id },
      { store: stale.store, current: { 'key-1': 4 } },
    )
    expect(await filterVisibleRecords(cHolds, typesWithVisibility(), fromStore)).toEqual([])
  })
})

describe('the responder filters before it answers', () => {
  async function leavesOf(
    records: ReadonlyArray<SignedRecord>,
    type: string,
  ): Promise<Array<RangeLeaf>> {
    const leaves: Array<RangeLeaf> = []
    for (const record of records) {
      if (record.type !== type) {
        continue
      }
      const op = await verifySignedRecord(record)
      const leaf = op === null ? null : rangeLeaf(decisionOf(record), LWW)
      if (leaf !== null) {
        leaves.push(leaf)
      }
    }
    return leaves
  }

  test('hidden records change neither fingerprints, nor leaves, nor get results', async () => {
    const w = world()
    const one = await keyRecords(w, 'key-1', 3)
    const two = await keyRecords(w, 'key-2', 3)
    const bWrapping = await wrappingFor(w, 'key-1', 3, w.bDID)
    const cWrapping = await wrappingFor(w, 'key-1', 3, w.cDID)
    const cTwo = await wrappingFor(w, 'key-2', 3, w.cDID)
    const visibleSet = [one.key, one.branch, ...one.entries, bWrapping]
    const hidden = [cWrapping, cTwo, two.key, two.branch, ...two.entries]

    const full = memoryStore([...visibleSet, ...hidden])
    const bare = memoryStore(visibleSet)
    const types = typesWithVisibility()
    const answersFor = async (store: RecordStoreAdapter) => {
      const ctx = contextFor(w, { peerDID: w.b.id }, { store })
      const all = await store.list([...types.keys()])
      const visible = await filterVisibleRecords(
        all.flatMap((decision) => decision.copies),
        types,
        ctx,
      )
      const answers: Record<string, unknown> = {}
      for (const type of [KEY, BRANCH, WRAPPING, ENTRY]) {
        const bounds: RangeBounds = { type, lower: null, upper: null }
        const leaves = await leavesOf(visible, type)
        answers[type] = {
          summary: summarizeRange(leaves, bounds),
          split: splitRange(leaves, bounds, RANGE_LEAF_THRESHOLD),
        }
      }
      const requested = await Promise.all(
        [...visibleSet, ...hidden].map((record) => store.get(record)),
      )
      const got = await filterVisibleRecords(
        requested.flatMap((decision) => decision?.copies ?? []),
        types,
        ctx,
      )
      return { answers, got: ids(got) }
    }

    const withHidden = await answersFor(full.store)
    const without = await answersFor(bare.store)
    expect(withHidden).toEqual(without)
    expect(withHidden.got).toEqual(ids(visibleSet))
    // What B learns is the count of what it may see: two entries of key-1, nothing of key-2.
    const entries = withHidden.answers[ENTRY] as { summary: { count: number } }
    expect(entries.summary.count).toBe(2)
  })

  test('a type with no visibility hook, or an unregistered type, is never sent', async () => {
    const w = world()
    const { store } = memoryStore()
    const bare = await makeRecord(w.owner, 'test.bare', 'one', {})
    const unknown = await makeRecord(w.owner, 'test.unknown', 'one', {})
    const types = new Map<string, RecordTypeDefinition>([
      [
        'test.bare',
        {
          type: 'test.bare',
          policy: LWW,
          dependsOn: [],
          authorize: async () => true,
          dependencies: () => [],
        },
      ],
    ])
    const ctx = contextFor(w, { peerDID: w.owner.id }, { store })
    expect(await filterVisibleRecords([bare, unknown], types, ctx)).toEqual([])
  })

  test('a record that no longer verifies is visible to no one', async () => {
    const w = world()
    const { store } = memoryStore()
    const key = await makeRecord(w.owner, KEY, 'key-1', { keyID: 'key-1', version: 3 })
    const tampered = { ...key, owner: w.bDID }
    const ctx = contextFor(w, { peerDID: w.b.id }, { store })
    expect(await visibleTo(tampered, ['ownerDevices'], ctx)).toBe(false)
  })
})
